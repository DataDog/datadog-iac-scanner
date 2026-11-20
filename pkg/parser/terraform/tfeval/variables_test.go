/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func resourcesByAddress(resources []ResolvedResource) map[string]ResolvedResource {
	out := make(map[string]ResolvedResource, len(resources))
	for _, r := range resources {
		out[r.ModuleAddress+"/"+r.Type+"."+r.Name] = r
	}
	return out
}

func TestEvaluateModule_VariableTypesShapeInputs(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "bucket", map[string]string{
		"main.tf": `
variable "names" { type = set(string) }
variable "settings" {
  type = object({
    versioning = optional(bool, true)
    encryption = optional(string, "aws:kms")
  })
}
variable "acl" {
  type     = string
  default  = "private"
  nullable = false
}
variable "replicas" { type = number }

resource "aws_s3_bucket" "this" {
  for_each   = var.names
  bucket     = each.key
  versioning = var.settings.versioning
  encryption = var.settings.encryption
  acl        = var.acl
  count_like = var.replicas + 1
}
`,
	})
	stack := writeModule(t, root, "stack", map[string]string{
		"main.tf": `
module "bucket" {
  source   = "../bucket"
  names    = ["logs", "data"]
  settings = { versioning = false }
  acl      = null
  replicas = "2"
}
`,
	})

	evaluation, err := New().EvaluateModule(context.Background(), stack, nil)
	resources := evaluation.Resources
	require.NoError(t, err)
	require.Len(t, resources, 2, "a list passed to a set(string) variable must expand for_each")

	byAddr := resourcesByAddress(resources)
	logs, ok := byAddr[`module.bucket/aws_s3_bucket.this["logs"]`]
	require.True(t, ok, "resources: %v", byAddr)
	require.True(t, logs.Attributes["versioning"].False(), "a value the caller sets wins over the optional default")
	requireString(t, logs.Attributes, "encryption", "aws:kms")
	requireString(t, logs.Attributes, "acl", "private")
	require.True(t, logs.Attributes["count_like"].RawEquals(cty.NumberIntVal(3)), "count_like = %#v", logs.Attributes["count_like"])
}

func TestEvaluateModule_PartlyKnownLocalsKeepKnownParts(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
variable "kms_key_arn" {}

locals {
  base = {
    encrypted = true
    kms_key   = var.kms_key_arn
  }
  config = merge(local.base, { name = "logs" })
}

resource "aws_ebs_volume" "v" {
  encrypted  = local.config.encrypted
  kms_key_id = local.config.kms_key
  tags       = { Name = local.config.name }
}
`,
	})

	evaluation, err := New().EvaluateModule(context.Background(), dir, nil)
	resources := evaluation.Resources
	require.NoError(t, err)
	v := findResource(t, resources, "aws_ebs_volume", "v")
	require.True(t, v.Attributes["encrypted"].True())
	require.False(t, v.Attributes["kms_key_id"].IsKnown())
	require.True(t, v.Attributes["tags"].GetAttr("Name").RawEquals(cty.StringVal("logs")))
}

func TestCanonicalInputsKeyKeepsKnownPartsOfPartlyUnknownValues(t *testing.T) {
	a := canonicalInputsKey(map[string]cty.Value{"cfg": cty.ObjectVal(map[string]cty.Value{
		"name": cty.StringVal("a"), "arn": cty.UnknownVal(cty.String),
	})})
	b := canonicalInputsKey(map[string]cty.Value{"cfg": cty.ObjectVal(map[string]cty.Value{
		"name": cty.StringVal("b"), "arn": cty.UnknownVal(cty.String),
	})})
	require.NotEqual(t, a, b)
}

func TestCanonicalInputsKeyDistinguishesCollectionTypes(t *testing.T) {
	elem := cty.UnknownVal(cty.String)
	listKey := canonicalInputsKey(map[string]cty.Value{"v": cty.ListVal([]cty.Value{elem})})
	tupleKey := canonicalInputsKey(map[string]cty.Value{"v": cty.TupleVal([]cty.Value{elem})})
	setKey := canonicalInputsKey(map[string]cty.Value{"v": cty.SetVal([]cty.Value{elem})})
	require.NotEqual(t, listKey, tupleKey)
	require.NotEqual(t, listKey, setKey)
	require.NotEqual(t, tupleKey, setKey)

	mapKey := canonicalInputsKey(map[string]cty.Value{"v": cty.MapVal(map[string]cty.Value{"k": elem})})
	objKey := canonicalInputsKey(map[string]cty.Value{"v": cty.ObjectVal(map[string]cty.Value{"k": elem})})
	require.NotEqual(t, mapKey, objKey)
}

func TestCanonicalInputsKeyDistinguishesWhollyKnownCollections(t *testing.T) {
	known := []cty.Value{cty.NumberIntVal(1), cty.NumberIntVal(2)}
	require.NotEqual(t,
		canonicalInputsKey(map[string]cty.Value{"v": cty.ListVal(known)}),
		canonicalInputsKey(map[string]cty.Value{"v": cty.SetVal(known)}),
	)
	require.NotEqual(t,
		canonicalInputsKey(map[string]cty.Value{"v": cty.ListValEmpty(cty.Number)}),
		canonicalInputsKey(map[string]cty.Value{"v": cty.SetValEmpty(cty.Number)}),
	)
	require.NotEqual(t,
		canonicalInputsKey(map[string]cty.Value{"v": cty.MapVal(map[string]cty.Value{"k": cty.StringVal("x")})}),
		canonicalInputsKey(map[string]cty.Value{"v": cty.ObjectVal(map[string]cty.Value{"k": cty.StringVal("x")})}),
	)
}

func TestCanonicalInputsKeyKeepsTypeOnNestedWhollyKnownCollections(t *testing.T) {
	// Partly known parent with a wholly known nested collection: cty/json would
	// encode both list and set as bare "[1,2]"; the typed walk must keep the type.
	known := []cty.Value{cty.NumberIntVal(1), cty.NumberIntVal(2)}
	listKey := encodeCtyForKey(cty.ObjectVal(map[string]cty.Value{
		"nested": cty.ListVal(known),
		"u":      cty.UnknownVal(cty.String),
	}))
	setKey := encodeCtyForKey(cty.ObjectVal(map[string]cty.Value{
		"nested": cty.SetVal(known),
		"u":      cty.UnknownVal(cty.String),
	}))
	require.NotEqual(t, listKey, setKey)
	require.Contains(t, listKey, `nested":list of number[`)
	require.Contains(t, setKey, `nested":set of number[`)
	require.NotContains(t, listKey, `nested":[`)
	require.NotContains(t, setKey, `nested":[`)
}

func TestCanonicalInputsKeyObjectAttributeOrderStable(t *testing.T) {
	a := canonicalInputsKey(map[string]cty.Value{"v": cty.ObjectVal(map[string]cty.Value{
		"z": cty.StringVal("z"),
		"a": cty.StringVal("a"),
		"m": cty.UnknownVal(cty.String),
	})})
	b := canonicalInputsKey(map[string]cty.Value{"v": cty.ObjectVal(map[string]cty.Value{
		"m": cty.UnknownVal(cty.String),
		"a": cty.StringVal("a"),
		"z": cty.StringVal("z"),
	})})
	require.Equal(t, a, b)
}

func TestLoadRootVarsReadsJSONAndAppliesTerraformPrecedence(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "stack", map[string]string{
		"terraform.tfvars":      `env = "base"` + "\n" + `region = "us-east-1"`,
		"terraform.tfvars.json": `{"env": "json", "tags": {"team": "sec"}}`,
		"a.auto.tfvars":         `env = "auto"`,
		"b.auto.tfvars.json":    `{"region": "eu-west-1"}`,
	})

	vars := New().LoadRootVars(dir)
	require.True(t, vars["env"].RawEquals(cty.StringVal("auto")))
	require.True(t, vars["region"].RawEquals(cty.StringVal("eu-west-1")))
	require.Equal(t, "sec", vars["tags"].GetAttr("team").AsString())
}

func TestLoadRootVarsIgnoresCaseMismatchedAutoTfvars(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "stack", map[string]string{
		"terraform.tfvars":    `env = "base"`,
		"prod.AUTO.TFVARS":    `env = "upper"`,
		"prod.auto.TFVARS":    `env = "mixed"`,
		"ok.auto.tfvars":      `region = "eu-west-1"`,
		"ok.auto.TFVARS.json": `{"region": "us-east-1"}`,
	})

	vars := New().LoadRootVars(dir)
	require.True(t, vars["env"].RawEquals(cty.StringVal("base")), "case-mismatched auto.tfvars must not override terraform.tfvars")
	require.True(t, vars["region"].RawEquals(cty.StringVal("eu-west-1")), "case-mismatched *.auto.tfvars.json must not override")
}

func TestEvaluateModule_VariableConformanceOutcomes(t *testing.T) {
	objectType := cty.Object(map[string]cty.Type{"enabled": cty.Bool})
	optional := `type=object({enabled=optional(bool,true)})`
	nullableDefault := "type=string\ndefault=\"safe\""
	nonNullableDefault := nullableDefault + "\nnullable=false"
	for _, contextName := range []string{"root", "module"} {
		t.Run(contextName, func(t *testing.T) {
			for _, test := range []struct {
				name, body  string
				provided    bool
				input, want cty.Value
				failed      bool
			}{
				{"converted number", "type=number", true, cty.StringVal("2"), cty.NumberIntVal(2), false},
				{"invalid number", "type=number", true, cty.StringVal("private-input-marker"), cty.UnknownVal(cty.Number), true},
				{"unknown number", "type=number", true, cty.UnknownVal(cty.Number), cty.UnknownVal(cty.Number), false},
				{"dynamic unknown", "type=number", true, cty.DynamicVal, cty.UnknownVal(cty.Number), false},
				{"unmaterialized provided value", "type=number", true, cty.NilVal, cty.UnknownVal(cty.Number), true},
				{"missing input", "type=number", false, cty.NilVal, cty.UnknownVal(cty.Number), false},
				{"incompatible concrete boolean", "type=number", true, cty.True, cty.UnknownVal(cty.Number), true},
				{"incompatible unknown type", "type=number", true, cty.UnknownVal(cty.Bool), cty.UnknownVal(cty.Number), true},
				{"nullable explicit null", nullableDefault, true, cty.NullVal(cty.String), cty.NullVal(cty.String), false},
				{"nonnullable default fallback", nonNullableDefault, true, cty.NullVal(cty.String), cty.StringVal("safe"), false},
				{"nonnullable rejected null", "type=string\nnullable=false", true, cty.NullVal(cty.String), cty.UnknownVal(cty.String), true},
				{"nonnullable missing input", "type=string\nnullable=false", false, cty.NilVal, cty.UnknownVal(cty.String), false},
				{"invalid selected default", "type=number\ndefault=\"private-default-marker\"", false, cty.NilVal, cty.UnknownVal(cty.Number), true},
				{"converted selected default", "type=number\ndefault=\"2\"", false, cty.NilVal, cty.NumberIntVal(2), false},
				{"nonnullable null default", "type=string\nnullable=false\ndefault=null", false, cty.NilVal, cty.UnknownVal(cty.String), true},
				{"optional defaults", optional, true, cty.EmptyObjectVal, cty.ObjectVal(map[string]cty.Value{"enabled": cty.True}), false},
				{"optional explicit false", optional, true, cty.ObjectVal(map[string]cty.Value{"enabled": cty.False}), cty.ObjectVal(map[string]cty.Value{"enabled": cty.False}), false},
				{"optional nested null", optional, true, cty.ObjectVal(map[string]cty.Value{"enabled": cty.NullVal(cty.Bool)}), cty.ObjectVal(map[string]cty.Value{"enabled": cty.True}), false},
				{"optional unknown field", optional, true, cty.ObjectVal(map[string]cty.Value{"enabled": cty.UnknownVal(cty.Bool)}), cty.ObjectVal(map[string]cty.Value{"enabled": cty.UnknownVal(cty.Bool).RefineNotNull()}), false},
				{"top level null stays null", optional, true, cty.NullVal(objectType), cty.NullVal(objectType), false},
				{"invalid optional field", optional, true, cty.ObjectVal(map[string]cty.Value{"enabled": cty.StringVal("private-field-marker")}), cty.UnknownVal(objectType), true},
			} {
				// HCL module arguments cannot carry the absent-value Go API sentinel.
				if contextName == "module" && test.provided && test.input == cty.NilVal {
					continue
				}
				t.Run(test.name, func(t *testing.T) {
					base := t.TempDir()
					declaration := "variable \"setting\" {\n" + test.body + "\n}\n"
					// Keep one known fact independent of the conformance observation.
					declaration += `resource "test_resource" "observed" {value=var.setting}`
					dir := writeModule(t, base, "subject", map[string]string{"main.tf": declaration})
					input := map[string]cty.Value{}
					if test.provided {
						input["setting"] = test.input
					}
					copies := 1
					if contextName == "module" {
						argument := ""
						if test.provided {
							argument = "setting=var.input"
						}
						source := fmt.Sprintf(`variable "input" {}
module "left" {
source="../subject"
%s
}
module "right" {
source="../subject"
%s
}`, argument, argument)
						dir = writeModule(t, base, "root", map[string]string{"main.tf": source})
						input = map[string]cty.Value{}
						if test.provided {
							input["input"] = test.input
						}
						copies = 2
					}
					evaluator := New()
					for range 2 {
						result, err := evaluator.EvaluateModule(context.Background(), dir, input)
						require.NoError(t, err)
						require.Len(t, result.Resources, copies)
						for _, resource := range result.Resources {
							require.True(t, test.want.RawEquals(resource.Attributes["value"]), "got %#v", resource.Attributes["value"])
						}
						require.Equal(t, test.failed, result.PolicyUnit(nil).Failure() != nil)
						observations := result.InventoryObservations()
						require.True(t, observations.EvaluationCompleted)
						require.Empty(t, observations.Gaps, "an attribute-only variable failure does not establish an inventory gap")
						diagnostics := result.Diagnostics()
						if !test.failed {
							require.Empty(t, diagnostics)
							continue
						}
						require.Len(t, diagnostics, copies)
						addresses := map[string]bool{}
						for _, diagnostic := range diagnostics {
							require.Equal(t, filepath.Join(base, "subject", "main.tf"), diagnostic.Subject.Filename)
							require.Contains(t, diagnostic.Detail, "setting")
							require.NotContains(t, diagnostic.Detail, "private-")
							addresses[diagnostic.ModuleAddress] = true
						}
						if contextName == "root" {
							require.Equal(t, map[string]bool{"": true}, addresses)
						} else {
							require.Equal(t, map[string]bool{"module.left": true, "module.right": true}, addresses)
						}
					}
				})
			}
		})
	}
}

func TestEvaluateModule_VariableConformanceInputTransitions(t *testing.T) {
	for _, mode := range []string{"root", "module", "json"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			filename := "main.tf"
			source := `variable "input" {type=number}
resource "test_resource" "observed" {value=var.input}`
			if mode == "json" {
				filename = "main.tf.json"
				source = `{"variable":{"input":{"type":"number"}},"resource":{"test_resource":{"observed":{"value":"${var.input}"}}}}`
			}
			dir := writeModule(t, base, "subject", map[string]string{filename: source})
			if mode == "module" {
				dir = writeModule(t, base, "root", map[string]string{"main.tf": `variable "input" {}
module "subject" {
source="../subject"
input=var.input
}`})
			}
			evaluator := New()
			for _, test := range []struct {
				input, want cty.Value
				failed      bool
			}{
				{cty.True, cty.UnknownVal(cty.Number), true},
				{cty.StringVal("2"), cty.NumberIntVal(2), false},
				{cty.UnknownVal(cty.Number), cty.UnknownVal(cty.Number), false},
				{cty.NullVal(cty.Number), cty.NullVal(cty.Number), false},
				{cty.True, cty.UnknownVal(cty.Number), true},
			} {
				result, err := evaluator.EvaluateModule(context.Background(), dir, map[string]cty.Value{"input": test.input})
				require.NoError(t, err)
				require.Len(t, result.Resources, 1)
				require.True(t, test.want.RawEquals(result.Resources[0].Attributes["value"]), "got %#v", result.Resources[0].Attributes["value"])
				require.Equal(t, test.failed, result.PolicyUnit(nil).Failure() != nil)
				require.Empty(t, result.InventoryObservations().Gaps)
				if test.failed {
					diagnostics := result.Diagnostics()
					require.Len(t, diagnostics, 1)
					require.Equal(t, filepath.Join(base, "subject", filename), diagnostics[0].Subject.Filename)
					address := ""
					if mode == "module" {
						address = "module.subject"
					}
					require.Equal(t, address, diagnostics[0].ModuleAddress)
				} else {
					require.Empty(t, result.Diagnostics())
				}
			}
		})
	}
}
