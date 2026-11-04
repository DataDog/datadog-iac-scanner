/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"os"
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

	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
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

	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
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

func writeDirectiveStack(t *testing.T, directive string, files map[string]string) string {
	t.Helper()
	dir := writeModule(t, t.TempDir(), "stack", map[string]string{
		"main.tf": "// dd_terraform_vars: " + directive + "\nvariable \"region\" {}\n",
	})
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	}
	return dir
}

func TestLoadRootVarsDirectiveRelative(t *testing.T) {
	dir := writeDirectiveStack(t, "vars/custom.tfvars", map[string]string{"vars/custom.tfvars": `region = "eu"`})
	require.Equal(t, map[string]cty.Value{"region": cty.StringVal("eu")}, New().LoadRootVars(dir))
}

func TestLoadRootVarsDirectiveLeadingSlashUnderDir(t *testing.T) {
	dir := writeDirectiveStack(t, "/vars/custom.tfvars", map[string]string{"vars/custom.tfvars": `region = "eu"`})
	require.Equal(t, map[string]cty.Value{"region": cty.StringVal("eu")}, New().LoadRootVars(dir))
}

func TestLoadRootVarsDirectiveAbsoluteOutsideDirSkipped(t *testing.T) {
	varsFile := filepath.Join(t.TempDir(), "custom.tfvars")
	require.NoError(t, os.WriteFile(varsFile, []byte(`region = "eu"`), 0o600))
	dir := writeDirectiveStack(t, filepath.ToSlash(varsFile), map[string]string{"terraform.tfvars": `region = "us"`})
	require.Equal(t, map[string]cty.Value{"region": cty.StringVal("us")}, New().LoadRootVars(dir))
}

func TestLoadRootVarsDirectiveBackslash(t *testing.T) {
	dir := writeDirectiveStack(t, `vars\custom.tfvars`, map[string]string{"vars/custom.tfvars": `region = "eu"`})
	require.Equal(t, map[string]cty.Value{"region": cty.StringVal("eu")}, New().LoadRootVars(dir))
}

func TestLoadRootVarsDirectiveOverridesAutoloaded(t *testing.T) {
	dir := writeDirectiveStack(t, "vars/custom.tfvars", map[string]string{
		"vars/custom.tfvars": "region = \"eu\"\nonly_directive = \"d\"\n",
		"terraform.tfvars":   "region = \"us\"\nonly_auto = \"a\"\n",
	})
	require.Equal(t, map[string]cty.Value{
		"region":         cty.StringVal("eu"),
		"only_directive": cty.StringVal("d"),
		"only_auto":      cty.StringVal("a"),
	}, New().LoadRootVars(dir))
}

func TestLoadRootVarsDirectiveMissingFile(t *testing.T) {
	dir := writeDirectiveStack(t, "vars/absent.tfvars", map[string]string{"terraform.tfvars": `region = "us"`})
	require.Equal(t, map[string]cty.Value{"region": cty.StringVal("us")}, New().LoadRootVars(dir))
}

func TestLoadRootVarsDirectiveOfShadowedFileIgnored(t *testing.T) {
	dir := writeDirectiveStack(t, "a.tfvars", map[string]string{
		"main.tofu": "// dd_terraform_vars: b.tfvars\nvariable \"region\" {}\n",
		"a.tfvars":  `region = "a"`,
		"b.tfvars":  `region = "b"`,
	})
	require.Equal(t, map[string]cty.Value{"region": cty.StringVal("b")}, New().LoadRootVars(dir))
}

func TestLoadRootVarsLegacyDirectiveAlias(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "stack", map[string]string{
		"main.tf":       "// kics_terraform_vars: custom.tfvars\nvariable \"region\" {}\n",
		"custom.tfvars": `region = "eu"`,
	})
	require.Equal(t, map[string]cty.Value{"region": cty.StringVal("eu")}, New().LoadRootVars(dir))
}

func TestLoadRootVarsVariablesFixture(t *testing.T) {
	vars := New().LoadRootVars(filepath.Join("..", "..", "..", "..", "test", "fixtures", "test_terraform_variables"))
	require.Equal(t, map[string]cty.Value{
		"test1":          cty.BoolVal(false),
		"test2":          cty.TupleVal([]cty.Value{cty.BoolVal(false), cty.BoolVal(true)}),
		"map1":           cty.ObjectVal(map[string]cty.Value{"map1key1": cty.StringVal("map2Key1")}),
		"map2":           cty.ObjectVal(map[string]cty.Value{"map2Key1": cty.StringVal("nestedMap")}),
		"map3":           cty.ObjectVal(map[string]cty.Value{"map3Key1": cty.StringVal("givenByVar")}),
		"test_terraform": cty.StringVal("terraform.tfvars"),
	}, vars)
}

func TestLoadRootVarsSkipsInvalidVarsFile(t *testing.T) {
	dir := writeModule(t, t.TempDir(), "stack", map[string]string{
		"terraform.tfvars":   `region = "us"`,
		"broken.auto.tfvars": "variable \"x\" {\n  default = 1\n}\n",
		"zz_ok.auto.tfvars":  `env = "prod"`,
	})
	require.Equal(t, map[string]cty.Value{"region": cty.StringVal("us"), "env": cty.StringVal("prod")}, New().LoadRootVars(dir))
}
