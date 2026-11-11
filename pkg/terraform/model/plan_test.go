/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

// xplanPlan is the plan of fixture xplan: companions of a bucket of another
// root, with a value the configuration does not write.
const xplanPlan = `{"format_version":"1.2","terraform_version":"1.6.0",
 "planned_values":{"root_module":{"resources":[
  {"address":"aws_s3_bucket_logging.x","mode":"managed","type":"aws_s3_bucket_logging","name":"x","provider_name":"registry.terraform.io/hashicorp/aws","schema_version":0,
   "values":{"bucket":"acme-prod-customer-data","target_bucket":"logs","target_prefix":"p/"},"sensitive_values":{}},
  {"address":"aws_s3_bucket_versioning.x","mode":"managed","type":"aws_s3_bucket_versioning","name":"x","provider_name":"registry.terraform.io/hashicorp/aws","schema_version":0,
   "values":{"bucket":"acme-prod-customer-data","versioning_configuration":[{"status":"Enabled","mfa_delete":"Enabled"}]},"sensitive_values":{}}
 ]}},
 "resource_changes":[
  {"address":"aws_s3_bucket_logging.x","mode":"managed","type":"aws_s3_bucket_logging","name":"x","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":null,"after":{"bucket":"acme-prod-customer-data","target_bucket":"logs","target_prefix":"p/"},"after_unknown":{}}},
  {"address":"aws_s3_bucket_versioning.x","mode":"managed","type":"aws_s3_bucket_versioning","name":"x","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":null,"after":{"bucket":"acme-prod-customer-data","versioning_configuration":[{"status":"Enabled","mfa_delete":"Enabled"}]},"after_unknown":{}}}
 ],
 "configuration":{"root_module":{"resources":[
  {"address":"aws_s3_bucket_logging.x","mode":"managed","type":"aws_s3_bucket_logging","name":"x","provider_config_key":"aws","expressions":{"bucket":{"constant_value":"acme-prod-customer-data"},"target_bucket":{"constant_value":"logs"}},"schema_version":0},
  {"address":"aws_s3_bucket_versioning.x","mode":"managed","type":"aws_s3_bucket_versioning","name":"x","provider_config_key":"aws","expressions":{"bucket":{"constant_value":"acme-prod-customer-data"}},"schema_version":0}
 ]}}}
`

// dupplanPlan is the plan of fixture dupplan, next to the source of the same
// stack.
const dupplanPlan = `{"format_version":"1.2","terraform_version":"1.6.0",
 "planned_values":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.data","mode":"managed","type":"aws_s3_bucket","name":"data","provider_name":"registry.terraform.io/hashicorp/aws","schema_version":0,"values":{"bucket":"acme-prod-customer-data"},"sensitive_values":{}}]}},
 "resource_changes":[{"address":"aws_s3_bucket.data","mode":"managed","type":"aws_s3_bucket","name":"data","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":null,"after":{"bucket":"acme-prod-customer-data"},"after_unknown":{"id":true,"arn":true}}}],
 "configuration":{"root_module":{"resources":[{"address":"aws_s3_bucket.data","mode":"managed","type":"aws_s3_bucket","name":"data","provider_config_key":"aws","expressions":{"bucket":{"constant_value":"acme-prod-customer-data"}},"schema_version":0}]}}}
`

const dupplanSource = `resource "aws_s3_bucket" "data" {
  bucket = "acme-prod-customer-data"
}
`

func loadPlans(t *testing.T, files map[string]string, plans ...string) *Scan {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	paths := make([]string, len(plans))
	for i, p := range plans {
		paths[i] = filepath.Join(dir, p)
	}
	scan, err := Load(context.Background(), dir, Options{Plans: paths})
	require.NoError(t, err)
	return scan
}

func onlyInstance(t *testing.T, r *Root, kind, typ string) *Instance {
	t.Helper()
	blocks := blocksOf(r, kind, typ)
	require.Len(t, blocks, 1, "%s %s", kind, typ)
	require.Len(t, blocks[0].Instances, 1)
	return blocks[0].Instances[0]
}

func instanceAt(t *testing.T, r *Root, addr string) *Instance {
	t.Helper()
	for _, m := range r.Modules {
		for _, b := range m.Blocks {
			for _, i := range b.Instances {
				if i.Address == addr {
					return i
				}
			}
		}
	}
	t.Fatalf("no instance %q", addr)
	return nil
}

func attrsOf(m map[string]cty.Value) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = conv(v)
	}
	return out
}

func refsOf(inst *Instance) []string {
	var out []string
	for _, r := range inst.Refs {
		s := strings.Join(r.Path, ".") + "->" + r.To.Address
		if r.Attr != "" {
			s += "." + r.Attr
		}
		if !r.Certain {
			s += " (may)"
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func TestPlanXPlanConfiguredAndComputed(t *testing.T) {
	s := loadPlans(t, map[string]string{
		"prod/main.tf":      dupplanSource,
		"plans/tfplan.json": xplanPlan,
	}, "plans/tfplan.json")
	require.Len(t, s.Roots, 2)
	require.Equal(t, "prod", s.Roots[0].ID)
	r := rootByID(t, s, "plans/tfplan.json")
	require.True(t, r.Plan)
	require.False(t, r.Incomplete, r.Notes)

	logging := onlyInstance(t, r, "resource", "aws_s3_bucket_logging")
	require.Equal(t, "aws_s3_bucket_logging.x", logging.Address)
	require.Equal(t, map[string]any{"bucket": "acme-prod-customer-data", "target_bucket": "logs"}, attrsOf(logging.Attrs))
	require.Equal(t, map[string]any{"target_prefix": "p/"}, attrsOf(logging.Computed))
	require.Equal(t, "plans/tfplan.json", logging.Block.File)
	require.Equal(t, 4, logging.Ranges[""].Start.Line, "[] is the values object")
	require.Equal(t, 4, logging.Ranges["target_prefix"].Start.Line)
	require.Equal(t, 4, logging.Block.Range.Start.Line)
	require.Nil(t, logging.Block.Syntax)
	require.Equal(t, "aws", logging.Block.Provider)

	// The configuration leaves dynamic blocks out: a list of objects it does
	// not show is kept as written, its references untraced.
	versioning := onlyInstance(t, r, "resource", "aws_s3_bucket_versioning")
	require.Equal(t, map[string]any{
		"bucket":                   "acme-prod-customer-data",
		"versioning_configuration": []any{map[string]any{"status": "Enabled", "mfa_delete": "Enabled"}},
	}, attrsOf(versioning.Attrs))
	require.Empty(t, versioning.Computed)
	require.True(t, versioning.Untraced["versioning_configuration.status"])
	require.Equal(t, 6, versioning.Ranges["versioning_configuration.0.status"].Start.Line)
}

func TestPlanNextToItsSourceIsItsOwnRoot(t *testing.T) {
	s := loadPlans(t, map[string]string{
		"prod/main.tf":     dupplanSource,
		"prod/tfplan.json": dupplanPlan,
	}, "prod/tfplan.json")
	require.Len(t, s.Roots, 2)
	src, plan := rootByID(t, s, "prod"), rootByID(t, s, "prod/tfplan.json")
	require.False(t, src.Plan)
	require.True(t, plan.Plan)
	require.Equal(t, plan.Dir, src.Dir)

	bucket := onlyInstance(t, plan, "resource", "aws_s3_bucket")
	require.Equal(t, map[string]any{"bucket": "acme-prod-customer-data"}, attrsOf(bucket.Attrs))
	require.Equal(t, map[string]any{"id": "P", "arn": "P"}, attrsOf(bucket.Computed))
	require.False(t, bucket.Block.Duplicate)
}

func TestPlanPlansOnlySkipsSources(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(dupplanSource), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tfplan.json"), []byte(dupplanPlan), 0o600))
	s, err := Load(context.Background(), dir, Options{Plans: []string{filepath.Join(dir, "tfplan.json")}, PlansOnly: true})
	require.NoError(t, err)
	require.Len(t, s.Roots, 1)
	require.Equal(t, "tfplan.json", s.Roots[0].ID)
}

// refsPlan exercises references: an indexed one, one without key to an
// expanded block, module arguments and outputs, a conditional and a local.
const refsPlan = `{"format_version":"1.2",
 "planned_values":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.b[0]","mode":"managed","type":"aws_s3_bucket","name":"b","index":0,"values":{"bucket":"b0"}},
  {"address":"aws_s3_bucket.b[1]","mode":"managed","type":"aws_s3_bucket","name":"b","index":1,"values":{"bucket":"b1"}},
  {"address":"aws_s3_bucket.c","mode":"managed","type":"aws_s3_bucket","name":"c","values":{"bucket":"c"}},
  {"address":"aws_s3_bucket_versioning.first","mode":"managed","type":"aws_s3_bucket_versioning","name":"first","values":{"versioning_configuration":[{"status":"Enabled"}]}},
  {"address":"aws_s3_bucket_versioning.any","mode":"managed","type":"aws_s3_bucket_versioning","name":"any","values":{}},
  {"address":"aws_s3_bucket_versioning.cond","mode":"managed","type":"aws_s3_bucket_versioning","name":"cond","values":{}},
  {"address":"aws_s3_bucket_versioning.local","mode":"managed","type":"aws_s3_bucket_versioning","name":"local","values":{}},
  {"address":"aws_s3_bucket_versioning.out","mode":"managed","type":"aws_s3_bucket_versioning","name":"out","values":{}}
 ],"child_modules":[{"address":"module.m[\"a\"]","resources":[
  {"address":"module.m[\"a\"].aws_s3_bucket_policy.p","mode":"managed","type":"aws_s3_bucket_policy","name":"p","values":{"policy":"{}"}}]}]}},
 "resource_changes":[
  {"address":"aws_s3_bucket_versioning.first","change":{"actions":["create"],"after_unknown":{"bucket":true,"versioning_configuration":[{}]}}},
  {"address":"aws_s3_bucket_versioning.any","change":{"actions":["create"],"after_unknown":{"bucket":true}}},
  {"address":"aws_s3_bucket_versioning.cond","change":{"actions":["create"],"after_unknown":{"bucket":true}}},
  {"address":"aws_s3_bucket_versioning.local","change":{"actions":["create"],"after_unknown":{"bucket":true}}},
  {"address":"aws_s3_bucket_versioning.out","change":{"actions":["create"],"after_unknown":{"bucket":true}}},
  {"address":"module.m[\"a\"].aws_s3_bucket_policy.p","change":{"actions":["create"],"after_unknown":{"bucket":true}}}
 ],
 "configuration":{"root_module":{
  "resources":[
   {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","expressions":{"bucket":{}},"count_expression":{"constant_value":2}},
   {"address":"aws_s3_bucket.c","mode":"managed","type":"aws_s3_bucket","name":"c","expressions":{"bucket":{"constant_value":"c"}}},
   {"address":"aws_s3_bucket_versioning.first","mode":"managed","type":"aws_s3_bucket_versioning","name":"first","expressions":{"bucket":{"references":["aws_s3_bucket.b[0].id","aws_s3_bucket.b[0]","aws_s3_bucket.b"]},"versioning_configuration":[{"status":{"constant_value":"Enabled"}}]}},
   {"address":"aws_s3_bucket_versioning.any","mode":"managed","type":"aws_s3_bucket_versioning","name":"any","expressions":{"bucket":{"references":["aws_s3_bucket.b","count.index"]}}},
   {"address":"aws_s3_bucket_versioning.cond","mode":"managed","type":"aws_s3_bucket_versioning","name":"cond","expressions":{"bucket":{"references":["var.on","aws_s3_bucket.c.id","aws_s3_bucket.c"]}}},
   {"address":"aws_s3_bucket_versioning.local","mode":"managed","type":"aws_s3_bucket_versioning","name":"local","expressions":{"bucket":{"references":["local.name"]}}},
   {"address":"aws_s3_bucket_versioning.out","mode":"managed","type":"aws_s3_bucket_versioning","name":"out","expressions":{"bucket":{"references":["module.m[\"a\"].bucket","module.m[\"a\"]","module.m"]}}}
  ],
  "module_calls":{"m":{"source":"./m","for_each_expression":{"constant_value":["a"]},
   "expressions":{"bucket":{"references":["aws_s3_bucket.c.id","aws_s3_bucket.c"]}},
   "module":{
    "outputs":{"bucket":{"expression":{"references":["var.bucket"]}}},
    "resources":[{"address":"aws_s3_bucket_policy.p","mode":"managed","type":"aws_s3_bucket_policy","name":"p","expressions":{"bucket":{"references":["var.bucket"]},"policy":{"constant_value":"{}"}}}],
    "variables":{"bucket":{}}}}}}}}
`

func TestPlanReferencesFromConfiguration(t *testing.T) {
	s := loadPlans(t, map[string]string{"tfplan.json": refsPlan}, "tfplan.json")
	r := rootByID(t, s, "tfplan.json")
	require.False(t, r.Incomplete, r.Notes)

	first := instanceAt(t, r, "aws_s3_bucket_versioning.first")
	require.Equal(t, []string{"bucket->aws_s3_bucket.b[0].id"}, refsOf(first))
	require.Equal(t, map[string]any{"bucket": "P", "versioning_configuration": []any{map[string]any{"status": "Enabled"}}}, attrsOf(first.Attrs))
	require.Empty(t, first.Untraced)

	keyless := instanceAt(t, r, "aws_s3_bucket_versioning.any")
	require.Equal(t, []string{"bucket->aws_s3_bucket.b[0] (may)", "bucket->aws_s3_bucket.b[1] (may)"}, refsOf(keyless))

	cond := instanceAt(t, r, "aws_s3_bucket_versioning.cond")
	require.Equal(t, []string{"bucket->aws_s3_bucket.c.id (may)"}, refsOf(cond))

	local := instanceAt(t, r, "aws_s3_bucket_versioning.local")
	require.Empty(t, local.Refs)
	require.True(t, local.Untraced["bucket"])

	out := instanceAt(t, r, "aws_s3_bucket_versioning.out")
	require.Equal(t, []string{"bucket->aws_s3_bucket.c.id"}, refsOf(out))

	policy := instanceAt(t, r, `module.m["a"].aws_s3_bucket_policy.p`)
	require.Equal(t, []string{"bucket->aws_s3_bucket.c.id"}, refsOf(policy))
	require.Equal(t, map[string]any{"bucket": "P", "policy": "{}"}, attrsOf(policy.Attrs))

	call := instanceAt(t, r, `module.m["a"]`)
	require.Equal(t, "module", call.Block.Kind)
	require.Equal(t, `["a"]`, call.Key)
	require.Equal(t, map[string]any{"bucket": "P", "source": "./m"}, attrsOf(call.Attrs))
	require.Equal(t, []string{"bucket->aws_s3_bucket.c.id"}, refsOf(call))

	b := blocksOf(r, "resource", "aws_s3_bucket")
	require.Equal(t, []string{"aws_s3_bucket.b[0]", "aws_s3_bucket.b[1]", "aws_s3_bucket.c"}, addresses(b))
}

func TestPlanIncomplete(t *testing.T) {
	const body = `"planned_values":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","values":{"bucket":"b","acl":"private"}}]}}`
	const config = `"configuration":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","expressions":{"bucket":{"constant_value":"b"}}}]}}`
	for name, tc := range map[string]struct {
		plan string
		note string
	}{
		"no configuration": {`{"format_version":"1.2",` + body + `}`, "plan has no configuration"},
		"errored":          {`{"format_version":"1.2","errored":true,` + body + `,` + config + `}`, "plan errored"},
		"not complete":     {`{"format_version":"1.2","complete":false,` + body + `,` + config + `}`, "plan is not complete"},
		"deferred":         {`{"format_version":"1.2","deferred_changes":[{"reason":"provider_config_unknown"}],` + body + `,` + config + `}`, "plan defers changes"},
		"missing resource": {
			`{"format_version":"1.2",` + body + `,"configuration":{"root_module":{"resources":[]}}}`,
			"no configuration for aws_s3_bucket.b",
		},
		"not json": {`{"format_version":`, "plan is not valid JSON"},
	} {
		t.Run(name, func(t *testing.T) {
			r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": tc.plan}, "tfplan.json"), "tfplan.json")
			require.True(t, r.Incomplete)
			require.Contains(t, r.Notes, tc.note)
		})
	}

	// Without configuration every planned value counts as written.
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": `{"format_version":"1.2",` + body + `}`}, "tfplan.json"), "tfplan.json")
	b := onlyInstance(t, r, "resource", "aws_s3_bucket")
	require.Equal(t, map[string]any{"bucket": "b", "acl": "private"}, attrsOf(b.Attrs))
	require.Empty(t, b.Computed)

	complete := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": `{"format_version":"1.2","complete":true,` + body + `,` + config + `}`}, "tfplan.json"), "tfplan.json")
	require.False(t, complete.Incomplete, complete.Notes)
	b = onlyInstance(t, complete, "resource", "aws_s3_bucket")
	require.Equal(t, map[string]any{"bucket": "b"}, attrsOf(b.Attrs))
	require.Equal(t, map[string]any{"acl": "private"}, attrsOf(b.Computed))
}

func TestPlanDuplicateAddress(t *testing.T) {
	const plan = `{"format_version":"1.2","planned_values":{"root_module":{"resources":[
{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","values":{"bucket":"one"}},
{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","values":{"bucket":"two"}},
{"address":"aws_s3_bucket_versioning.v","mode":"managed","type":"aws_s3_bucket_versioning","name":"v","values":{"bucket":"one"}}]}},
"configuration":{"root_module":{"resources":[
{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","expressions":{"bucket":{}}},
{"address":"aws_s3_bucket_versioning.v","mode":"managed","type":"aws_s3_bucket_versioning","name":"v","expressions":{"bucket":{"references":["aws_s3_bucket.b.id","aws_s3_bucket.b"]}}}]}}}`
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": plan}, "tfplan.json"), "tfplan.json")
	buckets := blocksOf(r, "resource", "aws_s3_bucket")
	require.Len(t, buckets, 2)
	require.True(t, buckets[0].Duplicate)
	require.True(t, buckets[1].Duplicate)
	require.Equal(t, []int{2, 3}, []int{buckets[0].Range.Start.Line, buckets[1].Range.Start.Line})
	v := onlyInstance(t, r, "resource", "aws_s3_bucket_versioning")
	require.Equal(t, []string{"bucket->aws_s3_bucket.b.id (may)", "bucket->aws_s3_bucket.b.id (may)"}, refsOf(v))
}

func TestPlanValueRules(t *testing.T) {
	const plan = `{"format_version":"1.2","planned_values":{"root_module":{"resources":[
{"address":"aws_instance.i","mode":"managed","type":"aws_instance","name":"i","values":{
  "user_data":"0123abcd","tags":{"a":"b"},"ami":"","ebs_block_device":[],"root_block_device":[{"encrypted":true,"volume_size":8}]}},
{"address":"data.aws_caller_identity.me","mode":"data","type":"aws_caller_identity","name":"me","values":{"account_id":"1"}}]},
 "outputs":{"ami":{"sensitive":false,"value":""}}},
"resource_changes":[{"address":"aws_instance.i","change":{"actions":["update"],"after_unknown":{"ami":true,"password_wo":false,"root_block_device":[{"volume_id":true}]}}}],
"prior_state":{"values":{"root_module":{"resources":[
 {"address":"data.aws_caller_identity.me","mode":"data","type":"aws_caller_identity","name":"me","values":{"account_id":"old"}},
 {"address":"data.aws_region.r","mode":"data","type":"aws_region","name":"r","values":{"name":"eu-west-1"}}]}}},
"configuration":{"provider_config":{
  "aws":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","expressions":{"region":{"constant_value":"us-east-1"}}},
  "aws.west":{"name":"aws","alias":"west","expressions":{"region":{"references":["var.region"]},"assume_role":[{"role_arn":{"constant_value":"arn:r"}}]}}},
 "root_module":{"outputs":{"ami":{"expression":{"references":["aws_instance.i.ami","aws_instance.i"]}}},
 "resources":[
 {"address":"aws_instance.i","mode":"managed","type":"aws_instance","name":"i","provider_config_key":"aws.west","expressions":{
   "user_data":{"constant_value":"#!/bin/sh"},"ami":{"constant_value":""},"password_wo":{"references":["var.pw"]},
   "root_block_device":[{"encrypted":{"constant_value":true}}]}},
 {"address":"data.aws_caller_identity.me","mode":"data","type":"aws_caller_identity","name":"me","provider_config_key":"aws","expressions":{}},
 {"address":"data.aws_region.r","mode":"data","type":"aws_region","name":"r","provider_config_key":"aws","expressions":{}}]}}}`
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": plan}, "tfplan.json"), "tfplan.json")
	require.False(t, r.Incomplete, r.Notes)
	i := instanceAt(t, r, "aws_instance.i")
	require.Equal(t, map[string]any{
		"user_data":         "#!/bin/sh",
		"ami":               "",
		"password_wo":       "P",
		"root_block_device": []any{map[string]any{"encrypted": true}},
	}, attrsOf(i.Attrs))
	require.Equal(t, map[string]any{
		"tags":              map[string]any{"a": "b"},
		"ebs_block_device":  []any{},
		"root_block_device": []any{map[string]any{"volume_size": int64(8), "volume_id": "P"}},
	}, attrsOf(i.Computed))
	require.Equal(t, "aws.west", i.Block.Provider)
	require.NotNil(t, i.Block.ProviderBlock)
	west := i.Block.ProviderBlock.Instances[0]
	require.Equal(t, "provider.aws.west", west.Address)
	require.Equal(t, map[string]any{"region": "P", "assume_role": []any{map[string]any{"role_arn": "arn:r"}}}, attrsOf(west.Attrs))
	require.Equal(t, map[string]any{"region": "us-east-1"}, attrsOf(instanceAt(t, r, "provider.aws").Attrs))

	me := instanceAt(t, r, "data.aws_caller_identity.me")
	require.Equal(t, map[string]any{"account_id": "1"}, attrsOf(me.Computed))
	require.Equal(t, map[string]any{"name": "eu-west-1"}, attrsOf(instanceAt(t, r, "data.aws_region.r").Computed))
	require.Empty(t, blocksOf(r, "data", "aws_caller_identity")[0].Instances[1:])

	out := instanceAt(t, r, "output.ami")
	require.Equal(t, map[string]any{"value": ""}, attrsOf(out.Attrs))
	require.Equal(t, []string{"value->aws_instance.i.ami"}, refsOf(out))
}

// A plan projects configuration variables, module calls and nested module
// outputs the way HCL does (E3), even when the call plans no resources.
func TestPlanProjectsVariablesModuleCallsAndOutputs(t *testing.T) {
	const plan = `{"format_version":"1.2","terraform_version":"1.9.0",
 "variables":{"region":{"value":"us-east-1"}},
 "planned_values":{"outputs":{"root_out":{"sensitive":false,"value":"v"}},
  "root_module":{"resources":[
   {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b",
    "provider_name":"registry.terraform.io/hashicorp/aws","schema_version":0,"values":{"bucket":"b"}}]}},
 "configuration":{"root_module":{
  "variables":{"region":{"default":"us-east-1"}},
  "module_calls":{"vpc":{"source":"git::https://example.com/vpc.git","module":{
   "outputs":{"id":{"expression":{"constant_value":"x"}}}}}},
  "outputs":{"root_out":{"expression":{"constant_value":"v"}}},
  "resources":[{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b",
   "provider_config_key":"aws","expressions":{"bucket":{"constant_value":"b"}},"schema_version":0}]}},
 "resource_changes":[{"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b",
  "provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],
   "before":null,"after":{"bucket":"b"},"after_unknown":{}}}]}`
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": plan}, "tfplan.json"), "tfplan.json")
	require.False(t, r.Incomplete, r.Notes)

	vars := blocksOf(r, "variable", "")
	require.Len(t, vars, 1)
	require.Equal(t, "region", vars[0].Name)
	require.Equal(t, map[string]any{"default": "us-east-1"}, attrsOf(vars[0].Instances[0].Attrs))

	calls := blocksOf(r, "module", "")
	require.Len(t, calls, 1)
	require.Equal(t, "vpc", calls[0].Name)
	require.Equal(t, "module.vpc", calls[0].Instances[0].Address)
	require.Equal(t, map[string]any{"source": "git::https://example.com/vpc.git"}, attrsOf(calls[0].Instances[0].Attrs))

	outs := blocksOf(r, "output", "")
	require.Len(t, outs, 2)
	byName := map[string]*Block{}
	for _, o := range outs {
		byName[o.Name] = o
	}
	require.Equal(t, map[string]any{"value": "v"}, attrsOf(byName["root_out"].Instances[0].Attrs))
	require.Equal(t, "output.root_out", byName["root_out"].Instances[0].Address)
	require.Equal(t, "module.vpc", byName["id"].Module.Address)
	require.Equal(t, "module.vpc.output.id", byName["id"].Instances[0].Address)
	require.Equal(t, map[string]any{"value": "x"}, attrsOf(byName["id"].Instances[0].Attrs))

	require.Equal(t, "aws_s3_bucket.b", onlyInstance(t, r, "resource", "aws_s3_bucket").Address)
}

// A written null is unset. When after_unknown also marks the attribute, the
// attribute stays absent and the unknown belongs in computed (E2).
func TestPlanConfiguredNullWithAfterUnknownIsAbsent(t *testing.T) {
	const plan = `{"format_version":"1.2","planned_values":{"root_module":{"resources":[
{"address":"aws_efs_file_system.a","mode":"managed","type":"aws_efs_file_system","name":"a","values":{"encrypted":true}},
{"address":"aws_emr_cluster.c","mode":"managed","type":"aws_emr_cluster","name":"c","values":{"name":"c","ec2_attributes":[{"instance_profile":"p"}]}}]}},
"resource_changes":[
{"address":"aws_efs_file_system.a","change":{"actions":["create"],"after_unknown":{"kms_key_id":true}}},
{"address":"aws_emr_cluster.c","change":{"actions":["create"],"after_unknown":{"ec2_attributes":[{"subnet_id":true}]}}}
],
"configuration":{"root_module":{"resources":[
{"address":"aws_efs_file_system.a","mode":"managed","type":"aws_efs_file_system","name":"a","provider_config_key":"aws","expressions":{"encrypted":{"constant_value":true},"kms_key_id":{"constant_value":null}}},
{"address":"aws_emr_cluster.c","mode":"managed","type":"aws_emr_cluster","name":"c","provider_config_key":"aws","expressions":{"name":{"constant_value":"c"},"ec2_attributes":[{"instance_profile":{"constant_value":"p"},"subnet_id":{"constant_value":null}}]}}
]}}}`
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": plan}, "tfplan.json"), "tfplan.json")
	efs := instanceAt(t, r, "aws_efs_file_system.a")
	require.Equal(t, map[string]any{"encrypted": true}, attrsOf(efs.Attrs))
	require.Equal(t, map[string]any{"kms_key_id": "P"}, attrsOf(efs.Computed))
	_, present := efs.Attrs["kms_key_id"]
	require.False(t, present)

	emr := instanceAt(t, r, "aws_emr_cluster.c")
	require.Equal(t, map[string]any{
		"name":           "c",
		"ec2_attributes": []any{map[string]any{"instance_profile": "p"}},
	}, attrsOf(emr.Attrs))
	require.Equal(t, map[string]any{
		"ec2_attributes": []any{map[string]any{"subnet_id": "P"}},
	}, attrsOf(emr.Computed))
}

// A constant_value list of objects may write null for a field; Terraform plans
// a provider default and may reorder set elements. Null stays absent (E2 for
// attribute-encoded nested objects).
func TestPlanConstantObjectNullFieldIsAbsent(t *testing.T) {
	const plan = `{"format_version":"1.2","planned_values":{"root_module":{"resources":[
{"address":"aws_security_group.g","mode":"managed","type":"aws_security_group","name":"g","values":{
  "name":"g",
  "ingress":[
    {"cidr_blocks":["0.0.0.0/0"],"description":"","from_port":443,"protocol":"tcp","to_port":443},
    {"cidr_blocks":["0.0.0.0/0"],"description":"http","from_port":80,"protocol":"tcp","to_port":80}
  ],
  "egress":[
    {"cidr_blocks":["0.0.0.0/0"],"description":"","from_port":0,"ipv6_cidr_blocks":["::/0"],"prefix_list_ids":[],"protocol":"-1","security_groups":[],"self":false,"to_port":0}
  ]
}}]}},
"resource_changes":[{"address":"aws_security_group.g","change":{"actions":["create"],"after_unknown":{}}}],
"configuration":{"root_module":{"resources":[
{"address":"aws_security_group.g","mode":"managed","type":"aws_security_group","name":"g","provider_config_key":"aws","expressions":{
  "name":{"constant_value":"g"},
  "ingress":{"constant_value":[
    {"cidr_blocks":["0.0.0.0/0"],"description":"http","from_port":80,"protocol":"tcp","to_port":80},
    {"cidr_blocks":["0.0.0.0/0"],"description":null,"from_port":443,"protocol":"tcp","to_port":443}
  ]},
  "egress":{"constant_value":[
    {"cidr_blocks":["0.0.0.0/0"],"description":null,"from_port":0,"ipv6_cidr_blocks":["::/0"],"prefix_list_ids":null,"protocol":"-1","security_groups":null,"self":null,"to_port":0}
  ]}
}}]}}}`
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": plan}, "tfplan.json"), "tfplan.json")
	sg := instanceAt(t, r, "aws_security_group.g")
	require.Equal(t, map[string]any{
		"name": "g",
		"ingress": []any{
			map[string]any{"cidr_blocks": []any{"0.0.0.0/0"}, "from_port": int64(443), "protocol": "tcp", "to_port": int64(443)},
			map[string]any{"cidr_blocks": []any{"0.0.0.0/0"}, "description": "http", "from_port": int64(80), "protocol": "tcp", "to_port": int64(80)},
		},
		"egress": []any{
			map[string]any{"cidr_blocks": []any{"0.0.0.0/0"}, "from_port": int64(0), "ipv6_cidr_blocks": []any{"::/0"}, "protocol": "-1", "to_port": int64(0)},
		},
	}, attrsOf(sg.Attrs))
	require.Equal(t, map[string]any{
		"ingress": []any{
			map[string]any{"description": ""},
			map[string]any{},
		},
		"egress": []any{
			map[string]any{"description": "", "prefix_list_ids": []any{}, "security_groups": []any{}, "self": false},
		},
	}, attrsOf(sg.Computed))
}

func TestPlanDeletedPriorDataIsLeftOut(t *testing.T) {
	const plan = `{"format_version":"1.2","planned_values":{"root_module":{}},
"resource_changes":[{"address":"data.aws_region.gone","change":{"actions":["delete"]}}],
"prior_state":{"values":{"root_module":{"resources":[
 {"address":"data.aws_region.gone","mode":"data","type":"aws_region","name":"gone","values":{"name":"x"}}]}}},
"configuration":{"root_module":{}}}`
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": plan}, "tfplan.json"), "tfplan.json")
	require.Empty(t, blocksOf(r, "data", "aws_region"))
}

func TestPlanEmptyPathUsesValuesObject(t *testing.T) {
	// Pretty-printed so the resource wrapper and its values object differ.
	const plan = `{
  "format_version": "1.2",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.b",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "b",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 0,
          "values": {
            "bucket": "b",
            "acl": "private"
          }
        }
      ]
    }
  },
  "configuration": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.b",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "b",
          "provider_config_key": "aws",
          "expressions": {
            "bucket": {"constant_value": "b"}
          },
          "schema_version": 0
        }
      ]
    }
  }
}
`
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": plan}, "tfplan.json"), "tfplan.json")
	b := onlyInstance(t, r, "resource", "aws_s3_bucket")
	require.Equal(t, 13, b.Ranges[""].Start.Line, "[] is the values object, not the resource wrapper")
	require.Equal(t, 13, b.Block.Range.Start.Line)
	require.Equal(t, 14, b.Ranges["bucket"].Start.Line)
	require.Equal(t, 15, b.Ranges["acl"].Start.Line)
}

func TestJSONPositions(t *testing.T) {
	src := []byte("{\"a\": {\"b\": [1, {\"c\": \"x\"}]},\n \"d\":\n  true}")
	root, err := jsonPositions("f.json", src, map[string]bool{"a": true})
	require.NoError(t, err)
	require.Nil(t, root.kid("d"))
	b := root.kid("a", "b")
	require.Equal(t, 1, b.rng.Start.Line)
	require.Equal(t, 8, b.rng.Start.Column)
	require.Equal(t, "{\"c\": \"x\"}", string(src[root.kid("a", "b", "1").rng.Start.Byte:root.kid("a", "b", "1").rng.End.Byte]))
	require.Equal(t, `"c": "x"`, string(src[root.kid("a", "b", "1", "c").rng.Start.Byte:root.kid("a", "b", "1", "c").rng.End.Byte]))
}

// barePlan lists its resources in a configuration without expressions.
const barePlan = `{"format_version":"1.2",
 "planned_values":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","values":{"bucket":"acme","force_destroy":false}},
  {"address":"aws_s3_bucket_versioning.v","mode":"managed","type":"aws_s3_bucket_versioning","name":"v","values":{"bucket":"acme"}}]}},
 "configuration":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","provider_config_key":"aws"},
  {"address":"aws_s3_bucket_versioning.v","mode":"managed","type":"aws_s3_bucket_versioning","name":"v","provider_config_key":"aws"}]}}}`

func TestPlanBareConfigurationWritesThePlannedValues(t *testing.T) {
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": barePlan}, "tfplan.json"), "tfplan.json")
	require.False(t, r.Incomplete, r.Notes)
	b := onlyInstance(t, r, "resource", "aws_s3_bucket")
	require.Equal(t, map[string]any{"bucket": "acme", "force_destroy": false}, attrsOf(b.Attrs))
	require.Empty(t, b.Computed)
	v := onlyInstance(t, r, "resource", "aws_s3_bucket_versioning")
	require.Equal(t, map[string]any{"bucket": "acme"}, attrsOf(v.Attrs))
}

func TestPlanEmptyBodyKeepsPlannedValuesComputed(t *testing.T) {
	plan := `{"format_version":"1.2",
 "planned_values":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","values":{"bucket":"acme","force_destroy":false}},
  {"address":"aws_vpc.v","mode":"managed","type":"aws_vpc","name":"v","values":{"cidr_block":"10.0.0.0/16"}}]}},
 "configuration":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","expressions":{"bucket":{"constant_value":"acme"}}},
  {"address":"aws_vpc.v","mode":"managed","type":"aws_vpc","name":"v"}]}}}`
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": plan}, "tfplan.json"), "tfplan.json")
	v := onlyInstance(t, r, "resource", "aws_vpc")
	require.Empty(t, v.Attrs)
	require.Equal(t, map[string]any{"cidr_block": "10.0.0.0/16"}, attrsOf(v.Computed))
}

func TestPlanConfigurationOnlyBlocks(t *testing.T) {
	plan := `{"format_version":"1.2","errored":false,"complete":true,
 "planned_values":{"root_module":{"resources":[
  {"address":"aws_codebuild_project.p","mode":"managed","type":"aws_codebuild_project","name":"p","values":{"name":"p"}}]}},
 "configuration":{"root_module":{"resources":[
  {"address":"aws_codebuild_project.p","mode":"managed","type":"aws_codebuild_project","name":"p","provider_config_key":"aws",
   "expressions":{"name":{"constant_value":"p"},"encryption_key":{"references":["data.aws_kms_key.k.arn","data.aws_kms_key.k"]}}},
  {"address":"data.aws_kms_key.k","mode":"data","type":"aws_kms_key","name":"k","provider_config_key":"aws",
   "expressions":{"key_id":{"constant_value":"alias/aws/s3"}}},
  {"address":"data.aws_kms_key.n","mode":"data","type":"aws_kms_key","name":"n","provider_config_key":"aws",
   "count_expression":{"references":["var.n"]},"expressions":{"key_id":{"constant_value":"alias/aws/s3"}}},
  {"address":"aws_kms_key.unplanned","mode":"managed","type":"aws_kms_key","name":"unplanned","provider_config_key":"aws",
   "expressions":{"description":{"constant_value":"k"}}}]}}}`
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": plan}, "tfplan.json"), "tfplan.json")
	blocks := blocksOf(r, "data", "aws_kms_key")
	require.Len(t, blocks, 1, "a block with count or for_each has the instances the plan lists")
	key := blocks[0].Instances[0]
	require.Equal(t, "data.aws_kms_key.k", key.Address)
	require.Equal(t, map[string]any{"key_id": "alias/aws/s3"}, attrsOf(key.Attrs))
	require.Equal(t, 7, key.Block.Range.Start.Line)
	require.Equal(t, "aws", key.Block.Provider)
	require.Empty(t, blocksOf(r, "resource", "aws_kms_key"), "the plan does not create a resource it does not hold")
	project := onlyInstance(t, r, "resource", "aws_codebuild_project")
	require.Equal(t, []string{"encryption_key->data.aws_kms_key.k.arn"}, refsOf(project))
}

func TestPlanCountIndexReadsTheSameIndex(t *testing.T) {
	plan := `{"format_version":"1.2",
 "planned_values":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.b[0]","mode":"managed","type":"aws_s3_bucket","name":"b","index":0,"values":{"bucket":"b-0"}},
  {"address":"aws_s3_bucket.b[1]","mode":"managed","type":"aws_s3_bucket","name":"b","index":1,"values":{"bucket":"b-1"}},
  {"address":"aws_s3_bucket_website_configuration.w[0]","mode":"managed","type":"aws_s3_bucket_website_configuration","name":"w","index":0,"values":{}},
  {"address":"aws_s3_bucket_website_configuration.w[1]","mode":"managed","type":"aws_s3_bucket_website_configuration","name":"w","index":1,"values":{}},
  {"address":"aws_s3_bucket_policy.p[0]","mode":"managed","type":"aws_s3_bucket_policy","name":"p","index":0,"values":{}},
  {"address":"aws_s3_bucket_acl.a[0]","mode":"managed","type":"aws_s3_bucket_acl","name":"a","index":0,"values":{}}]}},
 "configuration":{"root_module":{
  "variables":{"off":{}},
  "resources":[
  {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","name":"b","count_expression":{"constant_value":2},"expressions":{"bucket":{"references":["count.index"]}}},
  {"address":"aws_s3_bucket_website_configuration.w","mode":"managed","type":"aws_s3_bucket_website_configuration","name":"w","count_expression":{"constant_value":2},
   "expressions":{"bucket":{"references":["aws_s3_bucket.b","count.index"]}}},
  {"address":"aws_s3_bucket_policy.p","mode":"managed","type":"aws_s3_bucket_policy","name":"p","count_expression":{"constant_value":1},
   "expressions":{"bucket":{"references":["aws_s3_bucket.b","count.index","var.off"]}}},
  {"address":"aws_s3_bucket_acl.a","mode":"managed","type":"aws_s3_bucket_acl","name":"a","count_expression":{"constant_value":1},
   "expressions":{"bucket":{"references":["aws_s3_bucket.b[count.index].id","aws_s3_bucket.b[count.index]","aws_s3_bucket.b"]}}}]}}}`
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": plan}, "tfplan.json"), "tfplan.json")
	require.Equal(t, []string{"bucket->aws_s3_bucket.b[0]"}, refsOf(instanceAt(t, r, "aws_s3_bucket_website_configuration.w[0]")))
	require.Equal(t, []string{"bucket->aws_s3_bucket.b[1]"}, refsOf(instanceAt(t, r, "aws_s3_bucket_website_configuration.w[1]")))
	require.Equal(t, []string{"bucket->aws_s3_bucket.b[0] (may)", "bucket->aws_s3_bucket.b[1] (may)"},
		refsOf(instanceAt(t, r, "aws_s3_bucket_policy.p[0]")), "another input may change the index")
	require.Equal(t, []string{"bucket->aws_s3_bucket.b[0].id"},
		refsOf(instanceAt(t, r, "aws_s3_bucket_acl.a[0]")), "a plan lists block[count.index].id as one string")
}

const nestedListPlan = `{"format_version":"1.2","planned_values":{"root_module":{"resources":[
{"address":"kubernetes_pod.p","mode":"managed","type":"kubernetes_pod","name":"p","values":{"spec":[{"container":[
  {"name":"a","resources":[{"limits":{"cpu":"1"}}]},
  {"name":"b"}
]}]}}]}},
"resource_changes":[{"address":"kubernetes_pod.p","change":{"actions":["create"],"after_unknown":{"spec":[{"container":[{},{"resources":true}]}]}}}],
"configuration":{"root_module":{"resources":[
{"address":"kubernetes_pod.p","mode":"managed","type":"kubernetes_pod","name":"p","provider_config_key":"kubernetes","expressions":{"spec":[{"container":[
  {"name":{"constant_value":"a"},"resources":[{"limits":{"constant_value":{"cpu":"1"}}}]},
  {"name":{"constant_value":"b"}}
]}]}}
]}}}`

// An element of a nested block list knows only what its own configuration
// writes: a sibling that writes resources does not make the unknown resources
// of an element that writes none a written value.
func TestPlanNestedBlockElementsKeepTheirOwnConfiguration(t *testing.T) {
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": nestedListPlan}, "tfplan.json"), "tfplan.json")
	pod := instanceAt(t, r, "kubernetes_pod.p")
	require.Equal(t, map[string]any{"spec": []any{map[string]any{"container": []any{
		map[string]any{"name": "a", "resources": []any{map[string]any{"limits": map[string]any{"cpu": "1"}}}},
		map[string]any{"name": "b"},
	}}}}, attrsOf(pod.Attrs))
	require.Equal(t, map[string]any{"spec": []any{map[string]any{"container": []any{
		map[string]any{},
		map[string]any{"resources": "P"},
	}}}}, attrsOf(pod.Computed))
}

// When the elements of the plan do not line up with the bodies of the
// configuration, as for a set the plan reordered, they share the union of the
// bodies.
func TestPlanNestedBlockElementsOutOfOrderShareTheConfiguration(t *testing.T) {
	plan := strings.Replace(nestedListPlan,
		`{"name":"a","resources":[{"limits":{"cpu":"1"}}]},
  {"name":"b"}`,
		`{"name":"b"},
  {"name":"a","resources":[{"limits":{"cpu":"1"}}]}`, 1)
	plan = strings.Replace(plan, `"container":[{},{"resources":true}]`, `"container":[{"resources":true},{}]`, 1)
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": plan}, "tfplan.json"), "tfplan.json")
	pod := instanceAt(t, r, "kubernetes_pod.p")
	containers := attrsOf(pod.Attrs)["spec"].([]any)[0].(map[string]any)["container"].([]any)
	require.Equal(t, "b", containers[0].(map[string]any)["name"])
	require.Contains(t, containers[0], "resources", "the union of the bodies writes resources")
}

// An attribute the configuration writes and the plan leaves out as unknown is
// located at its expression in the configuration; a planned one keeps its line
// in the values.
func TestPlanUnknownAttributeIsLocatedInTheConfiguration(t *testing.T) {
	const plan = `{"format_version":"1.2",
"planned_values":{"root_module":{"resources":[
{"address":"azurerm_role_assignment.a","mode":"managed","type":"azurerm_role_assignment","name":"a","values":{
  "scope":"s"
}}]}},
"resource_changes":[{"address":"azurerm_role_assignment.a","change":{"actions":["create"],"after_unknown":{"role_definition_id":true}}}],
"configuration":{"root_module":{"resources":[
{"address":"azurerm_role_assignment.a","mode":"managed","type":"azurerm_role_assignment","name":"a","provider_config_key":"azurerm","expressions":{
  "scope":{"constant_value":"s"},
  "role_definition_id":{"references":["azurerm_role_definition.d.id"]},
  "condition":[{
    "version":{"constant_value":"2.0"}
  }]
}}
]}}}`
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": plan}, "tfplan.json"), "tfplan.json")
	inst := instanceAt(t, r, "azurerm_role_assignment.a")
	require.Equal(t, 10, inst.Ranges["role_definition_id"].Start.Line)
	require.Equal(t, 4, inst.Ranges["scope"].Start.Line, "a planned value keeps its range")
	require.Equal(t, 12, inst.Ranges["condition.0.version"].Start.Line)
	require.NotContains(t, inst.Ranges, "role_definition_id.references")
}

// A plan keeps provisioners out of planned_values; they are loaded from the
// configuration resource so tf.nested(..., "provisioner") matches HCL.
const provisionerPlan = `{"format_version":"1.2","planned_values":{"root_module":{"resources":[
{"address":"aws_instance.i","mode":"managed","type":"aws_instance","name":"i",
 "values":{"ami":"ami-1","instance_type":"t2.micro"}}]}},
"resource_changes":[{"address":"aws_instance.i","change":{"actions":["create"],"after_unknown":{"id":true}}}],
"configuration":{"root_module":{"resources":[
{"address":"aws_instance.i","mode":"managed","type":"aws_instance","name":"i","provider_config_key":"aws",
 "provisioners":[
  {"type":"remote-exec","expressions":{"inline":{"constant_value":["wget -O - http://example/creds > ~/.aws/credentials;"]}}},
  {"type":"file","expressions":{"content":{"constant_value":"x"},"destination":{"constant_value":"~/.aws/credentials"}}}
 ],
 "expressions":{"ami":{"constant_value":"ami-1"},"instance_type":{"constant_value":"t2.micro"}},"schema_version":1}
]}}}`

func TestPlanProvisionersFromConfiguration(t *testing.T) {
	r := rootByID(t, loadPlans(t, map[string]string{"tfplan.json": provisionerPlan}, "tfplan.json"), "tfplan.json")
	inst := instanceAt(t, r, "aws_instance.i")
	require.Equal(t, map[string]any{
		"ami":           "ami-1",
		"instance_type": "t2.micro",
		"provisioner": []any{map[string]any{
			"remote-exec": map[string]any{
				"inline": []any{"wget -O - http://example/creds > ~/.aws/credentials;"},
			},
			"file": map[string]any{
				"content":     "x",
				"destination": "~/.aws/credentials",
			},
		}},
	}, attrsOf(inst.Attrs))
	require.Contains(t, inst.Ranges, "provisioner.0.remote-exec")
	require.Contains(t, inst.Ranges, "provisioner.0.file.destination")
	require.Equal(t, inst.Ranges["provisioner.0.file.destination"].Start.Line,
		inst.Ranges["provisioner.0.file.0.destination"].Start.Line)
}
