/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

// Exercise the public parser, including directory resolution and both OpenTofu
// paths, so instance-local data cannot accidentally resolve only in modules.
func TestParserInstanceLocalData(t *testing.T) {
	hcl := `
data "google_iam_policy" "p" {
  count = 2
  binding {
    role = "roles/viewer"
    members = ["user:${count.index}@example.com"]
  }
}
locals {
  policies = data.google_iam_policy.p
}
resource "google_project_iam_policy" "counted" {
  count = 2
  policy_data = local.policies[count.index].policy_data
}
data "google_iam_policy" "keyed" {
  for_each = {a = "allUsers", b = "user:b@example.com"}
  binding {
    role = "roles/viewer"
    members = [each.value]
  }
}
resource "google_project_iam_policy" "keyed" {
  for_each = {a = "allUsers", b = "user:b@example.com"}
  policy_data = data.google_iam_policy.keyed[each.key].policy_data
}
`
	json := `{
  "data": {"google_iam_policy": {
    "p": {"count": 2, "binding": [{"role": "roles/viewer", "members": ["user:${count.index}@example.com"]}]},
    "keyed": {"for_each": {"a": "allUsers", "b": "user:b@example.com"},
      "binding": [{"role": "roles/viewer", "members": ["${each.value}"]}]}
  }},
  "locals": {"policies": "${data.google_iam_policy.p}"},
  "resource": {"google_project_iam_policy": {
    "counted": {"count": 2, "policy_data": "${local.policies[count.index].policy_data}"},
    "keyed": {"for_each": {"a": "allUsers", "b": "user:b@example.com"},
      "policy_data": "${data.google_iam_policy.keyed[each.key].policy_data}"}
  }}
}`
	for _, ext := range []string{".tf", ".tofu", ".tf.json", ".tofu.json"} {
		t.Run(ext, func(t *testing.T) {
			src := hcl
			if strings.HasSuffix(ext, ".json") {
				src = json
			}
			path := filepath.Join(t.TempDir(), "main"+ext)
			require.NoError(t, os.WriteFile(path, []byte(src), 0o600))
			_, layers, _, _, err := NewDefault().Parse(context.Background(), []byte(src), path, true, 15)
			require.NoError(t, err)
			require.Len(t, layers, 2)
			for i, layer := range layers {
				resources := layer["resource"].(model.Document)["google_project_iam_policy"].(model.Document)
				counted := resources["counted"].(model.Document)
				require.Contains(t, stringifyValue(counted["policy_data"]), fmt.Sprintf("user:%d@example.com", i))
				keyed := resources["keyed"].(model.Document)
				want := []string{"allUsers", "user:b@example.com"}[i]
				require.Contains(t, stringifyValue(keyed["policy_data"]), want)
			}
		})
	}
}

func TestLocalDataExpansionShapesAndFallback(t *testing.T) {
	dir := t.TempDir()
	src := `
data "google_iam_policy" "zero" { count = 0 }
data "google_iam_policy" "empty" { for_each = {} }
data "google_iam_policy" "unknown" { count = var.unknown }
data "google_iam_policy" "capped" { count = 55 }
data "google_iam_policy" "keys" { for_each = {for n in range(55): format("k%03d", n) => n} }
data "google_iam_policy" "huge" { count = 1000000000 }
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o600))
	vars := converter.VariableMap{"var": cty.ObjectVal(map[string]cty.Value{"unknown": cty.UnknownVal(cty.Number)})}
	got := getDataSourcePolicy(context.Background(), vfs.DiskFS{}, dir, vars, nil, "")["data"].GetAttr("google_iam_policy")
	require.True(t, got.GetAttr("zero").RawEquals(cty.EmptyTupleVal))
	require.True(t, got.GetAttr("empty").RawEquals(cty.EmptyObjectVal))
	require.False(t, got.GetAttr("unknown").IsKnown())
	capped := got.GetAttr("capped")
	require.Equal(t, 55, capped.LengthInt())
	require.True(t, capped.Index(cty.NumberIntVal(0)).IsKnown())
	require.False(t, capped.Index(cty.NumberIntVal(54)).IsKnown())
	keys := got.GetAttr("keys")
	require.Equal(t, 55, keys.LengthInt())
	require.True(t, keys.GetAttr("k000").IsKnown())
	require.False(t, keys.GetAttr("k054").IsKnown())
	require.False(t, got.GetAttr("huge").IsKnown())
}

func TestJSONInstanceFallbackAndLimits(t *testing.T) {
	for _, tc := range []struct {
		meta   string
		layers int
	}{
		{`"count": "${var.unknown}"`, 1},
		{`"for_each": "${var.unknown}"`, 1},
		{`"count": 55`, 51},
		{`"for_each": "${{for n in range(55): format(\"k%03d\", n) => n}}"`, 51},
	} {
		t.Run(tc.meta, func(t *testing.T) {
			bucket := "${count.index}"
			if strings.HasPrefix(tc.meta, `"for_each"`) {
				bucket = "${each.key}"
			}
			src := []byte(`{"resource":{"aws_s3_bucket":{"b":{` + tc.meta + `,"bucket":"` + bucket + `"}}}}`)
			layers, err := parseJSONConfigLayers(src, "main.tf.json", nil)
			require.NoError(t, err)
			require.Len(t, layers, tc.layers)
			last := jsonBucket(layers[len(layers)-1], "b")
			require.Equal(t, bucket, stringifyValue(last["bucket"]), "the unknown tail stays as written")
		})
	}

	src := []byte(`{"resource":{"aws_s3_bucket":{"b":{"count":3,"bucket":"b-${count.index}"}}}}`)
	file, diags := hcljson.Parse(src, "main.tf.json")
	require.False(t, diags.HasErrors())
	content, _, diags := file.Body.PartialContent(jsonConfigSchema)
	require.False(t, diags.HasErrors())
	budget := 1
	_, expanded := expandJSONInstances(content.Blocks[0], &hcl.EvalContext{}, src, &budget)
	require.False(t, expanded, "a block that does not fit must be converted as written")
	require.Equal(t, 1, budget, "refusal must not spend the remaining budget")
}

func TestJSONDynamicExpansionFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name, collection, extra string
		kept                    bool
	}{
		{"empty", `[]`, "", false},
		{"unknown", `"${var.ports}"`, "", true},
		{"capped", `"${range(257)}"`, "", true},
		{"labels", `[1]`, `,"labels":["named"]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := []byte(`{"resource":{"aws_s3_bucket":{"b":{"dynamic":{"ingress":{
"for_each":` + tc.collection + tc.extra + `,"content":{"from_port":"${ingress.value}"}
}}}}}}`)
			layers, err := parseJSONConfigLayers(src, "main.tf.json", nil)
			require.NoError(t, err)
			require.Len(t, layers, 1)
			_, kept := jsonBucket(layers[0], "b")["dynamic"]
			require.Equal(t, tc.kept, kept)
			require.NotContains(t, jsonBucket(layers[0], "b"), "ingress", "no partial generated blocks may escape fallback")
		})
	}
}
