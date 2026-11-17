package ruletest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// LegacyRoots evaluates HCL and plan JSON together. Modeling the HCL must not
// replace the plan's written document with schema-filled unknowns, or rules
// that use valid_key miss the plan finding main still reports.
func TestLegacyRootsFindsPlanJSON(t *testing.T) {
	assets := t.TempDir()
	writeFiles(t, assets, map[string]string{
		"libraries/common.rego": `package generic.common
import rego.v1
valid_key(obj, key) if object.get(obj, key, "undefined") != "undefined"
finding(b, path, meta) := result if {
	result := object.union({"_dd_id": b.id, "path": path}, meta)
}
`,
		"libraries/terraform.rego": `package generic.terraform
import rego.v1
_placeholder := "${unknown}"
blocks(types) := {b |
	some t in types
	some b in input.tf.blocks[t]
}
`,
		"libraries/terraform.json": `{}`,
		"queries/terraform/plan_key/metadata.json": `{
  "id": "terraform-plan-key-missing",
  "queryName": "Plan key missing",
  "severity": "MEDIUM",
  "platform": "Terraform",
  "category": "Access Control",
  "descriptionText": "test",
  "descriptionUrl": "https://example.com",
  "cloudProvider": "common"
}`,
		"queries/terraform/plan_key/query.rego": `package datadog
import data.generic.common as common_lib
DatadogPolicy contains result if {
	some i, name
	resource := input.document[i].resource.alicloud_kms_key[name]
	not common_lib.valid_key(resource, "is_enabled")
	result := {
		"documentId": input.document[i].id,
		"resourceType": "alicloud_kms_key",
		"resourceName": name,
		"searchKey": sprintf("alicloud_kms_key[%s]", [name]),
	}
}
`,
		"queries/terraform/plan_key/test/positive.tf": `resource "alicloud_kms_key" "key" {
  description = "from hcl"
}
`,
		"queries/terraform/plan_key/test/positive1.json": `{
  "format_version": "1.2",
  "terraform_version": "1.6.0",
  "planned_values": {"root_module": {"resources": [
    {"address": "alicloud_kms_key.key", "mode": "managed", "type": "alicloud_kms_key", "name": "key",
     "provider_name": "registry.terraform.io/aliyun/alicloud",
     "values": {"description": "Hello KMS", "status": "Enabled"}}
  ]}},
  "resource_changes": [
    {"address": "alicloud_kms_key.key", "mode": "managed", "type": "alicloud_kms_key", "name": "key",
     "provider_name": "registry.terraform.io/aliyun/alicloud",
     "change": {"actions": ["create"], "before": null,
       "after": {"description": "Hello KMS", "status": "Enabled"},
       "after_unknown": {"id": true, "is_enabled": true}}}
  ],
  "configuration": {"provider_config": {"alicloud": {"name": "alicloud", "expressions": {}}},
    "root_module": {"resources": [
      {"address": "alicloud_kms_key.key", "mode": "managed", "type": "alicloud_kms_key", "name": "key",
       "provider_config_key": "alicloud",
       "expressions": {"description": {"constant_value": "Hello KMS"}, "status": {"constant_value": "Enabled"}},
       "schema_version": 0}
    ]}}
}`,
		"queries/terraform/plan_key/test/positive_expected_result.json": `[
  {"queryName": "Plan key missing", "severity": "MEDIUM", "line": 1, "fileName": "positive.tf"},
  {"queryName": "Plan key missing", "severity": "MEDIUM", "line": 7, "fileName": "positive1.json"}
]`,
	})

	ctx := context.Background()
	suite, err := LoadDir(ctx, assets)
	require.NoError(t, err)
	require.Len(t, suite.Rules, 1)

	res, err := suite.Run(ctx, suite.Rules[0], Options{LegacyRoots: true, Timeout: 2 * time.Minute})
	require.NoError(t, err)
	for _, m := range res.Mismatches {
		t.Logf("mismatch kind=%v file=%s line=%d msg=%s", m.Kind, m.Finding.FileName, m.Finding.Line, m.Message)
	}
	require.True(t, res.Passed(), "HCL + plan under LegacyRoots must both raise findings")
}
