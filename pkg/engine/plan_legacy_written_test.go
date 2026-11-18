package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodel "github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

// Minimal plan JSON: one managed resource whose schema has computed attrs the
// model would fill with unknowns, but the JSON parser omits.
const legacyPlanJSON = `{
  "format_version": "1.2",
  "terraform_version": "1.6.0",
  "planned_values": {"root_module": {"resources": [
    {"address": "alicloud_kms_key.key", "mode": "managed", "type": "alicloud_kms_key", "name": "key",
     "provider_name": "registry.terraform.io/aliyun/alicloud",
     "values": {"description": "Hello KMS", "status": "Enabled", "pending_window_in_days": 7, "protection_level": "SOFTWARE"}}
  ]}},
  "resource_changes": [
    {"address": "alicloud_kms_key.key", "mode": "managed", "type": "alicloud_kms_key", "name": "key",
     "provider_name": "registry.terraform.io/aliyun/alicloud",
     "change": {"actions": ["create"], "before": null,
       "after": {"description": "Hello KMS", "status": "Enabled", "pending_window_in_days": 7, "protection_level": "SOFTWARE"},
       "after_unknown": {"id": true, "is_enabled": true, "arn": true}}}
  ],
  "configuration": {"provider_config": {"alicloud": {"name": "alicloud", "expressions": {}}},
    "root_module": {"resources": [
      {"address": "alicloud_kms_key.key", "mode": "managed", "type": "alicloud_kms_key", "name": "key",
       "provider_config_key": "alicloud",
       "expressions": {"description": {"constant_value": "Hello KMS"}, "status": {"constant_value": "Enabled"},
         "pending_window_in_days": {"constant_value": 7}, "protection_level": {"constant_value": "SOFTWARE"}},
       "schema_version": 0}
    ]}}
}`

// A modeled plan must not cover its path for legacy documents: rules that use
// valid_key against the JSON parser shape would otherwise lose findings when
// the model invents unknown computed attributes.
func TestLegacyPlanUsesWrittenDocument(t *testing.T) {
	tmp := t.TempDir()
	planPath := filepath.Join(tmp, "positive1.json")
	require.NoError(t, os.WriteFile(planPath, []byte(legacyPlanJSON), 0o600))

	scan, err := tfmodel.Load(context.Background(), tmp, &tfmodel.Options{
		Plans: []string{planPath}, PlansOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, scan.Roots, 1)

	writtenDoc := model.Document{
		legacyRootScopeKey: "forged-scope",
		"resource": map[string]any{
			"alicloud_kms_key": map[string]any{
				"key": map[string]any{"status": "Enabled"},
			},
		},
	}
	written := map[string]*model.FileMetadata{
		planPath: {
			ID: "p1", Kind: model.KindTerraformPlan, FilePath: planPath,
			Document: writtenDoc, OriginalData: legacyPlanJSON,
		},
	}
	built := &legacyBuild{}
	b := &legacyRootBuild{
		base:    tmp,
		written: written,
		byDir:   writtenByDir(written),
		opts: project.LegacyOptions{
			Base: tmp, Placeholder: legacyUnknown,
			FileID: func(path string) (string, bool) {
				if path == planPath {
					return "p1", true
				}
				return "", false
			},
			Taken: map[string]struct{}{},
		},
	}
	ins := &Inspector{fsys: vfs.DiskFS{}}
	ins.takeLegacyRoot(built, b, scan.Roots[0])
	require.Empty(t, built.docs, "modeled plan must not become a legacy document")
	require.Empty(t, built.covered, "modeled plan must not cover the written path")

	docs := ins.addWrittenSections(built.docs, built.covered, written, true, nil)
	require.Len(t, docs, 1)
	scopeLegacyDocuments(docs, written)
	require.Equal(t, filepath.Clean(planPath), docs[0][legacyRootScopeKey])
	res := docs[0]["resource"].(map[string]any)
	key := res["alicloud_kms_key"].(map[string]any)["key"].(map[string]any)
	_, hasIsEnabled := key["is_enabled"]
	require.False(t, hasIsEnabled, "written plan must omit invented computed keys")
	require.Equal(t, "Enabled", key["status"])
}
