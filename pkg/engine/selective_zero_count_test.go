/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

func TestInspect_SelectiveModelDropsZeroCount(t *testing.T) {
	tmpl := `locals {
  instances = %d
}

resource "aws_s3_bucket" "this" {
  count  = local.instances
  bucket = "zero-count-bucket"
}
`
	off := fmt.Sprintf(tmpl, 0)
	on := fmt.Sprintf(tmpl, 1)
	fsys := vfs.NewMemFS(map[string][]byte{
		"infra/off/main.tf": []byte(off),
		"infra/on/main.tf":  []byte(on),
	})
	files := append(parseRetargeted(t, off, "infra/off/main.tf", "off"),
		parseRetargeted(t, on, "infra/on/main.tf", "on")...)

	rule := model.QueryMetadata{
		Query: "bucket_rule", Content: rootBucketRule, InputData: "{}", Platform: "terraform",
		Metadata: map[string]interface{}{"id": "bucket-rule", "platform": "Terraform"}, Aggregation: 1,
	}
	ins := jsonEscalationInspector(t, fsys, rule)
	_, legacy := splitTerraformRules([]model.QueryMetadata{rule})

	layout, err := ins.terraformLayout(context.Background(), files)
	require.NoError(t, err)
	written := ins.terraformFiles(files)
	byDir := writtenByDir(written)
	targets := ruleTargetedResourceTypes(legacy, ins.terraformRuleLibraries()...)
	modeled, asWritten := legacyModeledRoots(layout.Roots, written, byDir, targets)
	t.Logf("roots=%q modeled=%q asWritten=%v byDir=%v written=%v", layout.Roots, modeled, asWritten, byDir, writtenKeys(written))

	vulns, err := ins.inspectTerraformLegacyStream(context.Background(), "test", files, legacy, false)
	require.NoError(t, err)
	for _, v := range vulns {
		require.NotEqual(t, "off", v.FileID, "zero-count revived: roots=%v modeled=%v asWritten=%v", layout.Roots, modeled, asWritten)
	}
	require.NotEmpty(t, vulns, "count=1 must still find")
}

func parseRetargeted(t *testing.T, content, path, id string) model.FileMetadatas {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	files := parseTerraformWritten(t, p)
	files[0].FilePath = path
	files[0].ID = id
	return files
}

func writtenKeys(m map[string]*model.FileMetadata) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
