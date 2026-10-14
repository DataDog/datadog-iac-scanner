/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

const expansionRules = aclRule

const expansionConfig = `
locals {
  acls = { one = "public-read", two = "private" }
}

resource "aws_s3_bucket" "plain" {
  acl = "public-read"
}

resource "aws_s3_bucket" "counted" {
  count = 3
  acl   = count.index == 2 ? "public-read" : "private"
}

resource "aws_s3_bucket" "keyed" {
  for_each = local.acls
  acl      = each.value
}

resource "aws_s3_bucket" "listed" {
  for_each = toset(["a", "b"])
  acl      = each.key == "b" ? "public-read" : "private"
}

resource "aws_s3_bucket" "constant" {
  count = 2
  acl   = "public-read"
}

resource "aws_s3_bucket" "disabled" {
  count = 0
  acl   = "public-read"
}

resource "aws_s3_bucket" "empty" {
  for_each = {}
  acl      = "public-read"
}
`

func expansionFindings(t *testing.T, root string, files model.FileMetadatas) []model.Vulnerability {
	t.Helper()
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "acl_rule", Content: expansionRules, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	return vulns
}

// A block expands into the same findings whether it is scanned in place or
// instantiated by a module call.
func TestInspect_ExpansionFindingsMatchBetweenFlatAndModule(t *testing.T) {
	root := t.TempDir()

	flatPath := filepath.Join(root, "flat", "main.tf")
	require.NoError(t, os.MkdirAll(filepath.Dir(flatPath), 0o755))
	require.NoError(t, os.WriteFile(flatPath, []byte(expansionConfig), 0o644))
	flat := expansionFindings(t, filepath.Dir(flatPath), parseTerraform(t, flatPath))

	rootPath := filepath.Join(root, "stack", "main.tf")
	modPath := filepath.Join(root, "modules", "buckets", "main.tf")
	require.NoError(t, os.MkdirAll(filepath.Dir(rootPath), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(modPath), 0o755))
	require.NoError(t, os.WriteFile(rootPath, []byte("module \"buckets\" {\n  source = \"../modules/buckets\"\n}\n"), 0o644))
	require.NoError(t, os.WriteFile(modPath, []byte(expansionConfig), 0o644))
	var files model.FileMetadatas
	files = append(files, parseTerraform(t, rootPath)...)
	files = append(files, parseTerraform(t, modPath)...)
	module := expansionFindings(t, root, files)

	// plain and the instances that are misconfigured; disabled and empty create nothing
	counts := func(vulns []model.Vulnerability) map[string]int {
		out := map[string]int{}
		for i := range vulns {
			out[vulns[i].ResourceName]++
		}
		return out
	}
	want := map[string]int{"plain": 1, "counted": 1, "keyed": 1, "listed": 1, "constant": 1}
	require.Equal(t, want, counts(flat), "flat")

	// A module call reports each instance, so two instances that do not
	// differ report twice at the same place; a plain file reports it once.
	want["constant"] = 2
	require.Equal(t, want, counts(module), "module")
}
