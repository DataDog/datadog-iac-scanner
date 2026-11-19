/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package scan

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func resultKeys(t *testing.T, base string, results *Results) []string {
	t.Helper()
	var out []string
	for _, r := range results.Results {
		rel, err := filepath.Rel(base, r.FileName)
		require.NoError(t, err)
		out = append(out, filepath.ToSlash(rel)+"|"+r.ModuleCallChain+"|"+r.ResourceID)
	}
	sort.Strings(out)
	return out
}

func scanWithRemoteModule(t *testing.T, root string, unscannedCaller bool) []string {
	t.Helper()
	require.NoError(t, os.MkdirAll(root, 0o755))
	_, manifestPath := writeRemoteModuleFixture(t, root)
	if unscannedCaller {
		dir := filepath.Join(filepath.Dir(root), "noise", "caller")
		require.NoError(t, os.MkdirAll(dir, 0o755))
		rel, err := filepath.Rel(dir, root)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"),
			[]byte("module \"hijack\" {\n  source = \""+filepath.ToSlash(rel)+"\"\n}\n"), 0o600))
	}
	params := remoteModuleScanParams(root)
	params.TerraformModules = TerraformModulesOn
	params.RemoteModulesManifestPath = manifestPath
	return resultKeys(t, filepath.Dir(root), executeRemoteModuleScan(t, params))
}

// A remote module package outside the repository does not widen the
// Terraform base, so an unscanned configuration next to the repository that
// calls it cannot change its findings.
func TestRemoteModuleOutsideRepoDoesNotChangeFindings(t *testing.T) {
	clean := scanWithRemoteModule(t, filepath.Join(t.TempDir(), "repo"), false)
	noisy := scanWithRemoteModule(t, filepath.Join(t.TempDir(), "repo"), true)
	require.NotEmpty(t, clean)
	require.Equal(t, clean, noisy, "a file outside the scanned path must not change findings")
}

// Two scanned paths under a shared parent: findings are reported on the
// scanned files only, whatever else that parent holds.
func TestTwoScanPathsReportOnlyScannedFiles(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"work/repo/main.tf":    `resource "aws_vpc" "repo" {}`,
		"work2/x/main.tf":      `resource "aws_vpc" "x" {}`,
		"other/caller/main.tf": "module \"hijack\" {\n  source = \"../../work/repo\"\n}\nresource \"aws_vpc\" \"caller\" {}\n",
	} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	params := remoteModuleScanParams(filepath.Join(dir, "work", "repo"))
	params.Path = []string{filepath.Join(dir, "work", "repo"), filepath.Join(dir, "work2", "x")}
	got := resultKeys(t, dir, executeRemoteModuleScan(t, params))
	require.Len(t, got, 2)
	require.Contains(t, got[0], "work/repo/main.tf||")
	require.Contains(t, got[1], "work2/x/main.tf||")
}
