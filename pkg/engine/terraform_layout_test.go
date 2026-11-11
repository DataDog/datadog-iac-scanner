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
	"sort"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

// readCountingFS counts the files read through it.
type readCountingFS struct {
	vfs.FS
	mu    sync.Mutex
	reads map[string]int
}

func (r *readCountingFS) ReadFile(name string) ([]byte, error) {
	r.mu.Lock()
	r.reads[filepath.Clean(name)]++
	r.mu.Unlock()
	return r.FS.ReadFile(name)
}

func (r *readCountingFS) Unwrap() vfs.FS { return r.FS }

func writeTerraformTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
}

func inspectBuckets(t *testing.T, repoPath string, fsys vfs.FS, files model.FileMetadatas) []string {
	t.Helper()
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "bucket", Content: bucketRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "bucket-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath:      repoPath,
		vb:            DefaultVulnerabilityBuilder,
		tracker:       &tracker.CITracker{},
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	if fsys != nil {
		ins.fsys = fsys
	}
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	var out []string
	for i := range vulns {
		rel, err := filepath.Rel(repoPath, vulns[i].FileName)
		require.NoError(t, err)
		out = append(out, filepath.ToSlash(rel)+"|"+vulns[i].ModuleCallChain)
	}
	sort.Strings(out)
	return out
}

// Files the scan leaves out (ignored, excluded or too large) are never read
// by the Terraform layout, in the scanned directory or next to it.
func TestInspect_TerraformLayoutReadsOnlyScannedFiles(t *testing.T) {
	dir := t.TempDir()
	writeTerraformTree(t, dir, map[string]string{
		"main.tf":            `resource "aws_s3_bucket" "scanned" {}`,
		"ignored.tf":         `resource "aws_s3_bucket" "ignored" {}`,
		"data/big.tf.json":   `{"resource": {"aws_s3_bucket": {"big": {}}}}`,
		"data/stack.json":    `{"resource": {"aws_s3_bucket": {"stack": {}}}}`,
		"other/terraform.tf": `module "repo" { source = "../" }`,
	})
	counting := &readCountingFS{FS: vfs.DiskFS{}, reads: map[string]int{}}
	got := inspectBuckets(t, dir, counting, parseTerraform(t, filepath.Join(dir, "main.tf")))
	require.Equal(t, []string{"main.tf|"}, got)
	for _, name := range []string{"ignored.tf", "data/big.tf.json", "data/stack.json", "other/terraform.tf"} {
		require.Zero(t, counting.reads[filepath.Join(dir, filepath.FromSlash(name))], "%s must not be read", name)
	}
}

// With two scanned paths under a shared parent, a configuration of that
// parent that was not scanned neither adds findings nor turns a scanned root
// into a module.
func TestInspect_TwoScanPathsReportOnlyScannedFiles(t *testing.T) {
	dir := t.TempDir()
	writeTerraformTree(t, dir, map[string]string{
		"work/repo/main.tf": `resource "aws_s3_bucket" "repo" {}`,
		"work2/x/main.tf":   `resource "aws_s3_bucket" "x" {}`,
		"other/caller/main.tf": `
module "hijack" { source = "../../work/repo" }
resource "aws_s3_bucket" "caller" {}
`,
	})
	var files model.FileMetadatas
	for _, name := range []string{"work/repo/main.tf", "work2/x/main.tf"} {
		files = append(files, parseTerraform(t, filepath.Join(dir, filepath.FromSlash(name)))...)
	}
	got := inspectBuckets(t, dir, nil, files)
	require.Equal(t, []string{"work/repo/main.tf|", "work2/x/main.tf|"}, got)
}
