/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

// countingFS records every path read through it.
type countingFS struct {
	vfs.FS
	mu    sync.Mutex
	reads map[string]int
}

func (c *countingFS) note(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads[filepath.Clean(name)]++
}

func (c *countingFS) ReadFile(name string) ([]byte, error) {
	c.note(name)
	return c.FS.ReadFile(name)
}

func (c *countingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	c.note(name)
	return c.FS.ReadDir(name)
}

func (c *countingFS) Stat(name string) (fs.FileInfo, error) {
	c.note(name)
	return c.FS.Stat(name)
}

func (c *countingFS) Unwrap() vfs.FS { return c.FS }

func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
}

func TestScanLayout_OnlyScannedFilesAreRead(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	writeTree(t, dir, map[string]string{
		"repo/main.tf": `
module "local" { source = "./modules/local" }
module "shared" { source = "../shared" }
resource "aws_s3_bucket" "scanned" {}
`,
		"repo/ignored.tf":              `resource "aws_s3_bucket" "ignored" {}`,
		"repo/data/big.tf.json":        `{"resource": {"aws_s3_bucket": {"big": {}}}}`,
		"repo/modules/local/main.tf":   `resource "aws_s3_bucket" "local" {}`,
		"repo/modules/local/extra.tf":  `resource "aws_s3_bucket" "extra" {}`,
		"shared/main.tf":               `resource "aws_s3_bucket" "shared" {}`,
		"unscanned/caller/main.tf":     `module "hijack" { source = "../../repo" }`,
		"repo/modules/unused/main.tf":  `resource "aws_s3_bucket" "unused" {}`,
		"repo/modules/unused/other.tf": `resource "aws_s3_bucket" "other" {}`,
	})
	scanned := map[string]bool{
		filepath.Join(repo, "main.tf"):                      true,
		filepath.Join(repo, "modules", "local", "main.tf"):  true,
		filepath.Join(repo, "modules", "unused", "main.tf"): true,
	}
	counting := &countingFS{FS: vfs.DiskFS{}, reads: map[string]int{}}
	scan, err := Load(context.Background(), repo, Options{FS: counting, Files: scanned})
	require.NoError(t, err)

	var ids []string
	for _, r := range scan.Roots {
		ids = append(ids, r.ID)
	}
	require.Equal(t, []string{".", "modules/unused"}, ids)
	require.Equal(t, []string{
		"aws_s3_bucket.scanned", "module.local.aws_s3_bucket.local", "module.shared.aws_s3_bucket.shared",
	}, addresses(blocksOf(rootByID(t, scan, "."), "resource", "aws_s3_bucket")))
	require.Equal(t, []string{"aws_s3_bucket.unused"},
		addresses(blocksOf(rootByID(t, scan, "modules/unused"), "resource", "aws_s3_bucket")))

	for _, name := range []string{
		"repo/ignored.tf", "repo/data/big.tf.json", "repo/data", "repo/modules/local/extra.tf",
		"repo/modules/unused/other.tf", "unscanned/caller/main.tf", "unscanned",
	} {
		require.Zero(t, counting.reads[filepath.Join(dir, filepath.FromSlash(name))], "%s must not be read", name)
	}
	require.NotZero(t, counting.reads[filepath.Join(dir, "shared", "main.tf")],
		"a module directory outside the scanned files is read as it is")
}

func TestScanLayout_PlansAreReadWithScannedFiles(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"main.tf":   `resource "aws_s3_bucket" "b" {}`,
		"plan.json": `{"format_version": "1.2", "planned_values": {"root_module": {}}}`,
	})
	plan := filepath.Join(dir, "plan.json")
	layout, err := ScanLayout(context.Background(), dir, Options{
		Files: map[string]bool{filepath.Join(dir, "main.tf"): true}, Plans: []string{plan},
	})
	require.NoError(t, err)
	require.Equal(t, []string{dir}, layout.Roots)
	require.Equal(t, []string{plan}, layout.Plans)
	_, err = layout.fsys.ReadFile(plan)
	require.NoError(t, err)
}

func TestScanLayout_StopsWhenCancelled(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"main.tf": `module "m" { source = "./m" }`, "m/main.tf": ``})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ScanLayout(ctx, dir, Options{})
	require.ErrorIs(t, err, context.Canceled)
	_, err = ScanLayout(ctx, dir, Options{Files: map[string]bool{filepath.Join(dir, "main.tf"): true}})
	require.ErrorIs(t, err, context.Canceled)
}

func TestScannedFS_HidesUnscannedConfigurationOfScannedDirectories(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"a/main.tf":          ``,
		"a/skipped.tf":       ``,
		"a/stack.json":       `{}`,
		"a/terraform.tfvars": ``,
		"a/sub/main.tf":      ``,
		"b/main.tf":          ``,
	})
	s := newScannedFS(vfs.DiskFS{}, map[string]bool{filepath.Join(dir, "a", "main.tf"): true}, nil)
	entries, err := s.ReadDir(filepath.Join(dir, "a"))
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	require.Equal(t, []string{"main.tf", "sub", "terraform.tfvars"}, names)

	_, err = s.ReadFile(filepath.Join(dir, "a", "skipped.tf"))
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, err = s.Stat(filepath.Join(dir, "a", "stack.json"))
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, err = s.Stat(filepath.Join(dir, "a", "sub"))
	require.NoError(t, err)
	_, err = s.ReadFile(filepath.Join(dir, "b", "main.tf"))
	require.NoError(t, err, "a directory without a scanned file is served as it is")
	matches, err := s.Glob(filepath.Join(dir, "a", "*.tf"))
	require.NoError(t, err)
	require.Equal(t, []string{filepath.Join(dir, "a", "main.tf")}, matches)
	require.True(t, vfs.IsDisk(s))
}

func TestEvaluate_CancelledSkipsDegraded(t *testing.T) {
	real := runEvaluation
	t.Cleanup(func() { runEvaluation = real })
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	runEvaluation = func(
		ctx context.Context, fsys vfs.FS, e *tfeval.Evaluator, dir string, inputs map[string]cty.Value, varsPath string,
	) *evaluation {
		calls++
		ev := real(ctx, fsys, e, dir, inputs, varsPath)
		cancel()
		ev.err = errors.New("evaluation failed")
		return ev
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"main.tf": `resource "aws_s3_bucket" "b" {}`})
	scan, err := Load(ctx, dir, Options{})
	require.NoError(t, err)
	require.Equal(t, 1, calls, "a cancelled root is not evaluated again in degraded mode")
	r := scan.Roots[0]
	require.False(t, r.Degraded)
	require.True(t, r.Incomplete)
	require.True(t, slices.ContainsFunc(r.Notes, func(n string) bool { return strings.HasPrefix(n, "evaluation failed") }))
}
