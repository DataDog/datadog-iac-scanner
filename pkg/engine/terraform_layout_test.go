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
	"io/fs"
	"sync/atomic"
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

func TestTerraformLayoutExcludesExternalPackageRootsButKeepsTargets(t *testing.T) {
	repo := t.TempDir()
	remoteSource := "example.com/acme/storage/aws"
	writeTerraformTree(t, repo, map[string]string{
		"cache/module/main.tf": `resource "aws_s3_bucket" "module" {}`,
		"cache/orphan/main.tf": `resource "aws_s3_bucket" "orphan" {}`,
		"stacks/a/main.tf":     `module "m" { source = "example.com/acme/storage/aws" }`,
		"stacks/b/main.tf":     `module "m" { source = "example.com/acme/storage/aws" }`,
	})
	moduleDir := filepath.Join(repo, "cache", "module")
	orphanDir := filepath.Join(repo, "cache", "orphan")
	stackADir := filepath.Join(repo, "stacks", "a")
	stackBDir := filepath.Join(repo, "stacks", "b")
	files := append(parseTerraformWritten(t, filepath.Join(moduleDir, "main.tf")),
		parseTerraformWritten(t, filepath.Join(repo, "cache", "orphan", "main.tf"))...)
	files = append(files, parseTerraformWritten(t, filepath.Join(stackADir, "main.tf"))...)
	files = append(files, parseTerraformWritten(t, filepath.Join(stackBDir, "main.tf"))...)

	ins := newTestInspector(t, inspectorOpts{})
	ins.SetRemoteModuleDirectories(map[string]RemoteModuleDirectory{
		RemoteModuleCallKey(stackADir, remoteSource, "", "m"):    {Path: moduleDir, PackageRoot: moduleDir},
		RemoteModuleCallKey(stackBDir, remoteSource, "", "m"):    {Path: moduleDir, PackageRoot: moduleDir},
		RemoteModuleKey(repo, "example.com/acme/orphan/aws", ""): {Path: orphanDir, PackageRoot: orphanDir},
	})
	layout, err := ins.terraformLayout(context.Background(), files)
	require.NoError(t, err)
	require.NotNil(t, layout)
	require.Equal(t, []string{stackADir, stackBDir}, layout.Roots,
		"only scanned repository directories are independent roots")

	root := layout.Root(context.Background(), ins.buildRemoteResolver(), stackADir)
	require.NotNil(t, root)
	var reachedModule bool
	for _, module := range root.Modules {
		if filepath.Clean(module.Dir) == moduleDir {
			reachedModule = true
			break
		}
	}
	require.True(t, reachedModule, "the referenced external package remains available as a module target")
}

type absFailFS struct{ vfs.FS }

func (absFailFS) Abs(string) (string, error) { return "", errAbsBoom }

var errAbsBoom = errString("abs boom")

type errString string

func (e errString) Error() string { return string(e) }

// A contract-only scan must not treat a Terraform layout load failure as an
// empty success: without a layout there is no contract input, so the error
// surfaces. Legacy-only scans still fall back to written documents.
func TestInspect_ContractLayoutFailureReturnsError(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(map[bool]string{false: "contract_only", true: "mixed"}[mixed], func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformTree(t, dir, map[string]string{
				"main.tf": `resource "aws_s3_bucket" "b" {}`,
			})
			files := parseTerraform(t, filepath.Join(dir, "main.tf"))
			opts := inspectorOpts{
				queries: []model.QueryMetadata{{
					Query: "bucket", Content: `package datadog
import data.generic.common as common
import data.generic.terraform as tf
DatadogPolicy contains result if {
  some b in tf.blocks("aws_s3_bucket")
  result := common.finding(b, [], {})
}
`, InputData: "{}", Platform: "terraform",
					Metadata: map[string]interface{}{"id": "bucket-rule", "platform": "Terraform"}, Aggregation: 1,
				}},
				repoPath: dir, vb: DefaultVulnerabilityBuilder, tracker: &tracker.CITracker{},
				flagEvaluator: featureflags.NewLocalEvaluator(),
			}
			if mixed {
				opts.queries = append(opts.queries, model.QueryMetadata{
					Query: "legacy", Content: bucketRule, InputData: "{}", Platform: "terraform",
					Metadata: map[string]interface{}{"id": "legacy-rule", "platform": "Terraform"}, Aggregation: 1,
				})
			}
			ins := newTestInspector(t, opts)
			ins.fsys = absFailFS{FS: vfs.DiskFS{}}
			_, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
			require.Error(t, err)
			require.ErrorContains(t, err, "terraform layout is empty despite scanned Terraform files")
		})
	}
}

type sourceCountingFS struct {
	vfs.FS
	reads int
	stats int
	dirs  atomic.Int64
}

func (s *sourceCountingFS) ReadFile(name string) ([]byte, error) {
	s.reads++
	return s.FS.ReadFile(name)
}

func (s *sourceCountingFS) Stat(name string) (fs.FileInfo, error) {
	s.stats++
	return s.FS.Stat(name)
}

func (s *sourceCountingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	s.dirs.Add(1)
	return s.FS.ReadDir(name)
}

func (s *sourceCountingFS) Unwrap() vfs.FS { return s.FS }

func TestWithScannedTerraformServesSnapshotsAndFallsBack(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "main.tf")
	vars := filepath.Join(dir, "env.tfvars")
	varsJSON := filepath.Join(dir, "env.tfvars.json")
	missingSnapshot := filepath.Join(dir, "missing-snapshot.tf")
	unscanned := filepath.Join(dir, "module", "main.tf")
	plan := filepath.Join(dir, "plan.tfplan")
	for path, data := range map[string]string{
		config:          "disk config",
		vars:            "disk vars",
		varsJSON:        "disk vars json",
		missingSnapshot: "filesystem fallback",
		unscanned:       "module config",
		plan:            "disk plan",
	} {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(data), 0o600))
	}
	fsy := &sourceCountingFS{FS: vfs.DiskFS{}}
	ins := &Inspector{fsys: fsy}
	files := model.FileMetadatas{
		{Kind: model.KindTerraform, FilePath: config, OriginalData: "scanned config"},
		{Kind: model.KindTerraform, FilePath: vars, OriginalData: "scanned vars"},
		{Kind: model.KindTerraform, FilePath: varsJSON, OriginalData: "scanned vars json"},
		{Kind: model.KindTerraform, FilePath: missingSnapshot},
		{Kind: model.KindTerraformPlan, FilePath: plan, OriginalData: "scanned plan"},
	}
	wrapped := ins.withScannedTerraform(files, []string{plan})

	require.NoError(t, os.WriteFile(config, []byte("changed after parse"), 0o600))
	for path, want := range map[string]string{
		config:   "scanned config",
		vars:     "scanned vars",
		varsJSON: "scanned vars json",
	} {
		for range 2 {
			got, err := wrapped.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, want, string(got))
		}
		info, err := wrapped.Stat(path)
		require.NoError(t, err)
		require.Equal(t, int64(len(want)), info.Size())
	}
	require.Zero(t, fsy.reads, "scanned sources should not reread disk")
	require.Zero(t, fsy.stats, "scanned source stats should come from the snapshot")
	require.True(t, vfs.IsDisk(wrapped), "Unwrap should preserve filesystem identity")

	got, err := wrapped.ReadFile(unscanned)
	require.NoError(t, err)
	require.Equal(t, "module config", string(got), "unscanned module files retain filesystem fallback")
	got, err = wrapped.ReadFile(missingSnapshot)
	require.NoError(t, err)
	require.Equal(t, "filesystem fallback", string(got), "missing source snapshots retain filesystem fallback")
	_, err = wrapped.ReadFile(filepath.Join(dir, "missing.tf"))
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.Equal(t, 3, fsy.reads, "fallback reads and misses should be delegated")

	got, err = wrapped.ReadFile(plan)
	require.NoError(t, err)
	require.Equal(t, "disk plan", string(got), "plan reads retain the existing disk-first behavior")
}

func TestTerraformSourceDirectoryCache(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(file, []byte("source"), 0o600))
	disk := &sourceCountingFS{FS: vfs.DiskFS{}}
	ins := &Inspector{fsys: disk}
	wrapped := ins.withScannedTerraform(model.FileMetadatas{
		{Kind: model.KindTerraform, FilePath: file, OriginalData: "source"},
	}, nil)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			entries, err := wrapped.ReadDir(dir)
			if err == nil && len(entries) > 0 {
				entries[0] = nil // A caller's in-place filtering cannot corrupt the cache.
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	entries, err := wrapped.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "main.tf", entries[0].Name())
	require.EqualValues(t, 1, disk.dirs.Load())

	other := filepath.Join(dir, "module")
	require.NoError(t, os.Mkdir(other, 0o755))
	_, err = wrapped.ReadDir(other)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(other, "new.tf"), []byte("new"), 0o600))
	entries, err = wrapped.ReadDir(other)
	require.NoError(t, err)
	require.Len(t, entries, 1, "resolver directories remain live")
	require.EqualValues(t, 3, disk.dirs.Load())
}

func TestTerraformSourceDirectoryCacheDoesNotRetainErrors(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "later")
	file := filepath.Join(dir, "main.tf")
	ins := &Inspector{fsys: vfs.DiskFS{}}
	wrapped := ins.withScannedTerraform(model.FileMetadatas{
		{Kind: model.KindTerraform, FilePath: file, OriginalData: "source"},
	}, nil)
	_, err := wrapped.ReadDir(dir)
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.NoError(t, os.Mkdir(dir, 0o755))
	_, err = wrapped.ReadDir(dir)
	require.NoError(t, err)
}

func TestTerraformSourceDirectoryCacheLeavesMemoryFilesystemUncached(t *testing.T) {
	file := "/root/main.tf"
	memory := &sourceCountingFS{FS: vfs.NewMemFS(map[string][]byte{file: []byte("source")})}
	ins := &Inspector{fsys: memory}
	wrapped := ins.withScannedTerraform(model.FileMetadatas{
		{Kind: model.KindTerraform, FilePath: file, OriginalData: "source"},
	}, nil)
	for range 2 {
		_, err := wrapped.ReadDir("/root")
		require.NoError(t, err)
	}
	require.EqualValues(t, 2, memory.dirs.Load())
}
