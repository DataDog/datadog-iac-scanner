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
	"sync/atomic"
	"testing"
	"time"

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

type delayedReadDirFS struct {
	vfs.FS
	delays map[string]time.Duration
	errs   map[string]error
	active atomic.Int32
	max    atomic.Int32
}

func (f *delayedReadDirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	n := f.active.Add(1)
	for old := f.max.Load(); n > old && !f.max.CompareAndSwap(old, n); old = f.max.Load() {
	}
	defer f.active.Add(-1)
	if delay := f.delays[filepath.Clean(name)]; delay > 0 {
		time.Sleep(delay)
	}
	if err := f.errs[filepath.Clean(name)]; err != nil {
		return nil, err
	}
	return f.FS.ReadDir(name)
}

func (f *delayedReadDirFS) Unwrap() vfs.FS { return f.FS }

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
	scan, err := Load(context.Background(), repo, &Options{FS: counting, Files: scanned})
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

func TestScannedDirs_ParallelReadsAggregateInSortedOrder(t *testing.T) {
	prev := rootWorkers
	rootWorkers = 4
	t.Cleanup(func() { rootWorkers = prev })
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"a/main.tf": `resource "aws_s3_bucket" "a" {}`,
		"b/main.tf": `resource "aws_s3_bucket" "b" {}`,
		"c/main.tf": `resource "aws_s3_bucket" "c" {}`,
	})
	fsys := &delayedReadDirFS{
		FS: vfs.DiskFS{},
		delays: map[string]time.Duration{
			filepath.Join(dir, "a"): 25 * time.Millisecond,
			filepath.Join(dir, "b"): 5 * time.Millisecond,
		},
	}
	files := map[string]bool{
		filepath.Join(dir, "c", "main.tf"): true,
		filepath.Join(dir, "a", "main.tf"): true,
		filepath.Join(dir, "b", "main.tf"): true,
	}
	dirs := map[string]*dirInfo{}
	got, err := scannedDirs(context.Background(), fsys, dir, files, dirs)
	require.NoError(t, err)
	require.Equal(t, []string{filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")}, got)
	require.GreaterOrEqual(t, fsys.max.Load(), int32(2), "directory reads run concurrently")
	require.Len(t, dirs, 3)
}

func TestScannedDirs_ReturnsFirstErrorInSortedOrder(t *testing.T) {
	prev := rootWorkers
	rootWorkers = 4
	t.Cleanup(func() { rootWorkers = prev })
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a/main.tf": ``, "b/main.tf": ``})
	first := errors.New("first sorted error")
	second := errors.New("second sorted error")
	fsys := &delayedReadDirFS{
		FS: vfs.DiskFS{},
		delays: map[string]time.Duration{
			filepath.Join(dir, "a"): 25 * time.Millisecond,
		},
		errs: map[string]error{
			filepath.Join(dir, "a"): first,
			filepath.Join(dir, "b"): second,
		},
	}
	files := map[string]bool{
		filepath.Join(dir, "b", "main.tf"): true,
		filepath.Join(dir, "a", "main.tf"): true,
	}
	_, err := scannedDirs(context.Background(), fsys, dir, files, map[string]*dirInfo{})
	require.ErrorIs(t, err, first)
}

func TestScanLayout_DeclarationSnapshotMatchesDiscovery(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"repo/main.tf": `
resource "aws_s3_bucket" "root" {}
module "local" { source = "./modules/local" }
module "remote" { source = "registry.example/acme/remote/aws" }
module "unknown" { source = var.module_source }
module "missing" { source = "./missing" }
`,
		"repo/resources.tf.json": `{"resource":{"aws_lambda_function":{"from_json":{}}}}`,
		"repo/ignored.tf":        `resource "aws_dynamodb_table" "ignored" {}`,
		"repo/broken.tf":         `resource "aws_glue_catalog_database" "broken" {`,
		"repo/modules/local/main.tf": `
resource "aws_instance" "local" {}
module "cycle" { source = "../../cycle" }
`,
		"repo/cycle/main.tf":  `module "local" { source = "../modules/local" }`,
		"remote/main.tf":      `resource "aws_ebs_volume" "remote" {}`,
		"unrelated/main.tf":   `resource "aws_sqs_queue" "unrelated" {}`,
		"isolated/main.tf":    `resource "aws_s3_bucket" "included" {}`,
		"isolated/ignored.tf": `resource "aws_dynamodb_table" "ignored" {}`,
		"isolated/broken.tf":  `resource "aws_glue_catalog_database" "broken" {`,
		"orphan-a/main.tf":    `module "b" { source = "../orphan-b" }`,
		"orphan-b/main.tf":    `module "a" { source = "../orphan-a" }`,
	})
	remoteDir := filepath.Join(dir, "remote")
	resolver := func(source, version, callerFile, moduleName string) (string, string, bool) {
		if source == "registry.example/acme/remote/aws" {
			return remoteDir, remoteDir, true
		}
		return "", "", false
	}
	files := map[string]bool{
		filepath.Join(dir, "repo", "main.tf"):           true,
		filepath.Join(dir, "repo", "resources.tf.json"): true,
		filepath.Join(dir, "repo", "broken.tf"):         true,
		filepath.Join(dir, "unrelated", "main.tf"):      true,
		filepath.Join(dir, "isolated", "main.tf"):       true,
		filepath.Join(dir, "isolated", "broken.tf"):     true,
		filepath.Join(dir, "orphan-a", "main.tf"):       true,
	}
	layout, err := ScanLayout(context.Background(), dir, &Options{FS: vfs.DiskFS{}, Files: files, Resolver: resolver})
	require.NoError(t, err)

	wantCalled := layout.CalledModuleDirectories(context.Background(), resolver)
	gotCalled, ok := layout.ScannedCalledModuleDirectories()
	require.True(t, ok)
	require.Equal(t, wantCalled, gotCalled)

	types := []string{
		"aws_s3_bucket", "aws_instance", "aws_ebs_volume", "aws_sqs_queue",
		"aws_dynamodb_table", "aws_lambda_function", "aws_glue_catalog_database",
	}
	for _, resourceType := range types {
		want := map[string]bool{}
		for _, root := range layout.Roots {
			if layout.MayDeclareResource(context.Background(), resolver, root, func(typ string) bool {
				return typ == resourceType
			}) {
				want[filepath.Clean(root)] = true
			}
		}
		got, ok := layout.ScannedResourceCandidates(resolver, func(typ string) bool { return typ == resourceType })
		require.True(t, ok)
		require.Equal(t, want, got, "resource type %s", resourceType)
	}
	require.Contains(t, gotCalled, filepath.Join(dir, "repo", "cycle"), "reachable cycles still include their edges")
	require.NotContains(t, gotCalled, filepath.Join(dir, "repo"), "the reachable cycle does not call the repository root")
	require.NotContains(t, gotCalled, filepath.Join(dir, "orphan-a"), "disconnected cycles are not reachable from layout roots")
	require.NotContains(t, gotCalled, filepath.Join(dir, "orphan-b"), "disconnected cycles are not reachable from layout roots")
	require.Contains(t, gotCalled, filepath.Join(dir, "repo", "modules", "local"))
	require.Contains(t, gotCalled, remoteDir)
	dynamoCandidates, ok := layout.ScannedResourceCandidates(resolver, func(typ string) bool { return typ == "aws_dynamodb_table" })
	require.True(t, ok)
	require.False(t, dynamoCandidates[filepath.Join(dir, "isolated")], "unscanned sibling configs are hidden from the snapshot")
	glueCandidates, ok := layout.ScannedResourceCandidates(resolver, func(typ string) bool { return typ == "aws_glue_catalog_database" })
	require.True(t, ok)
	require.False(t, glueCandidates[filepath.Join(dir, "isolated")], "malformed HCL remains skipped as by MayDeclareResource")

	fullLayout, err := ScanLayout(context.Background(), dir, &Options{})
	require.NoError(t, err)
	_, ok = fullLayout.ScannedCalledModuleDirectories()
	require.False(t, ok, "unscoped layouts use the original discovery path")
}

func TestScanLayout_PlansAreReadWithScannedFiles(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"main.tf":   `resource "aws_s3_bucket" "b" {}`,
		"plan.json": `{"format_version": "1.2", "planned_values": {"root_module": {}}}`,
	})
	plan := filepath.Join(dir, "plan.json")
	layout, err := ScanLayout(context.Background(), dir, &Options{
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
	_, err := ScanLayout(ctx, dir, &Options{})
	require.ErrorIs(t, err, context.Canceled)
	_, err = ScanLayout(ctx, dir, &Options{Files: map[string]bool{filepath.Join(dir, "main.tf"): true}})
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
	scan, err := Load(ctx, dir, &Options{})
	require.NoError(t, err)
	require.Equal(t, 1, calls, "a cancelled root is not evaluated again in degraded mode")
	r := scan.Roots[0]
	require.False(t, r.Degraded)
	require.True(t, r.Incomplete)
	require.True(t, slices.ContainsFunc(r.Notes, func(n string) bool { return strings.HasPrefix(n, "evaluation failed") }))
}

type cancelDeclarationFS struct {
	vfs.FS
	cancel context.CancelFunc
	reads  int
}

func (f *cancelDeclarationFS) ReadFile(name string) ([]byte, error) {
	if filepath.Base(name) == "main.tf" {
		f.reads++
		if f.reads == 1 {
			f.cancel()
		}
	}
	return f.FS.ReadFile(name)
}

func TestScanLayoutCancelsDuringLastDeclarationInspection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	file := "/repo/main.tf"
	fsys := &cancelDeclarationFS{
		FS:     vfs.NewMemFS(map[string][]byte{file: []byte(`resource "aws_s3_bucket" "b" {}`)}),
		cancel: cancel,
	}
	_, err := ScanLayout(ctx, "/repo", &Options{FS: fsys, Files: map[string]bool{file: true}})
	require.Equal(t, 1, fsys.reads, "cancel on the declaration parse; inventory no longer syntax-parses first")
	require.ErrorIs(t, err, context.Canceled)
}

func TestScannedResourceCandidatesUnavailableCallsOnly(t *testing.T) {
	remote := `module "r" { source = "registry.example/acme/r/aws" }`
	failingResolver := tfeval.RemoteResolver(func(string, string, string, string) (string, string, bool) {
		return "", "", false
	})
	check := func(name string, files map[string]string, scanResolver, checkResolver tfeval.RemoteResolver, want bool) {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			writeTree(t, base, files)
			scanned := make(map[string]bool, len(files))
			for name := range files {
				scanned[filepath.Join(base, filepath.FromSlash(name))] = true
			}
			layout, err := ScanLayout(context.Background(), base, &Options{Files: scanned, Resolver: scanResolver})
			require.NoError(t, err)
			require.Len(t, layout.Roots, 1)
			got, ok := layout.ScannedResourceCandidates(checkResolver, func(typ string) bool { return typ == "aws_s3_bucket" })
			require.True(t, ok)
			require.Equal(t, want, got[filepath.Clean(base)])
		})
	}
	check("static remote unavailable", map[string]string{"main.tf": remote}, nil, nil, false)
	check("snapshot nil then nonnil resolver", map[string]string{"main.tf": remote}, nil, failingResolver, true)
	check("dynamic source", map[string]string{"main.tf": `module "r" { source = var.module_source }`}, nil, nil, true)
	check("missing local", map[string]string{"main.tf": `module "r" { source = "./missing" }`}, nil, nil, true)
	check("nonnil resolver failure", map[string]string{"main.tf": remote}, failingResolver, failingResolver, true)
	check("parse failure", map[string]string{
		"main.tf":  `resource "aws_s3_bucket" "broken" {`,
		"other.tf": remote,
	}, nil, nil, true)
	check("direct companion", map[string]string{"main.tf": remote + `
resource "aws_s3_bucket" "x" {}`}, nil, nil, true)
	check("transitive companion", map[string]string{
		"main.tf": remote + `
module "child" { source = "./child" }`,
		"child/main.tf": `resource "aws_s3_bucket" "x" {}`,
	}, nil, nil, true)
}

func TestScannedLayoutReusesSuccessfulSyntaxAndFallsBackForFailures(t *testing.T) {
	base := t.TempDir()
	writeTree(t, base, map[string]string{
		"main.tf": `resource "aws_s3_bucket" "good" {}`,
		"bad.tf":  `resource "aws_s3_bucket" "broken" {`,
	})
	good := filepath.Join(base, "main.tf")
	bad := filepath.Join(base, "bad.tf")
	counting := &countingFS{FS: vfs.DiskFS{}, reads: map[string]int{}}
	layout, err := ScanLayout(context.Background(), base, &Options{
		FS: counting, Files: map[string]bool{good: true, bad: true},
	})
	require.NoError(t, err)
	require.Equal(t, 1, counting.reads[good], "valid HCL should be read and parsed once by declaration inspection")
	require.Equal(t, 2, counting.reads[bad], "a parser-rejected file falls back to the exact dirInfo syntax check")
	require.NotContains(t, layout.dirs[base].failed, good)
	require.Contains(t, layout.dirs[base].failed, bad)
}

func TestScannedLayoutFallbackPreservesTwinAndOverrideParseStatus(t *testing.T) {
	base := t.TempDir()
	writeTree(t, base, map[string]string{
		"main.tf":          `resource "aws_s3_bucket" "tf" {}`,
		"main.tofu":        `resource "aws_s3_bucket" "tofu" {}`,
		"main.tf.json":     `{"resource":{"aws_s3_bucket":{"tf_json":{}}}}`,
		"main.tofu.json":   `{"resource":{"aws_s3_bucket":{"tofu_json":{}}}}`,
		"good_override.tf": `resource "aws_s3_bucket" "override" {}`,
		"bad_override.tf":  `resource "aws_s3_bucket" "broken" {`,
	})
	files := map[string]bool{}
	for _, name := range []string{"main.tf", "main.tofu", "main.tf.json", "main.tofu.json", "good_override.tf", "bad_override.tf"} {
		files[filepath.Join(base, name)] = true
	}
	layout, err := ScanLayout(context.Background(), base, &Options{Files: files})
	require.NoError(t, err)
	require.Equal(t, []string{filepath.Join(base, "bad_override.tf")}, layout.dirs[base].failed)
	require.Equal(t, []string{filepath.Join(base, "good_override.tf"), filepath.Join(base, "main.tofu"), filepath.Join(base, "main.tofu.json")}, layout.declarationSummaries[base].ParsedFiles)
}

func TestScannedLayoutFallbackKeepsValidConfinedOutSymlinkJSONUnfailed(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	require.NoError(t, os.MkdirAll(repo, 0o755))
	external := filepath.Join(base, "external.tf.json")
	require.NoError(t, os.WriteFile(external, []byte(`{"resource":{"aws_s3_bucket":{"outside":{}}}}`), 0o600))
	link := filepath.Join(repo, "main.tf.json")
	if err := os.Symlink(external, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	layout, err := ScanLayout(context.Background(), repo, &Options{Files: map[string]bool{link: true}})
	require.NoError(t, err)
	require.NotContains(t, layout.declarationSummaries[repo].ParsedFiles, link, "the evaluator must honor symlink confinement")
	require.NotContains(t, layout.dirs[repo].failed, link, "fallback preserves the existing raw JSON parse result")
}

func TestScannedLayoutFallbackRecordsCalledModuleParseFailure(t *testing.T) {
	base := t.TempDir()
	writeTree(t, base, map[string]string{
		"main.tf":         `module "child" { source = "./child" }`,
		"child/broken.tf": `resource "aws_s3_bucket" "broken" {`,
	})
	root := filepath.Join(base, "main.tf")
	child := filepath.Join(base, "child", "broken.tf")
	layout, err := ScanLayout(context.Background(), base, &Options{Files: map[string]bool{root: true, child: true}})
	require.NoError(t, err)
	require.Contains(t, layout.declarationSummaries[base].CalledDirectories, filepath.Join(base, "child"))
	require.Contains(t, layout.dirs[filepath.Join(base, "child")].failed, child)
}
