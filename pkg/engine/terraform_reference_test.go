/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/schedule"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodel "github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	tfproject "github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/value"
	"github.com/stretchr/testify/require"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

const referenceCommonLib = `package generic.common

import rego.v1

finding(subject, path, details) := object.union(details, {"_dd_id": subject._dd_meta.id, "path": path})

is_list(v) if is_array(v)
`

const referenceTerraformLib = `package generic.terraform

import rego.v1

import data.generic.common

_dd := object.get(input, "_dd", {})

_placeholder := object.get(_dd, "placeholder", "\u0000dd-unknown")

blocks(type) := object.get(_dd, ["blocks", "resource", type], [])

by_id(id) := object.get(_dd, ["by_id", id], _placeholder)

_nested(block) := object.get(object.get(_dd, "nested", {}), object.get(block._dd_meta, "id", ""), {})

nested(block, name) := list if {
	list := object.get(_nested(block), name, null)
	common.is_list(list)
} else := list if {
	list := block[name]
	common.is_list(list)
} else := [_placeholder] if {
	block[name] == _placeholder
} else := []

related(block, type, path) := [by_id(id) | some id in object.get(_dd, ["related", block._dd_meta.id, type, path], [])]

literal_keys := {"aws_s3_bucket_versioning": {"bucket": {"aws_s3_bucket": ["bucket"]}}}
`

const referenceBucketRule = `package datadog

import rego.v1

import data.generic.common as common
import data.generic.terraform as tf

DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	result := common.finding(b, ["bucket"], {})
}
`

const referenceVersioningRule = `package datadog

import rego.v1

import data.generic.common as common
import data.generic.terraform as tf

DatadogPolicy contains result if {
	some b in tf.blocks("aws_s3_bucket")
	not versioned(b)
	result := common.finding(b, [], {})
}

versioned(b) if {
	some v in tf.related(b, "aws_s3_bucket_versioning", "bucket")
	some c in tf.nested(v, "versioning_configuration")
	c.status == "Enabled"
}
`

type referenceQueriesSource struct {
	queries []model.QueryMetadata
}

func (s *referenceQueriesSource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return s.queries, nil
}

func (s *referenceQueriesSource) GetQueryLibrary(_ context.Context, platform string) (source.RegoLibraries, error) {
	switch platform {
	case "common":
		return source.RegoLibraries{LibraryCode: referenceCommonLib, LibraryInputData: "{}"}, nil
	case "terraform":
		return source.RegoLibraries{LibraryCode: referenceTerraformLib, LibraryInputData: "{}"}, nil
	default:
		return source.RegoLibraries{LibraryCode: "package generic." + platform + "\n", LibraryInputData: "{}"}, nil
	}
}

func referenceQuery(name, id, content string) model.QueryMetadata {
	return model.QueryMetadata{
		Query: name, Content: content, InputData: "{}", Platform: "terraform",
		Metadata: map[string]interface{}{"id": id, "platform": "Terraform", "queryName": name, "severity": "MEDIUM"},
	}
}

// referenceFixture writes two identical envs sharing a module (digest/fanout),
// one distinct env, and a cross-root companion layout like the e2e cross-root
// fixture (ops versions prod; examples/ must not).
func referenceFixture(t *testing.T) (dir string, files model.FileMetadatas) {
	t.Helper()
	dir = t.TempDir()
	modDir := filepath.Join(dir, "modules", "svc")
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	modPath := writeFile(t, modDir, "main.tf", `
variable "name" {}
resource "aws_s3_bucket" "b" { bucket = var.name }
`)
	files = append(files, parseTerraform(t, modPath)...)

	for _, env := range []struct{ name, bucket string }{
		{"a", "shared"},
		{"b", "shared"},
		{"c", "other"},
	} {
		rootDir := filepath.Join(dir, "envs", env.name)
		require.NoError(t, os.MkdirAll(rootDir, 0o755))
		path := writeFile(t, rootDir, "main.tf", fmt.Sprintf(`
module "svc" {
  source = "../../modules/svc"
  name   = %q
}
`, env.bucket))
		files = append(files, parseTerraform(t, path)...)
	}

	prod := writeFile(t, filepath.Join(dir, "prod"), "main.tf", `
resource "aws_s3_bucket" "versioned_elsewhere" {
  bucket = "acme-versioned-elsewhere"
}
resource "aws_s3_bucket" "planted_in_example" {
  bucket = "acme-planted-in-example"
}
`)
	ops := writeFile(t, filepath.Join(dir, "ops"), "main.tf", `
resource "aws_s3_bucket_versioning" "prod" {
  bucket = "acme-versioned-elsewhere"
  versioning_configuration {
    status = "Enabled"
  }
}
`)
	example := writeFile(t, filepath.Join(dir, "examples", "demo"), "main.tf", `
resource "aws_s3_bucket_versioning" "planted" {
  bucket = "acme-planted-in-example"
  versioning_configuration {
    status = "Enabled"
  }
}
`)
	files = append(files, parseTerraform(t, prod)...)
	files = append(files, parseTerraform(t, ops)...)
	files = append(files, parseTerraform(t, example)...)
	return dir, files
}

func scanReferenceMode(t *testing.T, dir string, files model.FileMetadatas, reference bool) []model.Vulnerability {
	t.Helper()
	ins := newTestInspector(t, inspectorOpts{
		querySource: &referenceQueriesSource{queries: []model.QueryMetadata{
			referenceQuery("every_bucket", "every-bucket", referenceBucketRule),
			referenceQuery("bucket_without_versioning", "no-versioning", referenceVersioningRule),
		}},
		repoPath:      dir,
		vb:            DefaultVulnerabilityBuilder,
		tracker:       &tracker.CITracker{},
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetTerraformReferenceMode(reference)
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	return vulns
}

type findingKey struct {
	QueryID, File, ResourceType, ResourceName, SearchKey string
	Line                                                 int
}

func findingKeys(vulns []model.Vulnerability) []findingKey {
	out := make([]findingKey, len(vulns))
	for i := range vulns {
		out[i] = findingKey{
			QueryID: vulns[i].QueryID, File: filepath.ToSlash(vulns[i].FileName),
			ResourceType: vulns[i].ResourceType, ResourceName: vulns[i].ResourceName,
			SearchKey: vulns[i].SearchKey, Line: vulns[i].Line,
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.QueryID != b.QueryID {
			return a.QueryID < b.QueryID
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.ResourceName != b.ResourceName {
			return a.ResourceName < b.ResourceName
		}
		if a.SearchKey != b.SearchKey {
			return a.SearchKey < b.SearchKey
		}
		return a.Line < b.Line
	})
	return out
}

// Optimized chunking/merge/dedup/fanout and per-root reference evaluation
// report the same findings on a multi-root fixture with shared modules and
// cross-root literal companions.
func TestTerraformReferenceModeMatchesOptimized(t *testing.T) {
	dir, files := referenceFixture(t)
	optimized := findingKeys(scanReferenceMode(t, dir, files, false))
	reference := findingKeys(scanReferenceMode(t, dir, files, true))
	require.NotEmpty(t, optimized)
	require.Equal(t, optimized, reference)

	var planted, versionedElsewhere bool
	for _, k := range optimized {
		if k.QueryID != "no-versioning" {
			continue
		}
		switch k.ResourceName {
		case "planted_in_example":
			planted = true
			require.Contains(t, k.File, "/prod/")
		case "versioned_elsewhere":
			versionedElsewhere = true
		}
	}
	require.True(t, planted, "examples/ companions must not clear the planted bucket")
	require.False(t, versionedElsewhere, "ops companion must clear the versioned bucket")
}

func TestInspect_ElseBranchSchedulesSqsRoot(t *testing.T) {
	dir := t.TempDir()
	sqs := writeFile(t, dir, "sqs/main.tf", `resource "aws_sqs_queue" "only" {}`)
	files := parseTerraform(t, sqs)
	query := `package datadog

import rego.v1
import data.generic.common as common
import data.generic.terraform as tf

DatadogPolicy := out if {
	some b in tf.blocks("aws_s3_bucket")
	out := [common.finding(b, [], {})]
} else := out if {
	some q in tf.blocks("aws_sqs_queue")
	out := [common.finding(q, [], {})]
}
`
	meta := referenceQuery("else_branch", "else-branch", query)
	ins := newTestInspector(t, inspectorOpts{
		querySource: &referenceQueriesSource{queries: []model.QueryMetadata{meta}},
		repoPath:    dir, vb: DefaultVulnerabilityBuilder,
		tracker: &tracker.CITracker{}, flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 1)
	var sawSqs bool
	for i := range vulns {
		if vulns[i].ResourceType == "aws_sqs_queue" {
			sawSqs = true
		}
	}
	require.True(t, sawSqs, "the sqs-only root must not be skipped")
}

type crossIndexCandidate struct {
	dir string
	idx *project.CrossIndex
}

func serialCrossRootIndex(
	ctx context.Context, input *terraformInput, layout *tfmodel.Layout, keys project.LiteralKeys, opts project.Options,
) *project.CrossIndex {
	idx := project.NewCrossIndex()
	called := layout.CalledModuleDirectories(ctx, nil)
	want := func(t string) bool { _, ok := keys[t]; return ok }
	var candidates []crossIndexCandidate
	for _, dir := range layout.Roots {
		if ctx.Err() != nil {
			return idx
		}
		if !layout.MayDeclareResource(ctx, nil, dir, want) {
			continue
		}
		root := layout.Root(ctx, nil, dir)
		if input.scanned(root) && project.EvidenceRoot(root, nil) && project.HoldsCompanion(root, keys) {
			one := project.NewCrossIndex()
			one.Add(project.Project([]*tfmodel.Root{root}, opts))
			candidates = append(candidates, crossIndexCandidate{dir: filepath.Clean(root.Dir), idx: one})
		}
		root.Modules = nil
		if !called[filepath.Clean(root.Dir)] {
			layout.ReleaseRootParse(dir)
		}
	}
	for _, cand := range candidates {
		if !called[cand.dir] {
			idx.Merge(cand.idx)
		}
	}
	return idx
}

func crossMatchSignatures(t *testing.T, ctx context.Context, input *terraformInput, layout *tfmodel.Layout, opts project.Options) []string {
	t.Helper()
	var out []string
	require.NoError(t, layout.EachRoot(ctx, nil, layout.Roots, func(root *tfmodel.Root) error {
		if input.scanned(root) {
			p := project.Project([]*tfmodel.Root{root}, opts)
			for _, match := range p.Cross {
				out = append(out, fmt.Sprintf("%s/%s|%s/%s|%s", match.Target.Root, match.Target.Address,
					match.Evidence.Root, match.Evidence.Address, match.Evidence.File))
			}
		}
		root.Modules = nil
		return nil
	}))
	sort.Strings(out)
	return out
}

func TestCrossRootIndexParallelMatchesSerialWithSharedModuleRoots(t *testing.T) {
	dir, files := referenceFixture(t)
	companion := writeFile(t, filepath.Join(dir, "companions"), "main.tf", `
resource "aws_s3_bucket_versioning" "shared" {
  bucket = "shared"
}
`)
	files = append(files, parseTerraform(t, companion)...)
	ctx := context.Background()
	keys := project.LiteralKeys{
		"aws_s3_bucket_versioning": {"bucket": {"aws_s3_bucket": {"bucket"}}},
	}
	ins := newTestInspector(t, inspectorOpts{repoPath: dir})
	layout, err := ins.terraformLayout(ctx, files)
	require.NoError(t, err)
	require.NotNil(t, layout)
	input := &terraformInput{base: layout.Base, files: keyedFiles(ins.terraformFiles(files)), repoPath: dir}
	opts := project.Options{Placeholder: value.NewPlaceholder(), LiteralKeys: keys}

	parallel := ins.crossRootIndexLayout(ctx, input, layout, nil, opts)
	parallelOpts := opts
	parallelOpts.Cross = parallel
	got := crossMatchSignatures(t, ctx, input, layout, parallelOpts)

	serial := serialCrossRootIndex(ctx, input, layout, keys, opts)
	serialOpts := opts
	serialOpts.Cross = serial
	want := crossMatchSignatures(t, ctx, input, layout, serialOpts)
	require.NotEmpty(t, got, "fixture should exercise cross-root companion matches")
	require.Equal(t, want, got)
	require.True(t, slices.ContainsFunc(got, func(match string) bool {
		return strings.HasPrefix(match, "envs/a/module.svc.aws_s3_bucket.b|companions/aws_s3_bucket_versioning.shared")
	}), "the index should match evidence against a resource in a shared called module")
}

type deferredReferenceQueriesSource struct {
	referenceQueriesSource
}

func (s *deferredReferenceQueriesSource) GetQueryLibrary(ctx context.Context, platform string) (source.RegoLibraries, error) {
	library, err := s.referenceQueriesSource.GetQueryLibrary(ctx, platform)
	if err != nil || platform != "terraform" {
		return library, err
	}
	library.LibraryCode += `
variables := object.get(_dd, ["blocks", "variable"], [])
`
	return library, nil
}

func TestTerraformDeferredDecodeUsesRootOrderAfterWorkerCancellation(t *testing.T) {
	dir := t.TempDir()
	moduleDir := filepath.Join(dir, "modules", "shared")
	rootA := filepath.Join(dir, "envs", "a")
	rootB := filepath.Join(dir, "envs", "b")
	moduleFile := writeFile(t, moduleDir, "main.tf", `
variable "marker" {}
resource "aws_s3_bucket" "bucket" {
  bucket = var.marker
}
`)
	rootAFile := writeFile(t, rootA, "main.tf", `
module "shared" {
  source = "../../modules/shared"
  marker = "first"
}
`)
	rootBFile := writeFile(t, rootB, "main.tf", `
module "shared" {
  source = "../../modules/shared"
  marker = "second"
}
`)
	files := append(parseTerraform(t, moduleFile), parseTerraform(t, rootAFile)...)
	files = append(files, parseTerraform(t, rootBFile)...)

	query := referenceQuery("static_module_variable", "static-module-variable", `package datadog

import rego.v1

import data.generic.common as common
import data.generic.terraform as tf

DatadogPolicy contains result if {
	some variable in tf.variables
	some bucket in tf.blocks("aws_s3_bucket")
	result := common.finding(variable, [], {"descriptionText": bucket.bucket})
}
`)
	queries := &deferredReferenceQueriesSource{referenceQueriesSource{queries: []model.QueryMetadata{query}}}
	ins := newTestInspector(t, inspectorOpts{
		querySource:   queries,
		repoPath:      dir,
		vb:            DefaultVulnerabilityBuilder,
		tracker:       &tracker.CITracker{},
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ctx := context.Background()
	layout, err := ins.terraformLayout(ctx, files)
	require.NoError(t, err)
	stream, err := ins.newTerraformStream(ctx, "deferred-order", files, layout, []model.QueryMetadata{query}, nil, false)
	require.NoError(t, err)
	require.Len(t, stream.tfRun.queries.queries, 1)

	evaluate := func(rootDir string) QueryResult {
		t.Helper()
		root := stream.root(ctx, rootDir)
		require.NotNil(t, root)
		projection := tfproject.Project([]*tfmodel.Root{root}, stream.opts)
		variableBlocks := 0
		for _, loc := range projection.Blocks {
			if loc.Kind == "variable" && loc.Block != nil && loc.Block.Module != nil && loc.Block.Module.Address != "" {
				variableBlocks++
			}
		}
		require.Positive(t, variableBlocks, "the reported variable must be a static block inside the shared local module")
		rootInput := stream.input // retain the scan-wide written finding set across roots
		rootInput.projection = projection
		workerCtx, cancel := context.WithCancel(ctx)
		result := ins.evalQueryDeferred(workerCtx, stream.tfRun.queries,
			platformPayloads{full: projection.Input, terraform: &rootInput}, 0)
		cancel()
		require.NoError(t, result.err)
		require.NotNil(t, result.pending, "the worker should return before result decoding")
		return result
	}

	// Evaluate B before A, then aggregate in the intended root order. The
	// worker contexts are canceled immediately after evaluation returns.
	resultB := evaluate(rootB)
	resultA := evaluate(rootA)
	ins.aggregateQueryResults(ctx, stream.tfRun.queries, []QueryResult{resultA, resultB})

	findings := stream.tfRun.queries.findings(false)
	require.Len(t, findings, 1, "the shared static variable finding is reported once across module instances")
	require.Equal(t, "first", findings[0].Description, "root A owns the shared written finding even though B evaluated first")
}

func TestParallelRelationalRootsRetractFailedRuleAndKeepOrder(t *testing.T) {
	dir := t.TempDir()
	good := writeFile(t, filepath.Join(dir, "01-good"), "main.tf", `resource "aws_s3_bucket" "good" {
 acl = "private"
}`)
	bad := writeFile(t, filepath.Join(dir, "02-failing"), "main.tf", `resource "aws_s3_bucket" "bad" {
 acl = "private"
 tags = { conflict = "yes" }
}`)
	files := append(parseTerraform(t, good), parseTerraform(t, bad)...)
	failing := referenceQuery("conflicting", "conflicting-id", `package datadog
 import rego.v1
 import data.generic.common as common
 import data.generic.terraform as tf
 kind(b) := "private" if b.acl == "private"
 kind(b) := "conflict" if b.tags.conflict == "yes"
 DatadogPolicy contains result if {
  some b in tf.blocks("aws_s3_bucket")
  count(tf.blocks("aws_s3_bucket")) > 0
  kind(b) == "private"
  result := common.finding(b, [], {})
 }`)
	survivor := referenceQuery("survivor", "survivor-id", referenceVersioningRule)
	survivor.Metadata["queryName"] = "conflicting"
	scan := func(reference bool) []model.Vulnerability {
		ins := newTestInspector(t, inspectorOpts{
			querySource: &referenceQueriesSource{queries: []model.QueryMetadata{failing, survivor}},
			repoPath:    dir, vb: DefaultVulnerabilityBuilder,
			tracker: &tracker.CITracker{}, flagEvaluator: featureflags.NewLocalEvaluator(),
		})
		ins.SetTerraformReferenceMode(reference)
		vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
		require.NoError(t, err)
		require.Contains(t, ins.GetFailedQueries(), "conflicting")
		require.Len(t, vulns, 2)
		for _, vuln := range vulns {
			require.Equal(t, "survivor-id", vuln.QueryID)
		}
		if !reference {
			// Ensure the fixture exercises the per-root relational pool.
			rules := ins.newTerraformRules(context.Background(), []model.QueryMetadata{failing}, "placeholder", nil)
			require.Equal(t, schedule.Relational, rules.rule(terraformQueryKey(&failing)).harvest.Class)
		}
		return vulns
	}
	want := scan(true)
	got := scan(false)
	require.Equal(t, findingKeys(want), findingKeys(got))
	for i := range got {
		require.Equal(t, want[i].FileName, got[i].FileName)
	}
}

func TestParallelRelationalRootsPropagateCancellationDuringDecode(t *testing.T) {
	dir := t.TempDir()
	first := writeFile(t, filepath.Join(dir, "a"), "main.tf", `resource "aws_s3_bucket" "a" { bucket = "first" }`)
	second := writeFile(t, filepath.Join(dir, "b"), "main.tf", `resource "aws_s3_bucket" "b" { bucket = "second" }`)
	files := append(parseTerraform(t, first), parseTerraform(t, second)...)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var decoded atomic.Int32
	builder := func(ctx context.Context, q *QueryContext, tr Tracker, raw interface{},
		dl *detector.DetectLine, old bool, duration time.Duration,
	) (*model.Vulnerability, error) {
		vuln, err := DefaultVulnerabilityBuilder(ctx, q, tr, raw, dl, old, duration)
		if vuln != nil {
			decoded.Add(1)
			cancel()
		}
		return vuln, err
	}
	ins := newTestInspector(t, inspectorOpts{
		querySource: &referenceQueriesSource{queries: []model.QueryMetadata{
			referenceQuery("no_versioning", "no-versioning", referenceVersioningRule),
		}},
		repoPath: dir, vb: builder, tracker: &tracker.CITracker{},
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	vulns, err := ins.Inspect(ctx, "test", files, []string{"terraform"})
	require.Positive(t, decoded.Load(), "cancel while decoding, after the evaluation pool joins")
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, vulns)
}

func TestParallelRelationalWindowsMatchReference(t *testing.T) {
	dir := t.TempDir()
	var files model.FileMetadatas
	for i := range 25 {
		path := writeFile(t, filepath.Join(dir, fmt.Sprintf("root-%02d", i)), "main.tf", fmt.Sprintf(`
variable "opaque" {}
resource "aws_s3_bucket" "b" {
 bucket = "bucket-%d"
 tags = { opaque = var.opaque }
}`, i))
		files = append(files, parseTerraform(t, path)...)
	}
	scan := func(reference bool) []model.Vulnerability {
		ins := newTestInspector(t, inspectorOpts{
			querySource: &referenceQueriesSource{queries: []model.QueryMetadata{
				referenceQuery("no_versioning", "no-versioning", referenceVersioningRule),
			}},
			repoPath: dir, vb: DefaultVulnerabilityBuilder, tracker: &tracker.CITracker{},
			flagEvaluator: featureflags.NewLocalEvaluator(),
		})
		ins.SetTerraformReferenceMode(reference)
		got, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
		require.NoError(t, err)
		require.Empty(t, ins.GetFailedQueries())
		require.Len(t, got, 25)
		return got
	}
	want, got := scan(true), scan(false)
	require.Equal(t, findingKeys(want), findingKeys(got))
	for i := range got {
		require.Equal(t, want[i].FileName, got[i].FileName)
	}
}
