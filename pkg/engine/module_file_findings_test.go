/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

const bucketSource = "git::https://github.com/DataDog/cloud-inventory//terraform-modules/aws-bucket?ref=v1.2.0"

// writeRemoteBucketPackage lays down a fetched git package whose aws-bucket
// module calls a local helper declaring only outputs, called from two stacks.
func writeRemoteBucketPackage(t *testing.T) (repo, pkg string, files model.FileMetadatas) {
	t.Helper()
	repo = t.TempDir()
	pkg = t.TempDir()
	bucket := filepath.Join(pkg, "terraform-modules", "aws-bucket")
	helper := filepath.Join(pkg, "terraform-modules", "aws--helper")
	files = model.FileMetadatas{
		fileMeta("bucket-inputs", writeFile(t, bucket, "inputs.tf", `variable "name" {}
`)),
		fileMeta("bucket-main", writeFile(t, bucket, "main.tf", `module "helper" {
  source = "../aws--helper"
  name   = var.name
}
`)),
		fileMeta("helper-outputs", writeFile(t, helper, "@outputs.tf", `variable "name" {}
output "name" { value = var.name }
`)),
	}
	for _, stack := range []string{"stack-a", "stack-b"} {
		files = append(files, fileMeta(stack, writeFile(t, filepath.Join(repo, stack), "main.tf", `module "bucket" {
  source = "`+bucketSource+`"
  name   = "`+stack+`"
}
`)))
	}
	return repo, pkg, files
}

func resolveRemoteBucketPackage(
	t *testing.T,
	repo, pkg string,
	files model.FileMetadatas,
	targets *ruleTargets,
) moduleResolutionResult {
	t.Helper()
	bucket := filepath.Join(pkg, "terraform-modules", "aws-bucket")
	resolver := func(source, _, _, _ string) (string, string, bool) {
		return bucket, pkg, source == bucketSource
	}
	lookup := func(_, source, _, _ string) (RemoteModuleProvenance, bool) {
		if source != bucketSource {
			return RemoteModuleProvenance{}, false
		}
		return RemoteModuleProvenance{
			Source:      source,
			SourceType:  moduleSourceTypeGit,
			ResolvedRef: "0123456789abcdef",
			ModuleRoot:  bucket,
			PackageRoot: pkg,
		}, true
	}
	external := func(path string) bool { return pathWithinRoot(path, pkg) }
	return resolveModuleDocuments(context.Background(), files, repo, resolver, targets, lookup, nil, nil, external)
}

func TestResolveModuleDocuments_AttributesExternalModuleFilesToEveryCall(t *testing.T) {
	repo, pkg, files := writeRemoteBucketPackage(t)
	res := resolveRemoteBucketPackage(t, repo, pkg, files, nil)
	require.True(t, res.ok)

	require.NotContains(t, res.moduleFiles, "stack-a", "files of the scanned repository are reported where they are written")
	helper := res.moduleFiles["helper-outputs"]
	require.NotNil(t, helper, "a module declaring no resource is still reached by its calls")
	require.Len(t, helper.calls, 2)
	require.False(t, helper.keepWritten)
	require.Equal(t, "@outputs.tf", helper.name)

	chains := map[string]*model.ModuleAttribution{}
	for _, call := range helper.calls {
		chains[call.callChain] = call.attribution
	}
	require.Contains(t, chains, "stack-a/main.tf|module.bucket.module.helper")
	require.Contains(t, chains, "stack-b/main.tf|module.bucket.module.helper")

	attr := chains["stack-b/main.tf|module.bucket.module.helper"]
	require.Equal(t, model.SourceLocation{
		Filename: "stack-b/main.tf", LineStart: 2, LineEnd: 2, ColumnStart: 3, ColumnEnd: 14 + len(bucketSource),
	}, attr.CallSite)
	require.Equal(t, "terraform-modules/aws--helper", attr.ModuleCodeLocation.Filename)
	require.Equal(t, moduleSourceTypeGit, attr.SourceType)
	require.Equal(t, "https://github.com/datadog/cloud-inventory", attr.Source)
	require.Equal(t, "v1.2.0", attr.Version)
	require.Equal(t, moduleDependencyTransitive, attr.DependencyType)
	require.Len(t, attr.ModulePath, 2)
	require.Equal(t, "helper", attr.ModulePath[1].Name)
	require.Equal(t, "https://github.com/DataDog/cloud-inventory//terraform-modules/aws--helper", attr.ModulePath[1].Source)

	bucketInputs := res.moduleFiles["bucket-inputs"]
	require.NotNil(t, bucketInputs)
	require.Len(t, bucketInputs.calls, 2)
	require.Equal(t, "terraform-modules/aws-bucket", bucketInputs.calls[0].attribution.ModuleCodeLocation.Filename)
	require.Equal(t, moduleDependencyDirect, bucketInputs.calls[0].attribution.DependencyType)
}

func TestResolveModuleDocuments_AttributesExternalModuleFilesWithoutTargetedResources(t *testing.T) {
	repo, pkg, files := writeRemoteBucketPackage(t)
	targets := &ruleTargets{types: map[string]bool{"aws_s3_bucket": true}}
	res := resolveRemoteBucketPackage(t, repo, pkg, files, targets)
	require.True(t, res.ok)
	require.Empty(t, res.docs)
	require.Empty(t, res.calledDirs, "nothing instantiated, so no call site is stripped")
	require.Len(t, res.moduleFiles["helper-outputs"].calls, 2)
}

func TestResolveModuleDocuments_ExternalModuleNoScannedFileCallsIsLeftAsWritten(t *testing.T) {
	repo, pkg, files := writeRemoteBucketPackage(t)
	var external model.FileMetadatas
	for _, f := range files {
		if pathWithinRoot(f.FilePath, pkg) {
			external = append(external, f)
		}
	}
	res := resolveRemoteBucketPackage(t, repo, pkg, external, nil)
	for id, file := range res.moduleFiles {
		for _, call := range file.calls {
			require.False(t, pathWithinRoot(filepath.Join(repo, call.attribution.CallSite.Filename), pkg),
				"%s must not be attributed to a call site inside an external module", id)
		}
	}
	require.Empty(t, res.moduleFiles["helper-outputs"], "no scanned file calls the package")
}

func TestResolveModuleDocuments_NoExternalFilesRecordsNoCalls(t *testing.T) {
	repo, pkg, files := writeRemoteBucketPackage(t)
	bucket := filepath.Join(pkg, "terraform-modules", "aws-bucket")
	resolver := func(source, _, _, _ string) (string, string, bool) {
		return bucket, pkg, source == bucketSource
	}
	res := resolveModuleDocuments(context.Background(), files, repo, resolver, nil, nil, nil, nil, nil)
	require.True(t, res.ok)
	require.Nil(t, res.moduleFiles)
}

func TestAttributeModuleFileFindings(t *testing.T) {
	call := func(chain, root string) moduleCall {
		return moduleCall{callChain: chain, attribution: &model.ModuleAttribution{
			SourceType:         moduleSourceTypeGit,
			CallSite:           model.SourceLocation{Filename: root, LineStart: 2},
			ModuleCodeLocation: model.SourceLocation{Filename: "terraform-modules/aws--helper"},
			ModulePath:         []model.ModulePathHop{{Name: "bucket"}, {Name: "helper"}},
		}}
	}
	files := map[string]*moduleFileCalls{
		"helper": {
			calls:                []moduleCall{call("stack-a/main.tf|module.bucket.module.helper", "stack-a/main.tf"), call("stack-b/main.tf|module.bucket.module.helper", "stack-b/main.tf")},
			name:                 "@outputs.tf",
			writtenResourceTypes: map[string]bool{"aws_s3_bucket": true},
		},
		"partial": {
			calls:       []moduleCall{call("stack-a/main.tf|module.other", "stack-a/main.tf")},
			name:        "main.tf",
			keepWritten: true,
		},
	}
	attributed := &model.ModuleAttribution{}
	vulns := []model.Vulnerability{
		{QueryID: "repo", FileID: "stack-a"},
		{QueryID: "output", FileID: "helper", ResourceType: "output", Line: 2,
			VulnerabilityLocation: model.ResourceLocation{
				Start: model.ResourceLine{Line: 2, Col: 1}, End: model.ResourceLine{Line: 2, Col: 36},
			}},
		{QueryID: "written-resource", FileID: "helper", ResourceType: "aws_s3_bucket", Line: 5},
		{QueryID: "instantiated", FileID: "helper", ResourceType: "aws_s3_bucket", ModuleAttribution: attributed},
		{QueryID: "variable", FileID: "partial", ResourceType: "variable", Line: 1},
	}

	got := attributeModuleFileFindings(vulns, files)

	ids := make([]string, 0, len(got))
	for i := range got {
		ids = append(ids, got[i].QueryID+"@"+got[i].ModuleCallChain)
	}
	require.Equal(t, []string{
		"repo@",
		"output@stack-a/main.tf|module.bucket.module.helper",
		"output@stack-b/main.tf|module.bucket.module.helper",
		"written-resource@",
		"instantiated@",
		"variable@",
		"variable@stack-a/main.tf|module.other",
	}, ids)

	output := got[2].ModuleAttribution
	require.Equal(t, "stack-b/main.tf", output.CallSite.Filename)
	require.Equal(t, model.SourceLocation{
		Filename: "terraform-modules/aws--helper/@outputs.tf", LineStart: 2, LineEnd: 2, ColumnStart: 1, ColumnEnd: 36,
	}, output.ModuleCodeLocation)
	require.Same(t, attributed, got[4].ModuleAttribution)
	require.Nil(t, got[5].ModuleAttribution)
	require.Equal(t, model.SourceLocation{Filename: "terraform-modules/aws--helper/main.tf", LineStart: 1, LineEnd: 1, ColumnStart: 1, ColumnEnd: 2},
		got[6].ModuleAttribution.ModuleCodeLocation)
	require.Equal(t, "terraform-modules/aws--helper", files["helper"].calls[0].attribution.ModuleCodeLocation.Filename,
		"shared call attributions are not mutated")

	unchanged := []model.Vulnerability{{FileID: "stack-a"}}
	require.Equal(t, &unchanged[0], &attributeModuleFileFindings(unchanged, files)[0], "nothing is copied when nothing is attributed")
}

func TestRootsReachingKeepsRootsCallingTargetDirectories(t *testing.T) {
	graph := staticCallGraph{
		calls: map[string][]string{
			"a":      {"local", "ext"},
			"b":      {"local"},
			"c":      nil,
			"d":      {"opaque"},
			"e":      {"local", "opaque"},
			"local":  {"nested"},
			"nested": {"ext"},
		},
		opaque: map[string]bool{"opaque": true},
	}
	targets := map[string][]*model.FileMetadata{"ext": nil}
	require.Equal(t, []string{"a", "b", "d", "e"}, rootsReaching([]string{"a", "b", "c", "d", "e"}, graph, targets))
	require.Equal(t, []string{"c"}, rootsReaching([]string{"c"}, staticCallGraph{calls: graph.calls}, map[string][]*model.FileMetadata{"c": nil}))
	require.Empty(t, rootsReaching([]string{"c"}, graph, targets))
}

// A cycle in the static graph must not hide what a directory on it reaches.
func TestRootsReachingIsOrderIndependentOnCycles(t *testing.T) {
	graph := staticCallGraph{calls: map[string][]string{
		"r1": {"a"},
		"a":  {"b", "t"},
		"b":  {"a"},
		"r2": {"b"},
	}}
	targets := map[string][]*model.FileMetadata{"t": nil}
	require.Equal(t, []string{"r1", "r2"}, rootsReaching([]string{"r1", "r2"}, graph, targets))
	require.Equal(t, []string{"r2", "r1"}, rootsReaching([]string{"r2", "r1"}, graph, targets))
}

// parsedFileMeta reads path through the Terraform parser, as a scan does, so
// call discovery works from the parsed documents.
func parsedFileMeta(t *testing.T, id, path string) *model.FileMetadata {
	t.Helper()
	metas := parseTerraform(t, path)
	require.Len(t, metas, 1)
	metas[0].ID = id
	return metas[0]
}

func parsedPackage(t *testing.T, files model.FileMetadatas) model.FileMetadatas {
	t.Helper()
	out := make(model.FileMetadatas, 0, len(files))
	for _, f := range files {
		out = append(out, parsedFileMeta(t, f.ID, f.FilePath))
	}
	return out
}

func successfulRootIDs(res moduleResolutionResult, repo string) []string {
	var out []string
	for dir := range res.successfulRoots {
		rel, err := filepath.Rel(repo, dir)
		if err == nil {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}

// With nothing to resolve, only the roots whose calls reach the external
// package are evaluated, found through the parsed documents of a scan.
func TestResolveModuleDocuments_EvaluatesOnlyRootsReachingExternalModules(t *testing.T) {
	repo, pkg, files := writeRemoteBucketPackage(t)
	files = append(files,
		fileMeta("local-outputs", writeFile(t, filepath.Join(repo, "modules", "local"), "main.tf", `output "x" { value = 1 }
`)),
		fileMeta("stack-c", writeFile(t, filepath.Join(repo, "stack-c"), "main.tf", `module "local" {
  source = "../modules/local"
}
`)),
		fileMeta("stack-d", writeFile(t, filepath.Join(repo, "stack-d"), "main.tf", `module "bucket" {
  source = "`+bucketSource+`"
  name   = "stack-d"
}
module "local" {
  source = "../modules/local"
}
`)),
	)
	targets := &ruleTargets{types: map[string]bool{"aws_s3_bucket": true}}
	res := resolveRemoteBucketPackage(t, repo, pkg, parsedPackage(t, files), targets)
	require.True(t, res.ok)

	require.Equal(t, []string{"stack-a", "stack-b", "stack-d"}, successfulRootIDs(res, repo),
		"stack-c only calls a module of the scanned repository")
	require.Len(t, res.moduleFiles["helper-outputs"].calls, 3)
}

// A call whose source is built at evaluation time cannot be followed without
// evaluating it, so the roots making it, or reaching it, stay evaluated.
func TestResolveModuleDocuments_KeepsRootsWithDynamicModuleSources(t *testing.T) {
	repo, pkg, files := writeRemoteBucketPackage(t)
	files = append(files,
		fileMeta("local-dynamic", writeFile(t, filepath.Join(repo, "modules", "dynamic"), "main.tf", `variable "registry" {}
module "inner" {
  source = "${var.registry}/aws-bucket"
}
`)),
		fileMeta("stack-c", writeFile(t, filepath.Join(repo, "stack-c"), "main.tf", `variable "registry" {}
module "dynamic" {
  source = "${var.registry}/aws-bucket"
}
`)),
		fileMeta("stack-d", writeFile(t, filepath.Join(repo, "stack-d"), "main.tf", `module "dynamic" {
  source = "../modules/dynamic"
}
`)),
		fileMeta("stack-e", writeFile(t, filepath.Join(repo, "stack-e"), "main.tf", `module "local" {
  source = "../modules/local"
}
`)),
		fileMeta("local-outputs", writeFile(t, filepath.Join(repo, "modules", "local"), "main.tf", `output "x" { value = 1 }
`)),
	)
	targets := &ruleTargets{types: map[string]bool{"aws_s3_bucket": true}}
	res := resolveRemoteBucketPackage(t, repo, pkg, parsedPackage(t, files), targets)
	require.True(t, res.ok)

	require.Equal(t, []string{"stack-a", "stack-b", "stack-c", "stack-d"}, successfulRootIDs(res, repo))
}

func TestNewModuleCallIndexReturnsNilWithoutExternalFiles(t *testing.T) {
	repo := t.TempDir()
	local := filepath.Join(repo, "stack")
	idx := newModuleCallIndex(map[string][]*model.FileMetadata{
		local: {fileMeta("local", writeFile(t, local, "main.tf", `module "x" { source = "../mod" }`))},
	}, func(string) bool { return false })
	require.Nil(t, idx)
	require.Nil(t, newModuleCallIndex(nil, func(string) bool { return true }))
}

func TestDocumentResourceTypes(t *testing.T) {
	require.Nil(t, documentResourceTypes(model.Document{"resource": "not-a-map"}))
	require.Nil(t, documentResourceTypes(model.Document{}))
	require.Equal(t, map[string]bool{"aws_s3_bucket": true}, documentResourceTypes(model.Document{
		"resource": map[string]any{"aws_s3_bucket": map[string]any{"b": map[string]any{}}},
	}))
}

func TestAttributeModuleFileFindingsLeavesPreAttributedUnchanged(t *testing.T) {
	attr := &model.ModuleAttribution{CallSite: model.SourceLocation{Filename: "stack/main.tf"}}
	files := map[string]*moduleFileCalls{
		"ext": {calls: []moduleCall{{callChain: "chain", attribution: &model.ModuleAttribution{}}}, name: "main.tf"},
	}
	v := model.Vulnerability{FileID: "ext", ResourceType: "output", ModuleAttribution: attr}
	got := attributeModuleFileFindings([]model.Vulnerability{v}, files)
	require.Len(t, got, 1)
	require.Same(t, attr, got[0].ModuleAttribution)
}

func TestHasUnresolvableModuleCall(t *testing.T) {
	call := func(source any) *model.FileMetadata {
		return &model.FileMetadata{Document: model.Document{
			"module": map[string]any{"m": map[string]any{"source": source}},
		}}
	}
	require.False(t, hasUnresolvableModuleCall([]*model.FileMetadata{call("../local"), call("git::https://x/y?ref=v1"), nil}))
	require.False(t, hasUnresolvableModuleCall([]*model.FileMetadata{{Document: model.Document{"resource": map[string]any{}}}}))
	require.True(t, hasUnresolvableModuleCall([]*model.FileMetadata{call("${var.registry}/mod")}))
	require.True(t, hasUnresolvableModuleCall([]*model.FileMetadata{call("%{ if x }a%{ endif }")}))
	require.True(t, hasUnresolvableModuleCall([]*model.FileMetadata{call(nil)}))
	require.True(t, hasUnresolvableModuleCall([]*model.FileMetadata{{Document: model.Document{}}}), "an unparsed file is not known to be free of them")
}
