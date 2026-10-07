/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"path/filepath"
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
	require.Equal(t, "https://github.com/datadog/cloud-inventory//terraform-modules/aws--helper", attr.ModulePath[1].Source)

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
