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

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	tfmodel "github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
)

const movedFileRule = `package datadog

DatadogPolicy contains result if {
	some i
	doc := input.document[i]
	is_array(doc.moved)
	some idx
	m := doc.moved[idx]
	m.from

	result := {
		"documentId": doc.id,
		"resourceType": "moved",
		"resourceName": sprintf("%d", [idx]),
		"searchKey": sprintf("moved[%d]", [idx]),
	}
}

DatadogPolicy contains result if {
	some i
	doc := input.document[i]
	is_object(doc.moved)
	doc.moved.from

	result := {
		"documentId": doc.id,
		"resourceType": "moved",
		"resourceName": "",
		"searchKey": "moved",
	}
}
`

// Two files of one external module each declare one moved block. Both findings
// survive because they are different files. The module-wide index still gives
// the routed copies distinct stored addresses: the first file's block is
// moved.0 and the second file's is moved.1.
func TestInspect_ExternalModuleFileUnlabeledBlocksStayDistinct(t *testing.T) {
	root := t.TempDir()
	cacheDir := filepath.Join(root, "cache")
	stackDir := filepath.Join(root, "stack")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))
	require.NoError(t, os.MkdirAll(stackDir, 0o755))

	firstPath := filepath.Join(cacheDir, "first.tf")
	require.NoError(t, os.WriteFile(firstPath, []byte(`
moved {
  from = aws_a.first
  to   = aws_b.first
}
`), 0o644))
	secondPath := filepath.Join(cacheDir, "second.tf")
	require.NoError(t, os.WriteFile(secondPath, []byte(`
moved {
  from = aws_a.second
  to   = aws_b.second
}
`), 0o644))

	callerPath := filepath.Join(stackDir, "main.tf")
	require.NoError(t, os.WriteFile(callerPath, []byte(`
module "m" {
  source = "../cache"
}
`), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraform(t, firstPath)...)
	files = append(files, parseTerraform(t, secondPath)...)
	files = append(files, parseTerraform(t, callerPath)...)

	tr := &tracker.CITracker{}
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "moved_rule", Content: movedFileRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "moved-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		tracker:       tr,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetExternalModulePaths([]string{cacheDir})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())

	require.Len(t, vulns, 2, "each file's moved block is reported through the call")
	ids := map[string]bool{}
	for i := range vulns {
		require.NotEmpty(t, vulns[i].ResourceID, "each routed copy carries its address")
		ids[vulns[i].ResourceID] = true
	}
	require.Len(t, ids, 2, "the two routed addresses are distinct")
	require.Contains(t, ids, "module.m.moved.0", "first file's block is indexed first")
	require.Contains(t, ids, "module.m.moved.1", "second file's block keeps a distinct index")
}

func TestInspect_ExternalModuleVariableFindingsFollowResolvedCallers(t *testing.T) {
	repo := t.TempDir()
	cacheDir := filepath.Join(repo, "cache", "module")
	orphanDir := filepath.Join(repo, "cache", "orphan")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))
	require.NoError(t, os.MkdirAll(orphanDir, 0o755))

	modulePath := filepath.Join(cacheDir, "variables.tf")
	require.NoError(t, os.WriteFile(modulePath, []byte("variable \"placement_group\" {\n  default = \"group\"\n}\n"), 0o644))
	orphanPath := filepath.Join(orphanDir, "variables.tf")
	require.NoError(t, os.WriteFile(orphanPath, []byte("variable \"orphan\" {}\n"), 0o644))

	var files model.FileMetadatas
	files = append(files, parseTerraformWritten(t, modulePath)...)
	files = append(files, parseTerraformWritten(t, orphanPath)...)
	for _, env := range []string{"a", "b"} {
		path := filepath.Join(repo, "stacks", env, "main.tf")
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte("module \"module\" {\n  source = \"../../cache/module\"\n}\n"), 0o644))
		files = append(files, parseTerraformWritten(t, path)...)
	}

	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "variable_without_description", Content: variableWithoutDescriptionRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "variable-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath: repo, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetExternalModulePaths([]string{filepath.Join(repo, "cache")})
	ins.SetRemoteModuleDirectories(map[string]RemoteModuleDirectory{
		RemoteModuleKey(filepath.Join(repo, "stacks", "a"), "../../cache/module", ""): {
			Path: cacheDir, PackageRoot: filepath.Dir(cacheDir),
		},
		RemoteModuleKey(filepath.Join(repo, "stacks", "b"), "../../cache/module", ""): {
			Path: cacheDir, PackageRoot: filepath.Dir(cacheDir),
		},
		RemoteModuleKey(filepath.Join(repo, "stacks", "a"), "../../cache/orphan", ""): {
			Path: orphanDir, PackageRoot: filepath.Dir(orphanDir),
		},
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 2, "the written module finding is reported through each resolved call, and the orphan is dropped")
	callers := map[string]bool{}
	for i := range vulns {
		require.Equal(t, "placement_group", vulns[i].ResourceName)
		require.NotNil(t, vulns[i].ModuleAttribution)
		callers[vulns[i].ModuleAttribution.CallSite.Filename] = true
	}
	require.Contains(t, callers, "stacks/a/main.tf")
	require.Contains(t, callers, "stacks/b/main.tf")

	routing := newFindingRouting(files, repo)
	nestedExternal := model.Vulnerability{
		FileName: modulePath,
		ModuleAttribution: &model.ModuleAttribution{
			CallSite: model.SourceLocation{Filename: "cache/module/variables.tf"},
		},
	}
	require.Empty(t, routing.route(context.Background(), ins, []model.Vulnerability{nestedExternal}),
		"a call site in an external module is not a scanned-repository caller")
	validCall := model.Vulnerability{
		FileName: modulePath,
		ModuleAttribution: &model.ModuleAttribution{
			CallSite: model.SourceLocation{Filename: vulns[0].ModuleAttribution.CallSite.Filename},
		},
	}
	require.Len(t, routing.route(context.Background(), ins, []model.Vulnerability{validCall}), 1,
		"a finding with a scanned repository caller remains attributable")
	rootPath := filepath.Join(repo, "stacks", "a", "main.tf")
	rootFinding := model.Vulnerability{FileName: rootPath}
	require.Equal(t, []model.Vulnerability{rootFinding},
		routing.route(context.Background(), ins, []model.Vulnerability{rootFinding}),
		"non-external findings without module attribution remain untouched")
}

func TestLegacyModuleBlockIndexPreservesPerFileAttributions(t *testing.T) {
	repo := t.TempDir()
	callFile := filepath.Join(repo, "main.tf")
	module := &tfmodel.Module{
		Root:    &tfmodel.Root{ID: ".", Dir: repo},
		Address: "module.app",
		Dir:     filepath.Join(repo, "modules", "app"),
		Chain: []tfeval.CallSite{{
			ModuleName:    "app",
			Source:        "./modules/app",
			CalledFrom:    callFile,
			CalledLine:    2,
			CalledEndLine: 5,
		}},
	}

	block := func(kind, typ, name, file string, line int) *tfmodel.Block {
		b := &tfmodel.Block{
			Module: module,
			Kind:   kind,
			Type:   typ,
			Name:   name,
			File:   file,
			Range: hcl.Range{
				Filename: filepath.Join(repo, filepath.FromSlash(file)),
				Start:    hcl.Pos{Line: line, Column: 1},
				End:      hcl.Pos{Line: line + 1, Column: 2},
			},
			Syntax: &hclsyntax.Block{Body: &hclsyntax.Body{}},
		}
		b.Instances = []*tfmodel.Instance{{Block: b}}
		return b
	}
	module.Blocks = []*tfmodel.Block{
		block(address.KindResource, "aws_s3_bucket", "first", "modules/app/a.tf", 3),
		block(address.KindData, "aws_caller_identity", "current", "modules/app/a.tf", 8),
		block(address.KindProvider, "aws", "", "modules/app/a.tf", 12),
		block(address.KindEphemeral, "random_password", "secret", "modules/app/b.tf", 4),
		block(address.KindResource, "aws_kms_key", "key", "modules/app/b.tf", 9),
		block(address.KindResource, "aws_s3_bucket", "without_instances", "modules/app/b.tf", 15),
	}

	inspector := &Inspector{repoPath: repo}
	attribution := &terraformAttribution{cache: newModuleAttributionCache()}
	index := legacyModuleBlockIndex{}
	for _, rel := range []string{"modules/app/a.tf", "modules/app/b.tf"} {
		path := filepath.Join(repo, filepath.FromSlash(rel))
		written := &model.FileMetadata{ID: rel, FilePath: path, Kind: model.KindTerraform}
		doc := &project.LegacyDoc{
			Doc:    model.Document{legacyIDKey: "instance:" + rel},
			Path:   path,
			Module: module,
		}
		got := inspector.legacyModuleFile(written, doc, index.forFile(module, repo, path), "", attribution)

		// This is the former full-module scan, retained here as an independent
		// oracle for the blocks and attribution keys included in each file.
		want := map[string]*model.ModuleAttribution{}
		for _, b := range module.Blocks {
			if len(b.Instances) == 0 || project.JoinRoot(repo, b.File) != path {
				continue
			}
			r, kind := resolvedBlock(b, b.Instances[0], module, path)
			if r == nil {
				continue
			}
			if attr := attribution.resource(r, repo); attr != nil {
				want[moduleAttributionKey(kind, r.DefLine, r.DefColumn)] = attr
			}
		}
		require.Equal(t, want, got.ModuleAttributions, "file %s keeps the legacy attribution map", rel)
	}
}
