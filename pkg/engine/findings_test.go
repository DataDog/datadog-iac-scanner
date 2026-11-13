/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
)

// instanceFindings are the findings the instances of one count-expanded
// resource block raise: one per instance document, all of one identity.
func instanceFindings(instances int, line int) []model.Vulnerability {
	out := make([]model.Vulnerability, 0, instances)
	for i := 0; i < instances; i++ {
		out = append(out, model.Vulnerability{
			FileName: "modules/app/main.tf", Platform: "Terraform", QueryID: "q",
			ResourceType: "aws_s3_bucket", ResourceName: "replica",
			ModuleCallChain: "stack/main.tf|module.app",
			Line:            line + i, SearchKey: "aws_s3_bucket[replica].acl",
		})
	}
	return out
}

// decodeAll gives set the findings a rule raised, in the order
// DecodeQueryResults would, and returns what it kept.
func decodeAll(set *findingSet, raised []model.Vulnerability) []model.Vulnerability {
	for i := range raised {
		v := raised[i]
		set.addRouted(context.Background(), &Inspector{}, &v)
	}
	return set.findings()
}

func TestFindingSet_KeepsTheFirstFindingOfEachIdentity(t *testing.T) {
	set := newFindingSet(true, nil)
	raised := instanceFindings(3, 10)
	other := raised[0]
	other.ResourceName = "primary"
	raised = append(raised, other)

	got := decodeAll(set, raised)

	require.Len(t, got, 2)
	require.Equal(t, 10, got[0].Line, "the first instance's finding is the one kept")
	require.Equal(t, "primary", got[1].ResourceName, "a different identity is kept on its own")
}

// What the set keeps must be what the scan reports, so that keeping findings
// as they are decoded cannot change a report.
func TestFindingSet_KeepsWhatStorageReports(t *testing.T) {
	ctx := context.Background()
	raised := append(instanceFindings(3, 10), instanceFindings(2, 40)...)
	raised[3].ResourceName = "other"
	raised[4].ResourceName = "other"

	direct := storage.NewMemoryStorage()
	require.NoError(t, direct.SaveVulnerabilities(ctx, append([]model.Vulnerability(nil), raised...)))
	want, err := direct.GetVulnerabilities(ctx, "")
	require.NoError(t, err)

	kept := decodeAll(newFindingSet(true, nil), raised)
	reduced := storage.NewMemoryStorage()
	require.NoError(t, reduced.SaveVulnerabilities(ctx, append([]model.Vulnerability(nil), kept...)))
	got, err := reduced.GetVulnerabilities(ctx, "")
	require.NoError(t, err)

	require.Equal(t, want, got)
	require.ElementsMatch(t, want, kept, "nothing is left for storage to deduplicate")
}

// Two instances of one block share an identity, and a caller deduplicated
// onto the earlier instance is not a caller of the later one. Routing after
// keeping one finding would report only the later instance's callers.
func TestFindingSet_RoutesBeforeKeepingAnIdentity(t *testing.T) {
	chain := "stack/main.tf|module.app"
	finding := func(docID string, line int) model.Vulnerability {
		return model.Vulnerability{
			FileID: docID, FileName: "modules/app/main.tf", Platform: "Terraform", QueryID: "q",
			ResourceType: "aws_s3_bucket", ResourceName: "replica", ModuleCallChain: chain, Line: line,
		}
	}
	routing := newFindingRouting(map[string][]extraCallerInfo{
		"doc-early": {{callChain: "other/main.tf|module.app", docID: "doc-other"}},
	}, nil, nil, "/repo", nil)

	kept := decodeAll(newFindingSet(true, routing), []model.Vulnerability{
		finding("doc-early", 1), finding("doc-late", 2),
	})

	got := map[string]int{}
	for i := range kept {
		got[kept[i].ModuleCallChain] = kept[i].Line
	}
	require.Equal(t, map[string]int{
		chain:                      1,
		"other/main.tf|module.app": 1,
	}, got)
}

func TestFindingSet_KeepsEveryFindingWhenNotCompacting(t *testing.T) {
	raised := instanceFindings(3, 10)

	got := decodeAll(newFindingSet(false, nil), raised)

	require.Equal(t, raised, got, "every decoded finding is kept, identity included")
}

func TestNewFindingRouting_IndexesRootCallersOnly(t *testing.T) {
	repo := t.TempDir()
	files := model.FileMetadatas{
		{FilePath: filepath.Join(repo, "stack", "main.tf")},
		{FilePath: filepath.Join(repo, "modules", "app", "main.tf"), ModuleCallChain: "stack/main.tf|module.app"},
		nil,
	}
	routing := newFindingRouting(nil, nil, files, repo, nil)
	require.Len(t, routing.callers, 1)
	require.Contains(t, routing.callers, "stack/main.tf")
}

// openIngressRule fires once per ingress block open to the internet, mirroring
// the shape of production rules such as unknown_port_exposed_to_internet: one
// result per violating block of a resource, not one per resource.
const openIngressRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	sg := input.document[i].resource.aws_security_group[name]
	some j
	ingress := sg.ingress[j]
	some cidr_block in ingress.cidr_blocks
	cidr_block == "0.0.0.0/0"

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_security_group",
		"resourceName": name,
		"searchKey": sprintf("aws_security_group[%s].ingress[%d].cidr_blocks", [name, j]),
	}
}
`

// twoIngressBlocks is one aws_security_group with two independently open
// ingress blocks: two genuine violations of openIngressRule on one resource,
// at two different lines.
func twoIngressBlocks(t *testing.T) (model.FileMetadatas, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(path, []byte(`
resource "aws_security_group" "sg" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 3389
    to_port     = 3389
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`), 0o644))
	return parseTerraform(t, path), root
}

func openIngressQueries() []model.QueryMetadata {
	return []model.QueryMetadata{{
		Query:       "open_ingress_rule",
		Content:     openIngressRule,
		InputData:   "{}",
		Platform:    "terraform",
		Metadata:    map[string]interface{}{"id": "open-ingress", "platform": "Terraform"},
		Aggregation: 1,
	}}
}

// Inspect returns every decoded finding unless compaction is enabled.
func TestInspect_TwoViolationsOnOneResource_InspectReturnsBoth(t *testing.T) {
	files, root := twoIngressBlocks(t)
	ins := newTestInspector(t, inspectorOpts{
		queries:       openIngressQueries(),
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 2, "Inspect must return every decoded finding, one per violating ingress block")
	require.NotEqual(t, vulns[0].Line, vulns[1].Line, "the two violations are at different lines")
	require.Equal(t, model.FindingIdentity(&vulns[0]), model.FindingIdentity(&vulns[1]),
		"both violations are on the same resource and rule, so they share an identity")
}

// The scan path that retains findings for storage opts into decode-time
// identity reduction, so it keeps only the first of the two violations in
// model.CompareFindings order: the same reduction storage itself applies at
// the end of the scan.
func TestInspect_TwoViolationsOnOneResource_CompactedScanPathKeepsOne(t *testing.T) {
	files, root := twoIngressBlocks(t)
	ins := newTestInspector(t, inspectorOpts{
		queries:       openIngressQueries(),
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetCompactFindingsAtDecode(true)

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	require.Len(t, vulns, 1, "the scan path that retains findings for storage keeps one finding per identity")
	require.Equal(t, 6, vulns[0].Line, "the first violation in model.CompareFindings order (port 22) is the one kept")
}

const decodedBucketHCL = `
resource "aws_s3_bucket" "this" {
  acl = "public-read"
}
`

func parsedBucket(t *testing.T) *model.FileMetadata {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(path, []byte(decodedBucketHCL), 0o644))
	files := parseTerraform(t, path)
	require.Len(t, files, 1)
	return files[0]
}

func bucketItem(docID string) map[string]interface{} {
	return map[string]interface{}{
		"documentId":   docID,
		"searchKey":    "aws_s3_bucket[this].acl",
		"resourceType": "aws_s3_bucket",
		"resourceName": "this",
		"platform":     "Terraform",
		"id":           "bucket-rule",
	}
}

func bucketResultSet(items []map[string]interface{}) rego.ResultSet {
	bound := make([]interface{}, len(items))
	for i := range items {
		bound[i] = items[i]
	}
	return rego.ResultSet{{Bindings: map[string]interface{}{"result": bound}}}
}

func storedFindings(t *testing.T, vulns []model.Vulnerability) []model.Vulnerability {
	t.Helper()
	mem := storage.NewMemoryStorage()
	require.NoError(t, mem.SaveVulnerabilities(context.Background(), append([]model.Vulnerability(nil), vulns...)))
	got, err := mem.GetVulnerabilities(context.Background(), "")
	require.NoError(t, err)
	return got
}

// decodeCompacted runs DecodeQueryResults with compaction on and off and
// returns both.
func decodeCompacted(
	t *testing.T, ins *Inspector, files map[string]*model.FileMetadata,
	routing *findingRouting, items []map[string]interface{},
) (compacted, full []model.Vulnerability) {
	t.Helper()
	ctx := context.Background()
	run := func(compact bool) []model.Vulnerability {
		qCtx := &QueryContext{
			Ctx:           ctx,
			Files:         files,
			Query:         &PreparedQuery{Metadata: model.QueryMetadata{Query: "bucket_rule", Platform: "Terraform"}},
			FlagEvaluator: featureflags.NewLocalEvaluator(),
			findings:      newFindingSet(compact, routing),
		}
		got, _, _, err := ins.DecodeQueryResults(ctx, qCtx, ctx, bucketResultSet(items), 0)
		require.NoError(t, err)
		require.Empty(t, ins.GetFailedQueries())
		return got
	}
	return run(true), run(false)
}

func moduleCalls() *moduleFileCalls {
	return &moduleFileCalls{
		name: "main.tf",
		calls: []moduleCall{
			{callChain: "a/main.tf|module.m", attribution: &model.ModuleAttribution{}},
			{callChain: "b/main.tf|module.m", attribution: &model.ModuleAttribution{}},
		},
	}
}

// Compacting at decode has to report the same findings storage would keep,
// including the callers a result is routed to.
func TestDecodeQueryResults_CompactionMatchesStorageDedupe(t *testing.T) {
	ctx := context.Background()

	type spec struct {
		name        string
		routing     func(file *model.FileMetadata) *findingRouting
		items       func(file *model.FileMetadata) []map[string]interface{}
		files       func(file *model.FileMetadata) map[string]*model.FileMetadata
		ruleConfigs map[string]config.IacRuleConfig
	}

	one := func(file *model.FileMetadata) map[string]*model.FileMetadata {
		return map[string]*model.FileMetadata{file.ID: file}
	}
	twice := func(file *model.FileMetadata) []map[string]interface{} {
		return []map[string]interface{}{bucketItem(file.ID), bucketItem(file.ID)}
	}

	cases := []spec{
		{
			name:  "extra caller",
			files: one,
			items: twice,
			routing: func(file *model.FileMetadata) *findingRouting {
				return newFindingRouting(map[string][]extraCallerInfo{
					file.ID: {{callChain: "other/main.tf|module.app", docID: "doc-other"}},
				}, nil, nil, "", nil)
			},
		},
		{
			name:  "module file reported only through its calls",
			files: one,
			items: twice,
			routing: func(file *model.FileMetadata) *findingRouting {
				return newFindingRouting(nil, map[string]*moduleFileCalls{
					file.ID: moduleCalls(),
				}, nil, "", nil)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file := parsedBucket(t)
			file.ModuleCallChain = "stack/main.tf|module.app"
			ins := newTestInspector(t, inspectorOpts{vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator()})
			ins.ruleConfigs = tc.ruleConfigs
			compacted, full := decodeCompacted(t, ins, tc.files(file), tc.routing(file), tc.items(file))
			require.Equal(t, storedFindings(t, full), storedFindings(t, compacted))
		})
	}

	t.Run("rule path filter drops the last result raised", func(t *testing.T) {
		older := parsedBucket(t)
		newer := parsedBucket(t)
		newer.FilePath = older.FilePath
		newer.OriginalData = older.OriginalData
		newer.LinesOriginalData = older.LinesOriginalData
		chain := "stack/main.tf|module.app"
		older.ModuleCallChain = chain
		newer.ModuleCallChain = chain

		ins := newTestInspector(t, inspectorOpts{vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator()})
		detected := ins.detector.DetectLine(ctx, newer, "aws_s3_bucket[this].acl")
		require.Positive(t, detected.BlockLocation.Start.Line)
		callerName := "excluded/main.tf"
		newer.ModuleAttributions = map[string]*model.ModuleAttribution{
			moduleAttributionKey("aws_s3_bucket", detected.BlockLocation.Start.Line, detected.BlockLocation.Start.Col): {
				CallSite: model.SourceLocation{Filename: callerName},
			},
		}
		ins.ruleConfigs = map[string]config.IacRuleConfig{
			"bucket-rule": {IgnorePaths: []string{"**/excluded/**"}},
		}
		routing := newFindingRouting(nil, nil, model.FileMetadatas{
			{FilePath: callerName},
		}, "", nil)
		compacted, full := decodeCompacted(t, ins, map[string]*model.FileMetadata{
			older.ID: older, newer.ID: newer,
		}, routing, []map[string]interface{}{bucketItem(older.ID), bucketItem(newer.ID)})
		require.Equal(t, storedFindings(t, full), storedFindings(t, compacted))
		require.Len(t, compacted, 1, "the filtered result is dropped, so the earlier one is kept")
		require.Equal(t, older.ID, compacted[0].FileID)
	})

	// The failing document is raised first, so it is decoded after the other
	// document of the same path has been kept.
	for _, loaded := range []bool{false, true} {
		t.Run(fmt.Sprintf("failed line info is reported on the scanned file, loaded before decode %t", loaded), func(t *testing.T) {
			good := parsedBucket(t)
			bad := parsedBucket(t)
			bad.FilePath = good.FilePath
			chain := "stack/main.tf|module.app"
			good.ModuleCallChain = chain
			bad.ModuleCallChain = chain
			bad.LineInfoDocument = nil
			bad.SetLineInfoLoader(func(context.Context, *model.FileMetadata) (map[string]interface{}, error) {
				return nil, errors.New("reparse failed")
			})
			if loaded {
				require.Error(t, bad.EnsureLineInfoDocument(ctx))
			}

			ins := newTestInspector(t, inspectorOpts{vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator()})
			compacted, full := decodeCompacted(t, ins, map[string]*model.FileMetadata{
				good.ID: good, bad.ID: bad,
			}, nil, []map[string]interface{}{bucketItem(bad.ID), bucketItem(good.ID)})
			require.Len(t, full, 2)
			var failed *model.Vulnerability
			for i := range full {
				require.Equal(t, good.FilePath, full[i].FileName)
				if full[i].FileID == bad.ID {
					failed = &full[i]
				}
			}
			require.NotNil(t, failed)
			require.Equal(t, 1, failed.Line)
			require.Equal(t, 1, failed.VulnerabilityLocation.Start.Line)
			require.Equal(t, 1, failed.VulnerabilityLocation.End.Line)
			require.Equal(t, storedFindings(t, full), storedFindings(t, compacted))
			require.Len(t, compacted, 1)
			// Both findings land on line 1, so they compare equal in
			// model.CompareFindings order and the first decoded one is kept.
			require.Equal(t, bad.ID, compacted[0].FileID)
		})
	}
}

