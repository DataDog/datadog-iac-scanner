/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
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

// decodeAll gives set the findings a rule raised and returns what it kept.
func decodeAll(set *findingSet, raised []model.Vulnerability) []model.Vulnerability {
	for i := range raised {
		v := raised[i]
		set.addRouted(context.Background(), &Inspector{}, &v)
	}
	return set.findings()
}

// Of several findings of one identity, the first location is kept whatever
// order they were raised in.
func TestFindingSet_KeepsTheFirstFindingOfEachIdentity(t *testing.T) {
	raised := instanceFindings(3, 10)
	other := raised[0]
	other.ResourceName = "primary"
	raised = append(raised, other)

	for _, order := range [][]int{{0, 1, 2, 3}, {2, 1, 0, 3}, {1, 3, 2, 0}} {
		shuffled := make([]model.Vulnerability, 0, len(order))
		for _, i := range order {
			shuffled = append(shuffled, raised[i])
		}
		got := decodeAll(newFindingSet(true, nil), shuffled)

		require.Len(t, got, 2)
		byName := map[string]int{}
		for _, v := range got {
			byName[v.ResourceName] = v.Line
		}
		require.Equal(t, map[string]int{"replica": 10, "primary": 10}, byName,
			"the first instance's finding is kept, and a different identity on its own")
	}
}

// What the set keeps must be what the scan reports, so that keeping findings
// as they are decoded cannot change a report.
func TestFindingSet_KeepsWhatTheScanReports(t *testing.T) {
	ctx := context.Background()
	raised := append(instanceFindings(3, 10), instanceFindings(2, 40)...)
	raised[3].ResourceName = "other"
	raised[4].ResourceName = "other"
	raised[0], raised[2] = raised[2], raised[0]

	want := reportedFindings(raised)

	kept := decodeAll(newFindingSet(true, nil), raised)
	got := reportedFindings(kept)
	require.Equal(t, want, got)
	require.Len(t, kept, len(got), "nothing is left to deduplicate")

	stored := storage.NewMemoryStorage()
	require.NoError(t, stored.SaveVulnerabilities(ctx, append([]model.Vulnerability(nil), got...)))
	fromStorage, err := stored.GetVulnerabilities(ctx, "")
	require.NoError(t, err)
	require.Equal(t, want, fromStorage, "storage keeps what the engine reduced")
}

func TestFindingSet_DoesNotSkipAResultWhoseRemediationComesFirst(t *testing.T) {
	file := &model.FileMetadata{ID: "f", FilePath: "main.tf"}
	kept := model.Vulnerability{
		FileID: "f", FileName: "main.tf", Platform: model.TerraformPlatform, QueryID: "q",
		ResourceType: "aws_s3_bucket", ResourceName: "web", SearchKey: "aws_s3_bucket[web].acl",
		Remediation: "z",
	}
	set := newFindingSet(true, nil)
	set.addRouted(context.Background(), &Inspector{}, &kept)
	r, ok := newResultIdentity(file, kept.Platform, kept.ResourceType, kept.ResourceName, kept.QueryID, "")
	require.True(t, ok)
	r.platform = kept.Platform

	r.remediation = "a"
	require.False(t, set.supersedes(&r, file, kept.SearchKey))
	r.remediation = "z"
	require.True(t, set.supersedes(&r, file, kept.SearchKey))
}

func TestFindingSet_DoesNotSkipAResultWhoseSeverityComesFirst(t *testing.T) {
	file := &model.FileMetadata{ID: "f", FilePath: "main.tf"}
	kept := model.Vulnerability{
		FileID: "f", FileName: "main.tf", Platform: model.TerraformPlatform, QueryID: "q",
		ResourceType: "aws_s3_bucket", ResourceName: "web", SearchKey: "aws_s3_bucket[web].acl",
		Severity: model.SeverityLow,
	}
	set := newFindingSet(true, nil)
	set.addRouted(context.Background(), &Inspector{}, &kept)
	r, ok := newResultIdentity(file, kept.Platform, kept.ResourceType, kept.ResourceName, kept.QueryID, "")
	require.True(t, ok)
	r.platform = kept.Platform

	r.severity = string(model.SeverityCritical)
	require.False(t, set.supersedes(&r, file, kept.SearchKey))
	r.severity = string(model.SeverityLow)
	require.True(t, set.supersedes(&r, file, kept.SearchKey))
}

// Two results can share a legacy identity and still differ on QueryID;
// CompareFindings orders on QueryID before QueryName.
func TestFindingSet_DoesNotSkipAResultWhoseQueryIDComesFirst(t *testing.T) {
	file := &model.FileMetadata{ID: "f", FilePath: "main.tf"}
	kept := model.Vulnerability{
		FileID: "f", FileName: "main.tf", Platform: model.TerraformPlatform,
		QueryID: "z", LegacyQueryID: "legacy",
		ResourceType: "aws_s3_bucket", ResourceName: "web", SearchKey: "aws_s3_bucket[web].acl",
	}
	set := newFindingSet(true, nil)
	set.addRouted(context.Background(), &Inspector{}, &kept)
	r, ok := newResultIdentity(file, kept.Platform, kept.ResourceType, kept.ResourceName, "a", "legacy")
	require.True(t, ok)
	r.platform = kept.Platform

	require.False(t, set.supersedes(&r, file, kept.SearchKey),
		"QueryID a comes before kept z; skipping would change the report")
	r.queryID = "z"
	require.True(t, set.supersedes(&r, file, kept.SearchKey))
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
		finding("doc-early", 2), finding("doc-late", 1),
	})

	got := map[string]int{}
	for i := range kept {
		got[kept[i].ModuleCallChain] = kept[i].Line
	}
	require.Equal(t, map[string]int{
		chain:                      1,
		"other/main.tf|module.app": 2,
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

// TestFindingSet_SupersedesMeansRouteKeepsNothingNew guards the hand-kept
// agreement between supersedes and findingRouting.route: a skipped result's
// routed identities are all already kept. It may decline to skip.
func TestFindingSet_SupersedesMeansRouteKeepsNothingNew(t *testing.T) {
	testSupersedesMeansRouteKeepsNothingNew(t)

	require.False(t, newFindingSet(false, nil).supersedes(&resultIdentity{}, &model.FileMetadata{}, ""),
		"a set keeping every finding never skips one")
}

func testSupersedesMeansRouteKeepsNothingNew(t *testing.T) {
	ctx := context.Background()
	base := model.Vulnerability{
		FileID: "doc", FileName: "modules/app/main.tf", Platform: "Terraform", QueryID: "q",
		ResourceType: "aws_s3_bucket", ResourceName: "this", ModuleCallChain: "stack/main.tf|module.app",
	}
	scope := &model.TerraformScope{
		RootModule: "stack",
		Blocks:     map[model.TerraformBlock]bool{{Kind: "resource", Type: "aws_s3_bucket", Name: "this"}: true},
	}
	base.RootModule, base.ResourceID = scope.RootModule, "aws_s3_bucket.this"
	calls := []moduleCall{
		{callChain: "a/main.tf|module.m", moduleAddress: "module.m", rootModule: "a", attribution: &model.ModuleAttribution{}},
		{callChain: "b/main.tf|module.m", moduleAddress: "module.m", rootModule: "b", attribution: &model.ModuleAttribution{}},
	}
	moduleFiles := func(keepWritten bool, written map[string]bool) map[string]*moduleFileCalls {
		return map[string]*moduleFileCalls{
			"doc": {calls: calls, name: "main.tf", scope: scope, keepWritten: keepWritten, writtenResourceTypes: written},
		}
	}
	same := func(v model.Vulnerability, line int) model.Vulnerability {
		v.Line = line
		return v
	}

	cases := []struct {
		name        string
		routing     *findingRouting
		steps       []model.Vulnerability
		attr        []bool
		wantSkipped int
	}{
		{
			name:        "same identity",
			steps:       []model.Vulnerability{same(base, 1), same(base, 2), same(base, 3)},
			wantSkipped: 2,
		},
		{
			name: "instance documents of one written file",
			steps: []model.Vulnerability{
				func() model.Vulnerability { v := same(base, 1); v.FileID = "doc\x00chain\x000"; return v }(),
				func() model.Vulnerability { v := same(base, 1); v.FileID = "doc\x00chain\x001"; return v }(),
				func() model.Vulnerability { v := same(base, 1); v.FileID = "other"; return v }(),
			},
			wantSkipped: 1,
		},
		{
			name: "extra caller on the earlier instance only",
			routing: newFindingRouting(map[string][]extraCallerInfo{
				"doc-early": {{callChain: "other/main.tf|module.app", rootModule: "other", docID: "doc-other"}},
			}, nil, nil, "/repo", nil),
			steps: []model.Vulnerability{
				func() model.Vulnerability { v := same(base, 1); v.FileID = "doc-early"; return v }(),
				func() model.Vulnerability { v := same(base, 2); v.FileID = "doc-late"; return v }(),
				func() model.Vulnerability { v := same(base, 3); v.FileID = "doc-late"; return v }(),
			},
			wantSkipped: 0,
		},
		{
			name: "extra caller whose own document is an external module file",
			routing: newFindingRouting(map[string][]extraCallerInfo{
				"doc": {{callChain: "other/main.tf|module.app", rootModule: "other", docID: "ext"}},
			}, map[string]*moduleFileCalls{
				"ext": {calls: calls, name: "main.tf", scope: scope},
			}, nil, "/repo", nil),
			steps:       []model.Vulnerability{same(base, 1), same(base, 2)},
			wantSkipped: 1,
		},
		{
			name:        "module file kept as written and once per call",
			routing:     newFindingRouting(nil, moduleFiles(true, nil), nil, "/repo", nil),
			steps:       []model.Vulnerability{same(base, 1), same(base, 2)},
			wantSkipped: 1,
		},
		{
			name:        "module file reported only through its calls",
			routing:     newFindingRouting(nil, moduleFiles(false, nil), nil, "/repo", nil),
			steps:       []model.Vulnerability{same(base, 1), same(base, 2)},
			wantSkipped: 1,
		},
		{
			name:    "module file that the line may attribute",
			routing: newFindingRouting(nil, moduleFiles(false, nil), nil, "/repo", nil),
			steps: []model.Vulnerability{
				func() model.Vulnerability {
					v := same(base, 1)
					v.ModuleAttribution = &model.ModuleAttribution{}
					return v
				}(),
				func() model.Vulnerability {
					v := same(base, 2)
					v.ModuleAttribution = &model.ModuleAttribution{}
					return v
				}(),
			},
			attr:        []bool{true, true},
			wantSkipped: 0,
		},
		{
			name:        "resource type left as written",
			routing:     newFindingRouting(nil, moduleFiles(false, map[string]bool{"aws_s3_bucket": true}), nil, "/repo", nil),
			steps:       []model.Vulnerability{same(base, 1), same(base, 2)},
			wantSkipped: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := newFindingSet(true, tc.routing)
			skipped := 0
			for i := range tc.steps {
				step := tc.steps[i]
				file := &model.FileMetadata{
					ID: step.FileID, FilePath: step.FileName, ModuleCallChain: step.ModuleCallChain, TerraformScope: scope,
				}
				if tc.attr != nil && tc.attr[i] {
					file.ModuleAttributions = map[string]*model.ModuleAttribution{"": {}}
				}
				r, ok := newResultIdentity(file, step.Platform, step.ResourceType, step.ResourceName, step.QueryID, "")
				require.True(t, ok)
				r.platform, r.queryName = step.Platform, step.QueryName
				r.severity, r.description = string(step.Severity), step.Description
				r.remediation, r.remediationType = step.Remediation, step.RemediationType
				if set.supersedes(&r, file, step.SearchKey) {
					skipped++
					routed := tc.routing.route(ctx, &Inspector{}, []model.Vulnerability{step})
					for j := range routed {
						key := model.FindingIdentity(&routed[j])
						require.Truef(t, set.hasIdentity(key), "skipped a result route still keeps (%s)", key)
					}
					continue
				}
				set.addRouted(ctx, &Inspector{}, &step)
			}
			require.Equal(t, tc.wantSkipped, skipped)
		})
	}
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
// identity reduction, so it keeps only the first of the two violations.
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
	require.Equal(t, 6, vulns[0].Line, "the first violation (port 22) is the one kept")
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

func reportedFindings(vulns []model.Vulnerability) []model.Vulnerability {
	return model.FirstFindingPerIdentity(append([]model.Vulnerability(nil), vulns...))
}

// decodeCompacted runs DecodeQueryResults with compaction on and off and
// returns both, plus how many results the compacting run skipped.
func decodeCompacted(
	t *testing.T, ins *Inspector, files map[string]*model.FileMetadata,
	routing *findingRouting, items []map[string]interface{},
) (compacted, full []model.Vulnerability, skipped int) {
	t.Helper()
	ctx := context.Background()
	run := func(compact bool) []model.Vulnerability {
		tr := &tracker.CITracker{}
		ins.tracker = tr
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
		if compact {
			skipped = int(atomic.LoadInt64(&tr.SupersededResults))
		}
		return got
	}
	return run(true), run(false), skipped
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
		wantSkipped int
	}

	one := func(file *model.FileMetadata) map[string]*model.FileMetadata {
		return map[string]*model.FileMetadata{file.ID: file}
	}
	twice := func(file *model.FileMetadata) []map[string]interface{} {
		return []map[string]interface{}{bucketItem(file.ID), bucketItem(file.ID)}
	}

	cases := []spec{
		{
			name:        "extra caller",
			wantSkipped: 1,
			files:       one,
			items:       twice,
			routing: func(file *model.FileMetadata) *findingRouting {
				return newFindingRouting(map[string][]extraCallerInfo{
					file.ID: {{callChain: "other/main.tf|module.app", docID: "doc-other"}},
				}, nil, nil, "", nil)
			},
		},
		{
			name:        "module file reported only through its calls",
			wantSkipped: 1,
			files:       one,
			items:       twice,
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
			compacted, full, skipped := decodeCompacted(t, ins, tc.files(file), tc.routing(file), tc.items(file))
			require.Equal(t, reportedFindings(full), reportedFindings(compacted))
			require.Equal(t, tc.wantSkipped, skipped)
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
		compacted, full, skipped := decodeCompacted(t, ins, map[string]*model.FileMetadata{
			older.ID: older, newer.ID: newer,
		}, routing, []map[string]interface{}{bucketItem(older.ID), bucketItem(newer.ID)})
		require.Equal(t, reportedFindings(full), reportedFindings(compacted))
		require.Len(t, compacted, 1, "the filtered result is the last one raised, so the earlier one is kept")
		require.Equal(t, older.ID, compacted[0].FileID)
		require.Zero(t, skipped, "the last result was dropped, so it does not cover the earlier one")
	})

	// A document whose line detection fails reports line 1, which comes first
	// on its path, so that finding is the one kept.
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
			compacted, full, skipped := decodeCompacted(t, ins, map[string]*model.FileMetadata{
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
			require.Equal(t, reportedFindings(full), reportedFindings(compacted))
			require.Len(t, compacted, 1)
			require.Equal(t, bad.ID, compacted[0].FileID)
			require.Zero(t, skipped, "a line-1 fallback is never covered by another document's finding")
		})
	}
}

// supersededInstances inspects a counted bucket and reports how many line-info
// documents decoding parsed.
func supersededInstances(t *testing.T, instances int, compact bool) (detected int64, vulns []model.Vulnerability) {
	t.Helper()
	root := t.TempDir()
	sources := map[string]string{
		"stack/main.tf": `
module "bucket" {
  source = "../modules/bucket"
}
`,
		"modules/bucket/main.tf": fmt.Sprintf(`
resource "aws_s3_bucket" "this" {
  count  = %d
  bucket = "shared"
  acl    = "public-read"
}
`, instances),
	}
	var files model.FileMetadatas
	for name, content := range sources {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		files = append(files, parseTerraform(t, path)...)
	}
	// The builder detects the line of each result it is given unless it skips
	// the result as superseded, which the tracker counts.
	var calls atomic.Int64
	ciTracker := &tracker.CITracker{}
	ins := newTestInspector(t, inspectorOpts{
		tracker: ciTracker,
		queries: []model.QueryMetadata{{
			Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule", "platform": "Terraform"}, Aggregation: 1,
		}},
		repoPath: root,
		vb: func(ctx context.Context, qCtx *QueryContext, tracker Tracker, v interface{},
			lines *detector.DetectLine, useOldSeverities bool, queryDuration time.Duration) (*model.Vulnerability, error) {
			calls.Add(1)
			return DefaultVulnerabilityBuilder(ctx, qCtx, tracker, v, lines, useOldSeverities, queryDuration)
		},
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	ins.SetCompactFindingsAtDecode(compact)

	vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	return calls.Load() - atomic.LoadInt64(&ciTracker.SupersededResults), vulns
}

// On the scan path, instances of one counted resource share an identity, so
// only the instance that is kept may have its line detected.
func TestInspect_SupersededInstanceFindingsSkipLineDetection(t *testing.T) {
	sizes := []int{20, 40}
	detected := make([]int64, len(sizes))
	uncompacted := make([]int64, len(sizes))
	for i, n := range sizes {
		var vulns []model.Vulnerability
		detected[i], vulns = supersededInstances(t, n, true)
		require.Len(t, vulns, 1, "the instances share one identity")
		require.NotEmpty(t, vulns[0].ResourceID, "the kept finding still carries its address")

		uncompacted[i], vulns = supersededInstances(t, n, false)
		require.Len(t, vulns, n)
	}

	require.Equal(t, uncompacted[1]-uncompacted[0], int64(sizes[1]-sizes[0]),
		"without compaction, every decoded instance has its line detected")
	require.Equal(t, detected[0], detected[1], "only the finding that is kept has its line detected")

	detectedLarge, vulns := supersededInstances(t, 2000, true)
	require.Len(t, vulns, 1, "the instances share one identity")
	require.Equal(t, detected[0], detectedLarge, "a large expansion still detects the line once")
}

func (s *findingSet) hasIdentity(key string) bool {
	_, ok := s.kept[sha256.Sum256([]byte(key))]
	return ok
}
