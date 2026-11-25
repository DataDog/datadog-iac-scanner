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
	"slices"
	"strconv"
	"testing"
	"time"

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

// The replacement path must not depend on arrival: a later-arriving finding
// with a lower order displaces the retained duplicate, including on
// same-line ties, and what the set keeps is what storage keeps.
func TestFindingSet_KeepsTheFirstFindingWhateverTheArrivalOrder(t *testing.T) {
	raised := instanceFindings(3, 10)
	tie := raised[0]
	tie.SearchValue = "z" // same file, line and search key, lower order without it
	raised = append(raised, tie)

	orders := [][]int{
		{0, 1, 2, 3}, {3, 2, 1, 0}, {2, 3, 0, 1}, {1, 0, 3, 2}, {3, 0, 2, 1},
	}
	var want []model.Vulnerability
	for _, order := range orders {
		arriving := make([]model.Vulnerability, 0, len(order))
		for _, i := range order {
			arriving = append(arriving, raised[i])
		}

		kept := decodeAll(newFindingSet(true, nil), arriving)
		require.Len(t, kept, 1)
		stored := model.FirstFindingPerIdentity(append([]model.Vulnerability(nil), arriving...))
		require.Equal(t, stored, kept,
			"what the set keeps must be what storage keeps, whatever the arrival order")

		canonical := append([]model.Vulnerability(nil), kept...)
		model.SortFindings(canonical)
		if want == nil {
			want = canonical
			require.Equal(t, 10, canonical[0].Line, "the earliest line is the one kept")
			require.Empty(t, canonical[0].SearchValue, "the same-line tie goes to the lower search value")
			continue
		}
		require.Equal(t, want, canonical, "the kept finding must not depend on the arrival order")
	}
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
	repo := t.TempDir()
	chain := "stack/main.tf|module.app"
	finding := func(docID string, line int) model.Vulnerability {
		return model.Vulnerability{
			FileID: docID, FileName: "modules/app/main.tf", Platform: "Terraform", QueryID: "q",
			ResourceType: "aws_s3_bucket", ResourceName: "replica", ModuleCallChain: chain, Line: line,
			ModuleAttribution: &model.ModuleAttribution{CallSite: model.SourceLocation{Filename: "stack/main.tf"}},
			TerraformBlock:    moduleAttributionKey("aws_s3_bucket", "replica"),
		}
	}
	routing := newFindingRouting(map[string][]extraCallerInfo{
		"doc-early": {{callChain: "other/main.tf|module.app", docID: "doc-other",
			attributions: map[model.TerraformBlock]*model.ModuleAttribution{
				moduleAttributionKey("aws_s3_bucket", "replica"): {CallSite: model.SourceLocation{Filename: "other/main.tf"}},
			}}},
	}, nil, model.FileMetadatas{{FilePath: filepath.Join(repo, "stack/main.tf")}, {FilePath: filepath.Join(repo, "other/main.tf")}}, repo, nil)

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
			{callChain: "a/main.tf|module.m", attribution: &model.ModuleAttribution{CallSite: model.SourceLocation{Filename: "a/main.tf"}}},
			{callChain: "b/main.tf|module.m", attribution: &model.ModuleAttribution{CallSite: model.SourceLocation{Filename: "b/main.tf"}}},
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
				attrs := cloneModuleAttributions(file.ModuleAttributions)
				for _, attr := range attrs {
					attr.CallSite.Filename = "other/main.tf"
				}
				return newFindingRouting(map[string][]extraCallerInfo{
					file.ID: {{callChain: "other/main.tf|module.app", docID: "doc-other", attributions: attrs}},
				}, nil, model.FileMetadatas{{FilePath: "stack/main.tf"}, {FilePath: "other/main.tf"}}, "", nil)
			},
		},
		{
			name:  "module file reported only through its calls",
			files: one,
			items: twice,
			routing: func(file *model.FileMetadata) *findingRouting {
				return newFindingRouting(nil, map[string]*moduleFileCalls{
					file.ID: moduleCalls(),
				}, model.FileMetadatas{{FilePath: "a/main.tf"}, {FilePath: "b/main.tf"}}, "", nil)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file := parsedBucket(t)
			file.ModuleCallChain = "stack/main.tf|module.app"
			ins := newTestInspector(t, inspectorOpts{vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator()})
			ins.ruleConfigs = tc.ruleConfigs
			if tc.name == "extra caller" {
				file.ModuleAttributions = map[model.TerraformBlock]*model.ModuleAttribution{
					moduleAttributionKey("aws_s3_bucket", "this"): {
						CallSite: model.SourceLocation{Filename: "stack/main.tf"},
					},
				}
			}
			compacted, full := decodeCompacted(t, ins, tc.files(file), tc.routing(file), tc.items(file))
			require.Equal(t, storedFindings(t, full), storedFindings(t, compacted))
			require.Len(t, compacted, 2, "both callers survive identity reduction")
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
		older.ModuleAttributions = map[model.TerraformBlock]*model.ModuleAttribution{
			moduleAttributionKey("aws_s3_bucket", "this"): {
				CallSite: model.SourceLocation{Filename: "stack/main.tf"},
			},
		}
		newer.ModuleAttributions = map[model.TerraformBlock]*model.ModuleAttribution{
			moduleAttributionKey("aws_s3_bucket", "this"): {
				CallSite: model.SourceLocation{Filename: callerName},
			},
		}
		ins.ruleConfigs = map[string]config.IacRuleConfig{
			"bucket-rule": {IgnorePaths: []string{"**/excluded/**"}},
		}
		routing := newFindingRouting(nil, nil, model.FileMetadatas{
			{FilePath: callerName}, {FilePath: "stack/main.tf"},
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

func TestFindingSet_KeepsOccurrencesOfDroppedDuplicates(t *testing.T) {
	raised := instanceFindings(3, 10)
	raised[2].FileID = "other"

	require.Nil(t, decodeAll(newFindingSet(true, nil), raised)[0].ResourceOccurrences, "nothing is recorded by default")

	for i := range raised {
		raised[i].ResourceOccurrences = []*model.ResourceOccurrence{{DocumentID: strconv.Itoa(i)}}
	}
	set := newFindingSet(true, nil)
	set.recordDuplicates = true
	// The last arriving finding comes first in order, and replaces the kept one.
	got := decodeAll(set, []model.Vulnerability{raised[1], raised[2], raised[0]})
	require.Len(t, got, 1)
	require.Equal(t, 10, got[0].Line)
	require.ElementsMatch(t, []*model.ResourceOccurrence{
		raised[0].ResourceOccurrences[0], raised[1].ResourceOccurrences[0], raised[2].ResourceOccurrences[0],
	}, got[0].ResourceOccurrences)

	// The same occurrences whichever order the findings arrive in.
	for _, order := range [][]model.Vulnerability{
		{raised[0], raised[1], raised[2]},
		{raised[2], raised[1], raised[0]},
	} {
		set := newFindingSet(true, nil)
		set.recordDuplicates = true
		again := decodeAll(set, order)
		require.Equal(t, got[0].Line, again[0].Line)
		require.Equal(t, got[0].ResourceOccurrences, again[0].ResourceOccurrences)
	}

	// Many occurrences arriving in reverse order replace the kept finding
	// each time: the occurrences are gathered once, not replayed on every change.
	many := instanceFindings(3000, 1)
	for i := range many {
		many[i].ResourceOccurrences = []*model.ResourceOccurrence{{DocumentID: strconv.Itoa(i)}}
	}
	for _, reverse := range []bool{false, true} {
		in := slices.Clone(many)
		if reverse {
			slices.Reverse(in)
		}
		set := newFindingSet(true, nil)
		set.recordDuplicates = true
		start := time.Now()
		kept := decodeAll(set, in)
		require.Len(t, kept, 1)
		require.Equal(t, 1, kept[0].Line)
		require.Len(t, kept[0].ResourceOccurrences, 3000)
		require.Less(t, time.Since(start), time.Second, "reverse=%v", reverse)
	}
}

func TestFindingRouting_ResolvesOnlyScannedRepositoryCallSites(t *testing.T) {
	repo, outside := t.TempDir(), t.TempDir()
	cache := filepath.Join(repo, ".cache", "modules")
	external := func(path string) bool { return pathWithinRoot(path, cache) }
	caller := "stack/main.tf"
	files := model.FileMetadatas{
		{FilePath: filepath.Join(repo, caller)},
		{FilePath: filepath.Join(cache, "main.tf")},
		{FilePath: filepath.Join(outside, "main.tf")},
	}
	for _, predicate := range []func(string) bool{nil, external} {
		routing := newFindingRouting(nil, nil, files, repo, predicate)
		for _, tc := range []struct {
			name string
			file string
			call string
			want bool
		}{
			{name: "scanned caller", file: filepath.Join(outside, "resource.tf"), call: caller, want: true},
			{name: "unscanned caller", file: filepath.Join(outside, "resource.tf"), call: "absent/main.tf"},
			{name: "escaping caller", file: filepath.Join(outside, "resource.tf"), call: "../outside/main.tf"},
			{name: "absolute caller", file: filepath.Join(outside, "resource.tf"), call: filepath.Join(outside, "main.tf")},
			{name: "unreached file", file: filepath.Join(outside, "resource.tf")},
			{name: "ordinary repository finding", file: filepath.Join(repo, caller), want: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				v := model.Vulnerability{FileName: tc.file, Line: 20}
				if tc.call != "" {
					v.ModuleAttribution = &model.ModuleAttribution{CallSite: model.SourceLocation{Filename: tc.call, LineStart: 3}}
				}
				_, ok := routing.resolveLocation(&v)
				require.Equal(t, tc.want, ok)
				require.Equal(t, tc.file, v.FileName, "detected location and identity are preserved")
				require.Equal(t, 20, v.Line)
				if tc.want && tc.call != "" {
					require.Equal(t, &model.SourceLocation{
						Filename: caller, LineStart: 3, LineEnd: 3, ColumnStart: 1, ColumnEnd: 2,
					}, v.ReportLocation)
				} else {
					require.Nil(t, v.ReportLocation)
				}
			})
		}
	}
	// A cache inside the checkout still cannot act as a scanned caller.
	routing := newFindingRouting(nil, nil, files, repo, external)
	v := model.Vulnerability{ModuleAttribution: &model.ModuleAttribution{
		CallSite: model.SourceLocation{Filename: ".cache/modules/main.tf"},
	}}
	_, ok := routing.resolveLocation(&v)
	require.False(t, ok)
}
