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
			RootModule: "stack", ResourceID: "module.app.aws_s3_bucket.replica",
			Line: line + i, SearchKey: "aws_s3_bucket[replica].acl",
		})
	}
	return out
}

// decodeAll gives set the findings a rule raised, in the order
// DecodeQueryResults would, and returns what it kept.
func decodeAll(set *findingSet, raised []model.Vulnerability) []model.Vulnerability {
	for i := range set.order(len(raised)) {
		v := raised[i]
		set.addRouted(context.Background(), &Inspector{}, &v)
	}
	return set.findings()
}

func TestFindingSet_KeepsTheLastFindingOfEachIdentity(t *testing.T) {
	set := newFindingSet(true, nil)
	raised := instanceFindings(3, 10)
	other := raised[0]
	other.ResourceName = "primary"
	other.ResourceID = "module.app.aws_s3_bucket.primary"
	raised = append(raised, other)

	got := decodeAll(set, raised)

	require.Len(t, got, 2)
	require.Equal(t, 12, got[0].Line, "the last instance's finding is the one kept")
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
	require.Equal(t, want, kept, "nothing is left for storage to deduplicate")
}

// Two instances of one block share an identity, and a caller deduplicated
// onto the earlier instance is not a caller of the later one. Routing after
// keeping one finding would report only the later instance's callers.
func TestFindingSet_RoutesBeforeKeepingAnIdentity(t *testing.T) {
	finding := func(docID string, line int) model.Vulnerability {
		return model.Vulnerability{
			FileID: docID, FileName: "modules/app/main.tf", Platform: "Terraform", QueryID: "q",
			ResourceType: "aws_s3_bucket", ResourceName: "replica",
			RootModule: "stack", ResourceID: "module.app.aws_s3_bucket.replica", Line: line,
		}
	}
	routing := newFindingRouting(map[string][]extraCallerInfo{
		"doc-early": {{rootModule: "other", docID: "doc-other"}},
	}, nil, nil, "/repo")

	kept := decodeAll(newFindingSet(true, routing), []model.Vulnerability{
		finding("doc-early", 1), finding("doc-late", 2),
	})

	got := map[string]int{}
	for i := range kept {
		got[kept[i].RootModule] = kept[i].Line
	}
	require.Equal(t, map[string]int{"stack": 2, "other": 1}, got)
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
		{FilePath: filepath.Join(repo, "modules", "app", "main.tf"),
			TerraformScope: &model.TerraformScope{ModuleAddress: `module.app["x"]`}},
		nil,
	}
	routing := newFindingRouting(nil, nil, files, repo)
	require.Len(t, routing.callers, 1)
	require.Contains(t, routing.callers, "stack/main.tf")
}

// TestFindingSet_SupersedesMeansRouteKeepsNothingNew guards the hand-kept
// agreement between supersedes and findingRouting.route: a skipped result's
// routed identities are all already kept. It may decline to skip.
func TestFindingSet_SupersedesMeansRouteKeepsNothingNew(t *testing.T) {
	ctx := context.Background()
	base := model.Vulnerability{
		FileID: "doc", FileName: "modules/app/main.tf", Platform: "Terraform", QueryID: "q",
		ResourceType: "aws_s3_bucket", ResourceName: "this",
		RootModule: "stack", ResourceID: "aws_s3_bucket.this",
	}
	// resolvedFile is a file whose scope resolves the block the rules name, so
	// the identities are Terraform ones.
	resolvedFile := func(id string) *model.FileMetadata {
		return &model.FileMetadata{
			ID: id, FilePath: "modules/app/main.tf",
			TerraformScope: &model.TerraformScope{
				RootModule: "stack",
				Blocks:     map[model.TerraformBlock]bool{{Kind: "resource", Type: "aws_s3_bucket", Name: "this"}: true},
			},
		}
	}
	calls := []moduleCall{
		{moduleAddress: "module.m", rootModule: "a", attribution: &model.ModuleAttribution{}},
		{moduleAddress: "module.m", rootModule: "b", attribution: &model.ModuleAttribution{}},
	}
	moduleFiles := func(keepWritten bool, written map[string]bool) map[string]*moduleFileCalls {
		return map[string]*moduleFileCalls{
			"doc": {calls: calls, name: "main.tf", scope: resolvedFile("doc").TerraformScope,
				keepWritten: keepWritten, writtenResourceTypes: written},
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
			name: "extra caller on the earlier instance only",
			routing: newFindingRouting(map[string][]extraCallerInfo{
				"doc-early": {{rootModule: "other", docID: "doc-other"}},
			}, nil, nil, "/repo"),
			steps: []model.Vulnerability{
				func() model.Vulnerability { v := same(base, 1); v.FileID = "doc-early"; return v }(),
				func() model.Vulnerability { v := same(base, 2); v.FileID = "doc-late"; return v }(),
				func() model.Vulnerability { v := same(base, 3); v.FileID = "doc-late"; return v }(),
			},
			wantSkipped: 1,
		},
		{
			name: "extra caller whose own document is an external module file",
			routing: newFindingRouting(map[string][]extraCallerInfo{
				"doc": {{rootModule: "other", docID: "ext"}},
			}, map[string]*moduleFileCalls{
				"ext": {calls: calls, name: "main.tf", scope: resolvedFile("ext").TerraformScope},
			}, nil, "/repo"),
			steps:       []model.Vulnerability{same(base, 1), same(base, 2)},
			wantSkipped: 1,
		},
		{
			name:        "module file kept as written and once per call",
			routing:     newFindingRouting(nil, moduleFiles(true, nil), nil, "/repo"),
			steps:       []model.Vulnerability{same(base, 1), same(base, 2)},
			wantSkipped: 1,
		},
		{
			name:        "module file reported only through its calls",
			routing:     newFindingRouting(nil, moduleFiles(false, nil), nil, "/repo"),
			steps:       []model.Vulnerability{same(base, 1), same(base, 2)},
			wantSkipped: 1,
		},
		{
			name:    "module file that the line may attribute",
			routing: newFindingRouting(nil, moduleFiles(false, nil), nil, "/repo"),
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
			routing:     newFindingRouting(nil, moduleFiles(false, map[string]bool{"aws_s3_bucket": true}), nil, "/repo"),
			steps:       []model.Vulnerability{same(base, 1), same(base, 2)},
			wantSkipped: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := newFindingSet(true, tc.routing)
			skipped := 0
			for i := range set.order(len(tc.steps)) {
				step := tc.steps[i]
				file := resolvedFile(step.FileID)
				if tc.attr != nil && tc.attr[i] {
					file.ModuleAttributions = map[string]*model.ModuleAttribution{"": {}}
				}
				ids, ok := set.findingIdentities(file, step.Platform, step.ResourceType, step.ResourceName, step.QueryID, "")
				require.True(t, ok)
				if set.supersedes(ids) {
					skipped++
					routed := tc.routing.route(ctx, &Inspector{}, []model.Vulnerability{step})
					for j := range routed {
						require.Truef(t, set.has(model.FindingIdentity(&routed[j])),
							"skipped a result route still keeps (%s)", model.FindingIdentity(&routed[j]))
					}
					continue
				}
				set.addRouted(ctx, &Inspector{}, &step)
			}
			require.Equal(t, tc.wantSkipped, skipped)
		})
	}

	require.False(t, newFindingSet(false, nil).supersedes([]string{"anything"}),
		"a set keeping every finding never skips one")
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
// identity reduction, so it keeps only the last of the two violations: the
// same reduction storage itself would apply at the end of the scan.
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
	require.Equal(t, 11, vulns[0].Line, "the last decoded violation (port 3389) is the one kept")
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

func moduleCalls(keepWritten bool, written map[string]bool) map[string]*moduleFileCalls {
	return map[string]*moduleFileCalls{
		"mod": {
			name:        "main.tf",
			keepWritten: keepWritten,
			calls: []moduleCall{
				{moduleAddress: "module.m", rootModule: "a", attribution: &model.ModuleAttribution{}},
				{moduleAddress: "module.m", rootModule: "b", attribution: &model.ModuleAttribution{}},
			},
			writtenResourceTypes: written,
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
					file.ID: {{rootModule: "other", docID: "doc-other"}},
				}, nil, nil, "")
			},
		},
		{
			name:        "module file kept as written and once per call",
			wantSkipped: 1,
			files:       one,
			items:       twice,
			routing: func(file *model.FileMetadata) *findingRouting {
				return newFindingRouting(nil, map[string]*moduleFileCalls{
					file.ID: moduleCalls(true, nil)["mod"],
				}, nil, "")
			},
		},
		{
			name:        "module file reported only through its calls",
			wantSkipped: 1,
			files:       one,
			items:       twice,
			routing: func(file *model.FileMetadata) *findingRouting {
				return newFindingRouting(nil, map[string]*moduleFileCalls{
					file.ID: moduleCalls(false, nil)["mod"],
				}, nil, "")
			},
		},
		{
			name:        "resource type left as written",
			wantSkipped: 1,
			files:       one,
			items:       twice,
			routing: func(file *model.FileMetadata) *findingRouting {
				return newFindingRouting(nil, map[string]*moduleFileCalls{
					file.ID: moduleCalls(false, map[string]bool{"aws_s3_bucket": true})["mod"],
				}, nil, "")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file := parsedBucket(t)
			ins := newTestInspector(t, inspectorOpts{vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator()})
			ins.ruleConfigs = tc.ruleConfigs
			compacted, full, skipped := decodeCompacted(t, ins, tc.files(file), tc.routing(file), tc.items(file))
			require.Equal(t, storedFindings(t, full), storedFindings(t, compacted))
			require.Equal(t, tc.wantSkipped, skipped)
		})
	}

	t.Run("rule path filter drops the last result raised", func(t *testing.T) {
		older := parsedBucket(t)
		newer := parsedBucket(t)
		newer.FilePath = older.FilePath
		newer.OriginalData = older.OriginalData
		newer.LinesOriginalData = older.LinesOriginalData

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
		}, "")
		compacted, full, skipped := decodeCompacted(t, ins, map[string]*model.FileMetadata{
			older.ID: older, newer.ID: newer,
		}, routing, []map[string]interface{}{bucketItem(older.ID), bucketItem(newer.ID)})
		require.Equal(t, storedFindings(t, full), storedFindings(t, compacted))
		require.Len(t, compacted, 1, "the filtered result is the last one raised, so the earlier one is kept")
		require.Equal(t, older.ID, compacted[0].FileID)
		require.Zero(t, skipped, "the last result was dropped, so it does not cover the earlier one")
	})

	// The failing document is raised first, so it is decoded after the other
	// document of the same path has been kept.
	for _, loaded := range []bool{false, true} {
		t.Run(fmt.Sprintf("failed line info is reported on the scanned file, loaded before decode %t", loaded), func(t *testing.T) {
			good := parsedBucket(t)
			bad := parsedBucket(t)
			bad.FilePath = good.FilePath
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
			require.Equal(t, storedFindings(t, full), storedFindings(t, compacted))
			require.Len(t, compacted, 1)
			require.Equal(t, good.ID, compacted[0].FileID)
			require.Equal(t, 1, skipped)
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

// On the scan path, each instance of a counted resource resolves its own
// Terraform address (see K9CODESEC-7158), so the instances are distinct
// findings rather than one shared identity: compaction keeps every one of
// them, and none is skipped as superseded before its line is detected.
func TestInspect_CountedInstancesAreDistinctFindings(t *testing.T) {
	for _, n := range []int{20, 40} {
		detected, vulns := supersededInstances(t, n, true)
		require.Len(t, vulns, n, "each instance has its own resolved address, so none supersedes another")
		require.EqualValues(t, n, detected, "no instance is superseded, so every line is detected")

		detectedUncompacted, uncompactedVulns := supersededInstances(t, n, false)
		require.Len(t, uncompactedVulns, n)
		require.EqualValues(t, n, detectedUncompacted)
	}
}
