/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func orderedFindings() []Vulnerability {
	finding := func(file string, line int, key string) Vulnerability {
		return Vulnerability{
			FileName: file, Line: line, SearchKey: key, QueryID: "q", QueryName: "q", Severity: SeverityHigh,
			Platform: "Terraform", ResourceType: "aws_s3_bucket", ResourceName: "b",
			LineWithVulnerability: key,
		}
	}
	return []Vulnerability{
		finding("main.tf", 3, "aws_s3_bucket[b].acl"),
		finding("main.tf", 3, "aws_s3_bucket[b].policy"),
		finding("main.tf", 7, "aws_s3_bucket[b].acl"),
		finding("main_override.tf", 1, "aws_s3_bucket[b].acl"),
	}
}

func permutations(findings []Vulnerability) [][]Vulnerability {
	orders := [][]int{{0, 1, 2, 3}, {3, 2, 1, 0}, {2, 0, 3, 1}, {1, 3, 0, 2}}
	out := make([][]Vulnerability, 0, len(orders))
	for _, order := range orders {
		p := make([]Vulnerability, 0, len(order))
		for _, i := range order {
			p = append(p, findings[i])
		}
		out = append(out, p)
	}
	return out
}

func TestFirstFindingPerIdentity_KeepsTheFirstLocation(t *testing.T) {
	for _, raised := range permutations(orderedFindings()) {
		kept := FirstFindingPerIdentity(raised)
		require.Len(t, kept, 2, "the file is part of the identity, so the override is its own finding")
		byFile := map[string]Vulnerability{}
		for i := range kept {
			byFile[kept[i].FileName] = kept[i]
		}
		require.Equal(t, 3, byFile["main.tf"].Line)
		require.Equal(t, "aws_s3_bucket[b].acl", byFile["main.tf"].SearchKey)
		require.Equal(t, 1, byFile["main_override.tf"].Line)
	}
}

func TestFirstFindingPerIdentity_KeepsTheSameFindingWhateverTheInputOrder(t *testing.T) {
	base := orderedFindings()[0]
	differing := []func(v *Vulnerability){
		func(v *Vulnerability) { v.Remediation = "b" },
		func(v *Vulnerability) { v.VulnerabilityLocation.End.Line = 9 },
		func(v *Vulnerability) {
			v.ModuleAttribution = &ModuleAttribution{ModulePath: []ModulePathHop{{Name: "b"}}}
		},
		func(v *Vulnerability) {
			v.ModuleAttribution = &ModuleAttribution{ModulePath: []ModulePathHop{{Name: "a"}, {Name: "c"}}}
		},
	}
	raised := []Vulnerability{base}
	for _, change := range differing {
		v := base
		change(&v)
		raised = append(raised, v)
	}
	var want *Vulnerability
	for shift := range raised {
		order := append(slices.Clone(raised[shift:]), raised[:shift]...)
		if shift%2 == 1 {
			slices.Reverse(order)
		}
		kept := FirstFindingPerIdentity(order)
		require.Len(t, kept, 1)
		if want == nil {
			want = &kept[0]
			continue
		}
		require.Equal(t, *want, kept[0])
	}
	for i := range raised {
		for j := range raised {
			require.Equal(t, i == j, CompareFindings(&raised[i], &raised[j]) == 0, "%d and %d", i, j)
		}
	}
}

// mutationTable changes one reported field of a finding at a time: every
// field the reports carry except the three the order checks first (file,
// line and search key, covered by orderedFindings) and the per-run
// identifiers the order leaves out on purpose (QueryDuration, ID, ScanID,
// FileID). Two findings that differ in any of these must compare unequal,
// so first-of-identity can never follow arrival order.
func mutationTable() []func(v *Vulnerability) {
	lines := func(lines ...CodeLine) *[]CodeLine { return &lines }
	return []func(v *Vulnerability){
		func(v *Vulnerability) { v.QueryID = "q2" },
		func(v *Vulnerability) { v.LegacyQueryID = "legacy2" },
		func(v *Vulnerability) { v.QueryName = "other" },
		func(v *Vulnerability) { v.QueryURI = "https://docs.datadoghq.com/rule" },
		func(v *Vulnerability) { v.Platform = "Kubernetes" },
		func(v *Vulnerability) { v.Severity = SeverityCritical },
		func(v *Vulnerability) { v.Category = "Encryption" },
		func(v *Vulnerability) { v.CWE = "798" },
		func(v *Vulnerability) { v.Description = "different" },
		func(v *Vulnerability) { v.DescriptionID = "desc-2" },
		func(v *Vulnerability) { v.Experimental = true },
		func(v *Vulnerability) { v.CloudProvider = "aws" },
		func(v *Vulnerability) { v.ResourceType = "aws_s3_bucket_policy" },
		func(v *Vulnerability) { v.ResourceName = "c" },
		func(v *Vulnerability) { v.SearchValue = "value" },
		func(v *Vulnerability) { s := "value"; v.Value = &s },
		func(v *Vulnerability) { v.SearchLine = 5 },
		func(v *Vulnerability) { v.Remediation = "b" },
		func(v *Vulnerability) { v.RemediationType = "replacement" },
		func(v *Vulnerability) { v.RemediationLocation.Start.Line = 2 },
		func(v *Vulnerability) { v.VulnerabilityLocation.End.Line = 9 },
		func(v *Vulnerability) { v.BlockLocation.Start.Line = 2 },
		func(v *Vulnerability) { v.LineWithVulnerability = "other line text" },
		func(v *Vulnerability) { v.ResourceSource = "terraform" },
		func(v *Vulnerability) { v.FileSource = []string{"other.tf"} },
		// null vs [] is a wire difference, so the empty list is its own entry.
		func(v *Vulnerability) { v.FileSource = []string{} },
		func(v *Vulnerability) { v.VulnLines = lines(CodeLine{Position: 1, Line: "x"}) },
		func(v *Vulnerability) {
			v.VulnLines = lines(CodeLine{Position: 1, Line: "x"}, CodeLine{Position: 2, Line: "y"})
		},
		func(v *Vulnerability) { empty := []CodeLine{}; v.VulnLines = &empty },
		// A pointer to a nil slice serializes null, so it is its own entry too.
		func(v *Vulnerability) { nilLines := []CodeLine(nil); v.VulnLines = &nilLines },
		func(v *Vulnerability) { v.Frameworks = []Framework{{Framework: "cis"}} },
		func(v *Vulnerability) { v.Frameworks = []Framework{{Framework: "cis", Requirement: "1.2"}} },
		func(v *Vulnerability) { v.IsSuppressed = true },
		func(v *Vulnerability) { v.SuppressionKind = SuppressionKindInSource },
		func(v *Vulnerability) { v.SuppressionJustification = SuppressionJustificationIgnoreComment },
		func(v *Vulnerability) { v.ModuleCallChain = "stack/main.tf|module.a" },
		func(v *Vulnerability) { v.DetectedFileName = "modules/app/main.tf" },
		func(v *Vulnerability) { v.OrderPath = "registry.example.com/org/module/main.tf" },
		func(v *Vulnerability) { v.DetectedLineWithVulnerability = "detected text" },
		func(v *Vulnerability) {
			v.ModuleAttribution = &ModuleAttribution{ModulePath: []ModulePathHop{{Name: "b"}}}
		},
		func(v *Vulnerability) {
			v.ModuleAttribution = &ModuleAttribution{ModulePath: []ModulePathHop{{Name: "a"}, {Name: "c"}}}
		},
	}
}

// A path's separators are part of how a platform names a file, not of where
// the file is: the same logical path must order alike whichever form it was
// detected in, including pairs whose order hinges on a single character.
func TestCompareFindings_NormalizesPathSeparators(t *testing.T) {
	modulePath := func(module, sep string) string {
		return "registry.terraform.io" + sep + "acme" + sep + module + sep + "aws@1.0.0" + sep + "main.tf"
	}
	slashA := modulePath("a", "/")
	slashA0 := modulePath("a0", "/")
	backA := modulePath("a", "\\")
	backA0 := modulePath("a0", "\\")

	a := orderedFindings()[0]
	a.FileName = slashA
	a0 := a
	a0.FileName = slashA0
	aBack := a
	aBack.FileName = backA
	a0Back := a0
	a0Back.FileName = backA0

	// The two forms of one logical path are one ordering key.
	require.Zero(t, CompareFindings(&a, &aBack))
	require.Zero(t, CompareFindings(&a0, &a0Back))

	// The pair's order cannot hinge on the separator: without normalization,
	// the backslash form sorts a0 before a while the slash form sorts a
	// before a0.
	require.Negative(t, CompareFindings(&a, &a0))
	require.Negative(t, CompareFindings(&aBack, &a0Back))
	require.Positive(t, CompareFindings(&a0, &a))
	require.Positive(t, CompareFindings(&a0Back, &aBack))

	// The detected-name tie-break normalizes the same way.
	a.DetectedFileName = backA
	aBack.DetectedFileName = backA
	a0.DetectedFileName = backA0
	a0Back.DetectedFileName = backA0
	require.Zero(t, CompareFindings(&a, &aBack))
	require.Negative(t, CompareFindings(&a, &a0))
}

// CompareFindings must be a total order over every reported field: unequal
// findings compare asymmetrically in both directions, equal findings are
// exactly the same finding, and sorting is idempotent.
func TestCompareFindings_TotalOrderOverReportedFields(t *testing.T) {
	base := orderedFindings()[0]
	raised := []Vulnerability{base}
	for _, change := range mutationTable() {
		v := base
		change(&v)
		raised = append(raised, v)
	}
	for i := range raised {
		require.Zero(t, CompareFindings(&raised[i], &raised[i]), "%d compares equal to itself", i)
		for j := range raised {
			if i == j {
				continue
			}
			forward, backward := CompareFindings(&raised[i], &raised[j]), CompareFindings(&raised[j], &raised[i])
			require.Truef(t, forward < 0 && backward > 0 || forward > 0 && backward < 0,
				"%d and %d must order asymmetrically, got %d and %d", i, j, forward, backward)
		}
	}
	sorted := slices.Clone(raised)
	SortFindings(sorted)
	require.True(t, slices.IsSortedFunc(sorted, func(a, b Vulnerability) int { return CompareFindings(&a, &b) }))
	again := slices.Clone(sorted)
	SortFindings(again)
	require.Equal(t, sorted, again)
}

func TestCreateSummary_FilesOrderDoesNotDependOnInputOrder(t *testing.T) {
	var want []VulnerableFile
	for _, raised := range permutations(orderedFindings()) {
		files := CreateSummary(context.Background(), Counters{}, raised, "scan", nil, "", SCIInfo{}).Queries[0].Files
		got := make([]VulnerableFile, len(files))
		copy(got, files)
		if want == nil {
			want = got
			require.True(t, slices.IsSortedFunc(got, func(a, b VulnerableFile) int {
				if a.FileName != b.FileName {
					return strings.Compare(a.FileName, b.FileName)
				}
				return a.Line - b.Line
			}))
			continue
		}
		require.Equal(t, want, got)
	}
}
