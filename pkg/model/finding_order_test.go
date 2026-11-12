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
			Platform: "Terraform", ResourceType: "aws_s3_bucket", ResourceName: "b", RootModule: "stack",
			ResourceID: "aws_s3_bucket.b", LineWithVulnerability: key,
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
