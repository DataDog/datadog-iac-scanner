/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"cmp"
	"crypto/sha256"
	"sort"
)

// CompareFindings orders findings by where they are reported: file, line,
// then search key. The other reported fields break the remaining ties, so the
// order never depends on the order rules raised the findings in. The stored
// address comes last so it never decides which reported fields a duplicate
// keeps.
func CompareFindings(a, b *Vulnerability) int {
	if c := cmp.Compare(a.FileName, b.FileName); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Line, b.Line); c != 0 {
		return c
	}
	if c := cmp.Compare(a.SearchKey, b.SearchKey); c != 0 {
		return c
	}
	return cmp.Or(
		cmp.Compare(a.QueryID, b.QueryID),
		cmp.Compare(a.ResourceType, b.ResourceType),
		cmp.Compare(a.ResourceName, b.ResourceName),
		cmp.Compare(a.VulnerabilityLocation.Start.Col, b.VulnerabilityLocation.Start.Col),
		cmp.Compare(a.SearchValue, b.SearchValue),
		cmp.Compare(derefString(a.Value), derefString(b.Value)),
		cmp.Compare(callSite(a).Filename, callSite(b).Filename),
		cmp.Compare(callSite(a).LineStart, callSite(b).LineStart),
		cmp.Compare(a.RootModule, b.RootModule),
		cmp.Compare(a.ResourceID, b.ResourceID),
	)
}

// FirstFindingPerIdentity keeps, of the findings sharing an identity (see
// FindingIdentity), the first one in CompareFindings order, and returns the
// kept findings in that order. It reorders findings in place.
func FirstFindingPerIdentity(findings []Vulnerability) []Vulnerability {
	SortFindings(findings)
	seen := make(map[[sha256.Size]byte]struct{}, len(findings))
	kept := findings[:0]
	for i := range findings {
		digest := sha256.Sum256([]byte(FindingIdentity(&findings[i])))
		if _, duplicate := seen[digest]; duplicate {
			continue
		}
		seen[digest] = struct{}{}
		kept = append(kept, findings[i])
	}
	clear(findings[len(kept):])
	return kept
}

// SortFindings sorts findings in CompareFindings order.
func SortFindings(findings []Vulnerability) {
	sort.SliceStable(findings, func(i, j int) bool { return CompareFindings(&findings[i], &findings[j]) < 0 })
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func callSite(v *Vulnerability) SourceLocation {
	if v.ModuleAttribution == nil {
		return SourceLocation{}
	}
	return v.ModuleAttribution.CallSite
}
