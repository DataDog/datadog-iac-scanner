/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"cmp"
	"crypto/sha256"
	"slices"
	"sort"
)

// CompareFindings orders findings by where they are reported: file, line,
// then search key. The other reported fields break the remaining ties, so the
// order never depends on the order rules raised the findings in.
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
	if c := cmp.Or(
		cmp.Compare(a.QueryID, b.QueryID),
		cmp.Compare(a.ResourceType, b.ResourceType),
		cmp.Compare(a.ResourceName, b.ResourceName),
		cmp.Compare(a.VulnerabilityLocation.Start.Col, b.VulnerabilityLocation.Start.Col),
		cmp.Compare(a.SearchValue, b.SearchValue),
		cmp.Compare(derefString(a.Value), derefString(b.Value)),
		cmp.Compare(callSite(a).Filename, callSite(b).Filename),
		cmp.Compare(callSite(a).LineStart, callSite(b).LineStart),
	); c != 0 {
		return c
	}
	return compareReported(a, b)
}

// compareReported orders findings CompareFindings ties on by the rest of
// what they report, so two findings compare equal only when the report
// cannot tell them apart. QueryDuration is left out: it differs between runs.
func compareReported(a, b *Vulnerability) int {
	return cmp.Or(
		cmp.Compare(a.ModuleCallChain, b.ModuleCallChain),
		compareBool(a.Value != nil, b.Value != nil),
		cmp.Compare(a.SearchLine, b.SearchLine),
		compareResourceLocation(a.VulnerabilityLocation, b.VulnerabilityLocation),
		compareResourceLocation(a.BlockLocation, b.BlockLocation),
		compareResourceLocation(a.RemediationLocation, b.RemediationLocation),
		cmp.Compare(a.LineWithVulnerability, b.LineWithVulnerability),
		cmp.Compare(a.DetectedFileName, b.DetectedFileName),
		cmp.Compare(a.DetectedLineWithVulnerability, b.DetectedLineWithVulnerability),
		cmp.Compare(a.LegacyQueryID, b.LegacyQueryID),
		cmp.Compare(a.QueryName, b.QueryName),
		cmp.Compare(a.Platform, b.Platform),
		cmp.Compare(a.Severity, b.Severity),
		cmp.Compare(a.Description, b.Description),
		cmp.Compare(a.Remediation, b.Remediation),
		cmp.Compare(a.RemediationType, b.RemediationType),
		cmp.Compare(a.ResourceSource, b.ResourceSource),
		compareBool(a.IsSuppressed, b.IsSuppressed),
		cmp.Compare(a.SuppressionKind, b.SuppressionKind),
		cmp.Compare(a.SuppressionJustification, b.SuppressionJustification),
		compareAttribution(a.ModuleAttribution, b.ModuleAttribution),
	)
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

func compareResourceLocation(a, b ResourceLocation) int {
	return cmp.Or(
		cmp.Compare(a.Start.Line, b.Start.Line),
		cmp.Compare(a.Start.Col, b.Start.Col),
		cmp.Compare(a.End.Line, b.End.Line),
		cmp.Compare(a.End.Col, b.End.Col),
	)
}

func compareSourceLocation(a, b SourceLocation) int {
	return cmp.Or(
		cmp.Compare(a.Filename, b.Filename),
		cmp.Compare(a.LineStart, b.LineStart),
		cmp.Compare(a.LineEnd, b.LineEnd),
		cmp.Compare(a.ColumnStart, b.ColumnStart),
		cmp.Compare(a.ColumnEnd, b.ColumnEnd),
	)
}

func compareAttribution(a, b *ModuleAttribution) int {
	if a == nil || b == nil {
		return compareBool(a != nil, b != nil)
	}
	return cmp.Or(
		cmp.Compare(a.Source, b.Source),
		cmp.Compare(a.SourceType, b.SourceType),
		cmp.Compare(a.Version, b.Version),
		cmp.Compare(a.DependencyType, b.DependencyType),
		compareSourceLocation(a.CallSite, b.CallSite),
		compareSourceLocation(a.ModuleCodeLocation, b.ModuleCodeLocation),
		compareBool(a.ModuleCodeOwned, b.ModuleCodeOwned),
		cmp.Compare(a.ArgumentControl, b.ArgumentControl),
		slices.CompareFunc(a.ModulePath, b.ModulePath, func(x, y ModulePathHop) int {
			return cmp.Or(
				cmp.Compare(x.Name, y.Name),
				cmp.Compare(x.Source, y.Source),
				cmp.Compare(x.SourceType, y.SourceType),
				cmp.Compare(x.Version, y.Version),
				compareSourceLocation(x.CodeLocation, y.CodeLocation),
			)
		}),
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
