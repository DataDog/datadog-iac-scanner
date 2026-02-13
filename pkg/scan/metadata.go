package scan

import (
	"time"
)

type ScanMetadata struct {
	// StartTime contains the instant in which the analysis started.
	StartTime time.Time
	// EndTime contains the instant in which the analysis ended.
	EndTime time.Time
	// DiffAware contains whether the analyzer could use Diff-Aware scanning.
	DiffAware bool
	// CoresAvailable contains the number of cores that were available to the analyzer.
	CoresAvailable int
	// Stats contains statistics about the analysis.
	Stats ScanStats
	// RuleStats contains statistics about rules.
	RuleStats RuleStats
}

type ScanStats struct {
	// Violations contains the number of violations that were found.
	Violations int
	// Files contains the number of files that were analyzed.
	Files int
	// Rules contains the number of rules that were evaluated.
	Rules int
	// Duration contains the time it took to complete the analysis.
	Duration time.Duration
	// ViolationBreakdowns contains a breakdown of the violations by severity.
	ViolationBreakdowns map[string]map[string]int
	// ResourcesFound contains the number of resources that were analyzed.
	ResourcesScanned int
}

type RuleStats struct {
	// TimedOut contains a list of rules that timed out.
	TimedOut []string
	// MostExpensiveRule contains the rule that spent the most time executing during the analysis.
	MostExpensiveRule RuleTiming
	// SlowestRule contains the rule that spent the most time executing per file.
	SlowestRule RuleTiming
}

type RuleTiming struct {
	Name string
	Time time.Duration
}
