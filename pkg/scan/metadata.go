package scan

import (
	"time"
)

type ScanMetadata struct {
	ContractV2 *ContractV2Metadata `json:"contract_v2,omitempty"`
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
	// Incomplete reports that an unexpected duplicate ID caused a document to be rejected.
	Incomplete bool `json:",omitempty"`
	// PeakRSSBytes is the scanner process high-water resident set size.
	PeakRSSBytes uint64 `json:",omitempty"`
	// PeakRSSPhase is the scan phase in which PeakRSSBytes was reached.
	PeakRSSPhase string `json:",omitempty"`
	// Inventory reports the resource inventory, when the scan was asked for one.
	Inventory *InventoryMetadata `json:",omitempty"`
}

// InventoryMetadata reports what happened to the resource inventory.
type InventoryMetadata struct {
	// Status is "written" or "failed". A failed inventory writes no file.
	Status string
	// Reason is a short code for a failure: stale_file, write_error, panic,
	// path_conflict, terraform_evaluation_panic or documents_panic.
	Reason string `json:",omitempty"`
	// Error is the failure message.
	Error string `json:",omitempty"`
	// Resources, Files and FilesFailed count what the written inventory holds.
	Resources   int
	Files       int
	FilesFailed int
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
	// DuplicateDocumentIDs counts documents rejected for ID reuse.
	DuplicateDocumentIDs int
}

type RuleStats struct {
	// FailedToCompile contains rule IDs whose Rego failed to compile.
	FailedToCompile []string `json:"failed_to_compile,omitempty"`
	// FailedToEvaluate contains rule IDs that failed at runtime or while decoding findings.
	FailedToEvaluate []string `json:"failed_to_evaluate,omitempty"`
	// DefaultRuleCompileFailed reports compile errors in the default rule source.
	DefaultRuleCompileFailed bool `json:"default_rule_compile_failed,omitempty"`
	// TimedOut contains a list of rules that timed out.
	TimedOut []string
	// MostExpensiveRule contains the rule that spent the most time executing during the analysis.
	MostExpensiveRule RuleTiming
	// SlowestRule contains the rule that spent the most time executing per file.
	SlowestRule RuleTiming
}

// ContractV2Metadata contains additive counters for Contract v2 Terraform evaluation.
type ContractV2Metadata struct {
	RootsFailed          int `json:"roots_failed"`
	PlansFailed          int `json:"plans_failed"`
	RootsScopeIncomplete int `json:"roots_scope_incomplete"`
}

// SetContractV2Counters records runner counters in scan metadata. The runner
// owns the counter values; this setter keeps their public metadata contract in
// the scan package.
func (m *ScanMetadata) SetContractV2Counters(rootsFailed, plansFailed, rootsScopeIncomplete int) {
	m.ContractV2 = &ContractV2Metadata{
		RootsFailed:          rootsFailed,
		PlansFailed:          plansFailed,
		RootsScopeIncomplete: rootsScopeIncomplete,
	}
}

type RuleTiming struct {
	Name string
	Time time.Duration
}
