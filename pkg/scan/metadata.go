package scan

import (
	"encoding/json"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

type ScanMetadata struct {
	failedCoverage model.EvaluationFailures
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
	// PeakRSSBytes is the scanner process high-water resident set size.
	PeakRSSBytes uint64 `json:",omitempty"`
	// PeakRSSPhase is the scan phase in which PeakRSSBytes was reached.
	PeakRSSPhase string `json:",omitempty"`
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

// FailedCoverage returns immutable producer failures, separate from normal unknown values.
func (m *ScanMetadata) FailedCoverage() model.EvaluationFailures { return m.failedCoverage }

//nolint:gocritic // encoding/json must retain failed coverage for values and pointers; this copy occurs only when reporting.
func (m ScanMetadata) MarshalJSON() ([]byte, error) {
	type plain ScanMetadata
	return json.Marshal(struct {
		plain
		Evaluation *model.EvaluationReport `json:"evaluation,omitempty"`
	}{plain: plain(m), Evaluation: m.failedCoverage.Report()})
}
func (m *ScanMetadata) UnmarshalJSON(data []byte) error {
	type plain ScanMetadata
	var wire struct {
		plain
		Evaluation *model.EvaluationReport `json:"evaluation"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	failures, err := model.EvaluationFailuresFromReport(wire.Evaluation)
	if err != nil {
		return err
	}
	*m = ScanMetadata(wire.plain)
	m.failedCoverage = failures
	return nil
}
