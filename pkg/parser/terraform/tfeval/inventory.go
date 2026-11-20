/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"cmp"
	"errors"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// InventoryGapReason identifies native evidence that membership was not fully
// established. It is not a security finding or a rule-visible completeness flag.
type InventoryGapReason uint8

const (
	inventoryNoGap InventoryGapReason = iota
	InventoryConfigurationUnavailable
	InventoryDeclarationUnavailable
	InventoryExpansionUnknown
	InventoryExpansionInvalid
	InventoryModuleSourceUnavailable
	InventoryModuleDirectoryUnavailable
	InventoryRemoteModuleUnavailable
	InventoryModuleCycle
	InventoryModuleEvaluationFailed
	// The dependency-cycle fallback did not establish expansion keys.
	InventoryExpansionCycle
)

// InventoryGap identifies an authoritative declaration group in its declaring
// module occurrence. Kind/type/name disambiguate converted JSON declarations
// whose source anchors may overlap. Facts retain no AST or evaluation context.
type InventoryGap struct {
	Reason           InventoryGapReason
	ModuleAddress    string
	Subject          hcl.Range
	Kind, Type, Name string
	Detail           string
}

// InventoryObservations is an owned inspection snapshot, not a membership
// certificate. EvaluationCompleted means the native walk finished, not that
// Terraform validation succeeded or a selector's inventory is closed. An empty
// gap slice must not be used alone to certify completeness.
type InventoryObservations struct {
	RootDir             string
	EvaluationCompleted bool
	Gaps                []InventoryGap
}

func (r *ModuleEvaluation) InventoryObservations() InventoryObservations {
	return InventoryObservations{RootDir: r.rootDir, EvaluationCompleted: r.evaluationCompleted, Gaps: slices.Clone(r.inventoryGaps)}
}

func (o *evaluationObservations) inventoryGap(block *hclsyntax.Block, reason InventoryGapReason, detail string) {
	if o == nil {
		return
	}
	if reason == inventoryNoGap {
		delete(o.gaps, block)
		return
	}
	if o.gaps == nil {
		o.gaps = map[*hclsyntax.Block]*InventoryGap{}
	}
	gap := &InventoryGap{Reason: reason, Subject: block.Range(), Kind: block.Type, Detail: detail}
	if len(block.Labels) > 0 {
		gap.Name = block.Labels[len(block.Labels)-1]
	}
	if len(block.Labels) > 1 {
		gap.Type = block.Labels[0]
	}
	o.gaps[block] = gap
}

func (e *Evaluator) collectInventoryGaps(addr string, scope *ModuleScope) {
	for _, observation := range scope.observations.gaps {
		gap := *observation
		gap.ModuleAddress = addr
		e.inventoryGaps = append(e.inventoryGaps, gap)
	}
}

func sortInventoryGaps(gaps []InventoryGap) {
	slices.SortFunc(gaps, func(a, b InventoryGap) int {
		for _, pair := range [][2]string{{a.ModuleAddress, b.ModuleAddress}, {a.Subject.Filename, b.Subject.Filename}} {
			if c := strings.Compare(pair[0], pair[1]); c != 0 {
				return c
			}
		}
		if c := cmp.Compare(a.Subject.Start.Byte, b.Subject.Start.Byte); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Subject.End.Byte, b.Subject.End.Byte); c != 0 {
			return c
		}
		for _, pair := range [][2]string{{a.Kind, b.Kind}, {a.Type, b.Type}, {a.Name, b.Name}} {
			if c := strings.Compare(pair[0], pair[1]); c != 0 {
				return c
			}
		}
		if c := cmp.Compare(a.Reason, b.Reason); c != 0 {
			return c
		}
		return strings.Compare(a.Detail, b.Detail)
	})
}

// moduleSkip retains the actual recursion guard without classifying from log text.
type moduleSkip struct{ reason InventoryGapReason }

func (s *moduleSkip) Error() string { return ErrModuleNotEvaluated.Error() }
func (s *moduleSkip) Unwrap() error { return ErrModuleNotEvaluated }
func moduleFailureGap(err error) InventoryGapReason {
	var skip *moduleSkip
	if errors.As(err, &skip) {
		return skip.reason
	}
	return InventoryModuleEvaluationFailed
}

// collectConfigurationObservations consumes only parse-phase diagnostics. An
// ordinary expression failure does not imply missing declarations or members.
func (e *Evaluator) collectConfigurationObservations(addr string, parsed *dirParse) {
	var unavailableFiles map[string]bool
	for _, diagnostic := range parsed.diagnostics {
		diagnostic.ModuleAddress = addr
		e.diagnostics = append(e.diagnostics, diagnostic)
		if unavailableFiles[diagnostic.Subject.Filename] {
			continue
		}
		if unavailableFiles == nil {
			unavailableFiles = map[string]bool{}
		}
		unavailableFiles[diagnostic.Subject.Filename] = true
		e.inventoryGaps = append(e.inventoryGaps, InventoryGap{
			Reason: InventoryConfigurationUnavailable, ModuleAddress: addr,
			Subject: diagnostic.Subject, Kind: "configuration",
		})
	}
}
