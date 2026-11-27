// Package harness runs rule tests (fixture files and their expected findings)
// against the engine. It is shared by the scanner's test-rules command and the
// harness of the rules repository.
//
// A rule's tests come from the Datadog API (LoadAPI) or from a local assets
// directory in the rules repository layout (LoadDir):
//
//	assets/queries/<platform>/.../<rule>/metadata.json
//	assets/queries/<platform>/.../<rule>/query.rego
//	assets/queries/<platform>/.../<rule>/test/...            fixtures and positive_expected_result.json
//	assets/queries/<platform>/.../<rule>/test_arguments/...  fixtures and arguments_expected_result.json
//	assets/libraries/<platform>.rego, <platform>.json        libraries and their input data
//
// Fixture roots: every top-level positive* or negative* file of a test
// directory is evaluated as its own root, in its own directory, next to the
// top-level files that are not fixtures (certificates, tfvars, ...). Each
// top-level subdirectory of the test directory is one multi-file root per
// polarity: its whole tree is written and its positive* (or negative*) files
// are evaluated together. Argument test files are evaluated together as one
// root for each case. Options.LegacyRoots restores the previous grouping for
// legacy rules whose fixtures depend on it; Contract v2 rules remain isolated.
//
// Findings of the positive roots must match the expected findings exactly
// (query name, severity, line, and file base name when the expectation sets
// one); negative roots must produce none.
package harness

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/ruletest"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
)

// File is a test fixture. Name is its slash-separated path relative to the
// test directory.
type File struct {
	Name    string
	Content []byte
}

// Finding is one finding as rule tests compare it. FileName is a base name;
// an empty FileName in an expected finding matches any file.
type Finding struct {
	QueryName string
	Severity  string
	Line      int
	FileName  string
}

// Tests are a rule's fixtures and the findings expected from its positive files.
type Tests struct {
	Files    []File
	Expected []Finding
}

// ArgumentCase is one evaluation of the argument fixtures with the given rule
// arguments (nil means none).
type ArgumentCase struct {
	Arguments map[string]any
	Expected  []Finding
}

// ArgumentTests are fixtures evaluated once per case, with different rule arguments.
type ArgumentTests struct {
	Files []File
	Cases []ArgumentCase
}

// Rule is a rule with its tests.
type Rule struct {
	ID       string
	LegacyID string
	// LegacyIDs are the historical IDs the rule was published under.
	LegacyIDs []string
	// Platform is the metadata platform name, for example "Terraform".
	Platform      string
	Query         model.QueryMetadata
	Tests         *Tests
	ArgumentTests *ArgumentTests
}

// Match reports whether the rule belongs to one of platforms (case-insensitive)
// and has one of ids as its ID or one of its legacy IDs, case-insensitively.
// An empty list matches everything.
func (r *Rule) Match(platforms, ids []string) bool {
	if len(platforms) > 0 && !slices.ContainsFunc(platforms, func(p string) bool {
		return strings.EqualFold(p, r.Platform)
	}) {
		return false
	}
	if len(ids) == 0 {
		return true
	}
	return slices.ContainsFunc(ids, func(ref string) bool {
		return utils.RuleIDMatches(r.ID, r.LegacyID, r.LegacyIDs, ref)
	})
}

// Suite is a set of rules with the libraries they are evaluated with.
type Suite struct {
	Rules     []*Rule
	libraries source.QueriesSource
}

const platformKubernetes = "kubernetes"

// DefaultResourceKeyPlatforms are the platforms whose legacy results must
// carry resourceType and resourceName.
var DefaultResourceKeyPlatforms = []string{
	"terraform",
	"cloudformation",
	"ansible",
	platformKubernetes,
	"k8s",
	"googledeploymentmanager",
	"crossplane",
	"azureresourcemanager",
	"pulumi",
}

// Options tune a test run.
type Options struct {
	// UnknownMutations verifies that replacing a written HCL attribute with an
	// unknown cannot introduce a finding. Independent findings may remain.
	UnknownMutations bool
	// PairwiseUnknownMutations also replaces attribute pairs simultaneously.
	PairwiseUnknownMutations bool
	// Timeout bounds the whole test run of one rule; zero means no limit.
	Timeout time.Duration
	// ResourceKeyPlatforms replaces DefaultResourceKeyPlatforms when not nil.
	ResourceKeyPlatforms []string
	// RequireFixtures reports a rule whose tests have no positive or no
	// negative fixture.
	RequireFixtures bool
	// CheckOrderDeterminism re-evaluates each fixture root with its documents
	// reversed and reports findings that move or change.
	CheckOrderDeterminism bool
	// LegacyRoots evaluates all positive fixtures of a legacy rule's test
	// directory as one root, and likewise all negative ones, for fixtures
	// written before per-file roots. Contract v2 rules always keep independent
	// roots, even when this option is set.
	LegacyRoots bool
}

// MismatchKind classifies a Mismatch.
type MismatchKind string

const (
	// MissingFinding is an expected finding the rule did not produce.
	MissingFinding MismatchKind = "missing"
	// UnexpectedFinding is a finding no expectation accounts for.
	UnexpectedFinding MismatchKind = "unexpected"
	// InvalidResult is a raw rule result that breaks the result contract.
	InvalidResult MismatchKind = "invalid-result"
	// QueryFailed means the engine could not load or evaluate the rule.
	QueryFailed MismatchKind = "query-failed"
	// MissingFixtures means the tests lack positive or negative fixtures.
	MissingFixtures MismatchKind = "missing-fixtures"
	// UnknownUnsafe means uncertainty introduced a finding absent in the baseline.
	UnknownUnsafe MismatchKind = "unknown-unsafe"
	// OrderDependent means reversing the documents in one fixture root changed its findings.
	OrderDependent MismatchKind = "order-dependent"
)

// Mismatch is one difference between what a rule reports and its tests.
type Mismatch struct {
	Kind MismatchKind
	// Case is the 1-based argument case, or 0 for the rule's main tests.
	Case int
	// Arguments reports whether the argument case sets arguments.
	Arguments bool
	// Finding is set for MissingFinding and UnexpectedFinding.
	Finding Finding
	// Message describes the other kinds.
	Message string
}

// Result is the outcome of one rule's tests.
type Result struct {
	Rule       *Rule
	Mismatches []Mismatch
}

// Passed reports whether the rule matched all its tests.
func (r Result) Passed() bool {
	return len(r.Mismatches) == 0
}

// Run evaluates the rule's tests. The returned error is for failures of the
// harness itself (temporary files, parsing, engine setup, cancellation);
// differences from the tests are in Result.Mismatches.
func (s *Suite) Run(ctx context.Context, rule *Rule, opts Options) (Result, error) {
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	// The compiled-query cache keeps every rule it has seen.
	defer engine.ResetCompiledQueryCachesForTest()

	tmpDir, err := os.MkdirTemp("", "iac-rule-test-*")
	if err != nil {
		return Result{}, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir) // nolint:errcheck

	ev := &evaluator{
		query:                rule.Query,
		libraries:            s.libraries,
		resourceKeyPlatforms: opts.ResourceKeyPlatforms,
		tmpDir:               tmpDir,
	}
	if ev.resourceKeyPlatforms == nil {
		ev.resourceKeyPlatforms = DefaultResourceKeyPlatforms
	}

	res := Result{Rule: rule}
	if rule.Tests != nil {
		mismatches, err := ev.runTests(ctx, rule.Tests, opts)
		if err != nil {
			return Result{}, err
		}
		res.Mismatches = append(res.Mismatches, mismatches...)
	}
	if rule.ArgumentTests != nil {
		mismatches, err := ev.runArgumentTests(ctx, rule.ArgumentTests)
		if err != nil {
			return Result{}, err
		}
		res.Mismatches = append(res.Mismatches, mismatches...)
	}
	return res, nil
}

func (ev *evaluator) runTests(ctx context.Context, tests *Tests, opts Options) ([]Mismatch, error) {
	legacyRoots := opts.LegacyRoots && !engine.UsesContractV2(&ev.query)
	positives := fixtureRoots(tests.Files, positivePrefix, legacyRoots)
	negatives := fixtureRoots(tests.Files, negativePrefix, legacyRoots)
	if opts.RequireFixtures {
		var mismatches []Mismatch
		if len(positives) == 0 {
			mismatches = append(mismatches, Mismatch{Kind: MissingFixtures, Message: "No positive* sample files found"})
		}
		if len(negatives) == 0 {
			mismatches = append(mismatches, Mismatch{Kind: MissingFixtures, Message: "No negative* sample files found"})
		}
		if len(mismatches) > 0 {
			return mismatches, nil
		}
	}
	if len(positives) == 0 && len(negatives) == 0 {
		return nil, nil
	}

	positiveGot, positiveErrs, err := ev.evalRootsWithOrderCheck(ctx, positives, nil, opts.CheckOrderDeterminism)
	if err != nil {
		return nil, err
	}
	negativeGot, negativeErrs, err := ev.evalRootsWithOrderCheck(ctx, negatives, nil, opts.CheckOrderDeterminism)
	if err != nil {
		return nil, err
	}

	var mismatches []Mismatch
	mismatches = append(mismatches, positiveErrs...)
	mismatches = append(mismatches, negativeErrs...)
	mismatches = append(mismatches, compareExpectedFindings(tests.Expected, positiveGot)...)
	mismatches = append(mismatches, compareExpectedFindings(nil, negativeGot)...)
	if (opts.UnknownMutations || opts.PairwiseUnknownMutations) && engine.UsesContractV2(&ev.query) {
		mutations, err := ev.runUnknownMutations(ctx, slices.Concat(positives, negatives), opts.PairwiseUnknownMutations)
		if err != nil {
			return nil, err
		}
		mismatches = append(mismatches, mutations...)
	}
	return mismatches, nil
}

type unknownVariant struct {
	source     []byte
	attributes string
}

func unknownVariants(file File, pairwise bool) ([]unknownVariant, error) {
	mutations, err := ruletest.MutateAttributesToUnknown(file.Name, file.Content)
	if err != nil {
		return nil, err
	}
	variants := make([]unknownVariant, 0, len(mutations))
	for _, mutation := range mutations {
		variants = append(variants, unknownVariant{mutation.Source, mutation.Attribute})
	}
	if pairwise {
		pairs, err := ruletest.MutateAttributePairsToUnknown(file.Name, file.Content)
		if err != nil {
			return nil, err
		}
		for _, mutation := range pairs {
			variants = append(variants, unknownVariant{mutation.Source, strings.Join(mutation.Attributes, ", ")})
		}
	}
	return variants, nil
}

func unknownMismatches(label string, baseline, findings []findingObservation, errs []Mismatch) []Mismatch {
	var mismatches []Mismatch
	for _, failure := range errs {
		failure.Message = label + ": " + failure.Message
		mismatches = append(mismatches, failure)
	}
	for _, difference := range compareObservedFindings(baseline, findings) {
		if difference.Kind != UnexpectedFinding {
			continue
		}
		difference.Kind = UnknownUnsafe
		difference.Message = fmt.Sprintf("%s introduced finding %#v", label, difference.Finding)
		mismatches = append(mismatches, difference)
	}
	return mismatches
}

// runUnknownMutations checks information-loss monotonicity per fixture root.
// It deliberately compares finding identities instead of requiring zero output:
// an unknown remediation input must not hide an independently proven finding.
func (ev *evaluator) runUnknownMutations(ctx context.Context, roots []root, pairwise bool) ([]Mismatch, error) {
	var mismatches []Mismatch
	for _, original := range roots {
		baseline, errs, err := ev.evalRoots(ctx, []root{original}, nil)
		if err != nil {
			return nil, err
		}
		if len(errs) != 0 {
			continue
		} // Normal fixture evaluation already reports this failure.
		for fileIndex, file := range original.files {
			if !strings.HasSuffix(file.Name, ".tf") {
				continue
			}
			variants, err := unknownVariants(file, pairwise)
			if err != nil {
				return nil, err
			}
			for _, mutation := range variants {
				mutated := root{files: slices.Clone(original.files), parse: original.parse}
				mutated.files[fileIndex].Content = mutation.source
				findings, errs, err := ev.evalRoots(ctx, []root{mutated}, nil)
				if err != nil {
					return nil, err
				}
				label := fmt.Sprintf("unknown mutation %s [%s]", file.Name, mutation.attributes)
				mismatches = append(mismatches, unknownMismatches(label, baseline, findings, errs)...)
			}
		}
	}
	return mismatches, nil
}

func (ev *evaluator) runArgumentTests(ctx context.Context, tests *ArgumentTests) ([]Mismatch, error) {
	if len(tests.Files) == 0 {
		return []Mismatch{{Kind: MissingFixtures, Message: "No argument test sample files found"}}, nil
	}
	r := root{files: tests.Files}
	for _, f := range tests.Files {
		r.parse = append(r.parse, f.Name)
	}

	var mismatches []Mismatch
	for i, tc := range tests.Cases {
		got, errs, err := ev.evalRoots(ctx, []root{r}, tc.Arguments)
		if err != nil {
			return nil, err
		}
		caseMismatches := slices.Concat(errs, compareExpectedFindings(tc.Expected, got))
		for j := range caseMismatches {
			caseMismatches[j].Case = i + 1
			caseMismatches[j].Arguments = tc.Arguments != nil
		}
		mismatches = append(mismatches, caseMismatches...)
	}
	return mismatches, nil
}

// compareFindings returns one mismatch per expected finding with no match in
// got and one per finding of got left over. Expectations with a FileName are
// matched before wildcard ones so a wildcard cannot take their finding.
func compareFindings(expected, got []Finding) []Mismatch {
	remaining := slices.Clone(got)

	sorted := slices.Clone(expected)
	slices.SortStableFunc(sorted, func(a, b Finding) int {
		if (a.FileName == "") == (b.FileName == "") {
			return 0
		}
		if a.FileName != "" {
			return -1
		}
		return 1
	})

	var mismatches []Mismatch
	for _, exp := range sorted {
		idx := slices.IndexFunc(remaining, func(g Finding) bool {
			return findingsMatch(exp, g)
		})
		if idx == -1 {
			mismatches = append(mismatches, Mismatch{Kind: MissingFinding, Finding: exp})
		} else {
			remaining = slices.Delete(remaining, idx, idx+1)
		}
	}
	for _, g := range remaining {
		mismatches = append(mismatches, Mismatch{Kind: UnexpectedFinding, Finding: g})
	}
	return mismatches
}

func compareExpectedFindings(expected []Finding, got []findingObservation) []Mismatch {
	values := make([]Finding, len(got))
	for i := range got {
		values[i] = got[i].finding
	}
	return compareFindings(expected, values)
}

func compareObservedFindings(expected, got []findingObservation) []Mismatch {
	remaining := slices.Clone(got)
	var mismatches []Mismatch
	for _, exp := range expected {
		idx := slices.IndexFunc(remaining, func(candidate findingObservation) bool {
			return exp.path == candidate.path && findingsMatch(exp.finding, candidate.finding)
		})
		if idx == -1 {
			mismatches = append(mismatches, Mismatch{
				Kind: MissingFinding, Finding: exp.finding, Message: exp.path,
			})
		} else {
			remaining = slices.Delete(remaining, idx, idx+1)
		}
	}
	for _, candidate := range remaining {
		mismatches = append(mismatches, Mismatch{
			Kind: UnexpectedFinding, Finding: candidate.finding, Message: candidate.path,
		})
	}
	return mismatches
}

func findingsMatch(exp, got Finding) bool {
	return exp.QueryName == got.QueryName &&
		exp.Severity == got.Severity &&
		exp.Line == got.Line &&
		(exp.FileName == "" || exp.FileName == got.FileName)
}
