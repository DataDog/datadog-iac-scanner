/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"context"
	"embed"
	"fmt"
	"sync"

	"github.com/open-policy-agent/regal/pkg/linter"
	"github.com/open-policy-agent/regal/pkg/report"
	"github.com/open-policy-agent/regal/pkg/rules"
)

// regalRulesFS holds the Datadog custom-rule contract expressed as Regal rules. Only
// conventions Regal cannot know about belong here.
//
//go:embed regalrules
var regalRulesFS embed.FS

// enabledRegalCategories is limited to the embedded Datadog contract. The Regal "bugs"
// category mixes definite failures with advisory checks (constant-condition,
// unused-output-variable, …) that would reject working rules, so only a curated subset
// of bug rules is enabled individually below.
var enabledRegalCategories = []string{"datadog"}

// enabledRegalBugRules are Regal built-ins whose violations mean the rule cannot run
// correctly. Advisory bug rules stay off so patterns like `1 == 1` or an unused output
// variable do not block evaluation.
var enabledRegalBugRules = []string{
	"duplicate-rule",
	"impossible-not",
	"rule-shadows-builtin",
	"var-shadows-builtin",
	"zero-arity-function",
}

// regalRuleCodes maps a Regal rule title to the diagnostic code the scanner reports it
// under, keeping all codes in one vocabulary rather than mixing Regal's naming with
// OPA's rego_* codes. Rules absent from this map keep their "category/title" name.
var regalRuleCodes = map[string]string{
	"package-name":  codeInvalidPackage,
	"policy-rule":   codeMissingRule,
	"result-fields": codeMissingResultField,
	"sprintf-arity": codeSprintfArity,
}

// regalIgnoredRules are built-ins superseded by an embedded rule that reports the same
// problem with a more actionable message.
var regalIgnoredRules = []string{"sprintf-arguments-mismatch"}

// preparedLinter compiles Regal's rule bundle, which dominates lint cost and does not
// depend on the module being checked. The prepared query is read-only during evaluation,
// so reusing it across calls is safe and roughly an order of magnitude cheaper.
var preparedLinter = sync.OnceValues(func() (linter.Linter, error) {
	l, err := linter.NewLinter().
		WithCustomRulesFromFS(regalRulesFS, "regalrules").
		WithDisableAll(true).
		WithEnabledCategories(enabledRegalCategories...).
		WithEnabledRules(enabledRegalBugRules...).
		WithDisabledRules(regalIgnoredRules...).
		Prepare(context.Background())
	if err != nil {
		return linter.Linter{}, fmt.Errorf("preparing Regal linter: %w", err)
	}
	return l, nil
})

// lintWithRegal runs Regal over regoContent and returns its violations as diagnostics.
func lintWithRegal(ctx context.Context, regoContent string) ([]RegoValidationError, error) {
	prepared, err := preparedLinter()
	if err != nil {
		return nil, err
	}

	input, err := rules.InputFromText(customRuleFileName, regoContent)
	if err != nil {
		return nil, fmt.Errorf("preparing Regal input: %w", err)
	}

	result, err := prepared.WithInputModules(&input).Lint(ctx)
	if err != nil {
		return nil, fmt.Errorf("linting with Regal: %w", err)
	}

	errs := make([]RegoValidationError, 0, len(result.Violations))
	for i := range result.Violations {
		errs = append(errs, regoValidationErrorFromViolation(&result.Violations[i]))
	}
	return errs, nil
}

// regoValidationErrorFromViolation maps a Regal violation onto the scanner's diagnostic
// shape.
func regoValidationErrorFromViolation(v *report.Violation) RegoValidationError {
	code, ok := regalRuleCodes[v.Title]
	if !ok {
		code = v.Category + "/" + v.Title
	}
	e := RegoValidationError{
		Code:      code,
		Message:   v.Description,
		StartLine: v.Location.Row,
		StartCol:  v.Location.Column,
		EndLine:   v.Location.Row,
		EndCol:    v.Location.Column + 1,
	}
	if v.Location.End != nil {
		e.EndLine = v.Location.End.Row
		e.EndCol = v.Location.End.Column
	}
	return e
}
