package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"
)

// stubLibSource returns minimal Rego stubs sufficient for OPA compilation in tests.
type stubLibSource struct{}

func (s *stubLibSource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return nil, nil
}

func (s *stubLibSource) GetQueryLibrary(_ context.Context, platform string) (source.RegoLibraries, error) {
	switch strings.ToLower(platform) {
	case "terraform":
		return source.RegoLibraries{
			LibraryCode: `package generic.terraform
import rego.v1
resolve_s3_bucket_name(resource, name) := name
`,
			LibraryInputData: "{}",
		}, nil
	case "common":
		return source.RegoLibraries{
			LibraryCode: `package generic.common
import rego.v1
build_search_line(keys, obj) := keys
`,
			LibraryInputData: "{}",
		}, nil
	case "k8s", "kubernetes":
		return source.RegoLibraries{
			LibraryCode: `package generic.k8s
import rego.v1
is_privileged(container) := container.securityContext.privileged
`,
			LibraryInputData: "{}",
		}, nil
	default:
		return source.RegoLibraries{}, fmt.Errorf("no stub library for platform %q", platform)
	}
}

func testLibSource() source.QueriesSource { return &stubLibSource{} }

// validTerraformRego is a minimal DatadogPolicy rule that passes every phase.
const validTerraformRego = `package datadog

import data.generic.terraform as tf_lib

DatadogPolicy contains result if {
	some i, name
	resource := input.document[i].resource.aws_s3_bucket[name]
	resource.acl == "public-read"
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": tf_lib.resolve_s3_bucket_name(resource, name),
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
	}
}
`

// ── helpers ──────────────────────────────────────────────────────────────────

func validate(t *testing.T, platform, rego string) []RegoValidationError {
	t.Helper()
	errs, err := ValidateCustomRegoQuery(context.Background(), platform, rego, testLibSource())
	require.NoError(t, err)
	return errs
}

func errorCodes(errs []RegoValidationError) map[string]bool {
	m := make(map[string]bool, len(errs))
	for _, e := range errs {
		m[e.Code] = true
	}
	return m
}

func firstWithCode(errs []RegoValidationError, code string) (RegoValidationError, bool) {
	for _, e := range errs {
		if e.Code == code {
			return e, true
		}
	}
	return RegoValidationError{}, false
}

func allCodes(errs []RegoValidationError) []string {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, e.Code)
	}
	return out
}

// ── platform mapping ──────────────────────────────────────────────────────────

func TestPlatformTempFileName_CoversAllSupportedPlatforms(t *testing.T) {
	expected := map[string]string{
		"Ansible":        "scan-target.yaml",
		"CICD":           ".github/scan-target.yaml",
		"CloudFormation": scanTargetJSON,
		"Dockerfile":     "Dockerfile",
		"Kubernetes":     "scan-target.yaml",
		"Terraform":      "scan-target.tf",
	}
	require.Len(t, platforms.Supported, len(expected),
		"platforms.Supported changed; update the expected mapping and platformTempFileName in lockstep")
	for _, platform := range platforms.Supported {
		want, ok := expected[platform]
		require.True(t, ok, "no expected temp file name for platform %q; update this test", platform)
		assert.Equal(t, want, platformTempFileName(platform), "platform %q", platform)
	}
}

// ── happy path ────────────────────────────────────────────────────────────────

func TestValidate_ValidRuleProducesNoDiagnostics(t *testing.T) {
	errs := validate(t, "terraform", validTerraformRego)
	assert.Empty(t, allCodes(errs), "a contract-compliant rule must produce no diagnostics")
}

func TestValidate_ValidKubernetesRule(t *testing.T) {
	rego := `package datadog

DatadogPolicy contains result if {
	some i
	doc := input.document[i]
	doc.kind == "Pod"
	result := {
		"documentId": doc.id,
		"resourceType": "Pod",
		"resourceName": doc.metadata.name,
		"searchKey": "metadata.name",
	}
}
`
	errs := validate(t, "kubernetes", rego)
	assert.Empty(t, allCodes(errs))
}

// ── OPA parse errors pass through unchanged ───────────────────────────────────

func TestValidate_ParseErrorUsesOPACode(t *testing.T) {
	errs := validate(t, "terraform", "package datadog\n\nDatadogPolicy contains result if {\n\tresult := {\n")
	e, ok := firstWithCode(errs, "rego_parse_error")
	require.True(t, ok, "expected OPA parse error, got %v", errorCodes(errs))
	assert.Positive(t, e.StartLine, "parse errors must carry a source location")
}

// A module that does not parse cannot be analyzed further, so only OPA's parse
// diagnostics are returned rather than guesses about later phases.
func TestValidate_ParseFailureReturnsOnlyParseErrors(t *testing.T) {
	errs := validate(t, "terraform", "this is not rego at all {{{")
	require.NotEmpty(t, errs)
	for _, e := range errs {
		assert.Equal(t, "rego_parse_error", e.Code,
			"parse failure must not synthesize non-parse diagnostics, got %q", e.Code)
	}
}

// Regression: the previous text-scanning heuristics miscounted parentheses inside
// raw (backtick) strings and reported an unclosed call that did not exist.
func TestValidate_BacktickStringWithParensIsNotFlagged(t *testing.T) {
	rego := "package datadog\n\n" +
		"DatadogPolicy contains result if {\n" +
		"\tsome i\n" +
		"\tregex.match(`^(a|b)$`, \"a\")\n" +
		"\tresult := {\n" +
		"\t\t\"documentId\": input.document[i].id,\n" +
		"\t\t\"resourceType\": \"t\",\n" +
		"\t\t\"resourceName\": \"n\",\n" +
		"\t\t\"searchKey\": \"s\",\n" +
		"\t}\n}\n"
	errs := validate(t, "terraform", rego)
	assert.Empty(t, allCodes(errs), "raw strings containing parens must not produce errors")
}

// ── Datadog contract, enforced through embedded Regal rules ───────────────────

func TestValidate_WrongPackage(t *testing.T) {
	rego := strings.Replace(validTerraformRego, "package datadog", "package mypolicy", 1)
	errs := validate(t, "terraform", rego)

	e, ok := firstWithCode(errs, codeInvalidPackage)
	require.True(t, ok, "expected package-name violation, got %v", errorCodes(errs))
	assert.Contains(t, e.Message, "mypolicy")
}

func TestValidate_WrongRuleName(t *testing.T) {
	rego := strings.Replace(validTerraformRego, "DatadogPolicy contains", "MyPolicy contains", 1)
	errs := validate(t, "terraform", rego)

	_, ok := firstWithCode(errs, codeMissingRule)
	require.True(t, ok, "expected policy-rule violation, got %v", errorCodes(errs))
}

func TestValidate_MissingResultField(t *testing.T) {
	rego := strings.Replace(validTerraformRego, `"resourceName": tf_lib.resolve_s3_bucket_name(resource, name),`, "", 1)
	errs := validate(t, "terraform", rego)

	e, ok := firstWithCode(errs, codeMissingResultField)
	require.True(t, ok, "expected result-fields violation, got %v", errorCodes(errs))
	assert.Contains(t, e.Message, "resourceName")
}

func TestValidate_ReportsEveryMissingResultField(t *testing.T) {
	rego := `package datadog

DatadogPolicy contains result if {
	some i
	result := {"documentId": input.document[i].id}
}
`
	errs := validate(t, "terraform", rego)

	var missing []string
	for _, e := range errs {
		if e.Code == codeMissingResultField {
			missing = append(missing, e.Message)
		}
	}
	require.Len(t, missing, 3, "expected one diagnostic per missing field, got %v", missing)
	assert.Contains(t, strings.Join(missing, "|"), "resourceType")
	assert.Contains(t, strings.Join(missing, "|"), "resourceName")
	assert.Contains(t, strings.Join(missing, "|"), "searchKey")
}

// A wrong package name must not hide the other contract problems: all phases after
// parsing run against the same AST, so one broken convention no longer gates the rest.
func TestValidate_WrongPackageStillReportsFieldErrors(t *testing.T) {
	rego := `package wrong

DatadogPolicy contains result if {
	some i
	result := {"documentId": input.document[i].id}
}
`
	errs := validate(t, "terraform", rego)
	codes := errorCodes(errs)
	assert.True(t, codes[codeInvalidPackage], "expected package-name violation, got %v", codes)
	assert.True(t, codes[codeMissingResultField], "expected result-fields violations, got %v", codes)
}

// ── Author-facing message quality ─────────────────────────────────────────────
//
// OPA and Regal are accurate but terse. These pin the rewrites that turn their output
// into something a rule author can act on; see rego_messages.go.

// Forgetting the library import is the most common authoring mistake, and OPA can only
// describe it as an undefined function on a path the author never wrote.
func TestValidate_MissingLibraryImportNamesTheImportToAdd(t *testing.T) {
	rego := `package datadog

DatadogPolicy contains result if {
	some i, name
	resource := input.document[i].resource.aws_s3_bucket[name]
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": tf_lib.resolve_s3_bucket_name(resource, name),
		"searchKey": "s",
	}
}
`
	errs := validate(t, "terraform", rego)

	e, ok := firstWithCode(errs, codeMissingImport)
	require.True(t, ok, "expected a missing-import diagnostic, got %v", errorCodes(errs))
	assert.Contains(t, e.Message, "import data.generic.terraform as tf_lib")
	assert.Positive(t, e.StartLine)
}

// The suggested import is derived from the libraries actually loaded for the platform,
// not from a table of known aliases, so it works on any platform and echoes back
// whatever alias the author chose.
func TestValidate_MissingImportHintCoversAnyPlatformAndAlias(t *testing.T) {
	for _, tc := range []struct {
		name, platform, alias, call, wantImport string
	}{
		{
			name: "platform library", platform: "k8s", alias: "whatever",
			call: "whatever.is_privileged(c)", wantImport: "import data.generic.k8s as whatever",
		},
		{
			name: "common library", platform: "terraform", alias: "cmn",
			call: "cmn.build_search_line([], {})", wantImport: "import data.generic.common as cmn",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rego := fmt.Sprintf(`package datadog

DatadogPolicy contains result if {
	some i
	c := input.document[i]
	result := {
		"documentId": input.document[i].id,
		"resourceType": "t",
		"resourceName": %s,
		"searchKey": "s",
	}
}
`, tc.call)

			errs := validate(t, tc.platform, rego)
			e, ok := firstWithCode(errs, codeMissingImport)
			require.True(t, ok, "expected a missing-import diagnostic, got %v", errorCodes(errs))
			assert.Contains(t, e.Message, tc.wantImport)
			assert.Contains(t, e.Message, tc.alias, "should echo the author's own alias")
		})
	}
}

// A call to something no library defines is a genuine typo, not a forgotten import.
func TestValidate_UnknownFunctionIsNotReportedAsMissingImport(t *testing.T) {
	rego := `package datadog

DatadogPolicy contains result if {
	some i
	result := {
		"documentId": input.document[i].id,
		"resourceType": "t",
		"resourceName": nonsense.not_a_library_helper(1),
		"searchKey": "s",
	}
}
`
	errs := validate(t, "terraform", rego)
	_, ok := firstWithCode(errs, codeMissingImport)
	assert.False(t, ok, "should not invent an import for an unknown function, got %v", errorCodes(errs))
	assert.NotEmpty(t, errs, "but it must still be reported as an error")
}

// OPA resolves aliases before reporting, so an undefined library function comes back as
// a fully qualified path. Authors search for what they typed.
func TestValidate_TypeErrorsUseTheAuthorsAlias(t *testing.T) {
	rego := strings.Replace(validTerraformRego, "resolve_s3_bucket_name", "no_such_helper", 1)
	errs := validate(t, "terraform", rego)

	e, ok := firstWithCode(errs, "rego_type_error")
	require.True(t, ok, "expected a type error, got %v", errorCodes(errs))
	assert.Contains(t, e.Message, "tf_lib.no_such_helper")
	assert.NotContains(t, e.Message, "data.generic.terraform")
}

// "var x is unsafe" is Rego's vocabulary, not the author's, and OPA reports it against
// the whole expression — which underlines the entire line in an editor.
func TestValidate_UnsafeVarNamesTheVariableAndPointsAtIt(t *testing.T) {
	rego := `package datadog

DatadogPolicy contains result if {
	some i
	result := {
		"documentId": input.document[i].id,
		"resourceType": buckett.kind,
		"resourceName": "n",
		"searchKey": "s",
	}
}
`
	errs := validate(t, "terraform", rego)

	e, ok := firstWithCode(errs, "rego_unsafe_var_error")
	require.True(t, ok, "expected an unsafe-var diagnostic, got %v", errorCodes(errs))
	assert.Contains(t, e.Message, `undefined variable "buckett"`)
	assert.Equal(t, 7, e.StartLine, "should point at the variable, not the rule body")
	assert.Greater(t, e.EndCol, e.StartCol, "should span the variable, not the whole line")
}

// "result is unsafe" is always a consequence of an earlier error in the same body;
// reporting it doubles the diagnostics without adding information.
func TestValidate_CascadingResultErrorIsSuppressed(t *testing.T) {
	rego := `package datadog

DatadogPolicy contains result if {
	some i
	result := {
		"documentId": input.document[i].id,
		"resourceType": undefined_thing,
		"resourceName": "n",
		"searchKey": "s",
	}
}
`
	errs := validate(t, "terraform", rego)

	for _, e := range errs {
		assert.NotContains(t, e.Message, `variable "result"`,
			"the cascading result error should be suppressed: %+v", e)
	}
}

func TestValidate_ParseErrorsExplainTheLikelyCause(t *testing.T) {
	for name, tc := range map[string]struct {
		rego       string
		want       string
		wantLine   int
		wantNotCol int // column that must not be highlighted (OPA mis-fire)
	}{
		"unclosed brace": {
			rego: "package datadog\n\nDatadogPolicy contains result if {\n\tresult := {\n",
			want: "unclosed",
		},
		"missing separator": {
			rego: "package datadog\n\nDatadogPolicy contains result if {\n\tresult := {\n" +
				"\t\t\"documentId\": \"a\"\n\t\t\"searchKey\": \"b\",\n\t}\n}\n",
			want:     "expected ',' after field \"documentId\"",
			wantLine: 5,
		},
		"missing comma after resourceName": {
			rego: strings.Replace(validTerraformRego,
				`"resourceName": tf_lib.resolve_s3_bucket_name(resource, name),`,
				`"resourceName": tf_lib.resolve_s3_bucket_name(resource, name)`, 1),
			want:       "expected ',' after field \"resourceName\"",
			wantLine:   12,
			wantNotCol: 17, // OPA wrongly highlights `input` on the documentId line
		},
	} {
		t.Run(name, func(t *testing.T) {
			errs := validate(t, "terraform", tc.rego)
			require.NotEmpty(t, errs)
			assert.Contains(t, errs[0].Message, tc.want)
			if tc.wantLine > 0 {
				assert.Equal(t, tc.wantLine, errs[0].StartLine)
			}
			if tc.wantNotCol > 0 {
				assert.NotEqual(t, tc.wantNotCol, errs[0].StartCol,
					"should not highlight OPA's wrong token")
			}
		})
	}
}

func TestValidate_ParenInsideStringDoesNotTriggerUnclosedCall(t *testing.T) {
	rego := `package datadog

DatadogPolicy contains result if {
	some i, name
	result := {
		"documentId": input.document[i].id
		"searchKey": sprintf("prefix (%s", [name]),
	}
}
`
	errs := validate(t, "terraform", rego)
	require.NotEmpty(t, errs)
	for _, e := range errs {
		assert.NotContains(t, e.Message, "expected ')' to close function call",
			"paren inside a string literal must not trigger unclosed-call recovery")
	}
}

func TestValidate_TypeErrorAliasRewritePrefersLongestPath(t *testing.T) {
	rego := `package datadog

import data.generic as generic_alias
import data.generic.terraform as tf_alias

DatadogPolicy contains result if {
	some i
	result := {
		"documentId": input.document[i].id,
		"resourceType": "t",
		"resourceName": tf_alias.no_such_helper(),
		"searchKey": "s",
	}
}
`
	errs := validate(t, "terraform", rego)
	e, ok := firstWithCode(errs, "rego_type_error")
	require.True(t, ok, "got %v", errorCodes(errs))
	assert.Contains(t, e.Message, "tf_alias.no_such_helper")
	assert.NotContains(t, e.Message, "generic_alias.terraform")
}

// Regal detects sprintf arity mismatches but only reports "Mismatch in `sprintf`
// arguments count"; an embedded rule replaces it with the actual counts.
func TestValidate_SprintfArityMismatchIsReported(t *testing.T) {
	rego := `package datadog

DatadogPolicy contains result if {
	some i, name
	result := {
		"documentId": input.document[i].id,
		"resourceType": "t",
		"resourceName": name,
		"searchKey": sprintf("bucket[%s].%s", [name]),
	}
}
`
	errs := validate(t, "terraform", rego)
	e, ok := firstWithCode(errs, codeSprintfArity)
	require.True(t, ok, "expected the sprintf rule to fire, got %v", errorCodes(errs))
	assert.Contains(t, e.Message, "2 verb(s) but 1 argument(s)")
}

// "%%" is a literal percent, not a verb.
func TestValidate_SprintfEscapedPercentIsNotAVerb(t *testing.T) {
	rego := `package datadog

DatadogPolicy contains result if {
	some i, name
	result := {
		"documentId": input.document[i].id,
		"resourceType": "t",
		"resourceName": name,
		"searchKey": sprintf("100%% of bucket[%s]", [name]),
	}
}
`
	errs := validate(t, "terraform", rego)
	_, ok := firstWithCode(errs, codeSprintfArity)
	assert.False(t, ok, "escaped percent must not count as a verb, got %v", errorCodes(errs))
}

// Every diagnostic blocks evaluation, so Regal must only report the contract category
// and the curated bug rules — not advisory checks like constant-condition.
func TestValidate_OnlyCuratedRegalRulesAreReported(t *testing.T) {
	rego := `package datadog

DatadogPolicy contains result if {
	some i
	x := 1
	x == 1
	result := {
		"documentId": input.document[i].id,
		"resourceType": "t",
		"resourceName": "n",
		"searchKey": "s",
	}
}
`
	allowed := make(map[string]bool, len(enabledRegalBugRules))
	for _, rule := range enabledRegalBugRules {
		allowed["bugs/"+rule] = true
	}

	for _, errs := range [][]RegoValidationError{
		validate(t, "terraform", rego),
		validate(t, "terraform", validTerraformRego),
	} {
		for _, e := range errs {
			category, rule, isRegal := strings.Cut(e.Code, "/")
			if !isRegal {
				continue
			}
			switch category {
			case "datadog":
				continue
			case "bugs":
				assert.True(t, allowed["bugs/"+rule], "%s is not a curated bug rule", e.Code)
			default:
				assert.Fail(t, "unexpected Regal category %q", category)
			}
		}
	}
}

// Advisory bug rules such as constant-condition must not block evaluation.
func TestValidate_ConstantConditionDoesNotBlockEvaluation(t *testing.T) {
	rego := `package datadog

DatadogPolicy contains result if {
	some i
	1 == 1
	result := {
		"documentId": input.document[i].id,
		"resourceType": "t",
		"resourceName": "n",
		"searchKey": "s",
	}
}
`
	assert.Empty(t, allCodes(validate(t, "terraform", rego)))
}

func TestValidateRegoStructure_SkipsLibraryCompilation(t *testing.T) {
	rego := strings.Replace(validTerraformRego, `"resourceName": tf_lib.resolve_s3_bucket_name(resource, name),`, "", 1)
	errs := ValidateRegoStructure(rego)
	codes := errorCodes(errs)
	assert.False(t, codes[codeMissingImport], "ValidateRegoStructure must not load libraries")
	assert.True(t, codes[codeMissingResultField])

	assert.Empty(t, allCodes(ValidateRegoStructure(validTerraformRego)))
}

// A rule that is merely unidiomatic must still be runnable.
func TestValidate_UnidiomaticButWorkingRuleIsAccepted(t *testing.T) {
	// Uses implicit output vars and bare iteration, which Regal's idiomatic and style
	// categories both flag, but which is the established style across the rule corpus.
	rego := `package datadog

DatadogPolicy contains result if {
	resource := input.document[i].resource.aws_s3_bucket[name]
	resource.acl == "public-read"
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
	}
}
`
	assert.Empty(t, allCodes(validate(t, "terraform", rego)))
}

// ── OPA compile phase ─────────────────────────────────────────────────────────

func TestValidate_UndefinedLibraryFunctionIsReportedByOPA(t *testing.T) {
	rego := strings.Replace(
		validTerraformRego,
		"tf_lib.resolve_s3_bucket_name(resource, name)",
		"tf_lib.does_not_exist(resource, name)",
		1,
	)
	errs := validate(t, "terraform", rego)
	assert.NotEmpty(t, allCodes(errs), "an undefined library function must block evaluation")
}

func TestValidate_UnsafeBuiltinIsRejected(t *testing.T) {
	rego := `package datadog

DatadogPolicy contains result if {
	some i
	resp := http.send({"method": "get", "url": "https://example.com"})
	result := {
		"documentId": input.document[i].id,
		"resourceType": "t",
		"resourceName": "n",
		"searchKey": resp.status_code,
	}
}
`
	errs := validate(t, "terraform", rego)
	assert.NotEmpty(t, allCodes(errs), "http.send must be rejected")
}

// Any valid alias must work; the scanner does not maintain a table of known aliases.
func TestValidate_ArbitraryImportAliasIsAccepted(t *testing.T) {
	rego := `package datadog

import data.generic.terraform as whatever_name

DatadogPolicy contains result if {
	some i, name
	resource := input.document[i].resource.aws_s3_bucket[name]
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": whatever_name.resolve_s3_bucket_name(resource, name),
		"searchKey": "acl",
	}
}
`
	errs := validate(t, "terraform", rego)
	assert.Empty(t, allCodes(errs))
}

func TestValidate_UnsupportedPlatformReturnsError(t *testing.T) {
	_, err := ValidateCustomRegoQuery(context.Background(), "not-a-platform", validTerraformRego, testLibSource())
	require.Error(t, err, "an unknown platform has no library and must surface an error")
}

// ── ordering and deduplication ────────────────────────────────────────────────

func TestFinalizeDiagnostics_DedupesAndSortsByPosition(t *testing.T) {
	got := finalizeDiagnostics([]RegoValidationError{
		{Code: "b", Message: "later", StartLine: 12, StartCol: 3},
		{Code: "a", Message: "unlocated"},
		{Code: "c", Message: "earlier", StartLine: 4, StartCol: 9},
		{Code: "c", Message: "earlier", StartLine: 4, StartCol: 9},
		{Code: "d", Message: "same line", StartLine: 4, StartCol: 2},
	})

	codes := make([]string, 0, len(got))
	for _, e := range got {
		codes = append(codes, e.Code)
	}
	assert.Equal(t, []string{"d", "c", "b", "a"}, codes,
		"diagnostics sort by line then column, with unlocated entries last and duplicates removed")
}

// The prepared Regal linter is shared across calls, so validation must stay correct
// and race-free when requests are handled concurrently.
func TestValidate_ConcurrentUseIsSafe(t *testing.T) {
	inputs := []string{
		validTerraformRego,
		"package wrong\n\nDatadogPolicy contains result if { some i; result := {\"documentId\": input.document[i].id} }\n",
		"package datadog\n\nfoo := 1\n",
	}

	var wg sync.WaitGroup
	results := make([][]string, len(inputs)*4)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs, err := ValidateCustomRegoQuery(
				context.Background(), "terraform", inputs[i%len(inputs)], testLibSource(),
			)
			assert.NoError(t, err)
			results[i] = allCodes(errs)
		}()
	}
	wg.Wait()

	// Same input must always yield the same verdict, whichever goroutine ran it.
	for i := range results {
		assert.Equal(t, results[i%len(inputs)], results[i], "result %d diverged for the same input", i)
	}
}

// ── RunCustomRegoQuery integration ────────────────────────────────────────────

const cloudFormationJSONRego = `
package datadog

import rego.v1

DatadogPolicy contains result if {
	doc := input.document[i]
	doc.Resources[name].Type == "AWS::S3::Bucket"
	doc.Resources[name].Properties.AccessControl == "PublicRead"
	result := {
		"documentId":   doc.id,
		"resourceType": "AWS::S3::Bucket",
		"resourceName": name,
		"searchKey":    sprintf("Resources[%s].Properties.AccessControl", [name]),
	}
}
`

func TestRunCustomRegoQuery_CloudFormationJSON(t *testing.T) {
	fixture := filepath.FromSlash("../../test/fixtures/tfplan_flag_test/cloudformation.json")
	content, err := os.ReadFile(fixture)
	require.NoError(t, err)

	vulns, failedQueries, err := RunCustomRegoQuery(
		context.Background(),
		"cloudformation",
		cloudFormationJSONRego,
		content,
	)
	require.NoError(t, err)
	require.Empty(t, failedQueries, "custom rule should compile and run")
	require.NotEmpty(t, vulns, "CloudFormation JSON should be classified and scanned via custom evaluate")
}
