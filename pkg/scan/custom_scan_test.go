package scan

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/open-policy-agent/regal/pkg/linter"
	"github.com/open-policy-agent/regal/pkg/report"
	"github.com/open-policy-agent/regal/pkg/rules"
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
nested(block, name) := []
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

func TestCustomTerraformModuleFindingKeepsSourceLocation(t *testing.T) {
	const sample = `module "example" {
  source = "./missing"
  acl = "public-read"
}`
	const rule = `package datadog
DatadogPolicy contains result if {
  some doc in input.document
  doc.module.example.acl == "public-read"
  result := {
    "documentId": doc.id,
    "resourceType": "module",
    "resourceName": "example",
    "searchKey": "module[example].acl",
  }
}`
	run := func() model.Vulnerability {
		t.Helper()
		findings, failures, err := runCustomRegoQuery(t.Context(), "Terraform", rule, []byte(sample), testLibSource())
		require.NoError(t, err)
		require.Empty(t, failures)
		require.Len(t, findings, 1)
		finding := findings[0]
		require.True(t, filepath.IsAbs(finding.FileName))
		require.Equal(t, "scan-target.tf", filepath.Base(finding.FileName))
		require.Equal(t, "module[example].acl", finding.SearchKey)
		require.Equal(t, 3, finding.Line)
		require.Nil(t, finding.ModuleAttribution)
		return finding
	}
	first, second := run(), run()
	require.NotEqual(t, first.FileName, second.FileName)
	require.NotEmpty(t, first.FileID)
	require.Equal(t, first.FileID, second.FileID)
}

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

func validateWithSchemaIndex(t *testing.T, rego, schemaIndex string) []RegoValidationError {
	t.Helper()
	result := lintWithSchemaIndex(t, rego, schemaIndex)
	diagnostics := make([]RegoValidationError, 0, len(result.Violations))
	for i := range result.Violations {
		if result.Violations[i].Level == "notice" {
			continue
		}
		diagnostics = append(diagnostics, regoValidationErrorFromViolation(&result.Violations[i]))
	}
	return finalizeDiagnostics(diagnostics)
}

func lintWithSchemaIndex(t *testing.T, rego, schemaIndex string) report.Report {
	t.Helper()
	linterInstance, err := linter.NewLinter().
		WithCustomRulesFromFS(regalRulesFS, "regalrules").
		WithCustomRulesFromFS(fstest.MapFS{
			"schema_index.rego": &fstest.MapFile{Data: []byte(schemaIndex)},
		}, ".").
		WithDisableAll(true).
		WithEnabledCategories(enabledRegalCategories...).
		WithEnabledRules(enabledRegalBugRules...).
		WithDisabledRules(regalIgnoredRules...).
		Prepare(context.Background())
	require.NoError(t, err)
	input, err := rules.InputFromText(customRuleFileName, rego)
	require.NoError(t, err)
	result, err := linterInstance.WithInputModules(&input).Lint(context.Background())
	require.NoError(t, err)
	return result
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
		"DockerCompose":  "compose.yaml",
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

func TestValidate_ContractV2RulesAndAuthoringGuardrails(t *testing.T) {
	validV2 := `package datadog

import rego.v1

import data.datadog.iac
import data.datadog.output as dd_output

results contains result if {
	some bucket in input.resources.aws_s3_bucket
	iac.is_empty(bucket, ["versioning"])
	iac.no_related(bucket, "aws_s3_bucket_versioning", "bucket")
	result := dd_output.format(bucket, {"path": []})
}
`
	assert.Empty(t, allCodes(validate(t, "terraform", validV2)), "valid Contract v2 rule must pass validation")

	// Contract v2 rule with decoupled optional remediate(resource, finding) validates cleanly.
	validWithRemediate := `package datadog

import rego.v1

import data.datadog.iac
import data.datadog.output as dd_output

results contains result if {
	some b in input.resources.aws_s3_bucket
	iac.equals(b, ["acl"], "public-read")
	result := dd_output.format(b, {"path": ["acl"]})
}

remediate(b, _) := {
	"remediation": sprintf("restrict %s", [iac.get(b, ["bucket"])]),
	"remediationType": "replacement",
}
`
	assert.Empty(t, allCodes(validate(t, "terraform", validWithRemediate)))

	badReservedName := `package datadog

import rego.v1

output := true
results contains result if {
	some r in input.resources.aws_s3_bucket
	result := {"_dd_id": r.id, "path": []}
}
`
	reservedErr, ok := firstWithCode(validate(t, "terraform", badReservedName), "contract/reserved-name")
	require.True(t, ok)
	assert.Contains(t, reservedErr.Message, "output")

	badInlineObject := `package datadog

import rego.v1

results contains {"_dd_id": r.id} if {
	some r in input.resources.aws_s3_bucket
}
`
	assert.Contains(t, allCodes(validate(t, "terraform", badInlineObject)), "contract/bound-finding")

	badInternalField := `package datadog

import rego.v1

import data.datadog.output as dd_output

results contains result if {
	some r in input.resources.aws_s3_bucket
	r.attributes.x["$unknown"]
	result := dd_output.format(r, {})
}
`
	assert.Contains(t, allCodes(validate(t, "terraform", badInternalField)), "contract/no-internal-fields")

	badNonSetResults := `package datadog

import rego.v1

import data.datadog.output as dd_output

results := dd_output.format(input.resources.aws_s3_bucket[0], {})
`
	assert.Contains(t, allCodes(validate(t, "terraform", badNonSetResults)), codeMissingRule)

	assert.Contains(t, allCodes(validate(t, "k8s", validV2)), "contract/unsupported-platform")

	badLegacyInput := `package datadog

import rego.v1

import data.datadog.output as dd_output

results contains result if {
	some doc in input.document
	result := dd_output.format(doc, {})
}
`
	assert.Contains(t, allCodes(validate(t, "terraform", badLegacyInput)), "contract/no-legacy-document")

	badMixedEntry := `package datadog

import rego.v1

import data.datadog.output as dd_output

DatadogPolicy contains result if {
	some doc in input.document
	result := {"documentId": doc.id, "resourceType": "t", "resourceName": "n", "searchKey": "k"}
}

results contains result if {
	some r in input.resources.aws_s3_bucket
	result := dd_output.format(r, {})
}
`
	assert.Contains(t, allCodes(validate(t, "terraform", badMixedEntry)), codeMissingRule)

	// Legacy rule importing Contract v2 libraries must fail validation (mirrors scan-time compilation).
	badLegacyUsingV2Lib := `package datadog

import rego.v1

import data.datadog.iac

DatadogPolicy contains result if {
	some doc in input.document
	iac.is_true(doc, ["x"])
	result := {"documentId": doc.id, "resourceType": "t", "resourceName": "n", "searchKey": "k"}
}
`
	assert.NotEmpty(t, validate(t, "terraform", badLegacyUsingV2Lib))

	badImportLegacyDoc := `package datadog

import rego.v1

import data.datadog.output as dd_output
import input.document

results contains result if {
	some d in document
	result := dd_output.format(d, {})
}
`
	assert.Contains(t, allCodes(validate(t, "terraform", badImportLegacyDoc)), "contract/no-legacy-document")

	// Legitimate tag literal starting with _dd_ must be allowed.
	validTagLiteral := `package datadog

import rego.v1

import data.datadog.iac
import data.datadog.output as dd_output

results contains result if {
	some b in input.resources.aws_s3_bucket
	iac.equals(b, ["tags", "_dd_managed"], "true")
	result := dd_output.format(b, {})
}
`
	assert.Empty(t, validate(t, "terraform", validTagLiteral))
}

func TestValidate_ContractV2SchemaPath(t *testing.T) {
	const schema = `package custom.regal.rules.contract.schemadata
index := {
	"aws_s3_bucket": {
		"acl": true,
		"logging": {"target_bucket": true, "enabled": true},
		"tags": {"*": true},
	},
	"data.aws_ami": {"id": true},
	"aws_iam_policy": {"policy": true},
	"aws_s3_bucket_versioning": {"bucket": true},
}
`
	makeRule := func(body string) string {
		return `package datadog

import rego.v1
import data.datadog.iac
import data.datadog.output as dd_output
import data.datadog.terraform as tf

results contains result if {
	some bucket in input.resources.aws_s3_bucket
` + body + `
	result := dd_output.format(bucket, {"path": []})
}
`
	}
	for _, tc := range []struct {
		name      string
		body      string
		wantCode  string
		wantNoErr bool
		wantCount int
	}{
		{
			name:     "unknown resource type",
			body:     "some unknown in input.resources.aws_s3_buket\nresult := dd_output.format(unknown, {})",
			wantCode: "contract/schema-path",
		},
		{
			name:     "unknown attribute",
			body:     `iac.equals(bucket, ["logging", "target_buket"], "logs")`,
			wantCode: "contract/schema-path",
		},
		{
			name:     "unknown string path",
			body:     `iac.equals(bucket, "target_buket", "logs")`,
			wantCode: "contract/schema-path",
		},
		{
			name: "multiple unknown paths",
			body: `iac.equals(bucket, ["not_a_field_one"], "x")
iac.equals(bucket, ["not_a_field_two"], "y")`,
			wantCode:  "contract/schema-path",
			wantCount: 2,
		},
		{
			name: "multiple unknown data source types",
			body: `some first in input.resources.data.aws_unknown_data_source_one
some second in input.resources.data.aws_unknown_data_source_two`,
			wantCode:  "contract/schema-path",
			wantCount: 2,
		},
		{
			name:      "valid string path",
			body:      `iac.equals(bucket, "acl", "private")`,
			wantNoErr: true,
		},
		{
			name:      "nested attribute",
			body:      `iac.equals(bucket, ["logging", "target_bucket"], "logs")`,
			wantNoErr: true,
		},
		{
			name:      "map element wildcard",
			body:      `iac.equals(bucket, ["tags", "Environment"], "prod")`,
			wantNoErr: true,
		},
		{
			name:      "dynamic step leaves later steps unchecked",
			body:      `iac.equals(bucket, ["logging", input.dynamic_step, "target_buket"], "logs")`,
			wantNoErr: true,
		},
		{
			name: "block view extends the prefix",
			body: `some view in iac.blocks(bucket, "logging")
 iac.is_true(view, ["enabled"])`,
			wantNoErr: true,
		},
		{
			name: "value view extends the prefix",
			body: `view := tf.value_view(bucket, ["logging"])
iac.is_true(view, ["enabled"])`,
			wantNoErr: true,
		},
		{
			name:      "related path checks the related type",
			body:      `iac.related(bucket, "aws_iam_policy", "policy")`,
			wantNoErr: true,
		},
		{
			name:      "no_related path checks the related type",
			body:      `iac.no_related(bucket, "aws_s3_bucket_versioning", "bucket")`,
			wantNoErr: true,
		},
		{
			name:     "no_related misspelled related path",
			body:     `iac.no_related(bucket, "aws_s3_bucket_versioning", "buket")`,
			wantCode: "contract/schema-path",
		},
		{
			name:      "related_complete path checks the related type",
			body:      `iac.related_complete(bucket, "aws_s3_bucket_versioning", "bucket")`,
			wantNoErr: true,
		},
		{
			name:     "related_complete misspelled related path",
			body:     `iac.related_complete(bucket, "aws_s3_bucket_versioning", "buket")`,
			wantCode: "contract/schema-path",
		},
		{
			name:     "unknown related type",
			body:     `iac.related(bucket, "aws_iam_policty", "policy")`,
			wantCode: "contract/schema-path",
		},
		{
			name:     "no_related unknown related type",
			body:     `iac.no_related(bucket, "aws_s3_bucket_versioning_typo", "bucket")`,
			wantCode: "contract/schema-path",
		},
		{
			name:     "related_complete unknown related type",
			body:     `iac.related_complete(bucket, "aws_s3_bucket_versioning_typo", "bucket")`,
			wantCode: "contract/schema-path",
		},
		{
			name: "data source type is indexed separately",
			body: `some ami in input.resources.data.aws_ami
iac.equals(bucket, ["acl"], "private")`,
			wantNoErr: true,
		},
		{
			name: "bad path is suppressed with a reason",
			body: `# regal ignore:schema-path # reason: provider-version compatibility
 iac.equals(bucket, ["logging", "old_name"], "logs")`,
			wantNoErr: true,
		},
		{
			name: "suppression requires a reason",
			body: `# regal ignore:schema-path
 iac.equals(bucket, ["logging", "old_name"], "logs")`,
			wantCode: "contract/schema-path",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diagnostics := validateWithSchemaIndex(t, makeRule(tc.body), schema)
			codes := allCodes(diagnostics)
			if tc.wantNoErr {
				assert.NotContains(t, codes, "contract/schema-path", "%v", diagnostics)
				return
			}
			if tc.wantCount > 0 {
				assert.Equal(t, []string{"contract/schema-path", "contract/schema-path"}, codes, "%v", diagnostics)
				return
			}
			assert.Contains(t, codes, tc.wantCode, "%v", diagnostics)
		})
	}

	twoUnknownTypes := validateWithSchemaIndex(t, makeRule(`some first in input.resources.aws_not_a_type
some second in input.resources.aws_not_a_type2`), schema)
	assert.Equal(t, []string{"contract/schema-path", "contract/schema-path"}, allCodes(twoUnknownTypes), "%v", twoUnknownTypes)

	noIndex := validate(t, "terraform", makeRule(`iac.equals(bucket, ["logging", "typo"], "x")`))
	assert.NotContains(t, allCodes(noIndex), "contract/schema-path", "schema-path must be a no-op without generated schema data")

	legacyRule := func(path string) string {
		return `package datadog

import rego.v1
import data.datadog.iac

DatadogPolicy contains result if {
	some resource in input.resources.aws_s3_bucket
	iac.equals(resource, ` + path + `, "value")
	result := {"resourceType": "aws_s3_bucket"}
}
`
	}
	legacyValid := validateWithSchemaIndex(t, legacyRule(`["logging", "target_bucket"]`), schema)
	assert.NotContains(t, allCodes(legacyValid), "contract/schema-path", "%v", legacyValid)
	legacyInvalid := validateWithSchemaIndex(t, legacyRule(`["logging", "missing"]`), schema)
	assert.Contains(t, allCodes(legacyInvalid), "contract/schema-path", "%v", legacyInvalid)
}

func TestSchemaPathReportsCheckedAndUncheckedCoverage(t *testing.T) {
	const schema = `package custom.regal.rules.contract.schemadata
index := {"aws_s3_bucket": {"acl": true, "logging": {"target_bucket": true}}}
`
	body := `iac.equals(bucket, ["acl"], "private")
iac.equals(bucket, ["logging", input.dynamic_step, "target_bucket"], "logs")
iac.equals(input.uninferred_resource, ["acl"], "private")`
	result := lintWithSchemaIndex(t, `package datadog
import rego.v1
import data.datadog.iac
results contains result if {
    some bucket in input.resources.aws_s3_bucket
`+body+`
    result := {"resourceType": "aws_s3_bucket"}
}
`, schema)
	coverage := []report.Violation{}
	for _, violation := range result.Violations {
		if violation.Title == "schema-path-coverage" {
			coverage = append(coverage, violation)
		}
	}
	require.Len(t, coverage, 1)
	assert.Equal(t, "notice", coverage[0].Level)
	assert.Contains(t, coverage[0].Description, "checked=1 unchecked=2 unchecked_percent=67")
}

func TestValidate_ContractV2DoesNotReuseCompactedNestedIndices(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		legacy  bool
		wantBad bool
	}{
		{
			name: "path index",
			body: `some i, spec in iac.blocks(resource, "spec")
path := ["spec", i, "enabled"]
iac.is_true(resource, path)
result := dd_output.format(resource, {"path": path})`,
			wantBad: true,
		},
		{
			name: "helper argument",
			body: `some i, spec in iac.blocks(resource, "spec")
iac.is_true(resource, ["spec", i, "enabled"])
result := dd_output.format(resource, {"path": iac.path_of(spec, ["enabled"])})`,
			wantBad: true,
		},
		{
			name: "single alias of compacted blocks",
			body: `blocks := iac.blocks(resource, "spec")
some i, spec in blocks
iac.is_true(resource, ["spec", i, "enabled"])
result := dd_output.format(resource, {"path": iac.path_of(spec, ["enabled"])})`,
			wantBad: true,
		},
		{
			name: "reindex another view through generic Terraform alias",
			body: `some i, spec in iac.blocks(resource, "spec")
computed := tf.nested(resource, "spec")[i]
result := dd_output.format(resource, {"path": iac.path_of(computed, [])})`,
			wantBad: true,
		},
		{
			name: "unused index and returned block path",
			body: `some i, spec in iac.blocks(resource, "spec")
iac.is_true(spec, ["enabled"])
result := dd_output.format(resource, {"path": iac.path_of(spec, ["enabled"])})`,
		},
		{
			name: "index reused inside its comprehension",
			body: `paths := [p | some i, spec in iac.blocks(resource, "spec"); p := ["spec", i, "enabled"]]
some path in paths
result := dd_output.format(resource, {"path": path})`,
			wantBad: true,
		},
		{
			name: "index reused in comprehension head",
			body: `paths := [["spec", i, "enabled"] | some i, spec in iac.blocks(resource, "spec")]
some path in paths
result := dd_output.format(resource, {"path": path})`,
			wantBad: true,
		},
		{
			name: "outer index reused in nested comprehension",
			body: `some i, spec in iac.blocks(resource, "spec")
paths := [p | some k in ["enabled"]; p := ["spec", i, k]]
result := dd_output.format(resource, {"path": iac.path_of(spec, ["enabled"]), "paths": paths})`,
			wantBad: true,
		},
		{
			name: "outer index reused in every body",
			body: `some i, spec in iac.blocks(resource, "spec")
every k in ["enabled"] { iac.is_true(resource, ["spec", i, k]) }
result := dd_output.format(resource, {"path": iac.path_of(spec, ["enabled"])})`,
			wantBad: true,
		},
		{
			name: "independent comprehensions with the same index name",
			body: `a := [b | some i, b in iac.blocks(resource, "a")]
c := [b | some i, b in iac.blocks(resource, "c")]
count(a) > count(c)
result := dd_output.format(resource, {})`,
		},
		{
			name: "comprehension index and unrelated outer index",
			body: `a := [b | some i, b in iac.blocks(resource, "a")]
some i, x in input.resources.example_resource
x == resource
count(a) > i
result := dd_output.format(resource, {})`,
		},
		{
			name: "nested comprehension shadows compacted index",
			body: `some i, spec in iac.blocks(resource, "spec")
names := [n | some i, n in ["x", "y"]; i > 0]
iac.is_true(spec, ["enabled"])
result := dd_output.format(resource, {"path": iac.path_of(spec, ["enabled"]), "names": names})`,
		},
		{
			name: "every shadows compacted index",
			body: `some i, spec in iac.blocks(resource, "spec")
every i, n in ["x", "y"] { i < count(n) }
result := dd_output.format(resource, {"path": iac.path_of(spec, ["enabled"])})`,
		},
		{
			name: "outer alias reused in comprehension",
			body: `blocks := iac.blocks(resource, "spec")
paths := [["spec", i, "enabled"] | some i, spec in blocks]
some path in paths
result := dd_output.format(resource, {"path": path})`,
			wantBad: true,
		},
		{
			name: "comprehension alias reused in comprehension",
			body: `paths := [["spec", i, "enabled"] | blocks := iac.blocks(resource, "spec"); some i, spec in blocks]
some path in paths
result := dd_output.format(resource, {"path": path})`,
			wantBad: true,
		},
		{
			name: "comprehension alias name reused for another collection in a sibling comprehension",
			body: `a := [x | blocks := iac.blocks(resource, "a"); some x in blocks]
c := [y | blocks := input.resources.example_resource; some i, y in blocks; count(a) > i]
result := dd_output.format(resource, {"c": c})`,
		},
		{
			name: "comprehension alias name reused for another collection outside",
			body: `a := [x | blocks := iac.blocks(resource, "a"); some x in blocks]
blocks := input.resources.example_resource
some i, other in blocks
count(a) > i
result := dd_output.format(other, {})`,
		},
		{
			name: "comprehension shadows outer alias name",
			body: `blocks := iac.blocks(resource, "a")
c := [y | blocks := input.resources.example_resource; some i, y in blocks; i > 0]
result := dd_output.format(resource, {"c": c, "n": count(blocks)})`,
		},
		{
			name:   "legacy rule is outside the Contract v2 guard",
			legacy: true,
			body: `DatadogPolicy contains result if {
	some doc in input.document
	some i, spec in tf.nested(doc.resource.example_resource, "spec")
	result := {"documentId": doc.id, "resourceType": "example_resource", "resourceName": "example", "searchKey": i}
}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rego string
			if tc.legacy {
				rego = `package datadog

import rego.v1

import data.generic.terraform as tf

` + tc.body + `
`
			} else {
				rego = `package datadog

import rego.v1

import data.datadog.iac
import data.datadog.output as dd_output
import data.generic.terraform as tf

results contains result if {
	resource := input.resources.example_resource[0]
	` + strings.ReplaceAll(tc.body, "\n", "\n\t") + `
}
`
			}

			errs := validate(t, "terraform", rego)
			if tc.wantBad {
				assert.Contains(t, allCodes(errs), "contract/no-compacted-index-reuse")
			} else {
				assert.NotContains(t, allCodes(errs), "contract/no-compacted-index-reuse")
			}
		})
	}
}
