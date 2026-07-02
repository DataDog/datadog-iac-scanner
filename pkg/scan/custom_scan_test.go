package scan

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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
			LibraryCode:      "package generic.k8s\nimport rego.v1\n",
			LibraryInputData: "{}",
		}, nil
	default:
		return source.RegoLibraries{}, fmt.Errorf("no stub library for platform %q", platform)
	}
}

func testLibSource() source.QueriesSource { return &stubLibSource{} }

// validTerraformRego is a minimal DatadogPolicy rule that passes all validation phases.
const validTerraformRego = `
package datadog

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

DatadogPolicy contains result if {
	resource := input.document[i].resource.aws_s3_bucket[name]
	resource.acl == "public-read"
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": tf_lib.resolve_s3_bucket_name(resource, name),
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'acl' should be 'private'",
		"keyActualValue": sprintf("'acl' is '%s'", [resource.acl]),
		"searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", name, "acl"], []),
	}
}
`

// ── helpers ──────────────────────────────────────────────────────────────────

func errorCodes(errs []RegoValidationError) map[string]bool {
	m := make(map[string]bool, len(errs))
	for _, e := range errs {
		m[e.Code] = true
	}
	return m
}

func errorLines(errs []RegoValidationError) []int {
	lines := make([]int, 0, len(errs))
	for _, e := range errs {
		lines = append(lines, e.StartLine)
	}
	return lines
}

func firstWithCode(errs []RegoValidationError, code string) (RegoValidationError, bool) {
	for _, e := range errs {
		if e.Code == code {
			return e, true
		}
	}
	return RegoValidationError{}, false
}

// ── unit tests ────────────────────────────────────────────────────────────────

func TestParseImportAliases(t *testing.T) {
	src := `
import data.generic.terraform as tf_lib
import data.generic.common as common_lib
import data.generic.kubernetes as k8s_lib
`
	got := parseImportAliases(src)
	assert.Equal(t, "data.generic.terraform", got["tf_lib"])
	assert.Equal(t, "data.generic.common", got["common_lib"])
	assert.Equal(t, "data.generic.kubernetes", got["k8s_lib"])
	assert.Len(t, got, 3, "only 'as'-aliased imports should be collected")
}

func TestParseImportAliases_NoAlias(t *testing.T) {
	got := parseImportAliases(`import rego.v1`)
	assert.Empty(t, got, "bare imports without 'as' should be ignored")
}

// ── parse phase ───────────────────────────────────────────────────────────────

func TestValidateCustomRegoQuery_Valid(t *testing.T) {
	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", validTerraformRego, testLibSource())
	require.NoError(t, err)
	assert.Empty(t, errs, "valid rule should produce no errors")
}

func TestValidateCustomRegoQuery_MissingPackage(t *testing.T) {
	rego := strings.TrimPrefix(strings.Replace(validTerraformRego, "package datadog\n\n", "", 1), "\n")

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)
	require.NotEmpty(t, errs)
	assert.Equal(t, codeMissingPackage, errs[0].Code)
	assert.Contains(t, errs[0].Message, "package datadog")
	assert.Equal(t, 1, errs[0].StartLine)
}

func TestValidateCustomRegoQuery_MissingPackageRecovery(t *testing.T) {
	// Missing package + a missing result field: both should be reported thanks to
	// the recovery path that prepends "package datadog" and re-runs static checks.
	rego := strings.TrimPrefix(strings.Replace(validTerraformRego, "package datadog\n\n", "", 1), "\n")
	rego = strings.Replace(rego, `"resourceType": "aws_s3_bucket",`+"\n", "", 1)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)
	require.NotEmpty(t, errs)

	codes := errorCodes(errs)
	assert.True(t, codes[codeMissingPackage], "missing package must be reported")
	assert.True(t, codes["missing_result_field"], "static checks must still run after recovery")
}

func TestValidateCustomRegoQuery_MissingIf(t *testing.T) {
	rego := strings.Replace(validTerraformRego, "DatadogPolicy contains result if {", "DatadogPolicy contains result {", 1)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)
	require.NotEmpty(t, errs, "missing 'if' should produce a parse error")

	e := errs[0]
	assert.Equal(t, "rego_parse_error", e.Code)
	assert.Greater(t, e.StartLine, 0)
}

func TestValidateCustomRegoQuery_MissingInputRoot(t *testing.T) {
	rego := strings.Replace(validTerraformRego,
		"input.document[i].resource.aws_s3_bucket[name]",
		".document[i].resource.aws_s3_bucket[name]",
		1,
	)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)
	require.NotEmpty(t, errs)

	assert.Equal(t, "rego_parse_error", errs[0].Code)
	assert.Equal(t, "expected `input` before `.document`", errs[0].Message)
	assert.Equal(t, 8, errs[0].StartLine)
	assert.Equal(t, 14, errs[0].StartCol)
}

func TestValidateCustomRegoQuery_MissingComma(t *testing.T) {
	rego := strings.Replace(validTerraformRego,
		`"documentId": input.document[i].id,`,
		`"documentId": input.document[i].id`,
		1,
	)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)
	require.NotEmpty(t, errs)
	assert.Contains(t, errs[0].Message, `expected ',' after field "documentId"`)
	assert.Equal(t, 11, errs[0].StartLine)
}

func TestValidateCustomRegoQuery_MissingCommaAfterMiddleField(t *testing.T) {
	rego := strings.Replace(validTerraformRego,
		`"resourceType": "aws_s3_bucket",`,
		`"resourceType": "aws_s3_bucket"`,
		1,
	)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)
	require.NotEmpty(t, errs)
	assert.Contains(t, errs[0].Message, `expected ',' after field "resourceType"`)
	assert.Equal(t, 12, errs[0].StartLine)
}

func TestValidateCustomRegoQuery_TwoMissingCommas(t *testing.T) {
	rego := validTerraformRego
	rego = strings.Replace(rego, `"documentId": input.document[i].id,`, `"documentId": input.document[i].id`, 1)
	rego = strings.Replace(rego, `"resourceType": "aws_s3_bucket",`, `"resourceType": "aws_s3_bucket"`, 1)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(errs), 2, "all missing commas should be reported in one pass")
	assert.Contains(t, errorLines(errs), 11)
	assert.Contains(t, errorLines(errs), 12)
}

func TestValidateCustomRegoQuery_MissingClosingParen(t *testing.T) {
	rego := strings.Replace(validTerraformRego,
		`sprintf("aws_s3_bucket[%s].acl", [name]),`,
		`sprintf("aws_s3_bucket[%s].acl", [name],`,
		1,
	)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)
	require.NotEmpty(t, errs)
	assert.Equal(t, "rego_parse_error", errs[0].Code)
	assert.Contains(t, errs[0].Message, ")")
	assert.Equal(t, 14, errs[0].StartLine)
}

func TestValidateCustomRegoQuery_UnbalancedBrace(t *testing.T) {
	rego := validTerraformRego[:strings.LastIndex(validTerraformRego, "}")]

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)
	require.NotEmpty(t, errs, "removing closing brace should produce a parse error")

	e := errs[0]
	assert.Equal(t, "rego_parse_error", e.Code)
	assert.Contains(t, e.Message, "unclosed")
	assert.Greater(t, e.StartLine, 0)
}

func TestValidateCustomRegoQuery_ExtraClosingBrace(t *testing.T) {
	rego := validTerraformRego + "}\n"

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)
	require.NotEmpty(t, errs)

	e := errs[0]
	assert.Equal(t, "rego_parse_error", e.Code)
	assert.Contains(t, e.Message, "unexpected `}`")
	assert.Greater(t, e.StartLine, 0)
}

// ── static checks ─────────────────────────────────────────────────────────────

func TestValidateCustomRegoQuery_WrongPackage(t *testing.T) {
	rego := strings.Replace(validTerraformRego, "package datadog", "package mycompany", 1)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)
	require.NotEmpty(t, errs)

	e, ok := firstWithCode(errs, "invalid_package")
	require.True(t, ok, "invalid_package must be present")
	assert.Greater(t, e.StartLine, 0, "must carry a line number")
	assert.Greater(t, e.StartCol, 0, "must carry a column number")
}

func TestValidateCustomRegoQuery_WrongRuleName(t *testing.T) {
	rego := strings.Replace(validTerraformRego, "DatadogPolicy", "MyPolicy", -1)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)

	e, ok := firstWithCode(errs, "missing_rule")
	require.True(t, ok, "missing_rule must be present")
	assert.Greater(t, e.StartLine, 0, "must point to the misnamed rule")
	assert.Contains(t, e.Message, "The scanner evaluates")
}

func TestValidateCustomRegoQuery_SprintfArityMismatch(t *testing.T) {
	rego := strings.Replace(validTerraformRego,
		`sprintf("aws_s3_bucket[%s].acl", [name])`,
		`sprintf("aws_s3_bucket[%s].acl=%s", [name])`,
		1,
	)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)

	e, ok := firstWithCode(errs, "sprintf_arity")
	require.True(t, ok, "sprintf_arity must be reported")
	assert.Contains(t, e.Message, "zero Findings")
	assert.Greater(t, e.StartLine, 0)
}

func TestValidateCustomRegoQuery_MissingResultField(t *testing.T) {
	rego := strings.Replace(validTerraformRego,
		`"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),`+"\n",
		"",
		1,
	)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)

	e, ok := firstWithCode(errs, "missing_result_field")
	require.True(t, ok)
	assert.Contains(t, e.Message, "searchKey")
	assert.Contains(t, e.Message, "Findings")
	assert.Equal(t, 10, e.StartLine)
	assert.Equal(t, 2, e.StartCol)
}

func TestValidateCustomRegoQuery_MultipleResultFieldsMissing(t *testing.T) {
	rego := validTerraformRego
	rego = strings.Replace(rego, `"resourceType": "aws_s3_bucket",`+"\n", "", 1)
	rego = strings.Replace(rego, `"resourceName": tf_lib.resolve_s3_bucket_name(resource, name),`+"\n", "", 1)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)

	missing := make([]string, 0)
	for _, e := range errs {
		if e.Code == "missing_result_field" {
			missing = append(missing, e.Message)
		}
	}
	require.Len(t, missing, 2, "both missing fields should be reported")
	assert.True(t, strings.Contains(missing[0], "resourceType") || strings.Contains(missing[1], "resourceType"))
	assert.True(t, strings.Contains(missing[0], "resourceName") || strings.Contains(missing[1], "resourceName"))
}

func TestValidateCustomRegoQuery_MissingTfLibImport(t *testing.T) {
	rego := strings.Replace(validTerraformRego, "import data.generic.terraform as tf_lib\n", "", 1)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)

	e, ok := firstWithCode(errs, "missing_import")
	require.True(t, ok)
	assert.Contains(t, e.Message, "tf_lib")
	assert.Greater(t, e.StartLine, 0)
	assert.Greater(t, e.StartCol, 0)

	// Compile cascade should be filtered: no redundant "undefined function tf_lib." error.
	for _, e := range errs {
		assert.NotContains(t, e.Message, "undefined function tf_lib.")
	}
}

func TestValidateCustomRegoQuery_MissingCommonLibImport(t *testing.T) {
	rego := strings.Replace(validTerraformRego, "import data.generic.common as common_lib\n", "", 1)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)

	e, ok := firstWithCode(errs, "missing_import")
	require.True(t, ok)
	assert.Contains(t, e.Message, "common_lib")
	assert.Greater(t, e.StartLine, 0)

	for _, e := range errs {
		assert.NotContains(t, e.Message, "undefined function common_lib.")
	}
}

// ── OPA compilation phase ─────────────────────────────────────────────────────

func TestValidateCustomRegoQuery_UndefinedLibraryFunction(t *testing.T) {
	// Call a function that does not exist in tf_lib; OPA reports the fully-qualified
	// path, but enrichTypeErrors should translate it back to the alias the user wrote.
	rego := strings.Replace(validTerraformRego,
		"tf_lib.resolve_s3_bucket_name(resource, name)",
		"tf_lib.no_such_fn(resource, name)",
		1,
	)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)
	require.NotEmpty(t, errs)

	var typeErr *RegoValidationError
	for i := range errs {
		if errs[i].Code == "rego_type_error" {
			typeErr = &errs[i]
			break
		}
	}
	require.NotNil(t, typeErr, "rego_type_error must be present")
	assert.Contains(t, typeErr.Message, "tf_lib.no_such_fn",
		"alias form must be used, not data.generic.terraform.no_such_fn")
	assert.NotContains(t, typeErr.Message, "data.generic.terraform")
}

func TestValidateCustomRegoQuery_MissingResourceBinding(t *testing.T) {
	rego := strings.Replace(validTerraformRego,
		"\tresource := input.document[i].resource.aws_s3_bucket[name]\n",
		"",
		1,
	)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)
	require.NotEmpty(t, errs)

	// "result is unsafe" must not surface — it is always a cascade.
	for _, e := range errs {
		assert.NotContains(t, e.Message, "result is unsafe")
	}

	var hasResource, hasName bool
	for _, e := range errs {
		if e.Code != "rego_unsafe_var_error" {
			continue
		}
		if strings.Contains(e.Message, `"resource"`) {
			hasResource = true
			assert.Equal(t, 8, e.StartLine)
			assert.Equal(t, 2, e.StartCol)
			assert.Equal(t, 10, e.EndCol)
		}
		if strings.Contains(e.Message, `"name"`) {
			hasName = true
			assert.Greater(t, e.StartCol, 0)
		}
	}
	assert.True(t, hasResource, "resource usage must be flagged")
	assert.True(t, hasName, "name usage must be flagged")
}

// ── all-at-once behaviour ─────────────────────────────────────────────────────

func TestValidateCustomRegoQuery_AllErrorsInOneCall(t *testing.T) {
	rego := validTerraformRego
	rego = strings.Replace(rego, "package datadog", "package mycompany", 1)
	rego = strings.Replace(rego, `sprintf("aws_s3_bucket[%s].acl", [name])`, `sprintf("aws_s3_bucket[%s].acl=%s", [name])`, 1)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, testLibSource())
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(errs), 2)

	codes := errorCodes(errs)
	assert.True(t, codes["invalid_package"])
	assert.True(t, codes["sprintf_arity"])
}

// ── platform support ──────────────────────────────────────────────────────────

func TestValidateCustomRegoQuery_KubernetesPlatform(t *testing.T) {
	// Verifies that "kubernetes" platform loads the k8s library correctly
	// (libraryPlatform maps "kubernetes" → "k8s" to match the embedded asset).
	const k8sRego = `
package datadog

import rego.v1

DatadogPolicy contains result if {
	pod := input.document[_]
	result := {
		"documentId":   pod.id,
		"resourceType": "Pod",
		"resourceName": "pod",
		"searchKey":    "pod",
	}
}
`
	errs, err := ValidateCustomRegoQuery(context.Background(), "kubernetes", k8sRego, testLibSource())
	require.NoError(t, err, "kubernetes platform must not fail with a library-load error")
	// Content errors are fine; what matters is no internal "unable to get libraries" error.
	for _, e := range errs {
		assert.NotContains(t, e.Message, "unable to get libraries", "library must load correctly")
	}
}

// ── ValidateRegoStructure ─────────────────────────────────────────────────────

func TestValidateRegoStructure_Valid(t *testing.T) {
	errs := ValidateRegoStructure(validTerraformRego)
	assert.Empty(t, errs)
}

func TestValidateRegoStructure_WrongPackage(t *testing.T) {
	rego := strings.Replace(validTerraformRego, "package datadog", "package mycompany", 1)
	errs := ValidateRegoStructure(rego)
	require.NotEmpty(t, errs)
	assert.True(t, errorCodes(errs)["invalid_package"])
}

func TestValidateRegoStructure_MissingPackage(t *testing.T) {
	rego := strings.TrimPrefix(strings.Replace(validTerraformRego, "package datadog\n\n", "", 1), "\n")
	errs := ValidateRegoStructure(rego)
	// Returns parse errors; does not attempt recovery (unlike ValidateCustomRegoQuery).
	require.NotEmpty(t, errs)
	assert.True(t, errorCodes(errs)[codeMissingPackage], "must return parse error, not recover")
	assert.False(t, errorCodes(errs)["missing_result_field"], "recovery path must not run")
}
