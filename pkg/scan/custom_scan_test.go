package scan

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validTerraformRego is a minimal but complete DatadogPolicy rule that passes validation.
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

func TestValidateCustomRegoQuery_Valid(t *testing.T) {
	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", validTerraformRego)
	require.NoError(t, err)
	assert.Empty(t, errs, "valid rule should produce no errors")
}

// TestValidateCustomRegoQuery_MissingComma reproduces the original bug: a missing comma
// in the result object was returned with start_line=0 (no location) because errors.As
// failed to match ast.Errors. After the fix, start_line must be >0.
func TestValidateCustomRegoQuery_MissingComma(t *testing.T) {
	// Remove the comma after "documentId": input.document[i].id
	rego := strings.Replace(validTerraformRego,
		`"documentId": input.document[i].id,`,
		`"documentId": input.document[i].id`,
		1,
	)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego)
	require.NoError(t, err)
	require.NotEmpty(t, errs, "missing comma should produce at least one error")

	// The key assertion: start_line must be set so the frontend can highlight the line.
	for _, e := range errs {
		assert.Greater(t, e.StartLine, 0,
			"parse error must carry a line number (got start_line=0, meaning location was lost); error: %s", e.Message)
	}
}

// TestValidateCustomRegoQuery_WrongPackage catches the silent failure where a user
// writes `package mycompany` — OPA compiles it fine but the scanner finds zero findings
// because it evaluates data.datadog.DatadogPolicy.
func TestValidateCustomRegoQuery_WrongPackage(t *testing.T) {
	rego := strings.Replace(validTerraformRego, "package datadog", "package mycompany", 1)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego)
	require.NoError(t, err)
	require.NotEmpty(t, errs, "wrong package should be reported")
	assert.Equal(t, "invalid_package", errs[0].Code)
}

// TestValidateCustomRegoQuery_WrongRuleName catches the silent failure where a user
// names their rule `MyPolicy` instead of `DatadogPolicy`.
func TestValidateCustomRegoQuery_WrongRuleName(t *testing.T) {
	rego := strings.Replace(validTerraformRego, "DatadogPolicy", "MyPolicy", -1)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego)
	require.NoError(t, err)
	require.NotEmpty(t, errs, "wrong rule name should be reported")
	assert.Equal(t, "missing_rule", errs[0].Code)
}

// TestValidateCustomRegoQuery_MissingIf catches `DatadogPolicy contains result { ... }`
// without the `if` keyword (common mistake from Rego v0 habits).
func TestValidateCustomRegoQuery_MissingIf(t *testing.T) {
	rego := strings.Replace(validTerraformRego, "DatadogPolicy contains result if {", "DatadogPolicy contains result {", 1)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego)
	require.NoError(t, err)
	require.NotEmpty(t, errs, "missing 'if' should produce a parse error")
	assert.Greater(t, errs[0].StartLine, 0, "parse error must have a line number")
}

// TestValidateCustomRegoQuery_SprintfArityMismatch documents that OPA does NOT catch
// sprintf format/arg count mismatches at compile time — they fail silently at runtime
// (the call returns undefined, so the rule body fails to unify and produces no findings).
// This is a known limitation: users will see 0 findings rather than an error.
func TestValidateCustomRegoQuery_SprintfArityMismatch(t *testing.T) {
	rego := strings.Replace(validTerraformRego,
		`sprintf("aws_s3_bucket[%s].acl", [name])`,
		`sprintf("aws_s3_bucket[%s].acl=%s", [name])`,
		1,
	)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego)
	require.NoError(t, err)
	// OPA does not enforce sprintf arity statically — the mismatch is a runtime
	// undefined, not a compile error. No errors expected here.
	assert.Empty(t, errs, "sprintf arity mismatch is not caught at compile time")
}

// TestValidateCustomRegoQuery_MissingImport catches using tf_lib without importing it.
func TestValidateCustomRegoQuery_MissingImport(t *testing.T) {
	rego := strings.Replace(validTerraformRego,
		"import data.generic.terraform as tf_lib\n",
		"",
		1,
	)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego)
	require.NoError(t, err)
	require.NotEmpty(t, errs, "missing import should produce a compile error")
}

// TestValidateCustomRegoQuery_UnbalancedBrace catches a missing closing brace.
func TestValidateCustomRegoQuery_UnbalancedBrace(t *testing.T) {
	// Drop the last `}` that closes the rule body.
	rego := validTerraformRego[:strings.LastIndex(validTerraformRego, "}")]

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego)
	require.NoError(t, err)
	require.NotEmpty(t, errs, "unbalanced brace should produce a parse error")
	assert.Greater(t, errs[0].StartLine, 0, "parse error must have a line number")
}
