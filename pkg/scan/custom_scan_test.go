package scan

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validTerraformRego is a minimal DatadogPolicy rule that passes validation.
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

func TestValidateCustomRegoQuery_MissingComma(t *testing.T) {
	rego := strings.Replace(validTerraformRego,
		`"documentId": input.document[i].id,`,
		`"documentId": input.document[i].id`,
		1,
	)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego)
	require.NoError(t, err)
	require.NotEmpty(t, errs, "missing comma should produce at least one error")

	for _, e := range errs {
		assert.Greater(t, e.StartLine, 0, "parse error must carry a line number: %s", e.Message)
	}
}

func TestValidateRegoStructure_WrongPackage(t *testing.T) {
	rego := strings.Replace(validTerraformRego, "package datadog", "package mycompany", 1)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego)
	require.NoError(t, err)
	require.NotEmpty(t, errs, "wrong package should be reported")
	assert.Equal(t, "invalid_package", errs[0].Code)
}

func TestValidateCustomRegoQuery_WrongRuleName(t *testing.T) {
	rego := strings.Replace(validTerraformRego, "DatadogPolicy", "MyPolicy", -1)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego)
	require.NoError(t, err)
	require.NotEmpty(t, errs, "wrong rule name should be reported")
	assert.Equal(t, "missing_rule", errs[0].Code)
}

func TestValidateCustomRegoQuery_MissingIf(t *testing.T) {
	rego := strings.Replace(validTerraformRego, "DatadogPolicy contains result if {", "DatadogPolicy contains result {", 1)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego)
	require.NoError(t, err)
	require.NotEmpty(t, errs, "missing 'if' should produce a parse error")
	assert.Greater(t, errs[0].StartLine, 0, "parse error must have a line number")
}

func TestValidateCustomRegoQuery_SprintfArityMismatch(t *testing.T) {
	rego := strings.Replace(validTerraformRego,
		`sprintf("aws_s3_bucket[%s].acl", [name])`,
		`sprintf("aws_s3_bucket[%s].acl=%s", [name])`,
		1,
	)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego)
	require.NoError(t, err)
	require.NotEmpty(t, errs, "sprintf arity mismatch should be caught by AST walking")
	assert.Equal(t, "sprintf_arity", errs[0].Code)
	assert.Greater(t, errs[0].StartLine, 0, "sprintf arity error must have a line number")
}

func TestValidateCustomRegoQuery_MissingResultField(t *testing.T) {
	rego := strings.Replace(validTerraformRego,
		`"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),`+"\n",
		"",
		1,
	)

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego)
	require.NoError(t, err)
	require.NotEmpty(t, errs, "missing result field should be reported")
	codes := make([]string, 0, len(errs))
	for _, e := range errs {
		codes = append(codes, e.Code)
	}
	assert.Contains(t, codes, "missing_result_field")
}

func TestValidateCustomRegoQuery_AllResultFieldsPresent(t *testing.T) {
	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", validTerraformRego)
	require.NoError(t, err)
	for _, e := range errs {
		assert.NotEqual(t, "missing_result_field", e.Code,
			"valid rule should not report missing_result_field: %s", e.Message)
	}
}

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

func TestValidateCustomRegoQuery_UnbalancedBrace(t *testing.T) {
	rego := validTerraformRego[:strings.LastIndex(validTerraformRego, "}")]

	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego)
	require.NoError(t, err)
	require.NotEmpty(t, errs, "unbalanced brace should produce a parse error")
	assert.Greater(t, errs[0].StartLine, 0, "parse error must have a line number")
}
