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

// End-to-end scenarios covering rules an author would realistically write, across every
// platform the console exposes. They assert on outcomes rather than exact wording, since
// messages come from OPA and Regal and change as those tools improve.

// multiPlatformLibSource serves a stub library for every supported platform.
type multiPlatformLibSource struct{}

func (s *multiPlatformLibSource) GetQueries(
	_ context.Context, _ *source.QueryInspectorParameters,
) ([]model.QueryMetadata, error) {
	return nil, nil
}

func (s *multiPlatformLibSource) GetQueryLibrary(_ context.Context, platform string) (source.RegoLibraries, error) {
	type lib struct {
		pkg  string
		body string
	}
	spec := map[string]lib{
		"common":         {pkg: "generic.common", body: "build_search_line(keys, obj) := keys\n"},
		"terraform":      {pkg: "generic.terraform", body: "resolve_s3_bucket_name(resource, name) := name\n"},
		"cloudFormation": {pkg: "generic.cloudformation", body: "get_name(resource, name) := name\n"},
		"ansible":        {pkg: "generic.ansible", body: "get_name(resource, name) := name\n"},
		"k8s":            {pkg: "generic.k8s", body: "get_name(resource, name) := name\n"},
		"dockerfile":     {pkg: "generic.dockerfile", body: "get_name(resource, name) := name\n"},
		"cicd":           {pkg: "generic.cicd", body: "get_name(resource, name) := name\n"},
	}[platform]
	if spec.pkg == "" {
		return source.RegoLibraries{}, fmt.Errorf("no stub library for platform %q", platform)
	}
	return source.RegoLibraries{
		LibraryCode:      "package " + spec.pkg + "\nimport rego.v1\n" + spec.body,
		LibraryInputData: "{}",
	}, nil
}

func validateMulti(t *testing.T, platform, rego string) []RegoValidationError {
	t.Helper()
	errs, err := ValidateCustomRegoQuery(context.Background(), platform, rego, &multiPlatformLibSource{})
	require.NoError(t, err)
	return errs
}

// ruleFor builds a contract-compliant rule with imports and body injected verbatim.
func ruleFor(imports, body string) string {
	return "package datadog\n\n" + imports + `
DatadogPolicy contains result if {
	some i
` + body + `
	result := {
		"documentId": input.document[i].id,
		"resourceType": "some_type",
		"resourceName": "some_name",
		"searchKey": "some.key",
	}
}
`
}

// Calling a platform library without importing it is reported on every platform.
func TestScenario_MissingLibraryImportIsReportedOnEveryPlatform(t *testing.T) {
	for _, platform := range []string{
		"Terraform", "CloudFormation", "Ansible", "Kubernetes", "Dockerfile", "CICD",
	} {
		t.Run(platform, func(t *testing.T) {
			rego := ruleFor("", "\tname := lib.get_name({}, \"n\")")
			assert.NotEmpty(t, allCodes(validateMulti(t, platform, rego)),
				"an unimported library reference must be reported on %s", platform)
		})
	}
}

// The alias an author picks is their own choice; only OPA decides whether it resolves.
func TestScenario_UnconventionalAliasResolvesWhenImported(t *testing.T) {
	rego := ruleFor(
		"import data.generic.ansible as ansible_helpers_v2\n",
		"\tname := ansible_helpers_v2.get_name({}, \"n\")",
	)
	errs := validateMulti(t, "Ansible", rego)
	assert.Empty(t, allCodes(errs), "any alias must be accepted once the import exists")
}

// Referencing a library as a bare value rather than a call is equally unresolvable.
func TestScenario_MissingImportAsNonCallUsage(t *testing.T) {
	rego := ruleFor("", "\tname := k8s_lib.some_value")
	errs := validateMulti(t, "Kubernetes", rego)
	assert.NotEmpty(t, allCodes(errs))
}

// A plain typo is reported like any other unresolved reference — the scanner does not
// try to distinguish "missing import" from "misspelled variable".
func TestScenario_LocalVariableTypoIsReported(t *testing.T) {
	rego := ruleFor("", "\tbucket := input.document[i].resource\n\tname := buckett.acl")
	errs := validateMulti(t, "Dockerfile", rego)
	assert.NotEmpty(t, allCodes(errs))
}

// Several unrelated problems in one rule are all reported together, so an author can
// fix them in one pass instead of one round-trip per error.
func TestScenario_MultipleUnrelatedProblemsReportedTogether(t *testing.T) {
	rego := `package not_datadog

DatadogPolicy contains result if {
	some i
	result := {"documentId": input.document[i].id}
}
`
	errs := validateMulti(t, "CICD", rego)

	codes := errorCodes(errs)
	assert.True(t, codes[codeInvalidPackage], "got %v", codes)
	assert.True(t, codes[codeMissingResultField], "got %v", codes)
	assert.GreaterOrEqual(t, len(allCodes(errs)), 4,
		"expected the package error plus one per missing field, got %v", codes)
}

// A module with no rules at all is a contract violation, and must still carry a usable
// source location so the editor can place the marker.
func TestScenario_NoRulesAtAll(t *testing.T) {
	errs := validateMulti(t, "Terraform", "package datadog\n")

	e, ok := firstWithCode(errs, codeMissingRule)
	require.True(t, ok, "got %v", errorCodes(errs))
	assert.Positive(t, e.StartLine, "diagnostics must have a real location")
	assert.Positive(t, e.StartCol)
}

// A missing package declaration stops the parser, but the contract checks are re-run
// against a synthetically packaged copy so the author sees the rest of the problems in
// the same pass. Locations are reported against the original source.
func TestScenario_MissingPackageDeclaration(t *testing.T) {
	rego := `DatadogPolicy contains result if {
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
	errs := validateMulti(t, "Terraform", rego)
	require.NotEmpty(t, errs)

	codes := errorCodes(errs)
	assert.True(t, codes[codeMissingPackage], "got %v", codes)
	assert.True(t, codes[codeMissingImport], "missing-package recovery must also compile against libraries, got %v", codes)

	lineCount := strings.Count(rego, "\n")
	for _, e := range errs {
		assert.LessOrEqual(t, e.StartLine, lineCount,
			"recovered diagnostics must be shifted back onto the original source: %+v", e)
	}
}

// Every diagnostic reaching a client must be renderable: a location and a message.
func TestScenario_AllDiagnosticsAreRenderable(t *testing.T) {
	samples := []string{
		"package datadog\n",
		"package wrong\n\nDatadogPolicy contains result if { some i; result := {\"documentId\": input.document[i].id} }\n",
		"package datadog\n\nDatadogPolicy contains result if {\n\tresult := {\n",
		ruleFor("", "\tname := missing_lib.get_name({}, \"n\")"),
	}
	for _, rego := range samples {
		errs := validateMulti(t, "Terraform", rego)
		for _, e := range errs {
			assert.NotEmpty(t, e.Message, "diagnostic %q has no message", e.Code)
			assert.NotEmpty(t, e.Code, "diagnostic %q has no code", e.Message)
			assert.GreaterOrEqual(t, e.EndLine, e.StartLine, "diagnostic %q spans backwards", e.Code)
		}
	}
}

// Diagnostics arrive ordered by position regardless of which tool produced them.
func TestScenario_DiagnosticsAreOrderedByPosition(t *testing.T) {
	rego := `package wrong

DatadogPolicy contains result if {
	some i
	result := {"documentId": input.document[i].id}
}
`
	errs := validateMulti(t, "Terraform", rego)
	require.Greater(t, len(errs), 1)

	for i := 1; i < len(errs); i++ {
		prev, cur := errs[i-1], errs[i]
		if prev.StartLine == cur.StartLine {
			assert.LessOrEqual(t, prev.StartCol, cur.StartCol)
			continue
		}
		assert.Less(t, prev.StartLine, cur.StartLine)
	}
}

// A rule named anything other than DatadogPolicy never runs, so the missing-rule
// diagnostic must fire even though the module is otherwise well formed.
func TestScenario_RuleWithWrongNameIsReported(t *testing.T) {
	rego := `package datadog

MyPolicy contains result if {
	some i
	result := {"documentId": input.document[i].id}
}
`
	codes := errorCodes(validateMulti(t, "Terraform", rego))
	assert.True(t, codes[codeMissingRule], "got %v", codes)
}
