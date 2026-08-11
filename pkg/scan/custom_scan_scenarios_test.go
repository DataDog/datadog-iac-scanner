package scan

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// allPlatformLibSource stubs every platform's library with a distinct, realistic
// function so missing-import detection can be exercised across the whole platform
// matrix, not just Terraform.
type allPlatformLibSource struct{}

func (allPlatformLibSource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return nil, nil
}

func (allPlatformLibSource) GetQueryLibrary(_ context.Context, platform string) (source.RegoLibraries, error) {
	libs := map[string]string{
		"common": `package generic.common
import rego.v1
build_search_line(keys, obj) := keys
`,
		"terraform": `package generic.terraform
import rego.v1
resolve_s3_bucket_name(resource, name) := name
`,
		"cloudformation": `package generic.cloudformation
import rego.v1
get_resource_name(resource, key) := key
`,
		"ansible": `package generic.ansible
import rego.v1
get_resource_id(resource) := resource.id
`,
		"k8s": `package generic.k8s
import rego.v1
get_pod_name(pod) := pod.metadata.name
`,
		"dockerfile": `package generic.dockerfile
import rego.v1
get_line_of_key(input_lines, key) := 1
`,
		"cicd": `package generic.cicd
import rego.v1
get_job_name(job) := job.name
`,
	}
	code, ok := libs[strings.ToLower(platform)]
	if !ok {
		return source.RegoLibraries{}, fmt.Errorf("no stub library for platform %q", platform)
	}
	return source.RegoLibraries{LibraryCode: code, LibraryInputData: "{}"}, nil
}


// Scenario: CloudFormation rule that calls the platform library without importing it.
// Every platform other than Terraform previously got zero help here.
func TestScenario_CloudFormationMissingImport(t *testing.T) {
	rego := `
package datadog

import data.generic.common as common_lib

DatadogPolicy contains result if {
	bucket := input.document[i].Resources[name]
	bucket.Type == "AWS::S3::Bucket"
	result := {
		"documentId": input.document[i].id,
		"resourceType": "AWS::S3::Bucket",
		"resourceName": cf_lib.get_resource_name(bucket, name),
		"searchKey": sprintf("Resources.%s", [name]),
		"searchLine": common_lib.build_search_line(["Resources", name], []),
	}
}
`
	errs, err := ValidateCustomRegoQuery(context.Background(), "cloudFormation", rego, allPlatformLibSource{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	e, ok := firstWithCode(errs, "missing_import")
	if !ok {
		t.Fatalf("expected a missing_import diagnostic")
	}
	if !strings.Contains(e.Message, "data.generic.cloudformation") || !strings.Contains(e.Message, "cf_lib") {
		t.Fatalf("message should name the exact library and alias, got: %s", e.Message)
	}
	if e.StartLine == 0 {
		t.Fatalf("missing_import must carry a location")
	}
}

// Scenario: Ansible rule missing its import, using a non-conventional alias name to
// prove detection isn't keyed off a specific expected alias string.
func TestScenario_AnsibleMissingImport_UnconventionalAlias(t *testing.T) {
	rego := `
package datadog

DatadogPolicy contains result if {
	task := input.document[i].tasks[name]
	result := {
		"documentId": input.document[i].id,
		"resourceType": "task",
		"resourceName": my_custom_alias.get_resource_id(task),
		"searchKey": sprintf("tasks[%d]", [name]),
	}
}
`
	errs, err := ValidateCustomRegoQuery(context.Background(), "ansible", rego, allPlatformLibSource{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	e, ok := firstWithCode(errs, "missing_import")
	if !ok {
		t.Fatalf("expected a missing_import diagnostic even for a non-conventional alias")
	}
	if !strings.Contains(e.Message, "data.generic.ansible") || !strings.Contains(e.Message, "my_custom_alias") {
		t.Fatalf("message should preserve the user's chosen alias and name the ansible library, got: %s", e.Message)
	}
}

// Scenario: Kubernetes rule referencing an unimported library as a bare value (not a
// call) — exercises the unsafe-var fallback path rather than the undefined-function path.
func TestScenario_KubernetesMissingImport_NonCallUsage(t *testing.T) {
	rego := `
package datadog

DatadogPolicy contains result if {
	pod := input.document[_]
	name := k8s_lib.get_pod_name
	result := {
		"documentId": pod.id,
		"resourceType": "Pod",
		"resourceName": name,
		"searchKey": "pod",
	}
}
`
	errs, err := ValidateCustomRegoQuery(context.Background(), "kubernetes", rego, allPlatformLibSource{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	e, ok := firstWithCode(errs, "missing_import")
	if !ok {
		t.Fatalf("expected a missing_import diagnostic for the bare-value usage")
	}
	if !strings.Contains(e.Message, "data.generic.k8s") {
		t.Fatalf("message should name the k8s library, got: %s", e.Message)
	}
	if len(errs) != 1 {
		t.Fatalf("the 'name' binding's unsafety is a pure consequence of the missing import "+
			"and should be suppressed as a cascade, got %d errors: %+v", len(errs), errs)
	}
}

// Scenario: missing import and an independent undefined variable on the same line —
// cascade suppression must not hide the unrelated typo.
func TestScenario_KubernetesMissingImport_IndependentVarOnSameLine(t *testing.T) {
	rego := `
package datadog

DatadogPolicy contains result if {
	pod := input.document[_]
	name := [k8s_lib.get_pod_name, podd]
	result := {
		"documentId": pod.id,
		"resourceType": "Pod",
		"resourceName": name,
		"searchKey": "pod",
	}
}
`
	errs, err := ValidateCustomRegoQuery(context.Background(), "kubernetes", rego, allPlatformLibSource{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := firstWithCode(errs, "missing_import"); !ok {
		t.Fatalf("expected missing_import for k8s_lib, got: %+v", errs)
	}
	if _, ok := firstWithCode(errs, codeUnsafeVarError); !ok {
		t.Fatalf("expected unsafe-var diagnostic for independent typo podd, got: %+v", errs)
	}
	for _, e := range errs {
		if e.Code == codeUnsafeVarError && strings.Contains(e.Message, "podd") {
			return
		}
	}
	t.Fatalf("expected undefined variable podd to be reported, got: %+v", errs)
}

// Scenario: Dockerfile rule with a real typo (not a missing import) — must NOT be
// mislabeled as missing_import, and must NOT leak the internal qualified path.
func TestScenario_DockerfileTypoNotMislabeled(t *testing.T) {
	rego := `
package datadog

import data.generic.dockerfile as docker_lib

DatadogPolicy contains result if {
	cmd := input.document[i].Cmd[_]
	cmd.Value == "latest"
	result := {
		"documentId": input.document[i].id,
		"resourceType": "Cmd",
		"resourceName": "cmd",
		"searchKey": docker_lib.get_line_of_keyz(input.document[i], "Cmd"),
	}
}
`
	errs, err := ValidateCustomRegoQuery(context.Background(), "dockerfile", rego, allPlatformLibSource{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, e := range errs {
		if e.Code == "missing_import" {
			t.Fatalf("a real typo of an existing import must not be mislabeled missing_import: %+v", e)
		}
		if strings.Contains(e.Message, "data.generic.dockerfile") {
			t.Fatalf("qualified path leaked into message: %s", e.Message)
		}
	}
	if _, ok := firstWithCode(errs, "rego_type_error"); !ok {
		t.Fatalf("expected the genuine typo to still surface as a type error")
	}
}

// Scenario: multiple unrelated problems at once — wrong package, missing CICD import,
// and an sprintf arity mismatch. All three must be reported in one call.
func TestScenario_CICD_MultipleUnrelatedErrors(t *testing.T) {
	rego := `
package wrongpkg

DatadogPolicy contains result if {
	job := input.document[i].jobs[name]
	result := {
		"documentId": input.document[i].id,
		"resourceType": "job",
		"resourceName": cicd_lib.get_job_name(job),
		"searchKey": sprintf("jobs[%s].steps=%d", [name]),
	}
}
`
	errs, err := ValidateCustomRegoQuery(context.Background(), "cicd", rego, allPlatformLibSource{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	codes := errorCodes(errs)
	for _, want := range []string{"invalid_package", "missing_import", "sprintf_arity"} {
		if !codes[want] {
			t.Fatalf("expected code %q to be present, got codes: %v", want, codes)
		}
	}
}

// Scenario: a rule with no rules at all must still get a valid (non-zero) location.
func TestScenario_NoRulesAtAll(t *testing.T) {
	rego := `
package datadog

import rego.v1
`
	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, allPlatformLibSource{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	e, ok := firstWithCode(errs, "missing_rule")
	if !ok {
		t.Fatalf("expected missing_rule")
	}
	if e.StartLine == 0 {
		t.Fatalf("missing_rule must never report a zero location, got %+v", e)
	}
}

// Scenario: two independent syntax problems in one file — a missing comma AND an
// unclosed function call. Both must be reported, not just whichever heuristic runs first.
func TestScenario_MixedSyntaxErrors(t *testing.T) {
	rego := `
package datadog

import data.generic.common as common_lib

DatadogPolicy contains result if {
	resource := input.document[i].resource.aws_s3_bucket[name]
	result := {
		"documentId": input.document[i].id
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name],
	}
}
`
	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, allPlatformLibSource{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(errs) < 2 {
		t.Fatalf("expected at least 2 distinct parse diagnostics, got %d: %+v", len(errs), errs)
	}
	foundComma, foundParen := false, false
	for _, e := range errs {
		if strings.Contains(e.Message, "expected ','") {
			foundComma = true
		}
		if strings.Contains(e.Message, "expected ')'") {
			foundParen = true
		}
	}
	if !foundComma || !foundParen {
		t.Fatalf("expected both a missing-comma and an unclosed-paren diagnostic, got: %+v", errs)
	}
}

// Scenario: a missing comma alongside a sprintf format string that contains '(' inside
// quotes — must not fabricate an unclosed-paren diagnostic for the sprintf line.
func TestScenario_MixedSyntaxErrors_ParenInsideStringLiteral(t *testing.T) {
	rego := `
package datadog

import data.generic.common as common_lib

DatadogPolicy contains result if {
	resource := input.document[i].resource.aws_s3_bucket[name]
	result := {
		"documentId": input.document[i].id
		"searchKey": sprintf("prefix(%s", [name]),
	}
}
`
	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, allPlatformLibSource{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundComma := false
	for _, e := range errs {
		if strings.Contains(e.Message, "expected ','") {
			foundComma = true
		}
		if strings.Contains(e.Message, "expected ')'") {
			t.Fatalf("paren inside string literal must not trigger unclosed-paren heuristic, got: %+v", errs)
		}
	}
	if !foundComma {
		t.Fatalf("expected missing-comma diagnostic, got: %+v", errs)
	}
}

// Scenario: a genuine typo of a local variable (not a library alias at all) must keep
// getting the plain "undefined variable" message, not be mistaken for a missing import.
func TestScenario_GenuineLocalVariableTypo(t *testing.T) {
	rego := `
package datadog

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

DatadogPolicy contains result if {
	resource := input.document[i].resource.aws_s3_bucket[name]
	resource.acl == "public-read"
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": tf_lib.resolve_s3_bucket_name(resoure, name),
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", name, "acl"], []),
	}
}
`
	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, allPlatformLibSource{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(errs) != 1 {
		t.Fatalf("expected exactly one diagnostic for the typo, got %d: %+v", len(errs), errs)
	}
	e := errs[0]
	if e.Code == "missing_import" {
		t.Fatalf("a misspelled local variable must not be reported as a missing import: %+v", e)
	}
	if !strings.Contains(e.Message, `"resoure"`) {
		t.Fatalf("message should name the actual misspelled variable, got: %s", e.Message)
	}
}

// Scenario: the cheap, library-free ValidateRegoStructure path must still catch
// structural problems without needing network access to fetch libraries.
func TestScenario_ValidateRegoStructure_StillCatchesStructuralIssues(t *testing.T) {
	rego := `
package wrongpkg

MyRule contains result if {
	result := {
		"documentId": "x",
	}
}
`
	errs := ValidateRegoStructure(rego)

	codes := errorCodes(errs)
	for _, want := range []string{"invalid_package", "missing_rule"} {
		if !codes[want] {
			t.Fatalf("expected code %q, got codes: %v", want, codes)
		}
	}
}

// Scenario: missing package declaration AND a missing import AND a bad rule name, all
// at once — the recovery path must not stop short of the compile phase.
func TestScenario_MissingPackage_PlusMissingImport(t *testing.T) {
	rego := `import data.generic.common as common_lib

WrongRuleName contains result if {
	bucket := input.document[i].resource.aws_s3_bucket[name]
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": tf_lib.resolve_s3_bucket_name(bucket, name),
		"searchKey": sprintf("aws_s3_bucket[%s]", [name]),
	}
}
`
	errs, err := ValidateCustomRegoQuery(context.Background(), "terraform", rego, allPlatformLibSource{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	codes := errorCodes(errs)
	for _, want := range []string{codeMissingPackage, "missing_rule", "missing_import"} {
		if !codes[want] {
			t.Fatalf("expected code %q to be present even through the recovery path, got codes: %v", want, codes)
		}
	}
}
