/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// TestSafeCapabilities_BlocksUnsafeBuiltins is the security guard for the
// WithUnsafeBuiltins -> WithCapabilities migration: a rule referencing an unsafe
// builtin (http.send / opa.runtime) must still fail to compile under the shared
// compiler's capabilities, exactly as it did under WithUnsafeBuiltins.
func TestSafeCapabilities_BlocksUnsafeBuiltins(t *testing.T) {
	for name := range unsafeRegoFunctions {
		t.Run(name, func(t *testing.T) {
			src := "package datadog\nDatadogPolicy contains result if { result := " + name + "({}) }\n"
			mod, err := ast.ParseModuleWithOpts("rule", src, ast.ParserOptions{RegoVersion: ast.RegoV1})
			require.NoError(t, err)

			c := ast.NewCompiler().WithCapabilities(safeCapabilities())
			c.Compile(map[string]*ast.Module{"rule": mod})
			require.True(t, c.Failed(), "compile must reject the unsafe builtin %q", name)
		})
	}
}

// TestSafeCapabilities_AllowsNormalBuiltins guards the other direction: ordinary
// builtins the rules rely on (e.g. sprintf) stay available.
func TestSafeCapabilities_AllowsNormalBuiltins(t *testing.T) {
	src := "package datadog\nDatadogPolicy contains result if { result := sprintf(\"%d\", [1]) }\n"
	mod, err := ast.ParseModuleWithOpts("rule", src, ast.ParserOptions{RegoVersion: ast.RegoV1})
	require.NoError(t, err)

	c := ast.NewCompiler().WithCapabilities(safeCapabilities())
	c.Compile(map[string]*ast.Module{"rule": mod})
	require.False(t, c.Failed(), "compile must allow safe builtins: %v", c.Errors)
}

// secondRule is a second self-contained rule, distinct from aclRule, so the
// shared-compiler path must keep multiple rules independently addressable
// (the whole point of the per-rule package rename).
const secondRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	bucket := input.document[i].resource.aws_s3_bucket[name]
	not bucket.versioning

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "versioning should be set",
		"keyActualValue": "versioning is not set",
	}
}
`

// TestInspect_SharedCompiler_MatchesIsolated runs the same files + rules through
// both the isolated path (default) and the shared-compiler path
// (disableRuleIsolation), and asserts the findings are identical — the opt-in
// flag must never change results, only memory/compilation.
func TestInspect_SharedCompiler_MatchesIsolated(t *testing.T) {
	root := t.TempDir()
	stackDir := filepath.Join(root, "stack")
	require.NoError(t, os.MkdirAll(stackDir, 0o755))
	mainPath := filepath.Join(stackDir, "main.tf")
	require.NoError(t, os.WriteFile(mainPath, []byte(`
resource "aws_s3_bucket" "public" {
  acl = "public-read"
}

resource "aws_s3_bucket" "plain" {
  bucket = "x"
}
`), 0o644))

	queries := []model.QueryMetadata{
		{Query: "acl_rule", Content: aclRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "acl-rule"}, Aggregation: 1},
		{Query: "versioning_rule", Content: secondRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "versioning-rule"}, Aggregation: 1},
	}

	run := func(disableRuleIsolation bool) []model.Vulnerability {
		files := parseTerraform(t, mainPath)
		ins := newTestInspector(t, inspectorOpts{
			queries:              queries,
			repoPath:             root,
			vb:                   DefaultVulnerabilityBuilder,
			disableRuleIsolation: disableRuleIsolation,
		})
		vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
		require.NoError(t, err)
		require.Empty(t, ins.GetFailedQueries(), "no query should fail")
		return vulns
	}

	isolated := run(false)
	shared := run(true)

	require.NotEmpty(t, isolated, "the crafted file should trigger findings")
	require.Equal(t, summarize(isolated), summarize(shared),
		"shared-compiler mode must produce the same findings as isolated mode")
}

// customInputRule fires only when its result references data read from the
// query's own InputData (data.expected_acl). If shared mode were to run it
// against the per-platform base store (which lacks this rule's InputData), the
// reference would be undefined and the rule would NOT fire — exactly the
// false-negative the custom-input guard prevents.
const customInputRule = `package datadog

DatadogPolicy contains result if {
	some name, i
	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.acl == data.expected_acl

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "acl matched the configured expected_acl",
		"keyActualValue": sprintf("acl is %s", [bucket.acl]),
	}
}
`

// TestInspect_SharedCompiler_CustomInputData is the regression guard for the
// review finding: a rule whose Rego reads its custom InputData must produce the
// SAME findings in shared mode as in isolated mode. Shared mode must fall back
// to the isolated per-query store for such rules instead of running them against
// the input-data-less base store.
func TestInspect_SharedCompiler_CustomInputData(t *testing.T) {
	root := t.TempDir()
	mainPath := filepath.Join(root, "main.tf")
	require.NoError(t, os.WriteFile(mainPath, []byte(`
resource "aws_s3_bucket" "b" {
  acl = "public-read"
}
`), 0o644))

	// The rule fires only if data.expected_acl == "public-read", which lives in
	// the rule's InputData (not in any library or base store).
	queries := []model.QueryMetadata{
		{Query: "custom_input_rule", Content: customInputRule, InputData: `{"expected_acl":"public-read"}`,
			Platform: "terraform", Metadata: map[string]interface{}{"id": "custom-input-rule"}, Aggregation: 1},
	}

	run := func(disableRuleIsolation bool) []model.Vulnerability {
		files := parseTerraform(t, mainPath)
		ins := newTestInspector(t, inspectorOpts{
			queries:              queries,
			repoPath:             root,
			vb:                   DefaultVulnerabilityBuilder,
			disableRuleIsolation: disableRuleIsolation,
		})
		vulns, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
		require.NoError(t, err)
		require.Empty(t, ins.GetFailedQueries(), "no query should fail")
		return vulns
	}

	isolated := run(false)
	shared := run(true)

	require.NotEmpty(t, isolated, "the rule should fire when its custom InputData is present")
	require.Equal(t, summarize(isolated), summarize(shared),
		"a custom-InputData rule must yield identical findings in shared mode (no false negative)")
}

// TestLoadSharedQueries_ExcludesCustomInput pins the guard directly: a rule with
// custom InputData must NOT be prepared by the shared compiler (it would use the
// input-data-less base store); it must be absent from the returned map so the
// worker falls back to the isolated LoadQuery. A static-input rule alongside it
// must still be served from the shared compiler.
func TestLoadSharedQueries_ExcludesCustomInput(t *testing.T) {
	platform := "terraform"
	static := staticQuery(platform, "static_rule", "DatadogPolicy contains result if { result := \"x\" }\n")
	custom := staticQuery(platform, "custom_rule", "DatadogPolicy contains result if { result := \"y\" }\n")
	custom.InputData = `{"expected_acl":"public-read"}`

	loader := newCacheTestLoader(t, platform, []model.QueryMetadata{static, custom})
	stores, _ := baseStoresFor(platform, "{}")

	shared := loader.loadSharedQueries(context.Background(), []model.QueryMetadata{static, custom}, stores)

	if _, ok := shared[0]; !ok {
		t.Errorf("static-input rule (index 0) should be served from the shared compiler")
	}
	if _, ok := shared[1]; ok {
		t.Errorf("custom-input rule (index 1) must be excluded from shared compilation so it falls back to isolated LoadQuery")
	}
}

// summarize reduces findings to a comparable, order-independent multiset of the
// fields a caller/SARIF actually consumes, so the comparison is robust to
// worker ordering.
func summarize(vulns []model.Vulnerability) map[string]int {
	m := make(map[string]int)
	for _, v := range vulns {
		key := v.QueryID + "|" + v.QueryName + "|" + v.ResourceType + "|" + v.ResourceName + "|" + v.KeyActualValue
		m[key]++
	}
	return m
}
