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
