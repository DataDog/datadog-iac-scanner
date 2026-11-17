/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package schedule

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

func TestHarvestKnownBlockTypeKeysBeyondGeneralExpansionLimit(t *testing.T) {
	var supported strings.Builder
	const typeCount = 80
	for i := range typeCount {
		fmt.Fprintf(&supported, `"resource_%03d": "",`, i)
	}
	lib := `package generic.terraform
import rego.v1
supported := {` + supported.String() + `}
blocks(type) := object.get(input._dd, ["blocks", "resource", type], [])
`
	rule := `package datadog
import rego.v1
import data.generic.terraform as tf
DatadogPolicy contains result if {
	some typ, _ in tf.supported
	some block in tf.blocks(typ)
	result := {"id": block}
}
`
	c := compileModules(t, map[string]string{"lib.rego": lib, "rule.rego": rule})
	got := NewHarvester(c, Options{}).Harvest(ast.MustParseRef("data.datadog.DatadogPolicy"))
	require.False(t, got.AlwaysRun, "reasons: %v", got.Reasons)
	require.Equal(t, Anchored, got.Class, got.ClassReason)
	require.Len(t, got.Types, typeCount)
	for i := range typeCount {
		require.Contains(t, got.Types, TypeKey{Kind: KindResource, Type: fmt.Sprintf("resource_%03d", i)})
	}
}

func TestIndexStepsKeepsLargeKnownTypeSet(t *testing.T) {
	terms := make([]*ast.Term, maxExpand+1)
	for i := range terms {
		terms[i] = ast.StringTerm(fmt.Sprintf("resource_%03d", i))
	}
	got := steps(constVal(terms...))
	require.Len(t, got, maxExpand+1)
	require.Equal(t, terms, got)
}

func TestIndexBoundsCartesianExpansion(t *testing.T) {
	path := inputPath{ast.StringTerm("_dd"), ast.StringTerm("blocks"), ast.StringTerm(KindResource)}
	paths := make([]inputPath, maxExpand/2+1)
	for i := range paths {
		paths[i] = slices.Clone(path)
	}
	keys := constVal(ast.StringTerm("resource_a"), ast.StringTerm("resource_b"))
	f := &frame{eff: newEffects()}
	_ = f.index(absVal{paths: paths}, keys, true)
	require.NotEmpty(t, f.eff.dynamic, "large path-by-key products fall back to the conservative wildcard")
	require.Empty(t, f.eff.types)
}

func compileModules(t *testing.T, modules map[string]string) *ast.Compiler {
	t.Helper()
	parsed := make(map[string]*ast.Module, len(modules))
	for path, src := range modules {
		m, err := ast.ParseModule(path, src)
		require.NoError(t, err, path)
		parsed[path] = m
	}
	c := ast.NewCompiler()
	c.Compile(parsed)
	require.False(t, c.Failed(), "%v", c.Errors)
	return c
}

func TestHarvestSimpleBlocksStaysAnchored(t *testing.T) {
	c := compileModules(t, map[string]string{
		"lib.rego": `package generic.terraform
import rego.v1
_dd := input._dd if is_object(input._dd) else := {}
blocks_complete if object.get(_dd, "blocks_complete", true)
blocks(type) := object.get(_dd, ["blocks", "resource", type], [])
`,
		"rule.rego": `package datadog
import rego.v1
import data.generic.terraform as tf
DatadogPolicy contains result if {
	some bucket in tf.blocks("aws_s3_bucket")
	result := {"id": bucket}
}
`,
	})
	got := NewHarvester(c, Options{}).Harvest(ast.MustParseRef("data.datadog.DatadogPolicy"))
	require.False(t, got.AlwaysRun, "reasons: %v", got.Reasons)
	require.Equal(t, Anchored, got.Class, got.ClassReason)
	require.Equal(t, []TypeKey{{Kind: KindResource, Type: "aws_s3_bucket"}}, got.Types)
}

func TestHarvestNestedStaysTyped(t *testing.T) {
	c := compileModules(t, map[string]string{
		"lib.rego": `package generic.terraform
import rego.v1
_dd := input._dd if is_object(input._dd) else := {}
blocks(type) := object.get(_dd, ["blocks", "resource", type], [])
_meta(block) := block._dd_meta if is_object(block._dd_meta) else := {}
nested(block, name) := object.get(object.get(_dd, "nested", {}), [_meta(block).id, name], [])
`,
		"rule.rego": `package datadog
import rego.v1
import data.generic.terraform as tf
DatadogPolicy contains result if {
	some sg in tf.blocks("aws_security_group")
	some ingress in tf.nested(sg, "ingress")
	ingress.cidr_blocks[_] == "0.0.0.0/0"
	result := {"id": sg}
}
`,
	})
	got := NewHarvester(c, Options{}).Harvest(ast.MustParseRef("data.datadog.DatadogPolicy"))
	require.False(t, got.AlwaysRun, "reasons: %v", got.Reasons)
	require.Equal(t, Anchored, got.Class, got.ClassReason)
	require.Equal(t, []TypeKey{{Kind: KindResource, Type: "aws_security_group"}}, got.Types)
}

func TestHarvestBlocksCompleteIsMetadata(t *testing.T) {
	c := compileModules(t, map[string]string{
		"lib.rego": `package generic.terraform
import rego.v1
_dd := input._dd if is_object(input._dd) else := {}
blocks_complete if object.get(_dd, "blocks_complete", true)
blocks(type) := object.get(_dd, ["blocks", "resource", type], [])
no_blocks(type) if {
	blocks_complete
	count(blocks(type)) == 0
}
`,
		"rule.rego": `package datadog
import rego.v1
import data.generic.terraform as tf
DatadogPolicy contains result if {
	tf.no_blocks("aws_s3_bucket")
	result := {"absent": true}
}
`,
	})
	got := NewHarvester(c, Options{}).Harvest(ast.MustParseRef("data.datadog.DatadogPolicy"))
	require.False(t, got.AlwaysRun, "reasons: %v", got.Reasons)
	require.Contains(t, got.Types, TypeKey{Kind: KindResource, Type: "aws_s3_bucket"})
}

func TestHarvestElseBranches(t *testing.T) {
	const lib = `package generic.terraform
import rego.v1
blocks(type) := object.get(input._dd, ["blocks", "resource", type], [])
related(block, type, path) := object.get(input._dd, ["related", block._dd_meta.id, type, path], [])
`
	for _, tc := range []struct {
		name, elseBody string
		unknownBuiltin bool
	}{
		{name: "another_resource_type", elseBody: `some queue in tf.blocks("aws_sqs_queue")
out := [{"type": "sqs"}]`},
		{name: "relation", elseBody: `some bucket in tf.blocks("aws_s3_bucket")
some related in tf.related(bucket, "aws_sqs_queue", "bucket")
out := [{"type": "related"}]`},
		{name: "unknown_builtin", elseBody: `out := []`, unknownBuiltin: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := `package datadog
import rego.v1
import data.generic.terraform as tf
DatadogPolicy := out if {
	some bucket in tf.blocks("aws_s3_bucket")
	out := [{"type": "s3"}]
} else := out if {
	` + tc.elseBody + `
}
`
			c := compileModules(t, map[string]string{"lib.rego": lib, "rule.rego": policy})
			if tc.unknownBuiltin {
				body, err := ast.ParseBody("missing_builtin()")
				require.NoError(t, err)
				c.GetRulesExact(ast.MustParseRef("data.datadog.DatadogPolicy"))[0].Else.Body = body
			}
			got := NewHarvester(c, Options{}).Harvest(ast.MustParseRef("data.datadog.DatadogPolicy"))
			switch tc.name {
			case "another_resource_type":
				queue := TypeKey{Kind: KindResource, Type: "aws_sqs_queue"}
				require.Contains(t, got.Types, bucket)
				require.Contains(t, got.Types, queue)
				require.False(t, got.AlwaysRun, "reasons: %v", got.Reasons)
				plan := NewPlan([]Rule{got}, Roots{
					"s3":  {bucket: {Blocks: 1}},
					"sqs": {queue: {Blocks: 1}},
				}, PlanOptions{})
				require.Empty(t, plan.Skipped)
			case "relation":
				require.True(t, got.Relations)
				require.Equal(t, Relational, got.Class)
			case "unknown_builtin":
				require.True(t, got.AlwaysRun, "reasons: %v", got.Reasons)
				require.Contains(t, got.Reasons[0], "unknown builtin missing_builtin")
			}
		})
	}
}
