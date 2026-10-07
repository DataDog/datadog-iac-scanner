/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func singleCall(t *testing.T, src string) []tfeval.CallSite {
	t.Helper()
	return []tfeval.CallSite{{Body: parseBlockBody(t, src)}}
}

func TestModuleArgumentsReadInputsByIndexAndAsAWhole(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, `resource "t" "r" {
  a = var["acl"]
  b = local["via"]
  c = merge(var, {})
  d = var[local.key]
  e = local
  f = "literal"
}`),
		Scope: evaluatedScope(t, map[string]cty.Value{"acl": cty.StringVal("public-read")},
			"locals {\n  via = var.acl\n  key = \"acl\"\n}"),
		CallChain: singleCall(t, `module "m" {
  source = "./m"
  acl    = "public-read"
}`),
	}
	args := newModuleAttributionCache().resourceArguments(resource, "main.tf")
	requireCallerAt(t, args, 2, 3)
	requireCallerAt(t, args, 3, 3)
	requireControlAt(t, args, 4, model.ArgumentControlUnknown)
	requireControlAt(t, args, 5, model.ArgumentControlUnknown)
	requireControlAt(t, args, 6, model.ArgumentControlUnknown)
	requireControlAt(t, args, 7, model.ArgumentControlModule)
}

func TestModuleArgumentsOtherModuleOutputsAreNotSetByTheModule(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, `resource "t" "r" {
  cidr = module.net.cidr
}`),
		CallChain: singleCall(t, `module "m" {
  source = "./m"
}`),
	}
	args := newModuleAttributionCache().resourceArguments(resource, "main.tf")
	requireControlAt(t, args, 2, model.ArgumentControlUnknown)
}

func TestModuleArgumentsMemberLeftToItsDefault(t *testing.T) {
	body := parseBlockBody(t, `resource "t" "r" {
  mode = var.obj.mode
  whole = var.obj
  both  = [var.obj.mode, var.obj.size]
}`)
	for _, tt := range []struct {
		name string
		call string
		line int
		want model.ArgumentControl
	}{
		{"the caller passes the member", "obj = { mode = \"on\" }", 2, model.ArgumentControlCaller},
		{"the caller leaves the member to its default", "obj = {}", 2, model.ArgumentControlUnknown},
		{"the caller passes the member as null", "obj = { mode = null }", 2, model.ArgumentControlUnknown},
		{"the whole object is read", "obj = {}", 3, model.ArgumentControlCaller},
		{"two members of one object", "obj = { mode = \"on\", size = 1 }", 4, model.ArgumentControlCaller},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resource := &tfeval.ResolvedResource{
				Body:      body,
				Scope:     evaluatedScope(t, map[string]cty.Value{"obj": cty.EmptyObjectVal}, ""),
				CallChain: singleCall(t, "module \"m\" {\n  source = \"./m\"\n  "+tt.call+"\n}"),
			}
			args := newModuleAttributionCache().resourceArguments(resource, "main.tf")
			control, _ := controlAt(args, tt.line)
			require.Equal(t, tt.want, control)
		})
	}
}

func TestModuleArgumentsNullArgumentTakesModuleDefault(t *testing.T) {
	body := parseBlockBody(t, `resource "t" "r" {
  acl = var.acl
}`)
	call := "module \"m\" {\n  source = \"./m\"\n  acl    = null\n}"
	for _, tt := range []struct {
		name string
		acl  cty.Value
		want model.ArgumentControl
	}{
		{"the module default is used", cty.StringVal("private"), model.ArgumentControlUnknown},
		{"the module holds null too", cty.NullVal(cty.String), model.ArgumentControlCaller},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resource := &tfeval.ResolvedResource{
				Body:      body,
				Scope:     evaluatedScope(t, map[string]cty.Value{"acl": tt.acl}, ""),
				CallChain: singleCall(t, call),
			}
			args := newModuleAttributionCache().resourceArguments(resource, "main.tf")
			requireControlAt(t, args, 2, tt.want)
		})
	}
}

func TestModuleArgumentsSplitMultiLineValues(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, `resource "t" "r" {
  tags = {
    owner = var.owner
    team  = "platform"
    inner = {
      a = var.owner
      b = "x"
    }
  }
  list = [
    "first",
    var.owner,
  ]
}`),
		CallChain: singleCall(t, `module "m" {
  source = "./m"
  owner  = "me"
}`),
	}
	args := newModuleAttributionCache().resourceArguments(resource, "main.tf")
	requireCallerAt(t, args, 2, 3)
	requireCallerAt(t, args, 3, 3)
	requireControlAt(t, args, 4, model.ArgumentControlModule)
	requireCallerAt(t, args, 5, 3)
	requireCallerAt(t, args, 6, 3)
	requireControlAt(t, args, 7, model.ArgumentControlModule)
	requireControlAt(t, args, 11, model.ArgumentControlModule)
	requireCallerAt(t, args, 12, 3)
}

func TestModuleArgumentsEachFromMixedCollections(t *testing.T) {
	instance := func(body, key string, vars map[string]cty.Value) []model.ModuleArgument {
		resource := &tfeval.ResolvedResource{
			Body:  parseBlockBody(t, body),
			Scope: evaluatedScope(t, vars, ""),
			Iteration: map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{
				"key": cty.StringVal(key), "value": cty.StringVal("v"),
			})},
			CallChain: singleCall(t, "module \"m\" {\n  source = \"./m\"\n  a      = { y = \"1\" }\n  n      = \"dyn\"\n  names  = [\"n\"]\n}"),
		}
		return newModuleAttributionCache().resourceArguments(resource, "main.tf")
	}
	literal := "resource \"t\" \"r\" {\n  for_each = { k1 = var.a, k2 = \"lit\" }\n  x        = each.value\n  y        = each.key\n}"
	vars := map[string]cty.Value{"a": cty.StringVal("s")}
	args := instance(literal, "k1", vars)
	requireCallerAt(t, args, 3, 3)
	requireControlAt(t, args, 4, model.ArgumentControlModule)
	args = instance(literal, "k2", vars)
	requireControlAt(t, args, 3, model.ArgumentControlModule)
	requireControlAt(t, args, 4, model.ArgumentControlModule)

	merged := "resource \"t\" \"r\" {\n  for_each = merge(var.a, { z = \"1\" })\n  x        = each.key\n}"
	vars = map[string]cty.Value{"a": cty.ObjectVal(map[string]cty.Value{"y": cty.StringVal("1")})}
	requireCallerAt(t, instance(merged, "y", vars), 3, 3)
	requireControlAt(t, instance(merged, "z", vars), 3, model.ArgumentControlModule)

	set := "resource \"t\" \"r\" {\n  for_each = toset([\"fixed\", var.n])\n  x        = each.value\n}"
	vars = map[string]cty.Value{"n": cty.StringVal("dyn")}
	requireControlAt(t, instance(set, "fixed", vars), 3, model.ArgumentControlModule)
	requireCallerAt(t, instance(set, "dyn", vars), 3, 4)

	opaque := "resource \"t\" \"r\" {\n  for_each = toset(var.names)\n  x        = each.value\n}"
	requireCallerAt(t, instance(opaque, "n", map[string]cty.Value{"names": cty.SetVal([]cty.Value{cty.StringVal("n")})}), 3, 5)
}

func TestModuleAttributionCacheKeepsCallerScopesApart(t *testing.T) {
	cache := newModuleAttributionCache()
	outer := parseBlockBody(t, "module \"outer\" {\n  source = \"./o\"\n}")
	inner := parseBlockBody(t, "module \"inner\" {\n  source = \"./i\"\n}")
	first, second := &tfeval.ModuleScope{}, &tfeval.ModuleScope{}
	chain := func(scope *tfeval.ModuleScope) []tfeval.CallSite {
		return []tfeval.CallSite{{Body: outer}, {Body: inner, Caller: scope}}
	}
	a, _ := cache.chain(chain(first), true)
	b, _ := cache.chain(chain(second), true)
	again, _ := cache.chain(chain(first), true)
	require.NotSame(t, a, b)
	require.Same(t, a, again)
	byPath, _ := cache.chain(chain(first), false)
	samePath, _ := cache.chain(chain(second), false)
	require.Same(t, byPath, samePath)

	deep := make([]tfeval.CallSite, 20)
	for i := range deep {
		deep[i] = tfeval.CallSite{Body: outer}
	}
	node, ok := cache.chain(deep, true)
	require.True(t, ok)
	again, _ = cache.chain(deep, true)
	require.Same(t, node, again)
}

func TestModuleArgumentsTraceEachCallerScope(t *testing.T) {
	body := parseBlockBody(t, "resource \"t\" \"r\" {\n  size = var.size\n}")
	outer := parseBlockBody(t, "module \"outer\" {\n  source = \"./o\"\n  a = \"x\"\n  b = \"y\"\n}")
	inner := parseBlockBody(t, "module \"inner\" {\n  source = \"./i\"\n  size = var.a != null ? var.a : var.b\n}")
	scope := func(a cty.Value) *tfeval.ModuleScope {
		return evaluatedScope(t, map[string]cty.Value{"a": a, "b": cty.StringVal("y")}, "")
	}
	resource := func(caller *tfeval.ModuleScope) *tfeval.ResolvedResource {
		return &tfeval.ResolvedResource{
			Body: body, Scope: &tfeval.ModuleScope{},
			CallChain: []tfeval.CallSite{{Body: outer}, {Body: inner, Caller: caller}},
		}
	}
	cache := newModuleAttributionCache()
	requireCallerAt(t, cache.resourceArguments(resource(scope(cty.StringVal("x"))), "main.tf"), 2, 3)
	requireCallerAt(t, cache.resourceArguments(resource(scope(cty.NullVal(cty.String))), "main.tf"), 2, 4)
}

func TestModuleArgumentsAnalyzeEachInstanceOnce(t *testing.T) {
	body := parseBlockBody(t, "resource \"t\" \"r\" {\n  count = 3\n  acl = var.on ? var.a : var.b\n  x = count.index == 0 ? var.a : var.b\n}")
	scope := evaluatedScope(t, map[string]cty.Value{"on": cty.True, "a": cty.StringVal("a"), "b": cty.StringVal("b")}, "")
	cache := newModuleAttributionCache()
	for i := 0; i < 3; i++ {
		resource := &tfeval.ResolvedResource{
			Body: body, Scope: scope,
			Iteration: map[string]cty.Value{"count": cty.ObjectVal(map[string]cty.Value{"index": cty.NumberIntVal(int64(i))})},
			CallChain: singleCall(t, "module \"m\" {\n  source = \"./m\"\n}"),
		}
		cache.resourceAttributes(resource)
		cache.resourceAttributes(resource)
	}
	require.Len(t, cache.attributes, 3)
}

func TestModuleAttributionForResourceUsesNarrowestArgument(t *testing.T) {
	attrs := map[string]*model.ModuleAttribution{
		moduleAttributionKey("t", 1, 1): {
			Arguments: []model.ModuleArgument{
				{LineStart: 2, LineEnd: 6, Control: model.ArgumentControlCaller, CallSite: model.SourceLocation{LineStart: 9}},
				{LineStart: 4, LineEnd: 4, Control: model.ArgumentControlModule},
			},
		},
	}
	vuln := func(line int) *model.Vulnerability {
		v := &model.Vulnerability{ResourceType: "t", Line: line}
		v.BlockLocation.Start.Line, v.BlockLocation.Start.Col = 1, 1
		return v
	}
	inside := moduleAttributionForResource(attrs, vuln(4))
	require.Equal(t, model.ArgumentControlModule, inside.ArgumentControl)
	outside := moduleAttributionForResource(attrs, vuln(3))
	require.Equal(t, model.ArgumentControlCaller, outside.ArgumentControl)
	require.Equal(t, 9, outside.CallSite.LineStart)
}

func TestModuleArgumentsSplitLiteralsNestedInCalls(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, `resource "t" "r" {
  tags = merge(var.tags, {
    Env = "prod"
  })
  cidr = concat(var.c, [
    "0.0.0.0/0",
  ])
}`),
		CallChain: singleCall(t, `module "m" {
  source = "./m"
  tags   = {}
  c      = []
}`),
	}
	args := newModuleAttributionCache().resourceArguments(resource, "main.tf")
	requireCallerAt(t, args, 2, 3)
	requireControlAt(t, args, 3, model.ArgumentControlModule)
	requireCallerAt(t, args, 5, 4)
	requireControlAt(t, args, 6, model.ArgumentControlModule)
}

func TestModuleArgumentsMixedCollectionsAreAmbiguousWithoutAnInstance(t *testing.T) {
	// The evaluator does not expand a module call's for_each, so a resource
	// reached through it cannot tell which entry it came from.
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, "resource \"t\" \"r\" {\n  acl = var.acl\n}"),
		CallChain: []tfeval.CallSite{
			{Body: parseBlockBody(t, "module \"outer\" {\n  source = \"./o\"\n  x      = \"v\"\n}")},
			{Body: parseBlockBody(t, "module \"inner\" {\n  source   = \"./i\"\n  for_each = merge({ a = var.x }, { b = \"lit\" })\n  acl      = each.value\n}"),
				Caller: evaluatedScope(t, map[string]cty.Value{"x": cty.StringVal("v")}, "")},
		},
	}
	requireControlAt(t, newModuleAttributionCache().resourceArguments(resource, "main.tf"), 2, model.ArgumentControlUnknown)

	resource.CallChain[1].Body = parseBlockBody(t, "module \"inner\" {\n  source   = \"./i\"\n  for_each = { a = var.x, b = var.x }\n  acl      = each.value\n}")
	requireCallerAt(t, newModuleAttributionCache().resourceArguments(resource, "main.tf"), 2, 3)
}

func TestModuleArgumentsEachWithNumericKeys(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body:  parseBlockBody(t, "resource \"t\" \"r\" {\n  for_each = { a = var.x, 1 = \"lit\" }\n  acl      = each.value\n}"),
		Scope: evaluatedScope(t, map[string]cty.Value{"x": cty.StringVal("v")}, ""),
		Iteration: map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{
			"key": cty.StringVal("1"), "value": cty.StringVal("lit"),
		})},
		CallChain: singleCall(t, "module \"m\" {\n  source = \"./m\"\n  x      = \"v\"\n}"),
	}
	requireControlAt(t, newModuleAttributionCache().resourceArguments(resource, "main.tf"), 3, model.ArgumentControlModule)
}

func TestModuleArgumentsIndexEachCollectionOnce(t *testing.T) {
	cache := newModuleAttributionCache()
	body := parseBlockBody(t, "resource \"t\" \"r\" {\n  for_each = { a = var.x, b = var.x, c = \"lit\" }\n  acl      = each.value\n}")
	scope := evaluatedScope(t, map[string]cty.Value{"x": cty.StringVal("v")}, "")
	for _, key := range []string{"a", "b", "c"} {
		cache.resourceAttributes(&tfeval.ResolvedResource{
			Body: body, Scope: scope,
			Iteration: map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{
				"key": cty.StringVal(key), "value": cty.StringVal("v"),
			})},
		})
	}
	require.Len(t, cache.eachIndexes, 1)
}

func TestValueAnalyzerEvaluableNeedsEveryReferenceKnown(t *testing.T) {
	parse := func(src string) hclsyntax.Expression {
		expr, diags := hclsyntax.ParseExpression([]byte(src), "test.tf", hcl.InitialPos)
		require.False(t, diags.HasErrors(), diags.Error())
		return expr
	}
	a := newModuleAttributionCache().analyzer(evaluatedScope(t, map[string]cty.Value{
		"a": cty.StringVal("x"), "m": cty.EmptyObjectVal,
	}, ""), nil)
	for src, want := range map[string]bool{
		`var.a == "x"`:                       true,
		`var.a == data.x.y`:                  false,
		`lookup(var.m, aws_x.y.id)`:          false,
		`[for v in var.m : v]`:               true,
		`[for var in var.m : var]`:           true,
		`[for each in each.value : each]`:    false,
		`[for v in var.m : v][0] == aws.x.y`: false,
	} {
		require.Equal(t, want, a.evaluable(parse(src)), src)
	}
}

func TestModuleArgumentsTryOverUnevaluableLookupIsNotPinned(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, "resource \"t\" \"r\" {\n  x = try(lookup(var.m, aws_x.y.id), var.d)\n}"),
		Scope: evaluatedScope(t, map[string]cty.Value{
			"m": cty.MapValEmpty(cty.String), "d": cty.StringVal("v"),
		}, ""),
		CallChain: singleCall(t, "module \"m\" {\n  source = \"./m\"\n  m      = {}\n  d      = \"v\"\n}"),
	}
	args := newModuleAttributionCache().resourceArguments(resource, "main.tf")
	requireControlAt(t, args, 2, model.ArgumentControlUnknown)
}

func TestModuleArgumentsMixedDynamicCollectionsAreAmbiguous(t *testing.T) {
	for _, forEach := range []string{
		`concat(var.rules, [{ port = 22 }])`,
		`flatten([var.rules, [{ port = 22 }]])`,
		`var.on ? var.rules : [{ port = 22 }]`,
		`merge(var.rules, { ssh = { port = 22 } })`,
	} {
		t.Run(forEach, func(t *testing.T) {
			resource := &tfeval.ResolvedResource{
				Body:      parseBlockBody(t, "resource \"t\" \"r\" {\n  dynamic \"ingress\" {\n    for_each = "+forEach+"\n    content {\n      port = ingress.value.port\n    }\n  }\n}"),
				CallChain: singleCall(t, "module \"m\" {\n  source = \"./m\"\n  rules  = []\n  on     = true\n}"),
			}
			args := newModuleAttributionCache().resourceArguments(resource, "main.tf")
			requireControlAt(t, args, 5, model.ArgumentControlUnknown)
		})
	}
	resource := &tfeval.ResolvedResource{
		Body:      parseBlockBody(t, "resource \"t\" \"r\" {\n  dynamic \"ingress\" {\n    for_each = concat(var.rules, var.more)\n    content {\n      port = ingress.value.port\n    }\n  }\n}"),
		CallChain: singleCall(t, "module \"m\" {\n  source = \"./m\"\n  rules  = []\n  more   = []\n}"),
	}
	args := newModuleAttributionCache().resourceArguments(resource, "main.tf")
	requireControlAt(t, args, 5, model.ArgumentControlUnknown)
}

func TestModuleArgumentsLargeForEachStaysCheap(t *testing.T) {
	var items strings.Builder
	const instances = 3000
	for i := 0; i < instances; i++ {
		fmt.Fprintf(&items, "    k%d = var.x\n", i)
	}
	body := parseBlockBody(t, "resource \"t\" \"r\" {\n  for_each = {\n"+items.String()+"  }\n  acl = each.value\n}")
	scope := evaluatedScope(t, map[string]cty.Value{"x": cty.StringVal("v")}, "")
	chain := singleCall(t, "module \"m\" {\n  source = \"./m\"\n  x      = \"v\"\n}")
	cache := newModuleAttributionCache()
	start := time.Now()
	for i := 0; i < instances; i++ {
		args := cache.resourceArguments(&tfeval.ResolvedResource{
			Body: body, Scope: scope, CallChain: chain,
			Iteration: map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{
				"key": cty.StringVal(fmt.Sprintf("k%d", i)), "value": cty.StringVal("v"),
			})},
		}, "main.tf")
		require.LessOrEqual(t, len(args), 3, "an instance keeps the lines of the collection as a whole")
	}
	require.Less(t, time.Since(start), 5*time.Second)
	require.Len(t, cache.eachIndexes, 1)
}

func TestModuleArgumentsMixedCollectionThroughLocal(t *testing.T) {
	scope := evaluatedScope(t, map[string]cty.Value{
		"a": cty.ObjectVal(map[string]cty.Value{"a": cty.StringVal("1")}),
	}, "locals {\n  m = merge(var.a, { x = \"lit\" })\n  n = local.m\n}")
	instance := func(key string) []model.ModuleArgument {
		return newModuleAttributionCache().resourceArguments(&tfeval.ResolvedResource{
			Body:  parseBlockBody(t, "resource \"t\" \"r\" {\n  for_each = local.n\n  name     = each.key\n}"),
			Scope: scope,
			Iteration: map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{
				"key": cty.StringVal(key), "value": cty.StringVal("v"),
			})},
			CallChain: singleCall(t, "module \"m\" {\n  source = \"./m\"\n  a      = { a = \"1\" }\n}"),
		}, "main.tf")
	}
	requireCallerAt(t, instance("a"), 3, 3)
	requireControlAt(t, instance("x"), 3, model.ArgumentControlModule)
}

func TestModuleArgumentsDuplicateSetElementsAreAmbiguous(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body:  parseBlockBody(t, "resource \"t\" \"r\" {\n  for_each = toset([\"a\", var.x])\n  name     = each.value\n}"),
		Scope: evaluatedScope(t, map[string]cty.Value{"x": cty.StringVal("a")}, ""),
		Iteration: map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{
			"key": cty.StringVal("a"), "value": cty.StringVal("a"),
		})},
		CallChain: singleCall(t, "module \"m\" {\n  source = \"./m\"\n  x      = \"a\"\n}"),
	}
	requireControlAt(t, newModuleAttributionCache().resourceArguments(resource, "main.tf"), 3, model.ArgumentControlUnknown)
}

func TestModuleArgumentsMemberThroughMixedIntermediateArgument(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, "resource \"t\" \"r\" {\n  mode = var.obj.attr\n}"),
		CallChain: []tfeval.CallSite{
			{Body: parseBlockBody(t, "module \"outer\" {\n  source = \"./o\"\n  base   = { mode = \"a\" }\n}")},
			{
				Body:   parseBlockBody(t, "module \"inner\" {\n  source = \"./i\"\n  obj    = merge(var.base, { attr = \"lit\" })\n}"),
				Caller: evaluatedScope(t, map[string]cty.Value{"base": cty.ObjectVal(map[string]cty.Value{"mode": cty.StringVal("a")})}, ""),
			},
		},
	}
	requireControlAt(t, newModuleAttributionCache().resourceArguments(resource, "main.tf"), 2, model.ArgumentControlUnknown)
}

func TestModuleArgumentsEvaluateCallArgumentsOnce(t *testing.T) {
	cache := newModuleAttributionCache()
	chain := singleCall(t, "module \"m\" {\n  source = \"./m\"\n  obj    = { mode = \"on\" }\n}")
	body := parseBlockBody(t, "resource \"t\" \"r\" {\n  a = var.obj.mode\n  b = var.obj.mode\n  c = var.obj.mode\n}")
	scope := evaluatedScope(t, map[string]cty.Value{"obj": cty.EmptyObjectVal}, "")
	for i := 0; i < 3; i++ {
		cache.resourceArguments(&tfeval.ResolvedResource{Body: body, Scope: scope, CallChain: chain}, "main.tf")
	}
	require.Len(t, cache.argumentValues, 1)
}

func TestModuleArgumentsEmptyOperandsDoNotMixCollections(t *testing.T) {
	call := "module \"m\" {\n  source = \"./m\"\n  list   = []\n  m      = {}\n  tags   = {}\n}"
	for _, tt := range []struct {
		name, expr string
		want       model.ArgumentControl
	}{
		{"empty list literal", "concat(var.list, [])", model.ArgumentControlCaller},
		{"empty local", "merge(var.m, local.none)", model.ArgumentControlCaller},
		{"module-defined entries", "merge(var.m, { a = 1 })", model.ArgumentControlUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resource := &tfeval.ResolvedResource{
				Body: parseBlockBody(t, "resource \"t\" \"r\" {\n  dynamic \"ingress\" {\n    for_each = "+tt.expr+"\n    content {\n      port = ingress.value\n    }\n  }\n}"),
				Scope: evaluatedScope(t, map[string]cty.Value{
					"list": cty.EmptyTupleVal, "m": cty.EmptyObjectVal,
				}, "locals {\n  none = {}\n}"),
				CallChain: singleCall(t, call),
			}
			args := newModuleAttributionCache().resourceArguments(resource, "main.tf")
			control, _ := controlAt(args, 5)
			require.Equal(t, tt.want, control)
		})
	}
}

func TestModuleArgumentsNullMapMemberIsLeftToItsDefault(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body:      parseBlockBody(t, "resource \"t\" \"r\" {\n  mode = var.settings.mode\n}"),
		Scope:     evaluatedScope(t, map[string]cty.Value{"settings": cty.MapValEmpty(cty.String)}, ""),
		CallChain: singleCall(t, "module \"m\" {\n  source   = \"./m\"\n  settings = tomap({ mode = null })\n}"),
	}
	requireControlAt(t, newModuleAttributionCache().resourceArguments(resource, "main.tf"), 2, model.ArgumentControlUnknown)
}

func TestModuleArgumentsSelfReferencingLocalsTerminate(t *testing.T) {
	scope := evaluatedScope(t, map[string]cty.Value{"a": cty.ListVal([]cty.Value{cty.StringVal("p")})},
		"locals {\n  l = concat(local.l, var.a, [\"x\"])\n  m = merge(local.m, { k = var.a })\n}")
	for _, collection := range []string{"toset(local.l)", "local.m"} {
		require.NotPanics(t, func() {
			newModuleAttributionCache().resourceArguments(&tfeval.ResolvedResource{
				Body:  parseBlockBody(t, "resource \"t\" \"r\" {\n  for_each = "+collection+"\n  name     = each.key\n}"),
				Scope: scope,
				Iteration: map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{
					"key": cty.StringVal("x"), "value": cty.StringVal("x"),
				})},
				CallChain: singleCall(t, "module \"m\" {\n  source = \"./m\"\n  a      = [\"p\"]\n}"),
			}, "main.tf")
		})
	}
}

func TestModuleArgumentsBranchingLocalsStayLinear(t *testing.T) {
	var locals strings.Builder
	locals.WriteString("locals {\n  l0 = concat(var.a, [\"x\"])\n")
	const depth = 40
	for i := 1; i <= depth; i++ {
		fmt.Fprintf(&locals, "  l%d = distinct(concat(local.l%d, local.l%d))\n", i, i-1, i-1)
	}
	locals.WriteString("}")
	scope := evaluatedScope(t, map[string]cty.Value{"a": cty.ListVal([]cty.Value{cty.StringVal("p")})}, locals.String())
	start := time.Now()
	newModuleAttributionCache().resourceArguments(&tfeval.ResolvedResource{
		Body:      parseBlockBody(t, fmt.Sprintf("resource \"t\" \"r\" {\n  for_each = toset(local.l%d)\n  name     = each.key\n}", depth)),
		Scope:     scope,
		CallChain: singleCall(t, "module \"m\" {\n  source = \"./m\"\n  a      = [\"p\"]\n}"),
	}, "main.tf")
	require.Less(t, time.Since(start), 2*time.Second)
}

func TestModuleArgumentsMixedForExpressionIsAmbiguous(t *testing.T) {
	scope := evaluatedScope(t, map[string]cty.Value{
		"a": cty.ObjectVal(map[string]cty.Value{"a": cty.StringVal("1")}),
	}, "")
	instance := func(key string) []model.ModuleArgument {
		return newModuleAttributionCache().resourceArguments(&tfeval.ResolvedResource{
			Body:  parseBlockBody(t, "resource \"t\" \"r\" {\n  for_each = { for k, v in merge(var.a, { z = \"1\" }) : k => v }\n  name     = each.key\n}"),
			Scope: scope,
			Iteration: map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{
				"key": cty.StringVal(key), "value": cty.StringVal("1"),
			})},
			CallChain: singleCall(t, "module \"m\" {\n  source = \"./m\"\n  a      = { a = \"1\" }\n}"),
		}, "main.tf")
	}
	for _, key := range []string{"a", "z"} {
		for _, arg := range instance(key) {
			require.NotEqual(t, model.ArgumentControlCaller, arg.Control,
				"instance %q cannot be told apart from the caller's entries", key)
		}
	}
}

func TestModuleArgumentsMixedResultDoesNotDependOnInstanceOrder(t *testing.T) {
	scope := evaluatedScope(t, map[string]cty.Value{"a": cty.StringVal("s")}, "")
	body := parseBlockBody(t, "resource \"t\" \"r\" {\n  for_each = { k1 = var.a, k2 = \"lit\" }\n"+
		"  dynamic \"d\" {\n    for_each = [each.value, \"x\"]\n    content {\n      p = d.value\n    }\n  }\n}")
	analyze := func(cache *moduleAttributionCache, key, value string) []model.ModuleArgument {
		return cache.resourceArguments(&tfeval.ResolvedResource{
			Body: body, Scope: scope,
			Iteration: map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{
				"key": cty.StringVal(key), "value": cty.StringVal(value),
			})},
			CallChain: singleCall(t, "module \"m\" {\n  source = \"./m\"\n  a      = \"s\"\n}"),
		}, "main.tf")
	}
	for _, order := range [][2]string{{"k1", "k2"}, {"k2", "k1"}} {
		cache := newModuleAttributionCache()
		results := map[string][]model.ModuleArgument{}
		for _, key := range order {
			value := "s"
			if key == "k2" {
				value = "lit"
			}
			results[key] = analyze(cache, key, value)
		}
		for key, args := range results {
			for _, arg := range args {
				require.NotEqual(t, model.ArgumentControlCaller, arg.Control, "instance %s in order %v", key, order)
			}
		}
	}
}

func TestModuleArgumentsForExpressionMixesKeyAndValueOrigins(t *testing.T) {
	scope := evaluatedScope(t, map[string]cty.Value{
		"m": cty.ObjectVal(map[string]cty.Value{"a": cty.StringVal("1")}),
	}, "")
	for _, collection := range []string{
		"{ for k, v in var.m : k => \"lit\" }",
		"{ for x in [\"a\", \"b\"] : x => var.m }",
	} {
		args := newModuleAttributionCache().resourceArguments(&tfeval.ResolvedResource{
			Body:  parseBlockBody(t, "resource \"t\" \"r\" {\n  for_each = "+collection+"\n  name     = each.value\n}"),
			Scope: scope,
			Iteration: map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{
				"key": cty.StringVal("a"), "value": cty.StringVal("lit"),
			})},
			CallChain: singleCall(t, "module \"m\" {\n  source = \"./m\"\n  m      = { a = \"1\" }\n}"),
		}, "main.tf")
		for _, arg := range args {
			require.NotEqual(t, model.ArgumentControlCaller, arg.Control, collection)
		}
	}
}

func TestValueAnalyzerEvaluableWalksNestedForExpressionsOnce(t *testing.T) {
	expr := "var.m"
	for i := 0; i < 24; i++ {
		expr = "{ for k, v in " + expr + " : k => v }"
	}
	parsed, diags := hclsyntax.ParseExpression([]byte(expr), "test.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors())
	analyzer := newModuleAttributionCache().analyzer(evaluatedScope(t, map[string]cty.Value{"m": cty.EmptyObjectVal}, ""), nil)
	start := time.Now()
	require.True(t, analyzer.evaluable(parsed))
	require.Less(t, time.Since(start), 2*time.Second)
}
