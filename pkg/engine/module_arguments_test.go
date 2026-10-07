/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func parseBlockBody(t *testing.T, src string) *hclsyntax.Body {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(src), "test.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	body, ok := file.Body.(*hclsyntax.Body)
	require.True(t, ok)
	require.Len(t, body.Blocks, 1)
	return body.Blocks[0].Body
}

func parseLocals(t *testing.T, src string) map[string]hclsyntax.Expression {
	t.Helper()
	body := parseBlockBody(t, src)
	locals := make(map[string]hclsyntax.Expression, len(body.Attributes))
	for name, attr := range body.Attributes {
		locals[name] = attr.Expr
	}
	return locals
}

// evaluatedScope is a module scope with the given input values and its locals
// evaluated from them, as the evaluator leaves it.
func evaluatedScope(t *testing.T, vars map[string]cty.Value, localsSrc string) *tfeval.ModuleScope {
	t.Helper()
	scope := &tfeval.ModuleScope{Var: cty.ObjectVal(vars), Local: cty.EmptyObjectVal}
	if localsSrc == "" {
		return scope
	}
	scope.Locals = parseLocals(t, localsSrc)
	values := map[string]cty.Value{}
	ctx := &hcl.EvalContext{
		Variables: map[string]cty.Value{"var": scope.Var},
		Functions: functions.TerraformFuncs,
	}
	for range scope.Locals {
		ctx.Variables["local"] = cty.ObjectVal(values)
		for name, expr := range scope.Locals {
			if v, diags := expr.Value(ctx); !diags.HasErrors() {
				values[name] = v
			}
		}
	}
	scope.Local = cty.ObjectVal(values)
	return scope
}

// controlAt returns who controls the value on line, and the argument setting
// it when the caller does. A line no argument covers reads no module input.
func controlAt(args []model.ModuleArgument, line int) (model.ArgumentControl, model.SourceLocation) {
	for _, arg := range args {
		if line >= arg.LineStart && line <= arg.LineEnd {
			return arg.Control, arg.CallSite
		}
	}
	return model.ArgumentControlModule, model.SourceLocation{}
}

func requireCallerAt(t *testing.T, args []model.ModuleArgument, line, argumentLine int) {
	t.Helper()
	control, location := controlAt(args, line)
	require.Equal(t, model.ArgumentControlCaller, control, "line %d", line)
	require.Equal(t, argumentLine, location.LineStart, "line %d", line)
}

func requireControlAt(t *testing.T, args []model.ModuleArgument, line int, want model.ArgumentControl) {
	t.Helper()
	control, _ := controlAt(args, line)
	require.Equal(t, want, control, "line %d", line)
}

func TestModuleArgumentsTraceDirectCall(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, `resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = var.local_policy == "" ? data.aws_iam_policy_document.doc.json : var.local_policy
  tags   = merge(var.tags, var.extra_tags)
  acl    = var.acl
}`),
		Scope: evaluatedScope(t, map[string]cty.Value{
			"local_policy": cty.StringVal(`{"Statement":[]}`),
			"tags":         cty.EmptyObjectVal,
			"extra_tags":   cty.EmptyObjectVal,
			"acl":          cty.NullVal(cty.String),
		}, ""),
		CallChain: []tfeval.CallSite{{
			Body: parseBlockBody(t, `module "bucket" {
  source       = "git::https://github.com/acme/modules.git//bucket"
  bucket_name  = "example"
  local_policy = file("policy.json")
  tags         = {}
  extra_tags   = {}
}`),
		}},
	}

	args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")

	control, policy := controlAt(args, 3)
	require.Equal(t, model.ArgumentControlCaller, control)
	require.Equal(t, model.SourceLocation{
		Filename: "stack/main.tf", LineStart: 4, LineEnd: 4, ColumnStart: 3, ColumnEnd: 37,
	}, policy)
	requireControlAt(t, args, 2, model.ArgumentControlModule)
	requireControlAt(t, args, 4, model.ArgumentControlUnknown)
	requireControlAt(t, args, 5, model.ArgumentControlUnknown)
}

// Each case reads acl on line 2 of the resource; the call sets its argument on
// line 3.
func TestModuleArgumentsResolveChoicesWithEvaluatedValues(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		vars     map[string]cty.Value
		argument string
		locals   string
		want     model.ArgumentControl
	}{
		{
			name:     "coalesce falls back to a module local when the caller passes null",
			expr:     `coalesce(var.acl, local.default_acl)`,
			vars:     map[string]cty.Value{"acl": cty.NullVal(cty.String)},
			argument: `acl = null`,
			locals:   "locals {\n  default_acl = \"public-read\"\n}",
			want:     model.ArgumentControlUnknown,
		},
		{
			name:     "coalesce keeps the caller value it selects",
			expr:     `coalesce(var.acl, local.default_acl)`,
			vars:     map[string]cty.Value{"acl": cty.StringVal("public-read")},
			argument: `acl = "public-read"`,
			locals:   "locals {\n  default_acl = \"private\"\n}",
			want:     model.ArgumentControlCaller,
		},
		{
			name:     "coalesce skips an empty string",
			expr:     `coalesce(var.acl, "public-read")`,
			vars:     map[string]cty.Value{"acl": cty.StringVal("")},
			argument: `acl = ""`,
			want:     model.ArgumentControlUnknown,
		},
		{
			name:     "a conditional choosing a module default",
			expr:     `var.policy == "" ? data.aws_iam_policy_document.default.json : var.policy`,
			vars:     map[string]cty.Value{"policy": cty.StringVal("")},
			argument: `policy = ""`,
			want:     model.ArgumentControlUnknown,
		},
		{
			name:     "a conditional choosing the caller value",
			expr:     `var.policy == "" ? data.aws_iam_policy_document.default.json : var.policy`,
			vars:     map[string]cty.Value{"policy": cty.StringVal(`{"Statement":[]}`)},
			argument: `policy = file("policy.json")`,
			want:     model.ArgumentControlCaller,
		},
		{
			name:     "a module literal chosen by a caller toggle",
			expr:     `var.public ? "public-read" : "private"`,
			vars:     map[string]cty.Value{"public": cty.True},
			argument: `public = true`,
			want:     model.ArgumentControlUnknown,
		},
		{
			name: "a caller value chosen by another caller value",
			expr: `var.override != null ? var.override : var.acl`,
			vars: map[string]cty.Value{
				"override": cty.NullVal(cty.String),
				"acl":      cty.StringVal("public-read"),
			},
			argument: `acl = "public-read"`,
			want:     model.ArgumentControlCaller,
		},
		{
			name:     "try falls back when the caller value has no such attribute",
			expr:     `try(var.settings.acl, "public-read")`,
			vars:     map[string]cty.Value{"settings": cty.EmptyObjectVal},
			argument: `settings = {}`,
			want:     model.ArgumentControlUnknown,
		},
		{
			name:     "try keeps the caller value it evaluates",
			expr:     `try(var.settings.acl, "private")`,
			vars:     map[string]cty.Value{"settings": cty.ObjectVal(map[string]cty.Value{"acl": cty.StringVal("public-read")})},
			argument: `settings = { acl = "public-read" }`,
			want:     model.ArgumentControlCaller,
		},
		{
			name:     "try over a value not kept after evaluation is not resolved",
			expr:     `try(data.aws_s3_bucket.existing.acl, var.acl)`,
			vars:     map[string]cty.Value{"acl": cty.StringVal("public-read")},
			argument: `acl = "public-read"`,
			want:     model.ArgumentControlUnknown,
		},
		{
			name:     "lookup falls back to its default",
			expr:     `lookup(var.acls, "logs", "public-read")`,
			vars:     map[string]cty.Value{"acls": cty.MapValEmpty(cty.String)},
			argument: `acls = {}`,
			want:     model.ArgumentControlUnknown,
		},
		{
			name:     "lookup reads the caller map holding the key",
			expr:     `lookup(var.acls, "logs", "private")`,
			vars:     map[string]cty.Value{"acls": cty.MapVal(map[string]cty.Value{"logs": cty.StringVal("public-read")})},
			argument: `acls = { logs = "public-read" }`,
			want:     model.ArgumentControlCaller,
		},
		{
			name:     "coalescelist falls back on an empty caller list",
			expr:     `coalescelist(var.cidrs, ["0.0.0.0/0"])`,
			vars:     map[string]cty.Value{"cidrs": cty.ListValEmpty(cty.String)},
			argument: `cidrs = []`,
			want:     model.ArgumentControlUnknown,
		},
		{
			name:     "a module map indexed by a caller key",
			expr:     `local.acls[var.env]`,
			vars:     map[string]cty.Value{"env": cty.StringVal("prod")},
			argument: `env = "prod"`,
			locals:   "locals {\n  acls = { prod = \"public-read\" }\n}",
			want:     model.ArgumentControlUnknown,
		},
		{
			name:     "a choice resolved inside a local",
			expr:     `local.acl`,
			vars:     map[string]cty.Value{"acl": cty.NullVal(cty.String)},
			argument: `acl = null`,
			locals:   "locals {\n  acl = coalesce(var.acl, \"public-read\")\n}",
			want:     model.ArgumentControlUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := &tfeval.ResolvedResource{
				Body:  parseBlockBody(t, "resource \"aws_s3_bucket\" \"this\" {\n  acl = "+tt.expr+"\n}"),
				Scope: evaluatedScope(t, tt.vars, tt.locals),
				CallChain: []tfeval.CallSite{{
					Body: parseBlockBody(t, "module \"bucket\" {\n  source = \"../bucket\"\n  "+tt.argument+"\n}"),
				}},
			}
			args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
			control, location := controlAt(args, 2)
			require.Equal(t, tt.want, control)
			if tt.want == model.ArgumentControlCaller {
				require.Equal(t, 3, location.LineStart)
			}
		})
	}
}

func TestModuleArgumentsUnresolvedChoicesAreNotTraced(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, `resource "aws_s3_bucket" "this" {
  acl    = coalesce(var.acl, local.default_acl)
  bucket = var.name != "" ? var.name : var.name
}`),
		Scope: &tfeval.ModuleScope{Locals: parseLocals(t, "locals {\n  default_acl = \"public-read\"\n}")},
		CallChain: []tfeval.CallSite{{
			Body: parseBlockBody(t, `module "bucket" {
  source = "../bucket"
  acl    = aws_s3_bucket_acl.shared.acl
  name   = "logs"
}`),
		}},
	}

	args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
	requireControlAt(t, args, 2, model.ArgumentControlUnknown)
	requireCallerAt(t, args, 3, 4)
}

func TestModuleArgumentsTraceThroughIntermediateModule(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, `resource "aws_s3_bucket" "this" {
  acl = var.acl
}`),
		CallChain: []tfeval.CallSite{
			{Body: parseBlockBody(t, `module "wrapper" {
  source     = "../wrapper"
  bucket_acl = "public-read"
}`)},
			{Body: parseBlockBody(t, `module "bucket" {
  source = "../bucket"
  acl    = var.bucket_acl
}`)},
		},
	}

	args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
	control, location := controlAt(args, 2)
	require.Equal(t, model.ArgumentControlCaller, control)
	require.Equal(t, 3, location.LineStart)
	require.Equal(t, "stack/main.tf", location.Filename)

	resource.CallChain[1].Body = parseBlockBody(t, `module "bucket" {
  source = "../bucket"
  acl    = "private"
}`)
	args = newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
	requireControlAt(t, args, 2, model.ArgumentControlUnknown)
}

func TestModuleArgumentsTraceIterationValues(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, `resource "aws_security_group" "this" {
  for_each = var.groups
  name     = each.value.name

  dynamic "ingress" {
    for_each = var.ingress_rules
    iterator = rule
    content {
      cidr_blocks = rule.value.cidrs
      protocol    = "tcp"
    }
  }
}`),
		CallChain: []tfeval.CallSite{{
			Body: parseBlockBody(t, `module "sg" {
  source        = "../sg"
  groups        = { a = { name = "a" } }
  ingress_rules = [{ cidrs = ["0.0.0.0/0"] }]
}`),
		}},
	}

	args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
	requireCallerAt(t, args, 3, 3)
	requireCallerAt(t, args, 9, 4)
	for line := 5; line <= 8; line++ {
		requireCallerAt(t, args, line, 4)
	}
	requireControlAt(t, args, 10, model.ArgumentControlModule)
}

func TestModuleArgumentsTraceNestedDynamicBlocks(t *testing.T) {
	call := parseBlockBody(t, `module "sg" {
  source        = "../sg"
  groups        = { a = { rules = [] } }
  ingress_rules = []
}`)
	t.Run("inner for_each reads the outer iterator", func(t *testing.T) {
		resource := &tfeval.ResolvedResource{
			Body: parseBlockBody(t, `resource "aws_security_group" "this" {
  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      protocol = ingress.value.protocol
      dynamic "port" {
        for_each = ingress.value.ports
        content {
          from_port = port.value
        }
      }
    }
  }
}`),
			CallChain: []tfeval.CallSite{{Body: call}},
		}
		args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
		requireCallerAt(t, args, 5, 4)
		requireCallerAt(t, args, 6, 4)
		requireCallerAt(t, args, 9, 4)
	})
	t.Run("dynamic for_each reads the resource each", func(t *testing.T) {
		resource := &tfeval.ResolvedResource{
			Body: parseBlockBody(t, `resource "aws_security_group" "this" {
  for_each = var.groups
  dynamic "ingress" {
    for_each = each.value.rules
    content {
      cidr_blocks = ingress.value.cidrs
    }
  }
}`),
			CallChain: []tfeval.CallSite{{Body: call}},
		}
		args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
		requireCallerAt(t, args, 6, 3)
	})
	t.Run("an inner iterator shadows an outer one of the same name", func(t *testing.T) {
		resource := &tfeval.ResolvedResource{
			Body: parseBlockBody(t, `resource "aws_security_group" "this" {
  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      dynamic "ingress" {
        for_each = ["10.0.0.0/8"]
        content {
          cidr_blocks = ingress.value
        }
      }
    }
  }
}`),
			CallChain: []tfeval.CallSite{{Body: call}},
		}
		args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
		requireControlAt(t, args, 8, model.ArgumentControlModule)
	})
	t.Run("a choice on an iterator value is not resolved", func(t *testing.T) {
		resource := &tfeval.ResolvedResource{
			Body: parseBlockBody(t, `resource "aws_security_group" "this" {
  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      cidr_blocks = ingress.value.cidrs != null ? ingress.value.cidrs : ["0.0.0.0/0"]
    }
  }
}`),
			Scope:     evaluatedScope(t, map[string]cty.Value{"ingress_rules": cty.EmptyTupleVal}, ""),
			CallChain: []tfeval.CallSite{{Body: call}},
		}
		args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
		requireControlAt(t, args, 5, model.ArgumentControlUnknown)
	})
}

func TestModuleArgumentsResolveChoicesWithInstanceIteration(t *testing.T) {
	body := parseBlockBody(t, `resource "aws_s3_bucket" "this" {
  for_each = var.buckets
  bucket   = each.value.name
  acl      = each.value.acl == null ? var.default_acl : each.value.acl
}`)
	call := parseBlockBody(t, `module "buckets" {
  source      = "../buckets"
  buckets     = { a = { name = "a", acl = null }, b = { name = "b", acl = "private" } }
  default_acl = "public-read"
}`)
	scope := evaluatedScope(t, map[string]cty.Value{"default_acl": cty.StringVal("public-read")}, "")
	instance := func(acl cty.Value) *tfeval.ResolvedResource {
		return &tfeval.ResolvedResource{
			Body:  body,
			Scope: scope,
			Iteration: map[string]cty.Value{"each": cty.ObjectVal(map[string]cty.Value{
				"key":   cty.StringVal("a"),
				"value": cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal("a"), "acl": acl}),
			})},
			CallChain: []tfeval.CallSite{{Body: call}},
		}
	}

	cache := newModuleAttributionCache()
	defaulted := instance(cty.NullVal(cty.String))
	args := cache.resourceArguments(defaulted, "stack/main.tf")
	requireCallerAt(t, args, 3, 3)
	requireCallerAt(t, args, 4, 4)
	require.True(t, cache.resourceAttributes(defaulted).iterationDependent)

	args = cache.resourceArguments(instance(cty.StringVal("private")), "stack/main.tf")
	requireCallerAt(t, args, 4, 3)

	args = newModuleAttributionCache().resourceArguments(&tfeval.ResolvedResource{
		Body: body, Scope: scope, CallChain: []tfeval.CallSite{{Body: call}},
	}, "stack/main.tf")
	requireControlAt(t, args, 4, model.ArgumentControlUnknown)
}

func TestModuleArgumentsTraceIntermediateCallIteration(t *testing.T) {
	tests := []struct {
		name string
		call string
		want model.ArgumentControl
	}{
		{
			name: "each value of the call's for_each",
			call: "for_each = var.buckets\n  acl      = each.value.acl",
			want: model.ArgumentControlCaller,
		},
		{
			name: "an element picked by the call's count index",
			call: "count = length(var.buckets)\n  acl   = var.buckets[count.index]",
			want: model.ArgumentControlCaller,
		},
		{
			name: "a choice between the iteration and another input",
			call: "for_each = var.buckets\n  acl      = coalesce(each.value.acl, var.default_acl)",
			want: model.ArgumentControlUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := &tfeval.ResolvedResource{
				Body: parseBlockBody(t, `resource "aws_s3_bucket" "this" {
  acl = var.acl
}`),
				CallChain: []tfeval.CallSite{
					{Body: parseBlockBody(t, `module "wrapper" {
  source      = "../wrapper"
  buckets     = {}
  default_acl = "public-read"
}`)},
					{Body: parseBlockBody(t, "module \"bucket\" {\n  source   = \"../bucket\"\n  "+tt.call+"\n}")},
				},
			}

			args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
			control, location := controlAt(args, 2)
			require.Equal(t, tt.want, control)
			if tt.want == model.ArgumentControlCaller {
				require.Equal(t, 3, location.LineStart)
			}
		})
	}
}

func TestModuleArgumentsForExpressionVariablesShadowModuleReferences(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, `resource "aws_s3_bucket" "this" {
  tags = [for var in local.objects : var.value]
  acl  = [for k, v in var.acls : v]
}`),
		Scope: &tfeval.ModuleScope{Locals: parseLocals(t, `locals {
  objects = [{ value = "a" }]
}`)},
		CallChain: []tfeval.CallSite{{
			Body: parseBlockBody(t, `module "bucket" {
  source = "../bucket"
  value  = "unrelated"
  acls   = ["private"]
}`),
		}},
	}

	args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
	requireControlAt(t, args, 2, model.ArgumentControlModule)
	requireCallerAt(t, args, 3, 4)
}

func TestModuleArgumentsTraceThroughLocals(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, `resource "aws_s3_bucket" "this" {
  acl    = local.acl
  bucket = local.name
  tags   = local.looping
  policy = local.nested
}`),
		Scope: &tfeval.ModuleScope{Locals: parseLocals(t, `locals {
  acl     = var.acl
  name    = "${var.prefix}-${var.suffix}"
  looping = local.looping
  nested  = local.acl
}`)},
		CallChain: []tfeval.CallSite{{
			Body: parseBlockBody(t, `module "bucket" {
  source = "../bucket"
  acl    = "public-read"
  prefix = "a"
  suffix = "b"
}`),
		}},
	}

	args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
	requireCallerAt(t, args, 2, 3)
	requireCallerAt(t, args, 5, 3)
	requireControlAt(t, args, 3, model.ArgumentControlUnknown)
	requireControlAt(t, args, 4, model.ArgumentControlModule)
}

func TestModuleArgumentsTraceIntermediateCallerLocals(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, `resource "aws_s3_bucket" "this" {
  acl = var.acl
}`),
		CallChain: []tfeval.CallSite{
			{Body: parseBlockBody(t, `module "wrapper" {
  source     = "../wrapper"
  bucket_acl = "public-read"
}`)},
			{
				Body: parseBlockBody(t, `module "bucket" {
  source = "../bucket"
  acl    = local.acl
}`),
				Caller: evaluatedScope(t, map[string]cty.Value{"bucket_acl": cty.StringVal("public-read")}, `locals {
  acl = coalesce(var.bucket_acl, "private")
}`),
			},
		},
	}

	args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
	requireCallerAt(t, args, 2, 3)

	resource.CallChain[1].Caller = evaluatedScope(t, map[string]cty.Value{"bucket_acl": cty.NullVal(cty.String)}, `locals {
  acl = coalesce(var.bucket_acl, "public-read")
}`)
	args = newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
	requireControlAt(t, args, 2, model.ArgumentControlUnknown)
}

func TestValueAnalyzerReadsMatchVariables(t *testing.T) {
	const eachInput = "each_collection"
	for _, src := range []string{
		`var.a`,
		`var.a.b[var.b]`,
		`"${var.a}-${each.key}"`,
		`var.a == "" ? data.x.y.json : var.b`,
		`merge(var.a, { k = var.b, (var.c) = 1 }, { var = "literal key" })`,
		`[for x in var.a : x.name if x.enabled && var.b]`,
		`{ for k, v in var.a : k => v }`,
		`var.a[*].id`,
		`!var.a || -var.b > 0`,
		`(var.a)`,
		"<<EOT\n%{ for x in var.a }${x}-${each.value}%{ endfor }\nEOT\n",
		`try(var.a.b, lookup(var.c, "k", null))`,
		`coalesce(var.a, var.b, "c")`,
		`coalescelist(var.a, [var.b])`,
		`local.a`,
		`"literal"`,
	} {
		expr, diags := hclsyntax.ParseExpression([]byte(src), "test.tf", hcl.InitialPos)
		require.False(t, diags.HasErrors(), src)

		var want []string
		for _, traversal := range expr.Variables() {
			switch traversal.RootName() {
			case moduleVariableRoot:
				if step, ok := traversal[1].(hcl.TraverseAttr); ok && !slices.Contains(want, step.Name) {
					want = append(want, step.Name)
				}
			case resourceEachRoot:
				if !slices.Contains(want, eachInput) {
					want = append(want, eachInput)
				}
			}
		}
		a := newModuleAttributionCache().analyzer(nil, nil)
		a.iterators = []iteratorReads{{name: resourceEachRoot, reads: inputReads{value: []string{eachInput}}}}
		reads := a.reads(expr)
		require.ElementsMatch(t, want, appendMissing(slices.Clone(reads.value), reads.selector), src)
	}
}

func TestModuleAttributionForResourceNarrowsCallSite(t *testing.T) {
	whole := model.SourceLocation{Filename: "stack/main.tf", LineStart: 1, LineEnd: 35}
	argument := model.SourceLocation{Filename: "stack/main.tf", LineStart: 27, LineEnd: 27}
	attrs := map[string]*model.ModuleAttribution{
		moduleAttributionKey("aws_s3_bucket_policy", 10, 1): {
			CallSite:        whole,
			ArgumentControl: model.ArgumentControlModule,
			Arguments: []model.ModuleArgument{
				{LineStart: 12, LineEnd: 12, Control: model.ArgumentControlCaller, CallSite: argument},
				{LineStart: 13, LineEnd: 14, Control: model.ArgumentControlUnknown},
			},
		},
	}

	policy := func(line int) *model.Vulnerability {
		return &model.Vulnerability{
			ResourceType:  "aws_s3_bucket_policy",
			BlockLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 10, Col: 1}},
			Line:          line,
		}
	}
	got := moduleAttributionForResource(attrs, policy(12))
	require.Equal(t, argument, got.CallSite)
	require.Equal(t, model.ArgumentControlCaller, got.ArgumentControl)
	require.Nil(t, got.Arguments)

	got = moduleAttributionForResource(attrs, policy(14))
	require.Equal(t, whole, got.CallSite, "a value not traced keeps the call's source line")
	require.Equal(t, model.ArgumentControlUnknown, got.ArgumentControl)

	got = moduleAttributionForResource(attrs, policy(10))
	require.Equal(t, whole, got.CallSite)
	require.Equal(t, model.ArgumentControlModule, got.ArgumentControl)
	require.Equal(t, model.ArgumentControlModule, attrs[moduleAttributionKey("aws_s3_bucket_policy", 10, 1)].ArgumentControl,
		"narrowing works on a clone")

	attrs[moduleAttributionKey("aws_s3_bucket", 1, 1)] = nil
	require.Nil(t, moduleAttributionForResource(attrs, &model.Vulnerability{
		ResourceType:  "aws_s3_bucket",
		BlockLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 1, Col: 1}},
		Line:          1,
	}))
}

func TestBuildModuleAttributionAnchorsOnSourceArgument(t *testing.T) {
	repo := t.TempDir()
	callerPath := writeCallerFixture(t, repo, "stack/main.tf", `module "bucket" {
  source = "../modules/bucket"
  name   = "example"
}
`)
	resource := tfeval.ResolvedResource{
		Type:      "aws_s3_bucket",
		Name:      "this",
		DefinedIn: filepath.Join(repo, "modules", "bucket", "main.tf"),
		DefLine:   1,
		Body:      parseBlockBody(t, "resource \"aws_s3_bucket\" \"this\" {\n  bucket = var.name\n}"),
		CallChain: []tfeval.CallSite{{
			ModuleName:    "bucket",
			Source:        "../modules/bucket",
			CalledFrom:    callerPath,
			CalledLine:    1,
			CalledEndLine: 4,
			Body:          parseBlockBody(t, "module \"bucket\" {\n  source = \"../modules/bucket\"\n  name   = \"example\"\n}"),
		}},
	}

	attr := buildModuleAttribution(&resource, repo, nil, newModuleAttributionCache())
	require.NotNil(t, attr)
	require.Equal(t, 2, attr.CallSite.LineStart, "a finding not set by an argument points at the source")
	require.Equal(t, 2, attr.CallSite.LineEnd)
	require.Equal(t, 1, attr.ModulePath[0].CodeLocation.LineStart)

	narrowed := moduleAttributionForResource(
		map[string]*model.ModuleAttribution{moduleAttributionKey("aws_s3_bucket", 1, 0): attr},
		&model.Vulnerability{
			ResourceType:  "aws_s3_bucket",
			BlockLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 1}},
			Line:          2,
		},
	)
	require.Equal(t, 3, narrowed.CallSite.LineStart, "a finding set by an argument points at it")
	require.Equal(t, model.ArgumentControlCaller, narrowed.ArgumentControl)

	missing := moduleAttributionForResource(
		map[string]*model.ModuleAttribution{moduleAttributionKey("aws_s3_bucket", 1, 0): attr},
		&model.Vulnerability{
			ResourceType:  "aws_s3_bucket",
			BlockLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 1}},
			Line:          1,
		},
	)
	require.Equal(t, 2, missing.CallSite.LineStart)
	require.Equal(t, model.ArgumentControlModule, missing.ArgumentControl,
		"a finding on no input-reading attribute is the module's own")

	unanalyzed := buildModuleAttribution(&tfeval.ResolvedResource{
		Type: resource.Type, Name: resource.Name, DefinedIn: resource.DefinedIn,
		DefLine: resource.DefLine, CallChain: resource.CallChain,
	}, repo, nil, newModuleAttributionCache())
	require.Equal(t, model.ArgumentControlUnknown, unanalyzed.ArgumentControl,
		"a resource whose body was not kept cannot be told apart from its caller")
}

// Mirrors a remote package whose root module calls a sibling directory of the
// same package: the leaf is part of the package the user called.
func TestBuildModuleAttributionDescribesLocalCallsInsideRemotePackage(t *testing.T) {
	repo := t.TempDir()
	const source = "git::https://github.com/DataDog/cloud-inventory.git//terraform-modules/aws-security?ref=aws-security_v2.1.2"
	callerPath := writeCallerFixture(t, repo, "aws/staging/security/main.tf", `
module "security" {
  source = "`+source+`"
}
`)
	packageRoot := filepath.Join(repo, ".cache", "cloud-inventory")
	moduleRoot := filepath.Join(packageRoot, "terraform-modules", "aws-security")
	resource := tfeval.ResolvedResource{
		Type:       "aws_sns_topic",
		Name:       "this",
		DefinedIn:  filepath.Join(moduleRoot, "security-alerting", "main.tf"),
		DefLine:    1,
		DefEndLine: 5,
		CallChain: []tfeval.CallSite{
			{ModuleName: "security", Source: source, CalledFrom: callerPath, CalledLine: 2, CalledEndLine: 4},
			{
				ModuleName: "alerting-east", Source: "./security-alerting",
				CalledFrom: filepath.Join(moduleRoot, "security-alerting.tf"), CalledLine: 16, CalledEndLine: 25,
			},
		},
	}
	lookup := moduleProvenanceLookup(func(_, src, _, _ string) (RemoteModuleProvenance, bool) {
		if src != source {
			return RemoteModuleProvenance{}, false
		}
		return RemoteModuleProvenance{
			Source:      source,
			SourceType:  "git",
			ResolvedRef: "1c935a4e",
			ModuleRoot:  moduleRoot,
			PackageRoot: packageRoot,
		}, true
	})

	attr := buildModuleAttribution(&resource, repo, lookup, newModuleAttributionCache())
	require.NotNil(t, attr)
	const leafSource = "https://github.com/datadog/cloud-inventory//terraform-modules/aws-security/security-alerting"
	require.Equal(t, "transitive", attr.DependencyType)
	require.False(t, attr.ModuleCodeOwned)
	require.Equal(t, "https://github.com/datadog/cloud-inventory", attr.Source, "the package the file is named from")
	require.Equal(t, "git", attr.SourceType)
	require.Equal(t, "aws-security_v2.1.2", attr.Version)
	require.Equal(t, "terraform-modules/aws-security/security-alerting/main.tf", attr.ModuleCodeLocation.Filename)
	require.Len(t, attr.ModulePath, 2)
	require.Equal(t, "alerting-east", attr.ModulePath[1].Name)
	require.Equal(t, "git", attr.ModulePath[1].SourceType)
	require.Equal(t, "aws-security_v2.1.2", attr.ModulePath[1].Version)
	require.Equal(t, "aws-security_v2.1.2", attr.ModulePath[0].Version)
	require.Equal(t, "https://github.com/datadog/cloud-inventory//terraform-modules/aws-security", attr.ModulePath[0].Source)
	require.Equal(t, leafSource, attr.ModulePath[1].Source)
	require.Equal(t, "terraform-modules/aws-security/security-alerting.tf", attr.ModulePath[1].CodeLocation.Filename)
}

func TestBuildModuleAttributionTransitiveBeyondOneHop(t *testing.T) {
	repo := t.TempDir()
	callerPath := writeCallerFixture(t, repo, "stack/main.tf", "module \"a\" {\n  source = \"../modules/a\"\n}\n")
	resource := tfeval.ResolvedResource{
		Type:      "aws_s3_bucket",
		Name:      "this",
		DefinedIn: filepath.Join(repo, "modules", "b", "main.tf"),
		DefLine:   1,
		CallChain: []tfeval.CallSite{
			{ModuleName: "a", Source: "../modules/a", CalledFrom: callerPath, CalledLine: 1},
			{ModuleName: "b", Source: "../b", CalledFrom: filepath.Join(repo, "modules", "a", "main.tf"), CalledLine: 1},
		},
	}
	attr := buildModuleAttribution(&resource, repo, nil, nil)
	require.Equal(t, "transitive", attr.DependencyType, "more than one call is transitive, even within one package")
	require.Len(t, attr.ModulePath, 2)

	attr = buildModuleAttribution(&tfeval.ResolvedResource{
		Type:      resource.Type,
		Name:      resource.Name,
		DefinedIn: resource.DefinedIn,
		DefLine:   resource.DefLine,
		CallChain: resource.CallChain[:1],
	}, repo, nil, nil)
	require.Equal(t, "direct", attr.DependencyType)
	require.Len(t, attr.ModulePath, 1)
}

func TestModuleFileNameCollapsesPathsOutsideRepository(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "repo")
	outside := filepath.Join(filepath.Dir(repo), "shared", "main.tf")
	name, _ := moduleFileName(outside, repo, nil)
	require.Equal(t, "main.tf", name)
	name, _ = moduleFileName(filepath.Join(repo, "modules", "a", "main.tf"), repo, nil)
	require.Equal(t, "modules/a/main.tf", name)
}

func TestModuleAttributionCacheKeysByResourceAndChain(t *testing.T) {
	repo := t.TempDir()
	callerPath := writeCallerFixture(t, repo, "stack/main.tf", "module \"a\" {\n  source = \"../modules/a\"\n}\n")
	resourceBody := parseBlockBody(t, "resource \"aws_s3_bucket\" \"this\" {\n  acl = var.acl\n}")
	callA := parseBlockBody(t, "module \"a\" {\n  source = \"../modules/a\"\n  acl    = \"private\"\n}")
	callB := parseBlockBody(t, "module \"b\" {\n  source = \"../modules/a\"\n\n  acl    = \"public-read\"\n}")
	instance := func(name string, call *hclsyntax.Body) *tfeval.ResolvedResource {
		return &tfeval.ResolvedResource{
			Type:      "aws_s3_bucket",
			Name:      name,
			DefinedIn: filepath.Join(repo, "modules", "a", "main.tf"),
			DefLine:   1,
			Body:      resourceBody,
			CallChain: []tfeval.CallSite{{
				ModuleName: "a", Source: "../modules/a", CalledFrom: callerPath, CalledLine: 1, Body: call,
			}},
		}
	}

	cache := newModuleAttributionCache()
	first := cache.attribution(instance("this[0]", callA), repo, nil)
	require.Same(t, first, cache.attribution(instance("this[1]", callA), repo, nil),
		"instances of one block through the same call share an attribution")

	other := cache.attribution(instance("this", callB), repo, nil)
	require.NotSame(t, first, other)
	require.Equal(t, 3, first.Arguments[0].CallSite.LineStart)
	require.Equal(t, 4, other.Arguments[0].CallSite.LineStart)
}

func TestBuildModuleAttributionNamesRemoteFilesFromPackageRoot(t *testing.T) {
	repo := t.TempDir()
	callerPath := writeCallerFixture(t, repo, "stack/main.tf", `
module "bucket" {
  source = "git::https://github.com/DataDog/cloud-inventory.git//terraform-modules/aws-bucket?ref=v5"
}
`)
	packageRoot := filepath.Join(repo, ".cache", "cloud-inventory")
	moduleRoot := filepath.Join(packageRoot, "terraform-modules", "aws-bucket")
	resource := tfeval.ResolvedResource{
		Type:      "aws_s3_bucket_policy",
		Name:      "this",
		DefinedIn: filepath.Join(moduleRoot, "policy.tf"),
		DefLine:   1,
		CallChain: []tfeval.CallSite{{
			ModuleName: "bucket",
			Source:     "git::https://github.com/DataDog/cloud-inventory.git//terraform-modules/aws-bucket?ref=v5",
			CalledFrom: callerPath,
			CalledLine: 2,
		}},
	}
	lookup := moduleProvenanceLookup(func(_, _, _, _ string) (RemoteModuleProvenance, bool) {
		return RemoteModuleProvenance{
			Source:      resource.CallChain[0].Source,
			SourceType:  "git",
			ModuleRoot:  moduleRoot,
			PackageRoot: packageRoot,
		}, true
	})

	attr := buildModuleAttribution(&resource, repo, lookup, nil)
	require.NotNil(t, attr)
	require.Equal(t, "terraform-modules/aws-bucket/policy.tf", attr.ModuleCodeLocation.Filename)
	require.Equal(t, "https://github.com/datadog/cloud-inventory", attr.Source)
	require.Equal(t, "v5", attr.Version)
	require.Equal(t, "https://github.com/datadog/cloud-inventory//terraform-modules/aws-bucket", attr.ModulePath[0].Source)
}

func TestModuleArgumentsTraceDynamicBlockLabels(t *testing.T) {
	call := parseBlockBody(t, `module "m" {
  source = "../m"
  kind   = "local-exec"
  items  = ["a"]
}`)
	trace := func(forEach string) []model.ModuleArgument {
		resource := &tfeval.ResolvedResource{
			Body: parseBlockBody(t, `resource "null_resource" "this" {
  dynamic "provisioner" {
    for_each = `+forEach+`
    labels   = [var.kind]
    content {
      command = "true"
    }
  }
}`),
			CallChain: []tfeval.CallSite{{Body: call}},
		}
		return newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
	}
	t.Run("labels read an input while for_each reads none", func(t *testing.T) {
		requireCallerAt(t, trace(`["x"]`), 4, 3)
	})
	t.Run("labels and for_each read different inputs", func(t *testing.T) {
		requireControlAt(t, trace(`var.items`), 4, model.ArgumentControlUnknown)
	})
}
