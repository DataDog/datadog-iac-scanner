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
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
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

func argumentAt(args []model.ModuleArgument, line int) (model.SourceLocation, bool) {
	for _, arg := range args {
		if line >= arg.LineStart && line <= arg.LineEnd {
			return arg.CallSite, true
		}
	}
	return model.SourceLocation{}, false
}

func TestModuleArgumentsTraceDirectCall(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, `resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = var.local_policy == "" ? data.aws_iam_policy_document.doc.json : var.local_policy
  tags   = merge(var.tags, var.extra_tags)
  acl    = var.acl
}`),
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

	policy, ok := argumentAt(args, 3)
	require.True(t, ok)
	require.Equal(t, model.SourceLocation{
		Filename: "stack/main.tf", LineStart: 4, LineEnd: 4, ColumnStart: 3, ColumnEnd: 37,
	}, policy)

	_, ok = argumentAt(args, 2)
	require.False(t, ok, "a value not read from a variable keeps the whole call site")
	_, ok = argumentAt(args, 4)
	require.False(t, ok, "a value set by two arguments keeps the whole call site")
	_, ok = argumentAt(args, 5)
	require.False(t, ok, "a variable left to its default keeps the whole call site")
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
	location, ok := argumentAt(args, 2)
	require.True(t, ok)
	require.Equal(t, 3, location.LineStart)
	require.Equal(t, "stack/main.tf", location.Filename)

	resource.CallChain[1].Body = parseBlockBody(t, `module "bucket" {
  source = "../bucket"
  acl    = "private"
}`)
	args = newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
	_, ok = argumentAt(args, 2)
	require.False(t, ok, "a value fixed by an intermediate module keeps the whole call site")
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
	name, ok := argumentAt(args, 3)
	require.True(t, ok)
	require.Equal(t, 3, name.LineStart)
	cidrs, ok := argumentAt(args, 9)
	require.True(t, ok)
	require.Equal(t, 4, cidrs.LineStart)
}

func TestModuleArgumentsMixedIterationReadsAreNotTraced(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, `resource "aws_s3_bucket" "this" {
  for_each = var.buckets
  bucket   = each.value.name
  acl      = each.value.acl == null ? var.default_acl : each.value.acl
}`),
		CallChain: []tfeval.CallSite{{
			Body: parseBlockBody(t, `module "buckets" {
  source      = "../buckets"
  buckets     = { a = { name = "a", acl = null } }
  default_acl = "public-read"
}`),
		}},
	}

	args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
	_, ok := argumentAt(args, 3)
	require.True(t, ok, "a value read only through the iteration is traced")
	_, ok = argumentAt(args, 4)
	require.False(t, ok, "a value mixing the iteration and another variable is not traced")
}

func TestModuleArgumentsIntermediateCallIterationIsNotTraced(t *testing.T) {
	for name, argument := range map[string]string{
		"for_each": `coalesce(each.value.acl, var.default_acl)`,
		"count":    `var.acls[count.index] == null ? var.default_acl : "private"`,
	} {
		t.Run(name, func(t *testing.T) {
			resource := &tfeval.ResolvedResource{
				Body: parseBlockBody(t, `resource "aws_s3_bucket" "this" {
  acl = var.acl
}`),
				CallChain: []tfeval.CallSite{
					{Body: parseBlockBody(t, `module "wrapper" {
  source      = "../wrapper"
  default_acl = "public-read"
}`)},
					{Body: parseBlockBody(t, `module "bucket" {
  source = "../bucket"
  acl    = `+argument+`
}`)},
				},
			}

			args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
			_, ok := argumentAt(args, 2)
			require.False(t, ok, "a value depending on the call's iteration is not set by a single argument")
		})
	}
}

func TestModuleArgumentsForExpressionVariablesShadowModuleReferences(t *testing.T) {
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, `resource "aws_s3_bucket" "this" {
  tags = [for var in local.objects : var.value]
  acl  = [for k, v in var.acls : v]
}`),
		Locals: parseLocals(t, `locals {
  objects = [{ value = "a" }]
}`),
		CallChain: []tfeval.CallSite{{
			Body: parseBlockBody(t, `module "bucket" {
  source = "../bucket"
  value  = "unrelated"
  acls   = ["private"]
}`),
		}},
	}

	args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
	_, ok := argumentAt(args, 2)
	require.False(t, ok, "a loop variable named var is not the module input of that name")
	acl, ok := argumentAt(args, 3)
	require.True(t, ok, "the collection of a for expression is still read")
	require.Equal(t, 4, acl.LineStart)
}

func TestModuleArgumentsTraceThroughLocals(t *testing.T) {
	locals := parseLocals(t, `locals {
  acl     = var.acl
  name    = "${var.prefix}-${var.suffix}"
  looping = local.looping
  nested  = local.acl
}`)
	resource := &tfeval.ResolvedResource{
		Body: parseBlockBody(t, `resource "aws_s3_bucket" "this" {
  acl    = local.acl
  bucket = local.name
  tags   = local.looping
  policy = local.nested
}`),
		Locals: locals,
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
	acl, ok := argumentAt(args, 2)
	require.True(t, ok)
	require.Equal(t, 3, acl.LineStart)
	policy, ok := argumentAt(args, 5)
	require.True(t, ok, "locals reading locals are followed")
	require.Equal(t, 3, policy.LineStart)
	_, ok = argumentAt(args, 3)
	require.False(t, ok, "a local reading two variables is not traced")
	_, ok = argumentAt(args, 4)
	require.False(t, ok, "a self-referencing local is not traced")
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
				CallerLocals: parseLocals(t, `locals {
  acl = var.bucket_acl
}`),
			},
		},
	}

	args := newModuleAttributionCache().resourceArguments(resource, "stack/main.tf")
	location, ok := argumentAt(args, 2)
	require.True(t, ok)
	require.Equal(t, 3, location.LineStart)
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

func TestExpressionReadsMatchesVariables(t *testing.T) {
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
		`local.a`,
		`"literal"`,
	} {
		expr, diags := hclsyntax.ParseExpression([]byte(src), "test.tf", hcl.InitialPos)
		require.False(t, diags.HasErrors(), src)

		var want []string
		wantEach := false
		for _, traversal := range expr.Variables() {
			switch traversal.RootName() {
			case moduleVariableRoot:
				if step, ok := traversal[1].(hcl.TraverseAttr); ok && !slices.Contains(want, step.Name) {
					want = append(want, step.Name)
				}
			case resourceEachRoot:
				wantEach = true
			}
		}
		w := readsWalker{root: resourceEachRoot}
		w.walk(expr)
		require.ElementsMatch(t, want, w.names, src)
		require.Equal(t, wantEach, w.readsRoot, src)
	}
}

func TestModuleAttributionForResourceNarrowsCallSite(t *testing.T) {
	whole := model.SourceLocation{Filename: "stack/main.tf", LineStart: 1, LineEnd: 35}
	argument := model.SourceLocation{Filename: "stack/main.tf", LineStart: 27, LineEnd: 27}
	attrs := map[string]*model.ModuleAttribution{
		moduleAttributionKey("aws_s3_bucket_policy", 10, 1): {
			CallSite:  whole,
			Arguments: []model.ModuleArgument{{LineStart: 12, LineEnd: 12, CallSite: argument}},
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
	require.Nil(t, got.Arguments)

	got = moduleAttributionForResource(attrs, policy(10))
	require.Equal(t, whole, got.CallSite)

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
	require.True(t, narrowed.CallArgument)
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
