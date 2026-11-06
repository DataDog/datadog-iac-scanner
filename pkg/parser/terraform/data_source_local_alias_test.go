/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

func Test_getDataSourcePolicy_localAliasOfDataJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
locals {
  base_json = data.aws_iam_policy_document.base.json
}
data "aws_iam_policy_document" "base" {
  statement {
    sid     = "Base"
    actions = ["sqs:*"]
  }
}
data "aws_iam_policy_document" "combined" {
  source_policy_documents = [local.base_json]
  statement {
    sid     = "Own"
    actions = ["s3:GetObject"]
  }
}
`), 0o600))
	ctx := context.Background()
	inputVars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, inputVars, nil, "")
	var data map[string]map[string]map[string]string
	require.NoError(t, gocty.FromCtyValue(result["data"], &data))
	require.Equal(t,
		`{"Statement":[{"Actions":["sqs:*"],"Effect":"Allow","Sid":"Base"},{"Actions":["s3:GetObject"],"Effect":"Allow","Sid":"Own"}],"Version":"2012-10-17"}`+"\n",
		data["aws_iam_policy_document"]["combined"]["json"])
}

func Test_getDataSourcePolicy_localTryFallbackUpdatesWhenDataArrives(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
locals {
  base_json = try(data.aws_iam_policy_document.base.json, data.aws_iam_policy_document.root.json)
}
data "aws_iam_policy_document" "root" {
  statement {
    sid     = "Root"
    actions = ["iam:GetUser"]
  }
}
data "aws_iam_policy_document" "leaf" {
  statement {
    sid     = "Leaf"
    actions = ["ec2:*"]
  }
}
data "aws_iam_policy_document" "base" {
  source_policy_documents = [data.aws_iam_policy_document.leaf.json]
  statement {
    sid     = "Base"
    actions = ["sqs:*"]
  }
}
data "aws_iam_policy_document" "combined" {
  source_policy_documents = [local.base_json]
  statement {
    sid     = "Own"
    actions = ["s3:GetObject"]
  }
}
`), 0o600))
	ctx := context.Background()
	inputVars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, inputVars, nil, "")
	var data map[string]map[string]map[string]string
	require.NoError(t, gocty.FromCtyValue(result["data"], &data))
	// base only renders on the second pass, so the first one falls back to root
	// and the local has to be overwritten once base exists.
	combined := data["aws_iam_policy_document"]["combined"]["json"]
	require.Contains(t, combined, `"Sid":"Base"`)
	require.Contains(t, combined, `"Sid":"Leaf"`)
	require.NotContains(t, combined, `"Sid":"Root"`)
}

func scanDataSourceDir(t *testing.T, files map[string]string) (before, after map[string]cty.Value) {
	t.Helper()
	dir := writeTerraformDir(t, files)
	ctx := context.Background()
	inputVars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	before = inputVars["local"].AsValueMap()
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, inputVars, nil, "")
	return before, result["local"].AsValueMap()
}

const unrelatedLocals = `
variable "env" {
  default = "prod"
}
locals {
  bucket = "logs-${var.env}"
}
`

func Test_getDataSourcePolicy_unrelatedLocalsDoNotDependOnPolicyDocuments(t *testing.T) {
	before, withoutDoc := scanDataSourceDir(t, map[string]string{"main.tf": unrelatedLocals})
	_, withDoc := scanDataSourceDir(t, map[string]string{
		"main.tf": unrelatedLocals,
		"policy.tf": `
data "aws_iam_policy_document" "x" {
  statement {
    actions = ["s3:*"]
  }
}
`,
	})
	// The variable default resolves the local before any data pass, so it has
	// the same value with and without a policy document.
	for _, locals := range []map[string]cty.Value{before, withoutDoc, withDoc} {
		require.Contains(t, locals, "bucket")
		require.Equal(t, "logs-prod", locals["bucket"].AsString())
	}
}

func Test_getDataSourcePolicy_tryDoesNotKeepFallbackForExistingValues(t *testing.T) {
	_, locals := scanDataSourceDir(t, map[string]string{"main.tf": `
variable "acl" {
  default = "public-read"
}
locals {
  base = "public-read"
  from_var  = try(var.acl, "private")
  from_local = try(local.base, "private")
  has_local = can(local.base)
}
`})
	// var.acl exists, so the fallback must not replace it.
	require.Contains(t, locals, "from_var")
	require.Equal(t, "public-read", locals["from_var"].AsString())
	require.Equal(t, "public-read", locals["from_local"].AsString())
	require.True(t, locals["has_local"].True())
}

// Two locals blocks pin the declaration order: the first block is walked
// before the second, so x must be evaluated after local.y.
func Test_getDataSourcePolicy_tryWaitsForLocalFromLaterBlock(t *testing.T) {
	_, locals := scanDataSourceDir(t, map[string]string{"main.tf": `
locals {
  x = try(local.y, "fb")
}
locals {
  y = "real"
}
`})
	require.Equal(t, "real", locals["x"].AsString())
}

func Test_getDataSourcePolicy_nullLocalsAreStored(t *testing.T) {
	_, locals := scanDataSourceDir(t, map[string]string{"main.tf": `
locals {
  nothing  = lookup({}, "k", null)
  fallback = try(local.nothing, "fb")
}
`})
	// IsNull is true for a missing key too, so pin the key itself.
	require.Contains(t, locals, "nothing")
	require.True(t, locals["nothing"].IsNull())
	// try sees the resolved null and returns it, not the fallback.
	require.True(t, locals["fallback"].IsNull())
}

// A dynamic read of the whole local object resolves once the key it reads
// does, without waiting for a data pass.
func Test_getDataSourcePolicy_dynamicKeyLocalResolves(t *testing.T) {
	_, locals := scanDataSourceDir(t, map[string]string{"main.tf": `
locals {
  k   = "env"
  env = "production"
  acl = local[local.k]
}
`})
	require.Equal(t, "production", locals["acl"].AsString())
}

// try would keep a fallback for keys that may still appear.
func Test_getDataSourcePolicy_tryWithWholeObjectReadStaysUnresolved(t *testing.T) {
	_, locals := scanDataSourceDir(t, map[string]string{"main.tf": `
locals {
  x = try(local, "fb")
}
`})
	requireUnresolvedLocal(t, locals, "x")
}

func Test_getDataSourcePolicy_dataDependentNullLocalIsStored(t *testing.T) {
	_, locals := scanDataSourceDir(t, map[string]string{"main.tf": `
data "aws_iam_policy_document" "plain" {
  statement {
    actions = ["s3:*"]
  }
}
locals {
  out      = data.aws_iam_policy_document.plain.json != "" ? null : "set"
  missing  = try(data.aws_iam_policy_document.missing.json, null)
}
`})
	require.Contains(t, locals, "out")
	require.True(t, locals["out"].IsKnown())
	require.True(t, locals["out"].IsNull())
	// A data document the scanner did not render is not read as missing.
	requireUnresolvedLocal(t, locals, "missing")
}

// An unresolved local is missing from the locals returned, but a local read
// again once data is rendered still sees it as declared: a read of local as a
// whole does not take the fallback for it.
func Test_getDataSourcePolicy_wholeLocalReadSeesUnresolvedLocals(t *testing.T) {
	_, locals := scanDataSourceDir(t, map[string]string{"main.tf": `
variable "nodef" {
  type = string
}
data "aws_iam_policy_document" "plain" {
  statement {
    actions = ["s3:*"]
  }
}
locals {
  blocked = var.nodef
  doc     = data.aws_iam_policy_document.plain.json
  picked  = lookup(local, "blocked", "fallback")
}
`})
	require.Contains(t, locals, "doc")
	requireUnresolvedLocal(t, locals, "blocked")
	requireUnresolvedLocal(t, locals, "picked")
}

func Test_getDataSourcePolicy_localsReadingDataResolveThroughVariables(t *testing.T) {
	_, locals := scanDataSourceDir(t, map[string]string{
		"main.tf": unrelatedLocals + `
locals {
  base_json = data.aws_iam_policy_document.base.json
  tagged    = "${var.env}:${local.base_json}"
  indirect  = local["tagged"]
}
data "aws_iam_policy_document" "base" {
  statement {
    sid     = "Base"
    actions = ["sqs:*"]
  }
}
`,
	})
	require.Contains(t, locals, "bucket")
	require.Equal(t, "logs-prod", locals["bucket"].AsString())
	for _, name := range []string{"tagged", "indirect"} {
		require.True(t, locals[name].IsKnown(), name)
		require.Contains(t, locals[name].AsString(), `prod:{"Statement"`, name)
		require.Contains(t, locals[name].AsString(), `"Sid":"Base"`, name)
	}
}

func Test_getDataSourcePolicy_lastDeclarationOfALocalWins(t *testing.T) {
	_, locals := scanDataSourceDir(t, map[string]string{
		"main.tf": `
locals {
  base_json = data.aws_iam_policy_document.first.json
}
data "aws_iam_policy_document" "first" {
  statement {
    sid     = "First"
    actions = ["sqs:*"]
  }
}
data "aws_iam_policy_document" "second" {
  statement {
    sid     = "Second"
    actions = ["s3:*"]
  }
}
`,
		"main_override.tf": `
locals {
  base_json = data.aws_iam_policy_document.second.json
}
`,
	})
	require.Contains(t, locals["base_json"].AsString(), `"Sid":"Second"`)
	require.NotContains(t, locals["base_json"].AsString(), `"Sid":"First"`)
}

func Test_dataDependentLocals(t *testing.T) {
	parse := func(src string) []localAssignment {
		file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
		require.False(t, diags.HasErrors(), diags.Error())
		return localAssignmentsFromBody(file.Body.(*hclsyntax.Body))
	}
	names := func(in []localAssignment) []string {
		out := make([]string, len(in))
		for i, item := range in {
			out[i] = item.name
		}
		sort.Strings(out)
		return out
	}
	all := append(parse(`
locals {
  plain    = "p-${var.env}"
  chained  = local.plain
  direct   = data.aws_iam_policy_document.a.json
  through  = "${local.direct}!"
  indexed  = local["through"]
  dynamic  = local[var.which]
  override = "o"
}
`), parse(`
locals {
  override = data.aws_iam_policy_document.a.json
  twice    = data.aws_iam_policy_document.a.json
}
locals {
  twice = "no longer data"
}
`)...)
	// override takes its last declaration and twice stops reading data, while
	// dynamic may read any local that does.
	require.Equal(t, []string{"direct", "dynamic", "indexed", "override", "through"}, names(dataDependentLocals(all)))
	require.Empty(t, dataDependentLocals(parse(`locals { a = "x" }`)))
}

func Test_getDataSourcePolicy_sourceDocumentWithUnresolvedConditionStaysUnresolved(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
data "aws_iam_policy_document" "guarded" {
  source_policy_documents = [jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid = "Pub", Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "*"
      Condition = var.cond
    }]
  })]
}
data "aws_iam_policy_document" "plain" {
  statement {
    actions = ["s3:GetObject"]
  }
}
`), 0o600))
	ctx := context.Background()
	inputVars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, inputVars, nil, "")
	var data map[string]map[string]map[string]string
	require.NoError(t, gocty.FromCtyValue(result["data"], &data))
	require.NotContains(t, data["aws_iam_policy_document"], "guarded")
	require.Contains(t, data["aws_iam_policy_document"], "plain")
}

func Test_getDataSourcePolicy_functionOnlyLocalFeedsSourcePolicy(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
locals {
  encoded = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "FromLocal"
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "*"
    }]
  })
}
data "aws_iam_policy_document" "via" {
  source_policy_documents = [local.encoded]
}
data "aws_iam_policy_document" "plain" {
  statement {
    sid     = "Plain"
    actions = ["sqs:*"]
  }
}
`), 0o600))
	ctx := context.Background()
	vars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	require.Contains(t, vars["local"].AsValueMap(), "encoded")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, vars, nil, "")
	docs := result["data"].AsValueMap()["aws_iam_policy_document"].AsValueMap()
	require.Contains(t, docs, "plain")
	require.Contains(t, docs, "via")
	require.Contains(t, docs["via"].AsValueMap()["json"].AsString(), `"Sid":"FromLocal"`)
	// An unrelated var-only local keeps the value the variables give it when a
	// policy exists.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "extra.tf"), []byte(`
variable "env" { default = "prod" }
locals { bucket = "logs-${var.env}" }
`), 0o600))
	vars = getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	require.Contains(t, vars["local"].AsValueMap(), "bucket")
	require.Equal(t, "logs-prod", vars["local"].AsValueMap()["bucket"].AsString())
	result = getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, vars, nil, "")
	require.Contains(t, result["local"].AsValueMap(), "bucket")
	require.Equal(t, "logs-prod", result["local"].AsValueMap()["bucket"].AsString())
	require.Contains(t, result["data"].AsValueMap()["aws_iam_policy_document"].AsValueMap(), "via")
}

func Test_getDataSourcePolicy_JSONLocalChainFeedsSource(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf.json"), []byte(`{
  "locals": [{
    "a": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"FromJSON\",\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}",
    "b": "${local.a}",
    "c": "${local.b}",
    "d": "${local.c}"
  }],
  "data": {
    "aws_iam_policy_document": {
      "via": {
        "source_policy_documents": ["${local.d}"]
      }
    }
  }
}`), 0o600))
	ctx := context.Background()
	vars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	require.Contains(t, vars["local"].AsValueMap(), "d")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, vars, nil, "")
	docs := result["data"].AsValueMap()["aws_iam_policy_document"].AsValueMap()
	require.Contains(t, docs, "via")
	require.Contains(t, docs["via"].AsValueMap()["json"].AsString(), `"Sid":"FromJSON"`)
}

func Test_getDataSourcePolicy_sameFileLocalsLastWins(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
locals {
  acts = ["s3:Wrong"]
}
locals {
  acts = ["s3:Right"]
}
data "aws_iam_policy_document" "p" {
  statement {
    actions = local.acts
  }
}
`), 0o600))
	ctx := context.Background()
	vars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, vars, nil, "")
	docs := result["data"].AsValueMap()["aws_iam_policy_document"].AsValueMap()
	require.Contains(t, docs["p"].AsValueMap()["json"].AsString(), `"s3:Right"`)
	require.NotContains(t, docs["p"].AsValueMap()["json"].AsString(), `"s3:Wrong"`)
}

// A policy document reading itself through locals is a cycle Terraform
// rejects: it is left unrendered, however many locals alias it, while the
// documents outside the cycle still render.
func Test_getDataSourcePolicy_cycleThroughLocalsIsNotRendered(t *testing.T) {
	for _, ref := range []string{
		"data.aws_iam_policy_document.p.json",
		`data.aws_iam_policy_document["p"].json`,
		`data["aws_iam_policy_document"]["p"].json`,
		`lookup(data.aws_iam_policy_document, "p").json`,
		`values(data.aws_iam_policy_document)[0].json`,
		`data.aws_iam_policy_document[var.k].json`,
		`data.aws_iam_policy_document.*.json`,
		`data.aws_iam_policy_document["a.b"].json`,
		`data`,
		`data[var.kind].p`,
	} {
		t.Run(ref, func(t *testing.T) {
			assertCycleThroughLocalsIsNotRendered(t, ref)
		})
	}
}

func assertCycleThroughLocalsIsNotRendered(t *testing.T, ref string) {
	t.Helper()
	for _, aliases := range []int{2, 24} {
		var b strings.Builder
		fmt.Fprintf(&b, "locals {\n  l0 = [%s, \"x\"]\n", ref)
		for i := 0; i < aliases; i++ {
			fmt.Fprintf(&b, "  alias%d = [%s]\n", i, ref)
		}
		b.WriteString(`}
data "aws_iam_policy_document" "p" {
  statement {
    actions = [jsonencode(local.l0)]
  }
}
data "aws_iam_policy_document" "other" {
  statement {
    sid     = "Other"
    actions = ["s3:GetObject"]
  }
}
`)
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(b.String()), 0o600))
		ctx := context.Background()
		inputVars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
		result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, inputVars, nil, "")
		var data map[string]map[string]map[string]string
		require.NoError(t, gocty.FromCtyValue(result["data"], &data))
		require.NotContains(t, data["aws_iam_policy_document"], "p", "aliases=%d", aliases)
		require.Contains(t, data["aws_iam_policy_document"]["other"]["json"], `"Sid":"Other"`)
	}
}

func Test_getDataSourcePolicy_cycleThroughWholeLocalIsNotRendered(t *testing.T) {
	for _, expr := range []string{
		`lookup(local, "l0")`,
		`local[var.k]`,
		`values(local)[0]`,
		`local.*`,
		`local["a.b"]`,
	} {
		t.Run(expr, func(t *testing.T) {
			src := fmt.Sprintf(`
locals {
  l0 = [data.aws_iam_policy_document.p.json, "x"]
}
data "aws_iam_policy_document" "p" {
  statement {
    actions = [jsonencode(%s)]
  }
}
data "aws_iam_policy_document" "other" {
  statement {
    sid     = "Other"
    actions = ["s3:GetObject"]
  }
}
`, expr)
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o600))
			ctx := context.Background()
			inputVars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
			result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, inputVars, nil, "")
			var data map[string]map[string]map[string]string
			require.NoError(t, gocty.FromCtyValue(result["data"], &data))
			require.NotContains(t, data["aws_iam_policy_document"], "p")
			require.Contains(t, data["aws_iam_policy_document"]["other"]["json"], `"Sid":"Other"`)
		})
	}
}

func Test_getDataSourcePolicy_specificLocalDoesNotCycleThroughSibling(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
locals {
  alias = data.aws_iam_policy_document.p.json
  safe  = "s3:GetObject"
}
data "aws_iam_policy_document" "p" {
  statement {
    actions = [local.safe]
  }
}
`), 0o600))
	ctx := context.Background()
	inputVars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, inputVars, nil, "")
	var data map[string]map[string]map[string]string
	require.NoError(t, gocty.FromCtyValue(result["data"], &data))
	require.Contains(t, data["aws_iam_policy_document"]["p"]["json"], "s3:GetObject")
}

func Test_getDataSourcePolicy_dynamicIteratorNamedLocalStillRenders(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
locals {
  value   = data.aws_iam_policy_document.p.json
  actions = ["s3:GetObject"]
}
data "aws_iam_policy_document" "p" {
  dynamic "statement" {
    for_each = local.actions
    iterator = local
    content {
      actions = [local.value]
    }
  }
}
`), 0o600))
	ctx := context.Background()
	inputVars := getInputVariables(ctx, vfs.DiskFS{}, dir, "", "", nil, "")
	result := getDataSourcePolicy(ctx, vfs.DiskFS{}, dir, inputVars, nil, "")
	var data map[string]map[string]map[string]string
	require.NoError(t, gocty.FromCtyValue(result["data"], &data))
	require.Contains(t, data["aws_iam_policy_document"]["p"]["json"], "s3:GetObject")
}

func TestDataCycles(t *testing.T) {
	parse := func(src string) []hcl.Traversal {
		expr, diags := hclsyntax.ParseExpression([]byte(src), "main.tf", hcl.InitialPos)
		require.False(t, diags.HasErrors())
		return expr.Variables()
	}
	reads := map[string][]hcl.Traversal{
		DataKey("t", "self"):     parse(`data.t.self.json`),
		DataKey("t", "indexed"):  parse(`data.t["indexed"].json`),
		DataKey("t", "bracket"):  parse(`data["t"]["bracket"].json`),
		DataKey("t", "viaA"):     parse(`local.a`),
		DataKey("t", "chain"):    parse(`data.t.self.json`),
		DataKey("t", "plain"):    parse(`local.c`),
		DataKey("t", "runtime"):  parse(`data.t[var.name].json`),
		DataKey("t", "lookup"):   parse(`lookup(data.t, "lookup").json`),
		DataKey("t", "values"):   parse(`values(data.t)[0].json`),
		DataKey("t", "splat"):    parse(`data.t.*.json`),
		DataKey("t", "number"):   parse(`data.t[0].json`),
		DataKey("t", "dotted"):   parse(`data.t["a.b"].json`),
		DataKey("t", "viaLocal"): parse(`lookup(local, "alias")`),
		DataKey("t", "viaIndex"): parse(`local[var.k]`),
		DataKey("u", "other"):    parse(`data.t[var.name].json`),
		DataKey("u", "safe"):     parse(`local.c`),
	}
	locals := map[string][]hcl.Traversal{
		"a":     parse(`[local.b]`),
		"b":     parse(`data.t["viaA"].json`),
		"c":     parse(`var.x`),
		"alias": parse(`data.t.viaLocal.json`),
		"idx":   parse(`data.t.viaIndex.json`),
	}
	require.Equal(t, map[string]bool{
		DataKey("t", "self"):     true,
		DataKey("t", "indexed"):  true,
		DataKey("t", "bracket"):  true,
		DataKey("t", "viaA"):     true,
		DataKey("t", "runtime"):  true,
		DataKey("t", "lookup"):   true,
		DataKey("t", "values"):   true,
		DataKey("t", "splat"):    true,
		DataKey("t", "number"):   true,
		DataKey("t", "dotted"):   true,
		DataKey("t", "viaLocal"): true,
		DataKey("t", "viaIndex"): true,
	}, DataCycles(reads, locals))
}

func TestDataCycles_WholeDataReferenceReachesEveryBlock(t *testing.T) {
	parse := func(src string) []hcl.Traversal {
		expr, diags := hclsyntax.ParseExpression([]byte(src), "main.tf", hcl.InitialPos)
		require.False(t, diags.HasErrors())
		return expr.Variables()
	}
	reads := map[string][]hcl.Traversal{
		DataKey("t", "bare"):    parse(`data`),
		DataKey("t", "dynType"): parse(`data[var.kind].name`),
		DataKey("u", "sibling"): parse(`var.x`),
	}
	require.Equal(t, map[string]bool{
		DataKey("t", "bare"):    true,
		DataKey("t", "dynType"): true,
	}, DataCycles(reads, nil))
}

// Locals reading data are refreshed with the functions and path the other
// locals read, and a fallback is not taken past a root the scanner cannot read.
func Test_getDataSourcePolicy_dataLocalsReadFilesAndKeepUnreadableRootsUnresolved(t *testing.T) {
	_, locals := scanDataSourceDir(t, map[string]string{
		"actions.json": `["s3:GetObject"]`,
		"main.tf": `
data "aws_iam_policy_document" "p" {
  statement {
    actions = ["s3:*"]
  }
}
locals {
  from_file     = try(file("${path.module}/actions.json"), data.aws_iam_policy_document.p.json)
  from_resource = try(aws_s3_bucket.b.arn, data.aws_iam_policy_document.p.json)
}
`,
	})
	requireLocal(t, locals, "from_file", cty.StringVal(`["s3:GetObject"]`))
	requireUnresolvedLocal(t, locals, "from_resource")
}

// An override file decides a local reading data whatever its name sorts to.
func Test_getDataSourcePolicy_overrideFileWinsWhateverItsName(t *testing.T) {
	_, locals := scanDataSourceDir(t, map[string]string{
		"zmain.tf": `
locals {
  base_json = data.aws_iam_policy_document.first.json
}
data "aws_iam_policy_document" "first" {
  statement {
    sid     = "First"
    actions = ["sqs:*"]
  }
}
data "aws_iam_policy_document" "second" {
  statement {
    sid     = "Second"
    actions = ["s3:*"]
  }
}
`,
		"a_override.tf": `
locals {
  base_json = data.aws_iam_policy_document.second.json
}
`,
	})
	require.Contains(t, locals, "base_json")
	require.Contains(t, locals["base_json"].AsString(), `"Sid":"Second"`)
}

// A data-reading local that also reads a resource stays unresolved, even when
// the known first try argument comes from data: the scanner has no value for
// the resource, so it does not evaluate the local.
func Test_getDataSourcePolicy_dataLocalReadingAResourceStaysUnresolved(t *testing.T) {
	_, locals := scanDataSourceDir(t, map[string]string{"main.tf": `
data "aws_iam_policy_document" "p" {
  statement {
    sid     = "Known"
    actions = ["s3:GetObject"]
  }
}
locals {
  doc = try(data.aws_iam_policy_document.p.json, aws_iam_policy.x.policy)
}
`})
	requireUnresolvedLocal(t, locals, "doc")
}

// Data-reading locals evaluate templates as the other locals do: a template
// calling a function the scanner does not implement is unresolved, a supported
// file is read.
func Test_getDataSourcePolicy_dataLocalsTemplatesAndFiles(t *testing.T) {
	_, locals := scanDataSourceDir(t, map[string]string{
		"days.txt": "0",
		"main.tf": `
variable "template" {
  default = "$${ephemeralasnull(0)}"
}
variable "filename" {
  default = "days.txt"
}
data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
locals {
  from_template = length(data.aws_iam_policy_document.p.json) > 0 ? try(tonumber(templatestring(var.template, {})), 90) : 90
  template_alias = local.from_template
  from_file      = length(data.aws_iam_policy_document.p.json) > 0 ? tonumber(file("${path.module}/${var.filename}")) : 90
  file_alias     = local.from_file
}
`,
	})
	requireUnresolvedLocal(t, locals, "from_template")
	requireUnresolvedLocal(t, locals, "template_alias")
	requireLocal(t, locals, "from_file", cty.NumberIntVal(0))
	requireLocal(t, locals, "file_alias", cty.NumberIntVal(0))
}
