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
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// parseLogGroup parses file of dir with the default parser and returns the
// arguments of its aws_cloudwatch_log_group "g".
func parseLogGroup(t *testing.T, dir, file string) model.Document {
	t.Helper()
	path := filepath.Join(dir, file)
	src, err := os.ReadFile(path)
	require.NoError(t, err)
	_, docs, _, _, err := NewDefault().Parse(context.Background(), src, path, true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	return docs[0]["resource"].(model.Document)["aws_cloudwatch_log_group"].(model.Document)["g"].(model.Document)
}

func requireNumber(t *testing.T, got interface{}, want int64) {
	t.Helper()
	v, ok := got.(ctyjson.SimpleJSONValue)
	require.True(t, ok, "got %#v, want %d", got, want)
	require.True(t, v.RawEquals(cty.NumberIntVal(want)), "got %#v, want %d", v.Value, want)
}

// A local reads files and absolute paths with the functions the converter
// gives resource attributes, rooted at the directory scanned, so try and can
// do not fall back for a file that exists.
func TestParser_LocalsReadFilesLikeResourceAttributes(t *testing.T) {
	dir := writeTerraformDir(t, map[string]string{
		"days.txt": "0",
		"variables.tf": `
variable "filename" {
  default = "days.txt"
}
variable "relative" {
  default = "."
}
`,
		"locals.tf": `
locals {
  days      = try(tonumber(file("${path.module}/${var.filename}")), 90)
  present   = can(file("${path.module}/${var.filename}"))
  relative  = try(tonumber(file(var.filename)), 90)
  directory = abspath(var.relative)
  same_dir  = local.directory == abspath(path.module) ? 0 : 90
}
`,
		"main.tf": `
locals {
  alias = local.days
}
resource "aws_cloudwatch_log_group" "g" {
  name              = "sample"
  retention_in_days = local.alias
  direct            = try(tonumber(file("${path.module}/${var.filename}")), 90)
  present           = local.present
  relative          = local.relative
  same_dir          = local.same_dir
  directory         = local.directory
  direct_directory  = abspath(var.relative)
}
`,
	})
	group := parseLogGroup(t, dir, "main.tf")
	requireNumber(t, group["retention_in_days"], 0)
	requireNumber(t, group["direct"], 0)
	requireNumber(t, group["relative"], 0)
	requireNumber(t, group["same_dir"], 0)
	present, ok := group["present"].(ctyjson.SimpleJSONValue)
	require.True(t, ok, "present = %#v", group["present"])
	require.True(t, present.True())
	require.Equal(t, stringifyValue(group["direct_directory"]), stringifyValue(group["directory"]))
}

// A function the scanner does not implement is not a Terraform error, so a
// local calling it, and every local reading that one, stays unresolved instead
// of taking a try or can fallback.
func TestGetInputVariables_LocalsCallingUnimplementedFunctionsStayUnresolved(t *testing.T) {
	locals := rootLocals(t, map[string]string{
		"main.tf": `
variable "flag" {
  type      = bool
  sensitive = true
  default   = false
}
locals {
  valid     = can(sensitive(var.flag))
  revealed  = nonsensitive(sensitive(var.flag))
  ephemeral = try(ephemeralasnull(var.flag), true)
  provider  = try(provider::aws::arn_parse("arn:aws:s3:::b").service, "fallback")
  plain     = var.flag
}
`,
		"alias.tf": `
locals {
  alias = try(local.valid ? 0 : 90, 90)
}
`,
		"json.tf.json": `{"locals": {"from_json": "${try(sensitive(var.flag), true)}", "json_known": "${upper(\"a\")}"}}`,
	})
	for _, name := range []string{"valid", "revealed", "ephemeral", "provider", "alias", "from_json"} {
		requireUnresolvedLocal(t, locals, name)
	}
	requireLocal(t, locals, "plain", cty.False)
	requireLocal(t, locals, "json_known", cty.StringVal("A"))
}

func TestParser_LocalCallingUnimplementedFunctionKeepsResourceUnresolved(t *testing.T) {
	dir := writeTerraformDir(t, map[string]string{"main.tf": `
variable "flag" {
  type      = bool
  sensitive = true
  default   = false
}
locals {
  valid = can(sensitive(var.flag))
}
resource "aws_cloudwatch_log_group" "g" {
  name              = "sample"
  retention_in_days = local.valid ? 0 : 90
}
`})
	group := parseLogGroup(t, dir, "main.tf")
	require.Equal(t, "${local.valid ? 0 : 90}", group["retention_in_days"])
}

// Terraform applies override files after every other file, local by local,
// whatever their names sort to.
func TestGetInputVariables_OverrideFilesWinWhateverTheirNames(t *testing.T) {
	locals := rootLocals(t, map[string]string{
		"zmain.tf": `
variable "base" {
  default = true
}
variable "replacement" {
  default = false
}
locals {
  safe = var.base
  kept = "zmain"
}
`,
		"a_override.tf": `
locals {
  safe = var.replacement
}
`,
	})
	requireLocal(t, locals, "safe", cty.False)
	requireLocal(t, locals, "kept", cty.StringVal("zmain"))
}

func TestParser_OverrideFileDecidesResourceAttribute(t *testing.T) {
	dir := writeTerraformDir(t, map[string]string{
		"zmain.tf": `
variable "base" {
  default = true
}
variable "replacement" {
  default = false
}
locals {
  safe = var.base
}
resource "aws_cloudwatch_log_group" "g" {
  name              = "sample"
  retention_in_days = local.safe ? 90 : 0
}
`,
		"a_override.tf": `
locals {
  safe = var.replacement
}
`,
	})
	requireNumber(t, parseLogGroup(t, dir, "zmain.tf")["retention_in_days"], 0)
}

func TestGetInputVariables_JSONOverrideFilesWin(t *testing.T) {
	locals := rootLocals(t, map[string]string{
		"zmain.tf.json":      `{"variable": {"base": {"default": true}, "replacement": {"default": false}}, "locals": {"safe": "${var.base}"}}`,
		"a_override.tf.json": `{"locals": {"safe": "${var.replacement}"}}`,
	})
	requireLocal(t, locals, "safe", cty.False)
}

// An overridden literal is never evaluated, so the locals reading it get the
// override's value.
func TestGetInputVariables_OverriddenLiteralDoesNotReachDependents(t *testing.T) {
	locals := rootLocals(t, map[string]string{
		"a.tf": `
variable "safe" {
  default = false
}
locals {
  safe = true
}
`,
		"b.tf": `
locals {
  days = local.safe ? 90 : 0
}
`,
		"z_override.tf": `
locals {
  safe = var.safe
}
`,
	})
	requireLocal(t, locals, "safe", cty.False)
	requireLocal(t, locals, "days", cty.NumberIntVal(0))
}

func TestGetInputVariables_LaterOverrideFileWins(t *testing.T) {
	locals := rootLocals(t, map[string]string{
		"main.tf":       `locals { x = "main" }`,
		"a_override.tf": `locals { x = "a" }`,
		"b_override.tf": `locals { x = "b" }`,
		"override.tf":   `locals { y = "override" }`,
	})
	requireLocal(t, locals, "x", cty.StringVal("b"))
	requireLocal(t, locals, "y", cty.StringVal("override"))
}

// Root variables are conformed to their declared type, with the defaults of
// optional attributes, before any expression reads them.
func TestGetInputVariables_VariablesConformToTheirType(t *testing.T) {
	dir := writeTerraformDir(t, map[string]string{
		"main.tf": `
variable "config" {
  type    = object({ enabled = optional(bool, false) })
  default = {}
}
variable "days" {
  type = number
}
variable "bad" {
  type    = number
  default = "many"
}
locals {
  safe = try(var.config.enabled, true)
  bad  = try(var.bad + 1, 90)
}
`,
		"terraform.tfvars": `days = "30"`,
		"vars.tf.json":     `{"variable": {"names": {"type": "list(string)", "default": ["a", "b"]}}}`,
	})
	got := getInputVariables(context.Background(), vfs.DiskFS{}, dir, "", "", nil, "")
	vars := got["var"].AsValueMap()
	require.True(t, vars["config"].RawEquals(cty.ObjectVal(map[string]cty.Value{"enabled": cty.False})), "%#v", vars["config"])
	require.True(t, vars["days"].RawEquals(cty.NumberIntVal(30)), "%#v", vars["days"])
	require.True(t, vars["names"].RawEquals(cty.ListVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")})), "%#v", vars["names"])
	require.False(t, vars["bad"].IsKnown())
	locals := got["local"].AsValueMap()
	requireLocal(t, locals, "safe", cty.False)
	requireUnresolvedLocal(t, locals, "bad")
}

func TestParser_OptionalAttributeDefaultDecidesResourceAttribute(t *testing.T) {
	dir := writeTerraformDir(t, map[string]string{"main.tf": `
variable "config" {
  type    = object({ enabled = optional(bool, false) })
  default = {}
}
locals {
  safe = try(var.config.enabled, true)
}
resource "aws_cloudwatch_log_group" "g" {
  name              = "sample"
  retention_in_days = local.safe ? 90 : 0
  direct            = try(var.config.enabled, true) ? 90 : 0
}
`})
	group := parseLogGroup(t, dir, "main.tf")
	requireNumber(t, group["retention_in_days"], 0)
	requireNumber(t, group["direct"], 0)
}

// Locals in a cycle, which Terraform rejects, are unresolved, and so are the
// locals reading them.
func TestGetInputVariables_LocalsInACycleAreUnresolved(t *testing.T) {
	locals := rootLocals(t, map[string]string{"main.tf": `
locals {
  a      = local.b
  b      = local.a
  self   = local.self
  reader = try(local.a, 90)
  fine   = 1
}
`})
	for _, name := range []string{"a", "b", "self", "reader"} {
		requireUnresolvedLocal(t, locals, name)
	}
	requireLocal(t, locals, "fine", cty.NumberIntVal(1))
}

// A read of an undeclared local or variable, for instance one declared in a
// file that does not parse, stays unresolved rather than taking a fallback.
func TestGetInputVariables_ReadsOfUndeclaredNamesStayUnresolved(t *testing.T) {
	locals := rootLocals(t, map[string]string{
		"main.tf": `
locals {
  from_local = try(local.missing, 90)
  from_var   = try(var.missing, 90)
}
`,
		"broken.tf": `variable "missing" {`,
	})
	requireUnresolvedLocal(t, locals, "from_local")
	requireUnresolvedLocal(t, locals, "from_var")
}

// Each local is evaluated once, in dependency order, so a long chain declared
// in reverse across files resolves without a pass per link.
func TestGetInputVariables_LongReverseChainResolves(t *testing.T) {
	const n = 4000
	files := map[string]string{"main.tf": `variable "base" { default = 1 }`}
	for start := n - 1; start >= 0; start -= 100 {
		var b strings.Builder
		for i := start; i > start-100 && i >= 0; i-- {
			expr := "var.base"
			if i > 0 {
				expr = fmt.Sprintf("local.n%05d + 1", i-1)
			}
			fmt.Fprintf(&b, "locals { n%05d = %s }\n", i, expr)
		}
		files[fmt.Sprintf("%04d.tf", (n-1-start)/100)] = b.String()
	}
	locals := rootLocals(t, files)
	requireLocal(t, locals, fmt.Sprintf("n%05d", n-1), cty.NumberIntVal(n))
}

func Test_resolveRootLocalsEvaluatesEachLocalOnce(t *testing.T) {
	const n = 200
	var assignments []localAssignment
	for i := n - 1; i >= 0; i-- {
		src := "tick()"
		if i > 0 {
			src = fmt.Sprintf("local.n%03d + tick()", i-1)
		}
		expr, diags := hclsyntax.ParseExpression([]byte(src), "main.tf", hcl.InitialPos)
		require.False(t, diags.HasErrors(), diags.Error())
		assignments = append(assignments, localAssignment{name: fmt.Sprintf("n%03d", i), expr: expr})
	}
	calls := 0
	funcs := map[string]function.Function{"tick": function.New(&function.Spec{
		Type: function.StaticReturnType(cty.Number),
		Impl: func([]cty.Value, cty.Type) (cty.Value, error) {
			calls++
			return cty.NumberIntVal(1), nil
		},
	})}
	locals := resolveRootLocals(assignments, map[string]cty.Value{varReference: cty.EmptyObjectVal}, funcs)
	requireLocal(t, locals, fmt.Sprintf("n%03d", n-1), cty.NumberIntVal(n))
	require.Equal(t, n, calls)
}

// A local calling a function the scanner does not implement stays unresolved,
// even where the call does not decide the result: the scanner cannot tell
// whether Terraform would fail on it, which a surrounding try would read.
func TestGetInputVariables_LocalsCallingUnimplementedFunctionsStayUnresolvedEvenWhenUnused(t *testing.T) {
	locals := rootLocals(t, map[string]string{"main.tf": `
variable "value" {
  default = 0
}
locals {
  first_try   = try(90, sensitive(0))
  branch      = true ? 90 : sensitive(0)
  provider    = try(provider::sample::compute(var.value), 90)
  unsupported = try(sensitive(0), 90)
  error       = try(length([rsadecrypt("invalid", "invalid")]) == 1 ? 90 : 0, 0)
}
`})
	for _, name := range []string{"first_try", "branch", "provider", "unsupported", "error"} {
		requireUnresolvedLocal(t, locals, name)
	}
}

// A local calling templatestring or templatefile stays unresolved, whatever the
// template calls, so try does not fall back and no failure Terraform would
// raise is hidden.
func TestParser_LocalsRenderingTemplatesStayUnresolved(t *testing.T) {
	dir := writeTerraformDir(t, map[string]string{
		"days.tftpl": "${ephemeralasnull(0)}",
		"main.tf": `
variable "template" {
  default = "$${ephemeralasnull(0)}"
}
variable "filename" {
  default = "days.tftpl"
}
locals {
  from_string = try(tonumber(templatestring(var.template, {})), 90)
  from_file   = try(tonumber(templatefile("${path.module}/${var.filename}", {})), 90)
  implemented = templatestring("$${upper(\"abc\")}", {})
}
resource "aws_cloudwatch_log_group" "g" {
  name              = "sample"
  retention_in_days = local.from_string
  from_file         = local.from_file
  implemented       = local.implemented
}
`,
	})
	group := parseLogGroup(t, dir, "main.tf")
	require.Equal(t, "${local.from_string}", group["retention_in_days"])
	require.Equal(t, "${local.from_file}", group["from_file"])
	require.Equal(t, "${local.implemented}", group["implemented"])
}

func TestGetInputVariables_ImplementedFunctionsResolve(t *testing.T) {
	locals := rootLocals(t, map[string]string{
		"main.tf": `
variable "text" {
  default = "abc"
}
locals {
  days    = length(upper(var.text)) * 30
  objects = [for x in [var.text] : { k = upper(x) }]
}
`,
		"json.tf.json": `{"locals": {"json_days": "${length(upper(var.text))*30}", "escaped": "$${not_implemented()}", "literal": "not_implemented()"}}`,
	})
	requireLocal(t, locals, "days", cty.NumberIntVal(90))
	requireLocal(t, locals, "objects", cty.TupleVal([]cty.Value{cty.ObjectVal(map[string]cty.Value{"k": cty.StringVal("ABC")})}))
	requireLocal(t, locals, "json_days", cty.NumberIntVal(90))
	requireLocal(t, locals, "escaped", cty.StringVal("${not_implemented()}"))
	requireLocal(t, locals, "literal", cty.StringVal("not_implemented()"))
}

// A local reading a root the scanner has no value for (a resource,
// module.*, data.*, terraform.*) stays unresolved, even where that root does not
// decide the result: Terraform could fail on it, or give the result another
// type, as true ? 90 : terraform.workspace is the string "90".
func TestGetInputVariables_LocalsReadingRootsWithoutValueStayUnresolved(t *testing.T) {
	locals := rootLocals(t, map[string]string{"main.tf": `
variable "known" {
  default = 90
}
locals {
  known_first   = try(var.known, aws_s3_bucket.b.arn)
  resource      = try(aws_s3_bucket.b.arn, 90)
  workspace     = true ? 90 : terraform.workspace
  selected      = local.workspace == 90 ? 90 : 0
  module_output = try(length([module.child.missing]) == 1 ? 90 : 0, 0)
  data          = try(data.aws_iam_policy_document.p.json, "{}")
}
`})
	for _, name := range []string{"known_first", "resource", "workspace", "selected", "module_output", "data"} {
		requireUnresolvedLocal(t, locals, name)
	}
}

// A local is not evaluated with templatestring: the scanner's rendering
// differs from Terraform's (it may return a number, and it accepts a computed
// template argument Terraform rejects), and the template may call anything.
func TestGetInputVariables_LocalsCallingTemplateStringStayUnresolved(t *testing.T) {
	locals := rootLocals(t, map[string]string{
		"main.tf": `
variable "failing" {
  default = "$${rsadecrypt(\"invalid\", \"invalid\")}"
}
variable "known" {
  default = "$${upper(\"abc\")}"
}
variable "number" {
  default = "$${90}"
}
variable "plain" {
  default = "0"
}
locals {
  error    = try(length([templatestring(var.failing, {})]) == 1 ? 90 : 0, 0)
  known    = templatestring(var.known, {})
  days     = length(local.known) * 30
  number   = templatestring(var.number, {})
  computed = try(length([templatestring(format("%s", var.plain), {})]) == 1 ? 90 : 0, 0)
}
`,
	})
	for _, name := range []string{"error", "known", "days", "number", "computed"} {
		requireUnresolvedLocal(t, locals, name)
	}
}

// A local is evaluated only when every value it reads is wholly known, even
// where an unknown value would not decide the result: go-cty skips a function
// called with an unknown argument and folds unknown values into known
// results, such as length([unknown]) or a conditional's type.
func TestGetInputVariables_LocalsReadingUnknownValuesStayUnresolved(t *testing.T) {
	locals := rootLocals(t, map[string]string{
		"main.tf": `
variable "required" {
  type = string
}
variable "name" {
  default = "missing.txt"
}
locals {
  blocked   = sensitive("unused")
  selected  = true ? 90 : local.blocked
  days      = local.selected == 90 ? 90 : 0
  shape     = sensitive({ present = 1 })
  missing   = try(length([local.shape.missing]) == 1 ? 90 : 0, 0)
  typed     = true ? 90 : var.required
  typed_day = local.typed == 90 ? 90 : 0
  file_name = sensitive(var.name)
  from_file = try(length([file(local.file_name)]) == 1 ? 90 : 0, 0)
  known     = var.name
}
`,
	})
	for _, name := range []string{"blocked", "selected", "days", "shape", "missing", "typed", "typed_day", "file_name", "from_file"} {
		requireUnresolvedLocal(t, locals, name)
	}
	requireLocal(t, locals, "known", cty.StringVal("missing.txt"))
}

// Resource attributes keep evaluating templates as before: a template that
// fails makes try take its fallback, as in Terraform.
func TestParser_ResourceAttributeTemplateFailureTakesTryFallback(t *testing.T) {
	dir := writeTerraformDir(t, map[string]string{
		"bad.tftpl": `${rsadecrypt("invalid", "invalid")}`,
		"main.tf": `
variable "template" {
  default = "$${rsadecrypt(\"invalid\", \"invalid\")}"
}
locals {
  days = try(length([templatestring(var.template, {})]) == 1 ? 90 : 0, 0)
}
resource "aws_cloudwatch_log_group" "g" {
  name              = "sample"
  retention_in_days = try(length([templatestring(var.template, {})]) == 1 ? 90 : 0, 0)
  from_file         = try(length([templatefile("${path.module}/bad.tftpl", {})]) == 1 ? 90 : 0, 0)
  via_local         = local.days
}
`,
	})
	group := parseLogGroup(t, dir, "main.tf")
	requireNumber(t, group["retention_in_days"], 0)
	requireNumber(t, group["from_file"], 0)
	require.Equal(t, "${local.days}", group["via_local"])
}

// A read of local as a whole is evaluated after the locals it can see,
// whatever file declares them.
func TestGetInputVariables_WholeLocalReadSeesLocalsOfLaterFiles(t *testing.T) {
	locals := rootLocals(t, map[string]string{
		"variables.tf": `
variable "k" {
  default = "target"
}
variable "v" {
  default = "real"
}
`,
		"a.tf": `locals { x = local[var.k] }`,
		"z.tf": `locals { target = var.v }`,
	})
	requireLocal(t, locals, "x", cty.StringVal("real"))
}

func TestGetInputVariables_JSONLocalsReadingUnknownValuesStayUnresolved(t *testing.T) {
	locals := rootLocals(t, map[string]string{"main.tf.json": `{"locals": {
  "blocked":  "${sensitive(\"unused\")}",
  "selected": "${true ? 90 : local.blocked}",
  "days":     "${local.selected == 90 ? 90 : 0}"
}}`})
	for _, name := range []string{"blocked", "selected", "days"} {
		requireUnresolvedLocal(t, locals, name)
	}
}
