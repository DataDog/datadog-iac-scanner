/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
)

const testPlaceholder = "\u0000dd-unknown-test"

func project(t *testing.T, files map[string]string, keys LiteralKeys) *Projection {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	scan, err := model.Load(context.Background(), dir, model.Options{})
	require.NoError(t, err)
	return Project(scan.Roots, Options{Placeholder: testPlaceholder, LiteralKeys: keys})
}

func decode(t *testing.T, p *Projection) map[string]any {
	t.Helper()
	raw, err := ast.JSON(p.Input)
	require.NoError(t, err)
	return raw.(map[string]any)
}

func dd(t *testing.T, p *Projection) map[string]any {
	t.Helper()
	return decode(t, p)["_dd"].(map[string]any)
}

func get(v any, path ...string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func documentKeys(t *testing.T, p *Projection) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, d := range decode(t, p)["document"].([]any) {
		doc := d.(map[string]any)
		var keys []string
		for kind, v := range doc {
			switch kind {
			case "id", "file":
				continue
			case "resource", "data", "ephemeral":
				for typ, blocks := range v.(map[string]any) {
					for key := range blocks.(map[string]any) {
						keys = append(keys, kind+":"+typ+":"+key)
					}
				}
			case "module", "variable", "output":
				for key := range v.(map[string]any) {
					keys = append(keys, kind+":"+key)
				}
			case "provider":
				for typ, blocks := range v.(map[string]any) {
					for range blocks.([]any) {
						keys = append(keys, kind+":"+typ)
					}
				}
			case "locals":
				for range v.([]any) {
					keys = append(keys, kind)
				}
			}
		}
		sort.Strings(keys)
		out[doc["id"].(string)] = keys
	}
	return out
}

func TestDocumentsPerModuleInstanceAndFile(t *testing.T) {
	p := project(t, map[string]string{
		"main.tf": `
provider "aws" { region = "eu-west-1" }
resource "aws_instance" "c" {
  count = 2
  ami   = "a"
}
resource "aws_instance" "f" {
  for_each = toset(["x"])
}
module "m" {
  count  = 2
  source = "./m"
  name   = "n${count.index}"
}
`,
		"other.tf": `
variable "v" { default = 1 }
output "o" { value = var.v }
locals { l = 1 }
`,
		"m/main.tf": `
variable "name" {}
resource "aws_s3_bucket" "b" { bucket = var.name }
`,
	}, nil)
	require.Equal(t, map[string][]string{
		".||main.tf": {
			"module:m[0]", "module:m[1]", "provider:aws",
			"resource:aws_instance:c[0]", "resource:aws_instance:c[1]", `resource:aws_instance:f["x"]`,
		},
		".||other.tf":             {"locals", "output:o", "variable:v"},
		".|module.m[0]|m/main.tf": {"resource:aws_s3_bucket:b", "variable:name"},
		".|module.m[1]|m/main.tf": {"resource:aws_s3_bucket:b"},
	}, documentKeys(t, p))

	idx := dd(t, p)
	require.Equal(t, testPlaceholder, idx["placeholder"])
	meta := get(idx, "by_id", "./aws_instance.c[1]", "_dd_meta").(map[string]any)
	require.Equal(t, "./aws_instance.c[1]", meta["id"])
	require.Equal(t, "aws_instance.c[1]", meta["address"])
	require.Equal(t, "resource", meta["kind"])
	require.Equal(t, "aws_instance", meta["type"])
	require.Equal(t, "c", meta["label"])
	require.Equal(t, "c[1]", meta["key"])
	require.Equal(t, "", meta["module"])
	require.Equal(t, ".", meta["root"])
	require.Equal(t, "main.tf", meta["file"])
	require.Equal(t, float64(3), toFloat(meta["line"]))
	require.Equal(t, "./provider.aws", meta["provider"])
	require.Equal(t, map[string]any{}, meta["computed"])
	require.Equal(t, map[string]any{"template": map[string]any{}, "json": map[string]any{}, "nonliteral": []any{}}, meta["derived"])
	require.ElementsMatch(t, []any{"ami"}, meta["written"])

	bucket := get(idx, "by_id", `./module.m[1].aws_s3_bucket.b`).(map[string]any)
	require.Equal(t, "n1", bucket["bucket"])
	require.Equal(t, "module.m[1]", get(bucket, "_dd_meta", "module"))
	require.Equal(t, "./provider.aws", get(bucket, "_dd_meta", "provider"), "the default provider is inherited")

	call := get(idx, "by_id", "./module.m[0]").(map[string]any)
	require.Equal(t, "m[0]", get(call, "_dd_meta", "key"))
	require.Equal(t, "", get(call, "_dd_meta", "type"))
	require.Equal(t, "n0", call["name"])
	require.Len(t, get(idx, "blocks", "module"), 2)
	require.Len(t, get(idx, "blocks", "resource", "aws_instance"), 3)
	require.Len(t, get(idx, "blocks", "provider", "aws"), 1)
	require.Len(t, get(idx, "blocks", "locals"), 1)
	require.Equal(t, map[string]any{}, get(idx, "blocks", "data"))
}

func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return -1
}

var s3Keys = LiteralKeys{"aws_s3_bucket_versioning": {"bucket": {"aws_s3_bucket": {"bucket"}}}}

func ids(v any) []any {
	l, _ := v.([]any)
	return l
}

func TestReferenceIndexes(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
variable "x" {}
resource "aws_security_group" "web" {}
resource "aws_instance" "app" {
  vpc_security_group_ids = [aws_security_group.web.id]
}
resource "aws_instance" "maybe" {
  vpc_security_group_ids = var.x ? [aws_security_group.web.id] : []
}
resource "aws_lambda_function" "fn" {
  vpc_config { security_group_ids = [aws_security_group.web.id] }
}
`}, nil)
	idx := dd(t, p)
	require.Equal(t, []any{"./aws_instance.app", testPlaceholder},
		get(idx, "referrers", "./aws_security_group.web", "vpc_security_group_ids"), "an uncertain reference ends the list with the placeholder")
	require.Equal(t, []any{"./aws_lambda_function.fn"},
		get(idx, "referrers", "./aws_security_group.web", "vpc_config.security_group_ids"))
	require.Equal(t, []any{"./aws_instance.app", testPlaceholder},
		get(idx, "related", "./aws_security_group.web", "aws_instance", "vpc_security_group_ids"))
	require.Equal(t, []any{"./aws_security_group.web"}, get(idx, "targets", "./aws_instance.app", "vpc_security_group_ids"))
	require.Equal(t, []any{testPlaceholder}, get(idx, "targets", "./aws_instance.maybe", "vpc_security_group_ids"))
	require.NotContains(t, get(idx, "targets", "./aws_instance.app", "vpc_security_group_ids"), testPlaceholder,
		"targets answer for the block itself: another block's untraced value does not matter")
	require.Nil(t, get(idx, "targets", "./aws_security_group.web"), "a block that references nothing has no entry")
	for _, name := range []string{"untargeted", "incomplete", "literals"} {
		require.NotContains(t, idx, name, "the engine indexes hold final answers only")
	}
	require.True(t, p.Blocks["./aws_security_group.web"].RelPlaceholder)
	require.True(t, p.Blocks["./aws_lambda_function.fn"].RelPlaceholder,
		"an untraced path of a type may reference any block, so every block of the root may have a placeholder in related")
}

// A traced reference to a computed attribute (the id of a bucket) is a
// target of the referencing block and a related block of the target.
func TestTracedReferenceIsATarget(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "aws_s3_bucket" "b" { bucket = "x" }
resource "aws_cloudtrail" "foobar" {
  name           = "t"
  s3_bucket_name = aws_s3_bucket.b.id
}
resource "aws_s3_bucket_public_access_block" "pab" { bucket = aws_s3_bucket.b.id }
`}, LiteralKeys{
		"aws_cloudtrail":                    {"s3_bucket_name": {"aws_s3_bucket": {"bucket"}}},
		"aws_s3_bucket_public_access_block": {"bucket": {"aws_s3_bucket": {"bucket"}}},
	})
	idx := dd(t, p)
	require.Equal(t, []any{"./aws_s3_bucket.b"}, get(idx, "targets", "./aws_cloudtrail.foobar", "s3_bucket_name"))
	require.Equal(t, []any{"./aws_s3_bucket.b"}, get(idx, "targets", "./aws_s3_bucket_public_access_block.pab", "bucket"))
	require.Equal(t, []any{"./aws_cloudtrail.foobar"}, get(idx, "related", "./aws_s3_bucket.b", "aws_cloudtrail", "s3_bucket_name"))
	require.Equal(t, []any{"./aws_cloudtrail.foobar", "./aws_s3_bucket_public_access_block.pab"}, sortedAny(
		append(ids(get(idx, "referrers", "./aws_s3_bucket.b", "s3_bucket_name")), ids(get(idx, "referrers", "./aws_s3_bucket.b", "bucket"))...)))
	require.False(t, p.Blocks["./aws_cloudtrail.foobar"].RelPlaceholder)
}

// A reference to a target's arn is indexed under the source attribute path the
// same way a reference to id is: relation paths hold attribute names of the
// source only, so CloudWatch alarms that set metric_name from a filter.arn
// still list that filter in targets (and the filter lists the alarm in related).
func TestArnReferenceIsATarget(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "aws_cloudwatch_log_metric_filter" "f" {
  name           = "M"
  pattern        = "{ $.x = 1 }"
  log_group_name = "g"
  metric_transformation {
    name      = "M"
    namespace = "NS"
    value     = "1"
  }
}
resource "aws_sns_topic" "t" { name = "t" }
resource "aws_cloudwatch_metric_alarm" "a" {
  alarm_name          = "A"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.f.arn
  namespace           = "NS"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.t.arn]
}
`}, nil)
	idx := dd(t, p)
	require.Equal(t, []any{"./aws_cloudwatch_log_metric_filter.f"},
		get(idx, "targets", "./aws_cloudwatch_metric_alarm.a", "metric_name"))
	require.Equal(t, []any{"./aws_sns_topic.t"},
		get(idx, "targets", "./aws_cloudwatch_metric_alarm.a", "alarm_actions"))
	require.Equal(t, []any{"./aws_cloudwatch_metric_alarm.a"},
		get(idx, "related", "./aws_cloudwatch_log_metric_filter.f", "aws_cloudwatch_metric_alarm", "metric_name"))
	require.Equal(t, []any{"./aws_cloudwatch_metric_alarm.a"},
		get(idx, "related", "./aws_sns_topic.t", "aws_cloudwatch_metric_alarm", "alarm_actions"))
}

// A metric filter keeps its pattern as the evaluated string. The expression
// tree lives under _dd_meta.filter: "ok" with the tree, or "unsupported" with
// the placeholder when the parser cannot interpret the pattern (regex, for
// one), so a rule that cannot prove the pattern stays uncertain.
// Distinct reads of the same top-level attribute (tags.A and tags.B) each keep
// their full read path in targets, and a local alias that indexes further
// (local.tags.A) preserves the suffix on the read path.
func TestTargetsViaKeepsFullReadPaths(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "aws_s3_bucket" "b" {
  bucket = "b"
  tags   = { A = "a", B = "b" }
}
locals { tags = aws_s3_bucket.b.tags }
output "both" {
  value = [aws_s3_bucket.b.tags.A, aws_s3_bucket.b.tags.B]
}
output "from_local" {
  value = local.tags.A
}
`}, nil)
	idx := dd(t, p)
	require.Equal(t, []any{"./aws_s3_bucket.b"}, get(idx, "targets", "./output.both", "value#tags.A"))
	require.Equal(t, []any{"./aws_s3_bucket.b"}, get(idx, "targets", "./output.both", "value#tags.B"))
	require.Equal(t, []any{"./aws_s3_bucket.b"}, get(idx, "targets", "./output.from_local", "value#tags.A"),
		"local.tags.A must keep the .A suffix on the bucket tags read")
}

func TestMetricFilterPatternIsParsed(t *testing.T) {
	filter := func(name, pattern string) string {
		return `resource "aws_cloudwatch_log_metric_filter" "` + name + `" {
  name           = "M"
  pattern        = "` + pattern + `"
  log_group_name = "g"
  metric_transformation {
    name      = "M"
    namespace = "NS"
    value     = "1"
  }
}
`
	}
	p := project(t, map[string]string{"main.tf": filter("ok", `{ $.eventName = ConsoleLogin }`) +
		filter("bad", `{ $.eventName = `) +
		filter("regex", `{ ($.eventName = %^ConsoleLogin$%) && ($.additionalEventData.MFAUsed != \"Yes\") }`)}, nil)
	block := func(label string) ast.Object {
		return p.Blocks["./aws_cloudwatch_log_metric_filter."+label].Term.Value.(ast.Object)
	}
	pattern := func(label string) string {
		return string(block(label).Get(ast.StringTerm("pattern")).Value.(ast.String))
	}
	filterMeta := func(label string) ast.Object {
		meta := block(label).Get(ast.StringTerm("_dd_meta")).Value.(ast.Object)
		return meta.Get(ast.StringTerm("filter")).Value.(ast.Object)
	}
	require.Equal(t, `{ $.eventName = ConsoleLogin }`, pattern("ok"))
	require.Equal(t, `"ok"`, filterMeta("ok").Get(ast.StringTerm("status")).String())
	require.Contains(t, filterMeta("ok").Get(ast.StringTerm("expr")).String(), `_dd_filter_expr`)
	require.False(t, p.Blocks["./aws_cloudwatch_log_metric_filter.ok"].Placeholder)

	require.Equal(t, `{ $.eventName = `, pattern("bad"))
	require.Equal(t, `"unsupported"`, filterMeta("bad").Get(ast.StringTerm("status")).String())
	require.Equal(t, testPlaceholder, string(filterMeta("bad").Get(ast.StringTerm("expr")).Value.(ast.String)))
	require.True(t, p.Blocks["./aws_cloudwatch_log_metric_filter.bad"].Placeholder)

	require.Contains(t, pattern("regex"), `%^ConsoleLogin$%`)
	require.Equal(t, `"unsupported"`, filterMeta("regex").Get(ast.StringTerm("status")).String())
	require.Equal(t, testPlaceholder, string(filterMeta("regex").Get(ast.StringTerm("expr")).Value.(ast.String)))
	require.True(t, p.Blocks["./aws_cloudwatch_log_metric_filter.regex"].Placeholder)
}

func sortedAny(in []any) []any {
	sort.Slice(in, func(i, j int) bool { return in[i].(string) < in[j].(string) })
	return in
}

func TestLiteralCompanions(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
variable "x" {}
resource "aws_s3_bucket" "named" { bucket = "named" }
resource "aws_s3_bucket" "other" { bucket = "other" }
resource "aws_s3_bucket" "late" { bucket = "late-${var.x}" }
resource "aws_s3_bucket_versioning" "v" { bucket = "named" }
resource "aws_s3_bucket_versioning" "many" {
  count  = var.x
  bucket = "other"
}
resource "aws_s3_bucket_versioning" "path" { bucket = "${path.module}-late" }
`}, s3Keys)
	idx := dd(t, p)
	require.Equal(t, []any{"./aws_s3_bucket_versioning.v"},
		get(idx, "related", "./aws_s3_bucket.named", "aws_s3_bucket_versioning", "bucket"))
	require.Equal(t, []any{testPlaceholder}, get(idx, "related", "./aws_s3_bucket.other", "aws_s3_bucket_versioning", "bucket"),
		"a companion with an unknown count is uncertain")
	require.Equal(t, []any{testPlaceholder}, get(idx, "related", "./aws_s3_bucket.late", "aws_s3_bucket_versioning", "bucket"),
		"an unknown bucket name may match any literal; a path.* literal names nothing")
	require.Equal(t, []any{"./aws_s3_bucket.named", testPlaceholder}, get(idx, "targets", "./aws_s3_bucket_versioning.v", "bucket"),
		"the literal names the bucket; a bucket with an unknown name may be named too")
	require.Equal(t, []any{"./aws_s3_bucket.other", testPlaceholder}, get(idx, "targets", "./aws_s3_bucket_versioning.many", "bucket"),
		"a bucket whose name is unknown may be named too")
	require.Nil(t, get(idx, "targets", "./aws_s3_bucket_versioning.path", "bucket"), "a path.* literal names nothing")
}

// A literal that several blocks of its scope hold names all of them, and one
// that matches nothing in the scope is uncertain.
func TestLiteralAmbiguity(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "aws_s3_bucket" "one" { bucket = "same" }
resource "aws_s3_bucket" "two" { bucket = "same" }
resource "aws_s3_bucket_versioning" "v" { bucket = "same" }
resource "aws_s3_bucket_versioning" "elsewhere" { bucket = "absent" }
`}, s3Keys)
	idx := dd(t, p)
	require.Equal(t, []any{"./aws_s3_bucket.one", "./aws_s3_bucket.two"}, get(idx, "targets", "./aws_s3_bucket_versioning.v", "bucket"))
	require.Equal(t, []any{testPlaceholder}, get(idx, "targets", "./aws_s3_bucket_versioning.elsewhere", "bucket"))
}

func TestLiteralScopeFollowsTheProvider(t *testing.T) {
	keys := LiteralKeys{"aws_iam_role_policy_attachment": {"role": {"aws_iam_role": {"name"}}}}
	same := `
provider "aws" { region = "eu-west-1" }
resource "aws_iam_role" "r" { name = "app" }
resource "aws_iam_role_policy_attachment" "a" { role = "app" }
`
	p := project(t, map[string]string{"main.tf": same}, keys)
	require.Equal(t, []any{"./aws_iam_role_policy_attachment.a"},
		get(dd(t, p), "related", "./aws_iam_role.r", "aws_iam_role_policy_attachment", "role"))

	other := `
provider "aws" { region = "eu-west-1" }
provider "aws" {
  alias  = "west"
  region = "us-west-2"
}
resource "aws_iam_role" "r" { name = "app" }
resource "aws_iam_role_policy_attachment" "a" {
  provider = aws.west
  role     = "app"
}
`
	p = project(t, map[string]string{"main.tf": other}, keys)
	require.Nil(t, get(dd(t, p), "related", "./aws_iam_role.r", "aws_iam_role_policy_attachment", "role"),
		"a foreign provider scope does not name this role")
	require.Equal(t, []any{testPlaceholder}, get(dd(t, p), "targets", "./aws_iam_role_policy_attachment.a", "role"),
		"the literal may still name a role in that other account")
}

func TestNestedLocalCountIndexReference(t *testing.T) {
	keys := LiteralKeys{"aws_iam_role_policy": {"role": {"aws_iam_role": {"name", "id"}}}}
	p := project(t, map[string]string{"main.tf": `
locals {
  role_indexes = [0]
}
resource "aws_iam_role" "nested_indexed" {
  count = 1
  name  = "nested-indexed-role"
}
resource "aws_iam_role" "other" {
  count = 1
  name  = "other-role"
}
resource "aws_iam_role_policy" "dangerous_nested_index" {
  name = "dangerous_nested_index"
  role = aws_iam_role.nested_indexed[local.role_indexes[count.index]].id
  policy = "{}"
}
`}, keys)
	idx := dd(t, p)
	require.Equal(t, []any{"./aws_iam_role.nested_indexed[0]"},
		get(idx, "targets", "./aws_iam_role_policy.dangerous_nested_index", "role"))
	require.Equal(t, []any{"./aws_iam_role_policy.dangerous_nested_index"},
		get(idx, "related", "./aws_iam_role.nested_indexed[0]", "aws_iam_role_policy", "role"))
	require.Nil(t, get(idx, "related", "./aws_iam_role.other[0]", "aws_iam_role_policy", "role"))
	require.NotContains(t, get(idx, "related", "./aws_iam_role.nested_indexed[0]", "aws_iam_role_policy", "role"), testPlaceholder)
	require.NotContains(t, get(idx, "targets", "./aws_iam_role_policy.dangerous_nested_index", "role"), testPlaceholder)
}

func TestProviderScopedNameLiteral(t *testing.T) {
	keys := LiteralKeys{"aws_iam_role_policy": {"role": {"aws_iam_role": {"name"}}}}
	p := project(t, map[string]string{"main.tf": `
provider "aws" {
  alias  = "safe"
  region = "us-east-1"
}
provider "aws" {
  alias  = "foreign"
  region = "us-east-1"
}
resource "aws_iam_role" "safe" {
  provider = aws.safe
  name     = "shared-role"
}
resource "aws_iam_role" "foreign" {
  provider = aws.foreign
  name     = "shared-role"
}
resource "aws_iam_role_policy" "dangerous_inline" {
  provider = aws.foreign
  name     = "dangerous_inline"
  role     = "shared-role"
  policy   = "{}"
}
`}, keys)
	idx := dd(t, p)
	require.Equal(t, []any{"./aws_iam_role_policy.dangerous_inline"},
		get(idx, "related", "./aws_iam_role.foreign", "aws_iam_role_policy", "role"))
	require.Nil(t, get(idx, "related", "./aws_iam_role.safe", "aws_iam_role_policy", "role"),
		"a foreign-provider literal must not attach to the other provider's role")
	require.Equal(t, []any{"./aws_iam_role.foreign"},
		get(idx, "targets", "./aws_iam_role_policy.dangerous_inline", "role"))
	require.False(t, p.Blocks["./aws_iam_role.safe"].RelPlaceholder)
	require.False(t, p.Blocks["./aws_iam_role.foreign"].RelPlaceholder)
}

func TestCertainIAMUserReferenceOmitsLiteralPlaceholder(t *testing.T) {
	keys := LiteralKeys{"aws_iam_user_policy": {"user": {"aws_iam_user": {"name"}}}}
	p := project(t, map[string]string{"main.tf": `
resource "aws_iam_user" "alice" {
  name = "alice"
}
resource "aws_iam_user_policy" "p" {
  user   = aws_iam_user.alice.name
  policy = "{}"
}
`}, keys)
	idx := dd(t, p)
	require.Equal(t, []any{"./aws_iam_user.alice"}, get(idx, "targets", "./aws_iam_user_policy.p", "user"),
		"a certain reference is that block alone")
	require.Equal(t, []any{"./aws_iam_user_policy.p"},
		get(idx, "related", "./aws_iam_user.alice", "aws_iam_user_policy", "user"))
	require.Equal(t, []any{"./aws_iam_user_policy.p"}, get(idx, "referrers", "./aws_iam_user.alice", "user"))
	require.False(t, p.Blocks["./aws_iam_user.alice"].RelPlaceholder)
	require.False(t, p.Blocks["./aws_iam_user_policy.p"].RelPlaceholder)
}

func TestWrittenLiteralMatchesImplicitDefaultProvider(t *testing.T) {
	keys := LiteralKeys{"aws_iam_user_policy": {"user": {"aws_iam_user": {"name"}}}}
	p := project(t, map[string]string{"main.tf": `
resource "aws_iam_user" "dave" {
  name = "dave-user"
}
resource "aws_iam_user_policy" "p" {
  user = "dave-user"
}
`}, keys)
	idx := dd(t, p)
	require.Equal(t, []any{"./aws_iam_user.dave"}, get(idx, "targets", "./aws_iam_user_policy.p", "user"))
	require.Equal(t, []any{"./aws_iam_user_policy.p"},
		get(idx, "related", "./aws_iam_user.dave", "aws_iam_user_policy", "user"))
	require.False(t, p.Blocks["./aws_iam_user.dave"].RelPlaceholder)
	require.False(t, p.Blocks["./aws_iam_user_policy.p"].RelPlaceholder)

	unresolved := project(t, map[string]string{"main.tf": `
resource "aws_iam_user" "dave" {
  name = "dave-user"
}
resource "aws_iam_user_policy" "p" {
  provider = aws.west
  user     = "dave-user"
}
`}, keys)
	idx = dd(t, unresolved)
	require.Equal(t, []any{testPlaceholder}, get(idx, "targets", "./aws_iam_user_policy.p", "user"),
		"an unresolved provider alias is not the implicit default")
	require.Nil(t, get(idx, "related", "./aws_iam_user.dave", "aws_iam_user_policy", "user"),
		"a foreign provider scope does not name this user")

	aliases := project(t, map[string]string{"main.tf": `
resource "aws_iam_user" "dave" {
  provider = aws.east
  name     = "dave-user"
}
resource "aws_iam_user_policy" "p" {
  provider = aws.west
  user     = "dave-user"
}
`}, keys)
	idx = dd(t, aliases)
	require.Equal(t, []any{testPlaceholder}, get(idx, "targets", "./aws_iam_user_policy.p", "user"),
		"two unresolved aliases are not the same scope")
	require.Nil(t, get(idx, "related", "./aws_iam_user.dave", "aws_iam_user_policy", "user"),
		"a foreign provider scope does not name this user")
}

func TestUntracedValueEndsEveryListOfThePath(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
variable "x" {}
resource "aws_s3_bucket" "a" { bucket = "a" }
resource "aws_s3_bucket" "b" { bucket = "b" }
resource "aws_s3_bucket_policy" "p" { bucket = var.x }
resource "aws_s3_bucket_versioning" "v" { bucket = aws_s3_bucket.a.bucket }
`}, s3Keys)
	idx := dd(t, p)
	for _, b := range []string{"a", "b"} {
		require.Equal(t, []any{testPlaceholder}, get(idx, "related", "./aws_s3_bucket."+b, "aws_s3_bucket_policy", "bucket"))
		require.True(t, p.Blocks["./aws_s3_bucket."+b].RelPlaceholder)
	}
	require.Equal(t, []any{"./aws_s3_bucket_versioning.v", testPlaceholder}, get(idx, "referrers", "./aws_s3_bucket.a", "bucket"))
	require.Equal(t, []any{testPlaceholder}, get(idx, "referrers", "./aws_s3_bucket.b", "bucket"))
	require.Equal(t, []any{"./aws_s3_bucket_versioning.v"}, get(idx, "related", "./aws_s3_bucket.a", "aws_s3_bucket_versioning", "bucket"),
		"another path of the bucket is not affected")
	require.Equal(t, []any{testPlaceholder}, get(idx, "targets", "./aws_s3_bucket_policy.p", "bucket"))
}

// A reference to a managed address the complete root does not declare targets
// nothing: siblings of that type do not get a related placeholder.
func TestUndeclaredAddressTargetsNothing(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "aws_api_gateway_authorizer" "a" {
  name        = "a"
  rest_api_id = aws_api_gateway_rest_api.missing.id
}

resource "aws_api_gateway_rest_api" "other" {
  name = "other"
}
`}, nil)
	idx := dd(t, p)
	require.Nil(t, get(idx, "targets", "./aws_api_gateway_authorizer.a", "rest_api_id"))
	require.Nil(t, get(idx, "related", "./aws_api_gateway_rest_api.other", "aws_api_gateway_authorizer", "rest_api_id"))
	require.Nil(t, get(idx, "related", "./aws_api_gateway_rest_api.other"))
	require.False(t, p.Blocks["./aws_api_gateway_rest_api.other"].RelPlaceholder)
	require.False(t, p.Blocks["./aws_api_gateway_authorizer.a"].RelPlaceholder)
}

// for_each = <resource map> with each.value.id traces only the same-key
// subnet, so an unsecured sibling has an empty related list.
func TestEachValueOverResourceMapAssociation(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "azurerm_subnet" "protected" {
  for_each             = toset(["a", "b"])
  name                 = each.key
  resource_group_name  = "rg"
  virtual_network_name = "vn"
  address_prefixes     = ["10.2.0.0/24"]
}

resource "azurerm_subnet_network_security_group_association" "protected" {
  for_each                  = azurerm_subnet.protected
  subnet_id                 = each.value.id
  network_security_group_id = "nsg"
}

resource "azurerm_subnet" "unsecured" {
  name                 = "unsecured"
  resource_group_name  = "rg"
  virtual_network_name = "vn"
  address_prefixes     = ["10.2.1.0/24"]
}
`}, nil)
	idx := dd(t, p)
	require.Equal(t, []any{`./azurerm_subnet.protected["a"]`},
		get(idx, "targets", `./azurerm_subnet_network_security_group_association.protected["a"]`, "subnet_id"))
	require.Equal(t, []any{`./azurerm_subnet.protected["b"]`},
		get(idx, "targets", `./azurerm_subnet_network_security_group_association.protected["b"]`, "subnet_id"))
	require.Equal(t, []any{`./azurerm_subnet_network_security_group_association.protected["a"]`},
		get(idx, "related", `./azurerm_subnet.protected["a"]`, "azurerm_subnet_network_security_group_association", "subnet_id"))
	require.Equal(t, []any{`./azurerm_subnet_network_security_group_association.protected["b"]`},
		get(idx, "related", `./azurerm_subnet.protected["b"]`, "azurerm_subnet_network_security_group_association", "subnet_id"))
	require.Nil(t, get(idx, "related", "./azurerm_subnet.unsecured", "azurerm_subnet_network_security_group_association", "subnet_id"))
	require.Nil(t, get(idx, "related", "./azurerm_subnet.unsecured"))
	require.False(t, p.Blocks["./azurerm_subnet.unsecured"].RelPlaceholder)
}

func TestLocalMapLiteralIndexAssociation(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
locals {
  by_name = {
    a = azurerm_subnet.selected.id
    b = azurerm_subnet.unselected.id
  }
}
resource "azurerm_subnet" "selected" { name = "selected" }
resource "azurerm_subnet" "unselected" { name = "unselected" }
resource "azurerm_subnet_network_security_group_association" "selected" {
  subnet_id = local.by_name["a"]
}
resource "azurerm_subnet_network_security_group_association" "selected_dot" {
  subnet_id = local.by_name.a
}
`}, nil)
	idx := dd(t, p)
	for _, assoc := range []string{"./azurerm_subnet_network_security_group_association.selected", "./azurerm_subnet_network_security_group_association.selected_dot"} {
		require.Equal(t, []any{"./azurerm_subnet.selected"}, get(idx, "targets", assoc, "subnet_id"))
	}
	require.Equal(t, []any{
		"./azurerm_subnet_network_security_group_association.selected",
		"./azurerm_subnet_network_security_group_association.selected_dot",
	}, sortedAny(ids(get(idx, "related", "./azurerm_subnet.selected", "azurerm_subnet_network_security_group_association", "subnet_id"))))
	require.Nil(t, get(idx, "related", "./azurerm_subnet.unselected", "azurerm_subnet_network_security_group_association", "subnet_id"))
	require.False(t, p.Blocks["./azurerm_subnet.unselected"].RelPlaceholder)
}

func TestUndeclaredModuleTargetsNothing(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "azurerm_subnet" "first" { name = "first" }
resource "azurerm_subnet" "second" { name = "second" }
resource "azurerm_subnet_network_security_group_association" "unknown" {
  subnet_id = module.network.subnet_id
}
`}, nil)
	idx := dd(t, p)
	require.Nil(t, get(idx, "targets", "./azurerm_subnet_network_security_group_association.unknown", "subnet_id"))
	for _, subnet := range []string{"./azurerm_subnet.first", "./azurerm_subnet.second"} {
		require.Nil(t, get(idx, "related", subnet, "azurerm_subnet_network_security_group_association", "subnet_id"))
		require.False(t, p.Blocks[subnet].RelPlaceholder)
	}
}

func TestIncompleteRoot(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "aws_s3_bucket" "b" { bucket = "x" }
resource "aws_s3_bucket_versioning" "v" { bucket = aws_s3_bucket.b.bucket }
`, "broken.tf": `resource "aws_s3_bucket" "c" {`}, s3Keys)
	idx := dd(t, p)
	require.Equal(t, []any{"./aws_s3_bucket_versioning.v", testPlaceholder},
		get(idx, "related", "./aws_s3_bucket.b", "aws_s3_bucket_versioning", "bucket"))
	require.Equal(t, []any{"./aws_s3_bucket_versioning.v", testPlaceholder}, get(idx, "referrers", "./aws_s3_bucket.b", "bucket"))
	require.Equal(t, []any{"./aws_s3_bucket.b", testPlaceholder}, get(idx, "targets", "./aws_s3_bucket_versioning.v", "bucket"))
	require.True(t, p.Blocks["./aws_s3_bucket.b"].RelPlaceholder)
}

func TestInvariantValuesShareTerms(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "aws_instance" "c" {
  count = 3
  tags  = { team = "a", env = "prod" }
  name  = "c${count.index}"
}
`}, nil)
	byID := p.Input.(ast.Object).Get(ast.StringTerm("_dd")).Value.(ast.Object).Get(ast.StringTerm("by_id")).Value.(ast.Object)
	attr := func(id, name string) *ast.Term {
		return byID.Get(ast.StringTerm(id)).Value.(ast.Object).Get(ast.StringTerm(name))
	}
	require.Same(t, attr("./aws_instance.c[0]", "tags"), attr("./aws_instance.c[2]", "tags"))
	require.NotSame(t, attr("./aws_instance.c[0]", "name"), attr("./aws_instance.c[1]", "name"))
	meta := func(id string) ast.Object {
		return byID.Get(ast.StringTerm(id)).Value.(ast.Object).Get(ast.StringTerm("_dd_meta")).Value.(ast.Object)
	}
	require.Same(t, meta("./aws_instance.c[0]").Get(ast.StringTerm("lifecycle")), meta("./aws_instance.c[1]").Get(ast.StringTerm("lifecycle")))
}

// Written paths stay present for reference and unknown values; absent and
// computed attributes are not listed (B2-3).
func TestWrittenAttributePaths(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "aws_iam_user" "positive1_1" { name = "u" }
resource "aws_iam_user_policy" "p" {
  name   = "n"
  user   = aws_iam_user.user.name
  policy = "{}"
}
resource "aws_cloudfront_distribution" "d" {
  viewer_certificate {
    acm_certificate_arn = aws_acm_certificate.x.arn
  }
}
resource "aws_acm_certificate" "x" {}
resource "aws_s3_bucket" "plain" { bucket = "b" }
`}, nil)
	idx := dd(t, p)
	require.ElementsMatch(t, []any{"name", "user", "policy"},
		get(idx, "by_id", "./aws_iam_user_policy.p", "_dd_meta", "written"))
	require.Equal(t, testPlaceholder, get(idx, "by_id", "./aws_iam_user_policy.p", "user"),
		"a dangling reference is unknown, but the attribute stays written")
	require.ElementsMatch(t, []any{
		"viewer_certificate",
		"viewer_certificate.0",
		"viewer_certificate.0.acm_certificate_arn",
	}, get(idx, "by_id", "./aws_cloudfront_distribution.d", "_dd_meta", "written"))
	require.NotContains(t, get(idx, "by_id", "./aws_cloudfront_distribution.d"), "viewer_certificate")
	vc := get(idx, "nested", "./aws_cloudfront_distribution.d", "viewer_certificate").([]any)[0].(map[string]any)
	require.Equal(t, testPlaceholder, vc["acm_certificate_arn"])
	require.ElementsMatch(t, []any{"bucket"},
		get(idx, "by_id", "./aws_s3_bucket.plain", "_dd_meta", "written"))
	require.NotContains(t, get(idx, "by_id", "./aws_s3_bucket.plain", "_dd_meta", "written"), "acl")
}

func TestRangesPlaceholderBitsAndDerived(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
variable "u" {}
resource "aws_security_group" "sg" {
  ingress { from_port = 1 }
  dynamic "ingress" {
    for_each = [2, 3]
    content {
      from_port = ingress.value
    }
  }
}
resource "aws_s3_bucket" "b" {
  bucket = "b-${var.u}"
  policy = jsonencode({ Resource = var.u })
}
`}, nil)
	sg := p.Blocks["./aws_security_group.sg"]
	require.NotContains(t, get(dd(t, p), "by_id", "./aws_security_group.sg"), "ingress")
	require.Len(t, get(dd(t, p), "nested", "./aws_security_group.sg", "ingress"), 3)
	require.Equal(t, 3, sg.Range(nil).Start.Line)
	require.Equal(t, 4, sg.Range([]any{"ingress", 0}).Start.Line)
	require.Equal(t, 7, sg.Range([]any{"ingress", 2}).Start.Line, "a generated block maps to its content")
	require.Equal(t, 8, sg.Range([]any{"ingress", 2, "from_port"}).Start.Line)
	require.Equal(t, 7, sg.Range([]any{"ingress", 2, "missing"}).Start.Line, "a missing leaf is its deepest ancestor")
	require.Equal(t, 3, sg.Range([]any{"absent"}).Start.Line)
	require.False(t, sg.Placeholder)

	b := p.Blocks["./aws_s3_bucket.b"]
	require.True(t, b.Placeholder)
	require.True(t, p.Unknown[TypeKey{Root: ".", Kind: "resource", Type: "aws_s3_bucket"}])
	require.False(t, p.Unknown[TypeKey{Root: ".", Kind: "resource", Type: "aws_security_group"}])

	bucket := get(dd(t, p), "by_id", "./aws_s3_bucket.b").(map[string]any)
	require.Equal(t, testPlaceholder, bucket["bucket"])
	require.Equal(t, []any{"b-", testPlaceholder}, get(bucket, "_dd_meta", "derived", "template", "bucket"))
	require.Equal(t, map[string]any{"Resource": testPlaceholder}, get(bucket, "_dd_meta", "derived", "json", "policy"))
	require.Equal(t, "${var.u}", get(bucket, "_dd_meta", "derived", "json_expr", "policy", "Resource"))
}

func TestRangesInsideJSONDocuments(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
variable "u" {}
resource "aws_iam_policy" "encoded" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "*" }
      },
      {
        Effect = "Deny"
      },
    ]
  })
}
resource "aws_iam_policy" "heredoc" {
  policy = <<POLICY
{
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Resource": "${var.u}"
    }
  ]
}
POLICY
}
resource "aws_iam_policy" "single" {
  policy = <<-EOF
    {
      "Statement": {
        "Principal": "*",
        "Condition": { "Bool": { "aws:SecureTransport": "false" } }
      }
    }
  EOF
}
resource "aws_iam_policy" "quoted" {
  policy = "{\"Statement\": [{\"Principal\": \"*\"}]}"
}
resource "aws_iam_policy" "text" {
  policy = <<EOF
not json {
EOF
}
`}, nil)
	enc := p.Blocks["./aws_iam_policy.encoded"]
	require.Equal(t, 6, enc.Range([]any{"policy", "Statement"}).Start.Line)
	require.Equal(t, 7, enc.Range([]any{"policy", "Statement", 0}).Start.Line)
	require.Equal(t, 9, enc.Range([]any{"policy", "Statement", 0, "Principal"}).Start.Line)
	require.Equal(t, 9, enc.Range([]any{"policy", "Statement", 0, "Principal", "AWS"}).Start.Line)
	require.Equal(t, 11, enc.Range([]any{"policy", "Statement", 1}).Start.Line)
	require.Equal(t, 12, enc.Range([]any{"policy", "Statement", 1, "Effect"}).Start.Line)
	require.Equal(t, 11, enc.Range([]any{"policy", "Statement", 1, "Missing"}).Start.Line)

	hd := p.Blocks["./aws_iam_policy.heredoc"]
	require.Equal(t, 21, hd.Range([]any{"policy", "Statement", 0}).Start.Line)
	require.Equal(t, 23, hd.Range([]any{"policy", "Statement", 0, "Principal"}).Start.Line)
	require.Equal(t, 24, hd.Range([]any{"policy", "Statement", 0, "Resource"}).Start.Line, "an interpolation stands for string content")
	principal := hd.Range([]any{"policy", "Statement", 0, "Principal"})
	require.Equal(t, 7, principal.Start.Column)

	single := p.Blocks["./aws_iam_policy.single"]
	require.Equal(t, 33, single.Range([]any{"policy", "Statement", 0}).Start.Line, "an object read as a one-element list")
	require.Equal(t, 34, single.Range([]any{"policy", "Statement", 0, "Principal"}).Start.Line)
	require.Equal(t, 35, single.Range([]any{"policy", "Statement", 0, "Condition", "Bool", "aws:SecureTransport"}).Start.Line)

	require.Equal(t, 41, p.Blocks["./aws_iam_policy.quoted"].Range([]any{"policy", "Statement", 0, "Principal"}).Start.Line)
	require.Equal(t, 44, p.Blocks["./aws_iam_policy.text"].Range([]any{"policy", "Statement"}).Start.Line, "text that is not JSON is the attribute")
}

func TestRangeOfNestedBlockListName(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "google_sql_database_instance" "db" {
  settings {
    database_flags {
      name = "a"
    }
    database_flags {
      name = "b"
    }
  }
}
`}, nil)
	db := p.Blocks["./google_sql_database_instance.db"]
	require.Equal(t, 3, db.Range([]any{"settings"}).Start.Line)
	require.Equal(t, 4, db.Range([]any{"settings", 0, "database_flags"}).Start.Line, "the first block of the list")
	require.Equal(t, 7, db.Range([]any{"settings", 0, "database_flags", 1}).Start.Line)
	require.Equal(t, 3, db.Range([]any{"settings", 0, "absent"}).Start.Line)
}

func TestLiteralKeysFromModules(t *testing.T) {
	m := ast.MustParseModule(`package generic.terraform

literal_keys := {"aws_s3_bucket_acl": {"bucket": {"aws_s3_bucket": ["bucket"]}}}
`)
	keys, err := LiteralKeysFromModules(map[string]*ast.Module{"terraform.rego": m})
	require.NoError(t, err)
	require.Equal(t, LiteralKeys{"aws_s3_bucket_acl": {"bucket": {"aws_s3_bucket": {"bucket"}}}}, keys)

	other := ast.MustParseModule("package other\n\nliteral_keys := 1\n")
	keys, err = LiteralKeysFromModules(map[string]*ast.Module{"other.rego": other})
	require.NoError(t, err)
	require.Nil(t, keys)

	bad := ast.MustParseModule("package generic.terraform\n\nliteral_keys := 1\n")
	_, err = LiteralKeysFromModules(map[string]*ast.Module{"terraform.rego": bad})
	require.Error(t, err)
}

// A list attribute whose first element is unknown stays on the block: only a
// list of objects is a nested block, and an unknown string is not an object.
func TestUnknownFirstElementStaysOnBlock(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "aws_security_group" "sg" {
  name = "sg"
}
resource "aws_instance" "i" {
  security_groups = [aws_security_group.sg.id]
  ingress {
    from_port = 1
  }
}
`}, nil)
	idx := dd(t, p)
	require.Contains(t, get(idx, "by_id", "./aws_instance.i"), "security_groups")
	require.NotContains(t, get(idx, "nested", "./aws_instance.i"), "security_groups")
	require.Len(t, get(idx, "nested", "./aws_instance.i", "ingress"), 1)
}

// A jsonencode policy whose principal interpolates an unknown account id still
// exposes Action "kms:*" as a known string; only the unknown interpolation is
// the placeholder inside the principal ARN.
func TestJSONEncodePartialPrincipalKeepsKnownAction(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
data "aws_caller_identity" "current" {}
resource "aws_kms_key" "k" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}
`}, nil)
	meta := get(dd(t, p), "by_id", "./aws_kms_key.k", "_dd_meta", "derived")
	require.Equal(t, map[string]any{
		"Statement": []any{map[string]any{
			"Effect":    "Allow",
			"Principal": map[string]any{"AWS": "arn:aws:iam::" + testPlaceholder + ":root"},
			"Action":    "kms:*",
			"Resource":  "*",
		}},
	}, get(meta, "json", "policy"))
	require.Equal(t, "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
		get(meta, "json_expr", "policy", "Statement.0.Principal.AWS"))
}

// An unknown value of a rendered policy document is the placeholder inside the
// policy JSON: the policy stays valid JSON and its known statements stay known.
func TestPolicyDocumentUnknownPartIsThePlaceholderInItsJSON(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "aws_iam_role" "r" {
  name = "r"
}
data "aws_iam_policy_document" "d" {
  statement {
    actions   = ["logs:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.r.arn]
    }
  }
}
resource "aws_iam_policy" "p" {
  name   = "p"
  policy = data.aws_iam_policy_document.d.json
}
`}, nil)
	text := ""
	var find func(v any)
	find = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if s, ok := x["policy"].(string); ok {
				text = s
			}
			for _, e := range x {
				find(e)
			}
		case []any:
			for _, e := range x {
				find(e)
			}
		}
	}
	find(decode(t, p)["document"])
	var policy struct {
		Statement []struct {
			Actions    []string
			Resources  []string
			Principals map[string][]string
		}
	}
	require.NoError(t, json.Unmarshal([]byte(text), &policy), text)
	require.Len(t, policy.Statement, 1)
	require.Equal(t, []string{"logs:*"}, policy.Statement[0].Actions)
	require.Equal(t, []string{"*"}, policy.Statement[0].Resources)
	require.Equal(t, map[string][]string{"AWS": {testPlaceholder}}, policy.Statement[0].Principals)
	require.True(t, p.Blocks["./aws_iam_policy.p"].Placeholder)
}

func TestUnresolvedModuleMarksBlocksIncomplete(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "alicloud_ram_user" "u" { name = "u" }
module "remote" { source = "terraform-aws-modules/vpc/aws" }
`}, nil)
	require.False(t, p.BlocksComplete)
	require.Equal(t, false, get(dd(t, p), "blocks_complete"))
}

func TestCompleteRootMarksBlocksComplete(t *testing.T) {
	p := project(t, map[string]string{"main.tf": `
resource "alicloud_ram_user" "u" { name = "u" }
`}, nil)
	require.True(t, p.BlocksComplete)
	require.Equal(t, true, get(dd(t, p), "blocks_complete"))
}
