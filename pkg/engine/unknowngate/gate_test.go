package unknowngate

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const bucketsLib = `package datadog

buckets contains [name, b] if {
	some d in input.document
	some name, b in d.resource.aws_s3_bucket
}
`

// A derivation of a set that touches an unknown before its key is bound marks the element its
// key definition gives, whatever the order of the body. When the key depends on an iteration
// that has not run yet, the whole set is marked: a known over-taint.
func TestOrderDependentOvertaint(t *testing.T) {
	input := mustValue(t, `{"document": [{"resource": {
  "aws_s3_bucket": {
    "k1": {"bucket": "a", "acl": "public-read", "enc": false, "ports": [22]},
    "k2": {"bucket": "c", "acl": "public-read", "enc": false, "ports": [22]},
    "u":  {"bucket": "b", "acl": "${...}", "enc": "${...}", "ports": "${...}"}
  }
}}]}`)
	for _, tc := range []struct {
		name, body string
		known      bool
	}{
		{"key_first", "n := b.bucket\n\tb.enc == true", true},
		{"key_last", "b.enc == true\n\tn := b.bucket", true},
		{"key_from_later_iteration", "b.enc == true\n\tsome p in b.ports\n\tn := sprintf(\"%s:%d\", [b.bucket, p])", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGate(t, testPlaceholder, bucketsLib+`
enc_names contains n if {
	some [_, b] in buckets
	`+tc.body+`
}

DatadogPolicy contains {"rule": "A10", "name": name} if {
	some [name, b] in buckets
	not concat(":", [b.bucket, "22"]) in enc_names
	not b.bucket in enc_names
}
`)
			got := verdicts(t, g, input)
			assert.Equal(t, !tc.known, got["A10/k1"].Uncertain, "k1")
			assert.Equal(t, !tc.known, got["A10/k2"].Uncertain, "k2")
			assert.True(t, got["A10/u"].Uncertain, "u")
		})
	}
}

// A placeholder element of a list stands for any number of dynamic block instances, zero
// included: the substitution check removes it and expands to the count(...) bounds.
func TestCountRemovesDynamicElement(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

DatadogPolicy contains {"rule": "count_eq", "name": name} if {
	some name, sg in input.document[0].resource.aws_security_group
	count(sg.ingress) == 2
}

DatadogPolicy contains {"rule": "count_ne2", "name": name} if {
	some name, sg in input.document[0].resource.aws_security_group
	count(sg.ingress) != 2
	some ing in sg.ingress
	ing.cidr == "0.0.0.0/0"
}

DatadogPolicy contains {"rule": "count_gt", "name": name} if {
	some name, sg in input.document[0].resource.aws_security_group
	count(sg.ingress) > 0
	some ing in sg.ingress
	ing.cidr == "0.0.0.0/0"
}

DatadogPolicy contains {"rule": "count_lt3", "name": name} if {
	some name, sg in input.document[0].resource.aws_security_group
	count(sg.ingress) < 3
	some ing in sg.ingress
	ing.cidr == "0.0.0.0/0"
}

DatadogPolicy contains {"rule": "count_lt10", "name": name} if {
	some name, sg in input.document[0].resource.aws_security_group
	count(sg.ingress) < 10
	some ing in sg.ingress
	ing.cidr == "0.0.0.0/0"
}

DatadogPolicy contains {"rule": "count_lt34", "name": name} if {
	some name, sg in input.document[0].resource.aws_security_group
	count(sg.ingress) < 34
	some ing in sg.ingress
	ing.cidr == "0.0.0.0/0"
}

DatadogPolicy contains {"rule": "count_lt100", "name": name} if {
	some name, sg in input.document[0].resource.aws_security_group
	count(sg.ingress) < 100
	some ing in sg.ingress
	ing.cidr == "0.0.0.0/0"
}
`)
	input := mustValue(t, `{"document": [{"resource": {"aws_security_group": {"sg": {"ingress": [{"cidr": "0.0.0.0/0"}, "${...}"]}}}}]}`)
	got := verdicts(t, g, input)
	require.True(t, got["count_eq/sg"].Uncertain)
	assert.Equal(t, StageSubstitution, got["count_eq/sg"].Stage)
	// [concrete, PH] already has count 2, so != 2 never fires on that input.
	assert.NotContains(t, got, "count_ne2/sg")
	assert.False(t, got["count_gt/sg"].Uncertain)
	assert.True(t, got["count_lt3/sg"].Uncertain, "expand must be able to reach count >= 3")
	assert.True(t, got["count_lt10/sg"].Uncertain, "expand must be able to reach count >= 10")
	assert.True(t, got["count_lt34/sg"].Uncertain, "expand uses the count bound itself")
	assert.True(t, got["count_lt100/sg"].Uncertain, "expand uses the count bound itself")
	assert.Equal(t, []int{1, 2, 3, 10, 34, 100}, g.countExpands)

	g.tracerOnly = true
	got = verdicts(t, g, input)
	assert.False(t, got["count_eq/sg"].Uncertain, "the count of a list is shape only for the tracer")

	// != 2 on a longer list: remove the PH to hit count == 2.
	ne2 := mustValue(t, `{"document": [{"resource": {"aws_security_group": {"sg": {"ingress": [{"cidr": "0.0.0.0/0"}, {"cidr": "10.0.0.0/8"}, "${...}"]}}}}]}`)
	g.tracerOnly = false
	got = verdicts(t, g, ne2)
	assert.True(t, got["count_ne2/sg"].Uncertain, "remove can make count == 2; expand sizes still include 1")
	assert.Contains(t, g.countExpands, 1)
}

// Port numbers compared with attributes must not drive list-cardinality expansion.
func TestCountExpandIgnoresUnrelatedNumericConstants(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

DatadogPolicy contains {"rule": "port", "name": name} if {
	some name, sg in input.document[0].resource.aws_security_group
	count(sg.ingress) < 3
	some ing in sg.ingress
	ing.from_port <= 65535
	ing.cidr == "0.0.0.0/0"
}
`)
	assert.Equal(t, []int{1, 3}, g.countExpands, "65535 is a port bound, not a count bound")
	input := mustValue(t, `{"document": [{"resource": {"aws_security_group": {"sg": {"ingress": [{"cidr": "0.0.0.0/0", "from_port": 22}, "${...}"]}}}}]}`)
	got := verdicts(t, g, input)
	assert.True(t, got["port/sg"].Uncertain)
}

// The placeholder is compared by exact match: with a per-scan nonce, the text "${...}" in an
// input is a known value.
func TestPlaceholderNonce(t *testing.T) {
	src := bucketsLib + `
DatadogPolicy contains {"rule": "acl", "name": name} if {
	some [name, b] in buckets
	not b.acl == "private"
}
`
	input := mustValue(t, `{"document": [{"resource": {"aws_s3_bucket": {"u": {"acl": "${...}"}, "n": {"acl": "unknown-7f3a"}}}}]}`)
	got := verdicts(t, newTestGate(t, "unknown-7f3a", src), input)
	assert.False(t, got["acl/u"].Uncertain)
	assert.True(t, got["acl/n"].Uncertain)
}

// A result with _dd_id is identified by _dd_id, path and key: an unknown rendered into
// another field does not make it uncertain, an unknown rendered into the key does.
func TestBlockIdentity(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

finding(b, path, details) := object.union({"_dd_id": b.id, "path": path}, details)

DatadogPolicy contains finding(b, "enc", {"message": sprintf("bucket %s is not encrypted", [b.arn])}) if {
	some b in input.blocks
	b.enc == false
}

DatadogPolicy contains finding(b, "acl", {"key": sprintf("acl=%s", [b.arn])}) if {
	some b in input.blocks
	b.enc == false
}
`)
	input := mustValue(t, `{"blocks": [{"id": "x", "arn": "${...}", "enc": false}]}`)
	ctx := context.Background()
	results, err := g.Results(ctx, input)
	require.NoError(t, err)
	require.Len(t, results, 2)
	rep, err := g.Check(ctx, input, []Candidate{{Result: results[0]}, {Result: results[1]}})
	require.NoError(t, err)
	for i, r := range results {
		path := r.(ast.Object).Get(ast.StringTerm(fieldPath)).Value
		if path.Compare(ast.String("enc")) == 0 {
			assert.False(t, rep.Verdicts[i].Uncertain, "message only: %v", rep.Verdicts[i].Reason)
		} else {
			assert.True(t, rep.Verdicts[i].Uncertain, "key")
		}
	}
	assert.Equal(t, 1, rep.Suppressed)
}

// Comparing a value with the library's placeholder rule tests whether it is unknown, which
// does not depend on what the unknown stands for; a builtin operand holding it is still a
// touch.
func TestSentinelComparisons(t *testing.T) {
	modules := map[string]*ast.Module{}
	for name, src := range map[string]string{"lib.rego": `package generic.lib

_placeholder := object.get(input, "placeholder", "")

known(v) if {
	is_string(v)
	v != _placeholder
}

known_first(list) := array.concat(
	[x | some x in list; x != _placeholder],
	[x | some x in list; x == _placeholder],
)
`, "rule.rego": `package datadog

import data.generic.lib

DatadogPolicy contains {"rule": "known", "name": name} if {
	some name, b in input.buckets
	lib.known(b.name)
	b.acl == "public-read"
}

DatadogPolicy contains {"rule": "first", "name": name} if {
	some name, b in input.buckets
	first := lib.known_first(b.grants)[0]
	first == "everyone"
}
`} {
		m, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
		require.NoError(t, err)
		modules[name] = m
	}
	input := mustValue(t, `{"placeholder": "${...}", "buckets": {
		"k": {"name": "a", "acl": "public-read", "grants": ["everyone", "${...}"]},
		"u": {"name": "b", "acl": "public-read", "grants": ["${...}"]}
	}}`)
	for _, tc := range []struct {
		sentinels []string
		want      map[string]bool
	}{
		{nil, map[string]bool{"known/k": true, "known/u": true, "first/k": true}},
		{[]string{"data.generic.lib._placeholder"}, map[string]bool{"known/k": false, "known/u": false, "first/k": true}},
	} {
		g, err := New(Options{Placeholder: testPlaceholder, Modules: modules, Query: "data.datadog.DatadogPolicy", Sentinels: tc.sentinels})
		require.NoError(t, err)
		uncertain := map[string]bool{}
		for k, v := range verdicts(t, g, input) {
			uncertain[k] = v.Uncertain
		}
		assert.Equal(t, tc.want, uncertain, "sentinels %v", tc.sentinels)
	}
}

func TestNewErrors(t *testing.T) {
	_, err := New(Options{Query: "data.datadog.DatadogPolicy"})
	require.Error(t, err)
	m, err := ast.ParseModuleWithOpts("m.rego", "package datadog\n\nx := 1\n", ast.ParserOptions{RegoVersion: ast.RegoV1})
	require.NoError(t, err)
	_, err = New(Options{Placeholder: "p", Modules: map[string]*ast.Module{"m.rego": m}, Query: "data.datadog.DatadogPolicy"})
	require.Error(t, err, "no policy rule")
}

// placeholder is the unknown value of the test inputs.
const testPlaceholder = "${...}"

func mustValue(t testing.TB, s string) ast.Value {
	t.Helper()
	v, err := ast.ParseTerm(s)
	require.NoError(t, err)
	return v.Value
}

func newTestGate(t testing.TB, ph, src string) *Gate {
	t.Helper()
	return newMultiModuleGate(t, ph, map[string]string{"rule.rego": src})
}

func newMultiModuleGate(t testing.TB, ph string, sources map[string]string) *Gate {
	t.Helper()
	modules := make(map[string]*ast.Module, len(sources))
	for name, src := range sources {
		m, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
		require.NoError(t, err, name)
		modules[name] = m
	}
	g, err := New(Options{Placeholder: ph, Modules: modules, Query: "data.datadog.DatadogPolicy"})
	require.NoError(t, err)
	return g
}

// verdicts checks every result of the rule on input, with the whole input as scope, keyed by
// rule/name.
func verdicts(t testing.TB, g *Gate, input ast.Value) map[string]Verdict {
	t.Helper()
	ctx := context.Background()
	results, err := g.Results(ctx, input)
	require.NoError(t, err)
	cands := make([]Candidate, len(results))
	for i, r := range results {
		cands[i] = Candidate{Result: r}
	}
	rep, err := g.Check(ctx, input, cands)
	require.NoError(t, err)
	out := map[string]Verdict{}
	for i, r := range results {
		obj, ok := r.(ast.Object)
		require.True(t, ok, "result %v", r)
		rule, _ := obj.Get(ast.StringTerm("rule")).Value.(ast.String)
		name, _ := obj.Get(ast.StringTerm("name")).Value.(ast.String)
		out[string(rule)+"/"+string(name)] = rep.Verdicts[i]
	}
	return out
}
