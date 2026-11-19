package unknowngate

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown"
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

// A direct placeholder list element leaves cardinality open. Count comparisons are rejected
// during tracing instead of relying on a finite set of cardinality substitutions.
func TestCountRejectsOpenCardinality(t *testing.T) {
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
	assert.Equal(t, StageTracer, got["count_eq/sg"].Stage)
	// [concrete, PH] already has count 2, so != 2 never fires on that input.
	assert.NotContains(t, got, "count_ne2/sg")
	assert.True(t, got["count_gt/sg"].Uncertain, "the gate does not infer a lower-bound proof from an open inventory")
	assert.True(t, got["count_lt3/sg"].Uncertain, "open cardinality is rejected before finite substitutions")
	assert.True(t, got["count_lt10/sg"].Uncertain, "open cardinality is rejected before finite substitutions")
	assert.True(t, got["count_lt34/sg"].Uncertain, "open cardinality is rejected before finite substitutions")
	assert.True(t, got["count_lt100/sg"].Uncertain, "open cardinality is rejected before finite substitutions")
	assert.Equal(t, []int{1, 2, 3, 10, 34, 100}, g.countExpands)

	g.tracerOnly = true
	got = verdicts(t, g, input)
	assert.True(t, got["count_eq/sg"].Uncertain, "an open list count is uncertain during tracing")

	// != 2 on a longer list: remove the PH to hit count == 2.
	ne2 := mustValue(t, `{"document": [{"resource": {"aws_security_group": {"sg": {"ingress": [{"cidr": "0.0.0.0/0"}, {"cidr": "10.0.0.0/8"}, "${...}"]}}}}]}`)
	g.tracerOnly = false
	got = verdicts(t, g, ne2)
	assert.True(t, got["count_ne2/sg"].Uncertain, "an open list count is uncertain during tracing")
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

func TestCountOpenCollectionsTouchesUnknownCardinality(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog
import rego.v1

DatadogPolicy contains {"rule": "direct", "name": "candidate"} if count(input.open) != 12
DatadogPolicy contains {"rule": "arithmetic", "name": "candidate"} if 2 * count(input.open) != 24
DatadogPolicy contains {"rule": "dynamic", "name": "candidate"} if count(input.open) != input.limit
DatadogPolicy contains {"rule": "unknown_key", "name": "candidate"} if count(input.unknown_key) != 3
DatadogPolicy contains {"rule": "known_array_shape", "name": "candidate"} if count(input.known_array_shape) != 12
DatadogPolicy contains {"rule": "known_object_shape", "name": "candidate"} if count(input.known_object_shape) != 3
DatadogPolicy contains {"rule": "known_set_shape", "name": "candidate"} if count({"first", "second"}) == 2
DatadogPolicy contains {"rule": "independent", "name": "candidate"} if count(input.complete) != 12
DatadogPolicy contains {"rule": "unknown_key_text", "name": "candidate"} if count(input.unknown_key_text) != 1
DatadogPolicy contains {"rule": "unknown_set_text", "name": "candidate"} if {
	value := sprintf("value-%s-suffix", [input.unknown])
	count({value, "value-`+testPlaceholder+`-suffix"}) != 2
}
`)
	input := mustValue(t, `{"open":["item-0","item-1","item-2","item-3","item-4","item-5","item-6","item-7","item-8","item-9","`+testPlaceholder+`"],"limit":12,"unknown":"`+testPlaceholder+`","unknown_key":{"item":"known","`+testPlaceholder+`":"unknown-key"},"unknown_key_text":{"key-`+testPlaceholder+`-suffix":"value","key-known-suffix":"other"},"known_array_shape":[{"value":"`+testPlaceholder+`"},{"value":"known"}],"known_object_shape":{"first":"`+testPlaceholder+`","second":"known"},"complete":["item-0","item-1","item-2","item-3","item-4","item-5","item-6","item-7","item-8","item-9"]}`)
	got := verdicts(t, g, input)
	for _, rule := range []string{"direct", "arithmetic", "dynamic", "unknown_key", "unknown_key_text", "unknown_set_text"} {
		require.Contains(t, got, rule+"/candidate")
		assert.True(t, got[rule+"/candidate"].Uncertain, rule)
		assert.Equal(t, StageTracer, got[rule+"/candidate"].Stage, rule)
	}
	for _, rule := range []string{"known_array_shape", "known_object_shape", "known_set_shape", "independent"} {
		require.Contains(t, got, rule+"/candidate")
		assert.False(t, got[rule+"/candidate"].Uncertain, rule)
	}
}

func TestCountOfStringDerivedByHelperTouchesUnknownLength(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog
import rego.v1

label(value) := sprintf("prefix%s", [value])
DatadogPolicy contains {"rule": "rendered_length", "name": "candidate"} if count(label(input.unknown)) != 42
`)
	input := mustValue(t, `{"unknown":"`+testPlaceholder+`"}`)
	got := verdicts(t, g, input)
	assert.True(t, got["rendered_length/candidate"].Uncertain)
	assert.Equal(t, StageTracer, got["rendered_length/candidate"].Stage)
}

func TestCountOfSetWithUnknownMemberTouchesCardinality(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog
import rego.v1

DatadogPolicy contains {"rule": "set_length", "name": "candidate"} if {
	values := {{"value": input.unknown}, {"value": "known"}}
	count(values) != 1
}
`)
	input := mustValue(t, `{"unknown":"`+testPlaceholder+`"}`)
	got := verdicts(t, g, input)
	assert.True(t, got["set_length/candidate"].Uncertain)
}

func TestComprehensionCountTouchesOpenInventory(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog
import rego.v1

DatadogPolicy contains {"rule": "all_members", "name": "candidate"} if {
	items := [true | some _ in input.open]
	count(items) != 12
}
DatadogPolicy contains {"rule": "filtered_members", "name": "candidate"} if {
	items := [x.name | some x in input.open; is_object(x)]
	count(items) != 12
}
DatadogPolicy contains {"rule": "known_members", "name": "candidate"} if {
	items := [x.name | some x in input.closed; is_object(x)]
	count(items) != 12
}
`)
	input := mustValue(t, `{"open":[{"name":"item-0"},{"name":"item-1"},{"name":"item-2"},{"name":"item-3"},{"name":"item-4"},{"name":"item-5"},{"name":"item-6"},{"name":"item-7"},{"name":"item-8"},{"name":"item-9"},"`+testPlaceholder+`"],"closed":[{"name":"item-0"},{"name":"item-1"},{"name":"item-2"},{"name":"item-3"},{"name":"item-4"},{"name":"item-5"},{"name":"item-6"},{"name":"item-7"},{"name":"item-8"},{"name":"item-9"}]}`)
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 3)
	candidates := make([]Candidate, len(results))
	for i, result := range results {
		candidates[i] = Candidate{Result: result}
	}
	report, err := g.Check(context.Background(), input, candidates)
	require.NoError(t, err)
	require.Len(t, report.Verdicts, 3)
	got := map[string]Verdict{}
	for i, result := range results {
		obj, ok := result.(ast.Object)
		require.True(t, ok)
		rule, _ := obj.Get(ast.StringTerm("rule")).Value.(ast.String)
		got[string(rule)] = report.Verdicts[i]
	}
	for _, rule := range []string{"all_members", "filtered_members"} {
		require.Contains(t, got, rule)
		assert.True(t, got[rule].Uncertain, rule)
		assert.Equal(t, StageTracer, got[rule].Stage, rule)
	}
	require.Contains(t, got, "known_members")
	assert.False(t, got["known_members"].Uncertain)
}

func TestFailedNestedElseFunctionPropagatesMembershipTouch(t *testing.T) {
	g := newMultiModuleGate(t, testPlaceholder, map[string]string{
		"catalog.rego": `package generic.catalog
import rego.v1

allowed_values := {"alpha", "beta"}
allowed_alias := input.allowed
`,
		"rule.rego": `package datadog
import rego.v1
import data.generic.catalog

wrapper(kind, value) := false if {
	not kind in {"special", "ordinary"}
} else := special_match(kind, value)

special_match(kind, value) if {
	kind == "special"
	value in catalog.allowed_values
}

DatadogPolicy contains {"rule": "virtual_unknown", "name": "candidate"} if {
	input.kind == "special"
	not wrapper(input.kind, input.value)
}
DatadogPolicy contains {"rule": "virtual_known", "name": "candidate"} if {
input.kind == "special"
	not wrapper(input.kind, input.safe_value)
}
DatadogPolicy contains {"rule": "actual_empty", "name": "candidate"} if not input.value in input.empty_values
DatadogPolicy contains {"rule": "virtual_unknown_collection", "name": "candidate"} if not "safe" in catalog.allowed_alias
`,
	})
	input := mustValue(t, `{"kind":"special","value":"`+testPlaceholder+`","safe_value":"other","empty_values":[],"allowed":"`+testPlaceholder+`"}`)
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 4)
	candidates := make([]Candidate, len(results))
	for i, result := range results {
		candidates[i] = Candidate{Result: result}
	}
	report, err := g.Check(context.Background(), input, candidates)
	require.NoError(t, err)
	require.Len(t, report.Verdicts, 4)
	got := map[string]Verdict{}
	for i, result := range results {
		obj, ok := result.(ast.Object)
		require.True(t, ok)
		rule, _ := obj.Get(ast.StringTerm("rule")).Value.(ast.String)
		got[string(rule)] = report.Verdicts[i]
	}
	require.Contains(t, got, "virtual_unknown")
	assert.True(t, got["virtual_unknown"].Uncertain, "a virtual set could contain an unknown needle")
	assert.Equal(t, StageTracer, got["virtual_unknown"].Stage)
	require.Contains(t, got, "virtual_known")
	assert.False(t, got["virtual_known"].Uncertain, "a known nonmember remains certain")
	require.Contains(t, got, "actual_empty")
	assert.False(t, got["actual_empty"].Uncertain, "an actual empty set cannot contain any needle")
	require.Contains(t, got, "virtual_unknown_collection")
	assert.True(t, got["virtual_unknown_collection"].Uncertain, "a virtual collection with an unknown value can contain a known needle")
}

func TestStage2StillRunsForIndependentFindingWithOpenInventory(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog
import rego.v1

DatadogPolicy contains {"rule": "independent", "name": "candidate"} if true
`)
	input := mustValue(t, `{"open":["known","`+testPlaceholder+`"]}`)
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 1)

	report, err := g.Check(context.Background(), input, []Candidate{{Result: results[0]}})
	require.NoError(t, err)
	require.Len(t, report.Verdicts, 1)
	assert.False(t, report.Verdicts[0].Uncertain)
	assert.Positive(t, report.SubstitutionEvals, "an independent finding still exercises Stage 2 for the unknown-bearing scope")
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
	return newMultiModuleGateWithStore(t, ph, sources, nil)
}

func newMultiModuleGateWithStore(t testing.TB, ph string, sources map[string]string, store storage.Store) *Gate {
	t.Helper()
	modules := make(map[string]*ast.Module, len(sources))
	for name, src := range sources {
		m, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
		require.NoError(t, err, name)
		modules[name] = m
	}
	g, err := New(Options{Placeholder: ph, Modules: modules, Query: "data.datadog.DatadogPolicy", Store: store})
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

type cancelOnReadStore struct {
	storage.Store
	cancel           context.CancelFunc
	cancelAt         int
	reads            int
	cancelledAt      int
	readsAfterCancel int
}

func (s *cancelOnReadStore) Read(ctx context.Context, txn storage.Transaction, path storage.Path) (any, error) {
	s.reads++
	if s.cancel != nil && s.cancelAt > 0 && s.reads == s.cancelAt {
		s.cancel()
		s.cancelledAt = s.reads
	}
	if s.cancelledAt > 0 && s.reads > s.cancelledAt {
		s.readsAfterCancel++
	}
	return s.Store.Read(ctx, txn, path)
}

func probeCall(t testing.TB, g *Gate) (*ast.Rule, *ast.Expr) {
	t.Helper()
	rules := g.traced.GetRulesExact(ast.MustParseRef("data.datadog.DatadogPolicy"))
	require.Len(t, rules, 1)
	for _, expr := range rules[0].Body {
		if expr.IsCall() && expr.Operator().String() == "data.generic.lib.read" {
			return rules[0], expr
		}
	}
	t.Fatal("compiled rule does not call the helper")
	return nil, nil
}

func tracerWithContext(g *Gate, ctx context.Context, input ast.Value) *tracer {
	return newTracer(g, ctx, input)
}

func TestCheckStopsWhenCanceled(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{"pre-canceled", func(t *testing.T) {
			g := newTestGate(t, testPlaceholder, `package datadog
DatadogPolicy contains {"rule": "x", "name": "x"} if input.flag
`)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := g.Check(ctx, mustValue(t, `{"flag": true}`), []Candidate{{Result: mustValue(t, `{"rule": "x", "name": "x"}`)}})
			require.ErrorIs(t, err, context.Canceled)
		}},
		{"during-evaluation", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			store := &cancelOnReadStore{
				Store:  inmem.NewFromObject(map[string]any{"test": map[string]any{"enabled": true}}),
				cancel: cancel, cancelAt: 1,
			}
			g := newMultiModuleGateWithStore(t, testPlaceholder, map[string]string{"rule.rego": `package datadog
DatadogPolicy contains {"rule": "read", "name": "x"} if data.test.enabled
`}, store)
			_, err := g.Check(ctx, mustValue(t, `{}`), []Candidate{{Result: mustValue(t, `{"rule": "read", "name": "x"}`)}})
			require.ErrorIs(t, err, context.Canceled)
			require.Positive(t, store.reads)
		}},
		{"inside-probe", func(t *testing.T) {
			sources := map[string]string{
				"lib.rego": `package generic.lib
read() := data.other.value if data.test.enabled
`,
				"rule.rego": `package datadog
import rego.v1
import data.generic.lib as lib
DatadogPolicy contains {"rule": "probe", "name": name} if name := lib.read()
`,
			}
			ctx, cancel := context.WithCancel(context.Background())
			store := &cancelOnReadStore{
				Store: inmem.NewFromObject(map[string]any{
					"test":  map[string]any{"enabled": true},
					"other": map[string]any{"value": "x"},
				}),
				cancel: cancel, cancelAt: 1,
			}
			g := newMultiModuleGateWithStore(t, testPlaceholder, sources, store)
			rule, call := probeCall(t, g)
			tr := tracerWithContext(g, ctx, mustValue(t, `{}`))
			got := tr.evalCall(&frame{input: tr.input}, rule, call, &topdown.Event{}, 0)
			require.Nil(t, got)
			require.ErrorIs(t, ctx.Err(), context.Canceled)
			require.Equal(t, 1, store.cancelledAt)
			require.Zero(t, store.readsAfterCancel, "probe must not make a later store read after cancellation")
			require.Empty(t, tr.probes.m, "canceled probe must not cache a partial result")

			controlStore := &cancelOnReadStore{Store: inmem.NewFromObject(map[string]any{
				"test":  map[string]any{"enabled": true},
				"other": map[string]any{"value": "x"},
			})}
			controlGate := newMultiModuleGateWithStore(t, testPlaceholder, sources, controlStore)
			controlRule, controlCall := probeCall(t, controlGate)
			controlTracer := tracerWithContext(controlGate, context.Background(), mustValue(t, `{}`))
			controlResult := controlTracer.evalCall(&frame{input: controlTracer.input}, controlRule, controlCall, &topdown.Event{}, 0)
			require.Equal(t, ast.String("x"), controlResult)
			require.GreaterOrEqual(t, controlStore.reads, 2, "control must read both data paths")
			require.Zero(t, controlStore.readsAfterCancel)
			require.Len(t, controlTracer.probes.m, 1)
			cached := false
			for _, entries := range controlTracer.probes.m {
				for _, entry := range entries {
					cached = cached || ast.Compare(entry.v, ast.String("x")) == 0
				}
			}
			require.True(t, cached, "uncanceled probe must cache its result")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}
func TestCombinedSubstitutionChecksUnknownsIndividually(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog
import rego.v1

DatadogPolicy contains {"rule": "same_count", "name": name} if {
	some name, sg in input.document[0].resource.aws_security_group
	count(sg.ingress) == count(sg.egress)
}
`)
	input := mustValue(t, `{"document": [{"resource": {"aws_security_group": {"sg": {"ingress": [{"cidr": "a"}, "`+testPlaceholder+`"], "egress": [{"cidr": "b"}, "`+testPlaceholder+`"]}}}}]}`)
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 1)
	report, err := g.Check(context.Background(), input, []Candidate{{Result: results[0]}})
	require.NoError(t, err)
	require.True(t, report.Verdicts[0].Uncertain)
	require.Equal(t, StageTracer, report.Verdicts[0].Stage)

	// Preserve the Stage 2 individual-confirmation regression using this same result. The full
	// Check correctly stops at Stage 1 now that both open list counts are unknown.
	ph := newPlaceholder(testPlaceholder)
	id, mask := ph.identity(results[0])
	stage2Job := job{index: 0, cand: Candidate{Result: results[0]}, id: id, mask: mask}
	out := make([]Verdict, 1)
	sub := &substitution{g: g, ctx: context.Background(), input: input, ph: ph}
	require.NoError(t, sub.batch([]job{stage2Job}, out))
	require.True(t, out[0].Uncertain)
	require.Equal(t, StageSubstitution, out[0].Stage)
}

func TestCombinedSubstitutionConfirmsAcrossCandidateScopes(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog
import rego.v1

DatadogPolicy contains {"rule": "same_count", "name": a.name} if {
	some a in input.blocks
	some b in input.blocks
	a.id != b.id
	count(a.items) == count(b.items)
}
`)
	input := mustValue(t, `{"blocks": [
		{"id": "a", "name": "a", "items": ["`+testPlaceholder+`"]},
		{"id": "b", "name": "b", "items": ["`+testPlaceholder+`"]}
	]}`)
	blocks := input.(ast.Object).Get(ast.StringTerm("blocks")).Value.(*ast.Array)
	scopes := []ast.Value{blocks.Elem(0).Value, blocks.Elem(1).Value}
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 2)

	ph := newPlaceholder(testPlaceholder)
	r := batchReplacement{replacement: replacement{remove: true}, listOnly: true}
	replacements := newValueMap[ast.Value]()
	for _, scope := range scopes {
		replacements.put(scope, replaceEvery(scope, r, ph))
		occ := occurrences(scope, ph)
		require.Len(t, occ, 1)
		singleScope := replaceAt(scope, occ[0].path, r.replacement)
		singleInput := rebuild(input, ph, func(v ast.Value) (ast.Value, bool) {
			return singleScope, sameValue(v, scope)
		})
		singleResults, err := g.Results(context.Background(), singleInput)
		require.NoError(t, err)
		require.Empty(t, singleResults, "either single-scope substitution must remove both results")
	}
	combinedInput := replaceScopes(input, replacements, ph)
	combinedResults, err := g.Results(context.Background(), combinedInput)
	require.NoError(t, err)
	require.Len(t, combinedResults, len(results))
	for _, result := range results {
		matched := false
		for _, combinedResult := range combinedResults {
			matched = matched || ast.Compare(result, combinedResult) == 0
		}
		require.True(t, matched, "combined substitution keeps result %v", result)
	}

	candidates := make([]Candidate, len(results))
	for i, result := range results {
		name := result.(ast.Object).Get(ast.StringTerm("name")).Value.(ast.String)
		idx := 0
		if name == "b" {
			idx = 1
		}
		candidates[i] = Candidate{Result: result, Scope: []ast.Value{scopes[idx]}}
	}
	report, err := g.Check(context.Background(), input, candidates)
	require.NoError(t, err)
	for i, verdict := range report.Verdicts {
		require.True(t, verdict.Uncertain, "candidate %v", candidates[i].Result)
		require.Equal(t, StageTracer, verdict.Stage)
	}

	jobs := make([]job, len(results))
	for i, result := range results {
		id, mask := ph.identity(result)
		jobs[i] = job{index: i, cand: candidates[i], id: id, mask: mask}
	}
	stage2 := &substitution{g: g, ctx: context.Background(), input: input, ph: ph}
	stage2Verdicts := make([]Verdict, len(jobs))
	require.NoError(t, stage2.batch(jobs, stage2Verdicts))
	for i, verdict := range stage2Verdicts {
		require.True(t, verdict.Uncertain, "Stage 2 candidate %v", candidates[i].Result)
		require.Equal(t, StageSubstitution, verdict.Stage)
	}
}
