package unknowngate

import (
	"context"
	"testing"

	"errors"
	"fmt"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"sync/atomic"
	"time"
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

func TestCheckCachesMinimalTraceResultsAndFallsBackToWholeInput(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

DatadogPolicy contains {"rule": "item", "name": b.name} if {
	some b in input.blocks
}
`)
	input := mustValue(t, `{"blocks":[{"name":"a","unused":"${...}"},{"name":"b","unused":"${...}"}]}`)
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 2)
	minimal := mustValue(t, `{"blocks":[]}`)
	candidates := []Candidate{
		{Result: results[0], Input: minimal},
		{Result: results[1], Input: minimal},
	}

	report, err := g.Check(context.Background(), input, candidates)
	require.NoError(t, err)
	require.Equal(t, 2, report.TracedEvals, "the shared minimal input and whole input should each be traced once")
	require.Len(t, report.Verdicts, 2)
	for i, verdict := range report.Verdicts {
		require.False(t, verdict.Uncertain, "candidate %d: %s", i, verdict.Reason)
	}
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
func TestProbePropagatesSensitivityFlags(t *testing.T) {
	modules := map[string]*ast.Module{}
	for name, source := range map[string]string{
		"terraform.rego": `package generic.terraform
_placeholder := "${...}"
`,
		"lib.rego": `package generic.lib
read() := data.other.value if {
	data.test.enabled
	count(input.block.items) == 1
	time.now_ns() > 0
	contains(data.generic.terraform._placeholder, "$")
}
`,
		"rule.rego": `package datadog
import rego.v1
import data.generic.lib as lib
DatadogPolicy contains {"rule": "probe", "name": name} if name := lib.read()
`,
	} {
		m, err := ast.ParseModuleWithOpts(name, source, ast.ParserOptions{RegoVersion: ast.RegoV1})
		require.NoError(t, err, name)
		modules[name] = m
	}
	store := inmem.NewFromObject(map[string]any{
		"test":  map[string]any{"enabled": true},
		"other": map[string]any{"value": "x"},
	})
	g, err := New(Options{
		Placeholder: testPlaceholder,
		Modules:     modules,
		Query:       "data.datadog.DatadogPolicy",
		Sentinels:   []string{"data.generic.terraform._placeholder"},
		Store:       store,
	})
	require.NoError(t, err)
	parent := tracerWithContext(g, context.Background(), mustValue(t, `{"block":{"items":["${...}"]}}`))
	_, callExpr := probeCall(t, g)
	operands := callExpr.Operands()
	args := []*ast.Term{ast.NewTerm(callExpr.Operator())}
	args = append(args, operands[:len(operands)-1]...)
	call := ast.NewTerm(ast.Call(args))

	got, ok := g.probe(parent, parent.input, call)
	require.True(t, ok)
	require.Equal(t, ast.String("x"), got)
	require.True(t, parent.structuralSensitive, "array shape reads observed inside the probe must propagate")
	require.True(t, parent.substitutionSensitive, "nondeterminism observed inside the probe must propagate")
	require.True(t, parent.sentinelRead, "sentinel reads observed inside the probe must propagate")
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
	t.Logf("verdict=%+v substitution evaluations=%d", report.Verdicts[0], report.SubstitutionEvals)
	require.True(t, report.Verdicts[0].Uncertain)
	require.Equal(t, StageSubstitution, report.Verdicts[0].Stage)
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
		require.Equal(t, StageSubstitution, verdict.Stage)
	}
}

func TestBatchRoundCachesSharedConfirmationEvaluation(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

DatadogPolicy contains {"rule": "one"} if input.flag == true
DatadogPolicy contains {"rule": "two"} if input.flag == true
`)
	input := mustValue(t, `{"flag": "${...}"}`)
	ph := newPlaceholder(testPlaceholder)
	expectations := []ast.Value{
		mustValue(t, `{"rule": "one"}`),
		mustValue(t, `{"rule": "two"}`),
	}
	jobs := make([]job, len(expectations))
	scopes := make([][]ast.Value, len(expectations))
	for i, result := range expectations {
		id, mask := ph.identity(result)
		jobs[i] = job{index: i, cand: Candidate{Result: result}, id: id, mask: mask}
		scopes[i] = []ast.Value{input}
	}
	r := batchReplacement{replacement: replacement{value: ast.Boolean(false)}}

	// Compute the two uncached verdicts directly. Both jobs share exactly the
	// same changed input but have different result identities.
	uncached := &substitution{g: g, ctx: context.Background(), input: input, ph: ph}
	want := make([]Verdict, len(jobs))
	for i := range jobs {
		got, err := uncached.confirm(scopes[i], r, &jobs[i], nil)
		require.NoError(t, err)
		want[i] = got
	}

	cached := &substitution{g: g, ctx: context.Background(), input: input, ph: ph}
	got := make([]Verdict, len(jobs))
	decided, err := cached.batchRound(jobs, scopes, []ast.Value{input}, r, got)
	require.NoError(t, err)
	require.Equal(t, len(jobs), decided)
	require.Equal(t, want, got)
	require.True(t, got[0].Uncertain)
	require.True(t, got[1].Uncertain)
	// One initial batch evaluation plus one shared confirmation evaluation;
	// without the cache it would be one plus one evaluation for each job.
	require.Less(t, cached.evals, 1+uncached.evals)
	require.Equal(t, 2, cached.evals)
}

func TestBatchRoundCacheKeepsPerCandidateMaskedIdentities(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

DatadogPolicy contains {"name": "keep", "message": sprintf("flag=%v", [input.flag])} if input.flag != true
DatadogPolicy contains {"name": "drop", "message": "drop ${...}"} if input.flag == "${...}"
`)
	input := mustValue(t, `{"flag": "${...}", "other": "${...}"}`)
	ph := newPlaceholder(testPlaceholder)
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	byName := map[string]ast.Value{}
	for _, result := range results {
		obj := result.(ast.Object)
		byName[string(obj.Get(ast.InternedTerm("name")).Value.(ast.String))] = result
	}
	require.Contains(t, byName, "keep")
	require.Contains(t, byName, "drop")

	jobs := make([]job, 2)
	scopes := make([][]ast.Value, 2)
	for i, name := range []string{"keep", "drop"} {
		result := byName[name]
		id, mask := ph.identity(result)
		require.Contains(t, mask, "message", "placeholder text in a message is excluded from identity")
		jobs[i] = job{index: i, cand: Candidate{Result: result}, id: id, mask: mask}
		scopes[i] = []ast.Value{input}
	}
	r := batchReplacement{replacement: replacement{value: ast.Boolean(false)}}

	uncached := &substitution{g: g, ctx: context.Background(), input: input, ph: ph}
	want := make([]Verdict, len(jobs))
	for i := range jobs {
		got, err := uncached.confirm(scopes[i], r, &jobs[i], nil)
		require.NoError(t, err)
		want[i] = got
	}

	cached := &substitution{g: g, ctx: context.Background(), input: input, ph: ph}
	got := make([]Verdict, len(jobs))
	decided, err := cached.batchRound(jobs, scopes, []ast.Value{input}, r, got)
	require.NoError(t, err)
	require.Equal(t, 1, decided, "only the missing result is suppressed")
	require.Equal(t, want, got)
	require.False(t, got[0].Uncertain, "the surviving identity remains certain despite its changed message")
	require.True(t, got[1].Uncertain, "the dropped identity remains uncertain")
	require.Less(t, cached.evals, 1+uncached.evals)
}

func TestParallelInputGroupsPreserveGateVerdicts(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

DatadogPolicy contains {"rule": "item", "name": b.name} if {
	some b in input.blocks
}
`)
	const candidatesCount = 24
	candidates := make([]Candidate, 0, candidatesCount)
	var blocks strings.Builder
	for i := range candidatesCount {
		name := fmt.Sprintf("name-%d", i)
		blockText := fmt.Sprintf(`{"name":%q,"unknown":{"nested":"${...}"}}`, name)
		if i > 0 {
			blocks.WriteByte(',')
		}
		blocks.WriteString(blockText)
		block := mustValue(t, blockText)
		candidates = append(candidates, Candidate{
			Result: mustValue(t, fmt.Sprintf(`{"rule":"item","name":%q}`, name)),
			Input:  mustValue(t, fmt.Sprintf(`{"blocks":[%s]}`, blockText)),
			Scope:  []ast.Value{block},
		})
	}
	input := mustValue(t, `{"blocks":[`+blocks.String()+`]}`)
	sequential, err := g.Check(context.Background(), input, candidates)
	require.NoError(t, err)

	g.tryAcquireSubstitutionWorker = func() (func(), bool) { return func() {}, true }
	parallel, err := g.Check(context.Background(), input, candidates)
	require.NoError(t, err)
	require.Equal(t, sequential.Verdicts, parallel.Verdicts)
	require.Equal(t, sequential.Suppressed, parallel.Suppressed)
	require.Equal(t, sequential.TracedEvals, parallel.TracedEvals)
	require.Equal(t, sequential.SubstitutionEvals, parallel.SubstitutionEvals)
	require.Len(t, parallel.Verdicts, candidatesCount)
	for i := range parallel.Verdicts {
		require.False(t, parallel.Verdicts[i].Uncertain, "candidate %d", i)
	}
}

func TestParallelInputGroupsRunsInlineWhenBudgetIsUnavailable(t *testing.T) {
	groups := []int{1, 2, 3, 4}
	var called atomic.Int64
	results, err := parallelInputGroups(context.Background(), groups, func() (func(), bool) {
		return nil, false
	}, func(_ context.Context, i int) (int, error) {
		called.Add(1)
		return i, nil
	})
	require.NoError(t, err)
	require.Equal(t, groups, results)
	require.EqualValues(t, len(groups), called.Load())
}

func TestParallelInputGroupsBoundedAndReturnsSlots(t *testing.T) {
	const slotBudget = 3
	var slots, inFlight, maxInFlight atomic.Int64
	allRunning := make(chan struct{})
	var signalOnce atomic.Bool
	tryAcquire := func() (func(), bool) {
		for {
			current := slots.Load()
			if current >= slotBudget {
				return nil, false
			}
			if slots.CompareAndSwap(current, current+1) {
				return func() { slots.Add(-1) }, true
			}
		}
	}
	groups := make([]int, 30)
	for i := range groups {
		groups[i] = i
	}
	results, err := parallelInputGroups(context.Background(), groups, tryAcquire, func(_ context.Context, i int) (int, error) {
		if i == 0 {
			return i, nil
		}
		current := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			old := maxInFlight.Load()
			if current <= old || maxInFlight.CompareAndSwap(old, current) {
				break
			}
		}
		if current == maxParallelSubstitutionWorkers && signalOnce.CompareAndSwap(false, true) {
			close(allRunning)
		}
		select {
		case <-allRunning:
		case <-time.After(2 * time.Second):
			return 0, errors.New("caller and three extra workers did not overlap")
		}
		return i, nil
	})
	require.NoError(t, err)
	require.Equal(t, groups, results)
	require.EqualValues(t, maxParallelSubstitutionWorkers, maxInFlight.Load())
	require.Zero(t, slots.Load(), "all borrowed CPU slots must be released")
}

func TestParallelInputGroupsRetriesAfterAWorkerReleasesSlot(t *testing.T) {
	var slot atomic.Bool
	var acquisitions atomic.Int64
	released := make(chan struct{})
	tryAcquire := func() (func(), bool) {
		if !slot.CompareAndSwap(false, true) {
			return nil, false
		}
		acquisition := acquisitions.Add(1)
		return func() {
			slot.Store(false)
			if acquisition == 1 {
				close(released)
			}
		}, true
	}
	finishFirst := make(chan struct{})
	groups := []int{0, 1, 2, 3}
	results, err := parallelInputGroups(context.Background(), groups, tryAcquire, func(_ context.Context, i int) (int, error) {
		switch i {
		case 1:
			<-finishFirst
		case 2:
			close(finishFirst)
			<-released
		}
		return i, nil
	})
	require.NoError(t, err)
	require.Equal(t, groups, results)
	require.EqualValues(t, 2, acquisitions.Load(), "the released slot should be retried for the next group")
	require.False(t, slot.Load())
}

func TestParallelInputGroupsReturnsFirstErrorInInputOrder(t *testing.T) {
	firstErr := errors.New("first by index")
	secondErr := errors.New("second by index")
	workersStarted := make(chan struct{})
	var workerStarts atomic.Int64
	groups := []int{0, 1, 2, 3}
	_, err := parallelInputGroups(context.Background(), groups, func() (func(), bool) {
		return func() {}, true
	}, func(_ context.Context, i int) (int, error) {
		switch i {
		case 1:
			if workerStarts.Add(1) == 3 {
				close(workersStarted)
			}
			<-workersStarted
			return i, firstErr
		case 2:
			if workerStarts.Add(1) == 3 {
				close(workersStarted)
			}
			<-workersStarted
			return i, secondErr
		case 3:
			if workerStarts.Add(1) == 3 {
				close(workersStarted)
			}
			return i, nil
		}
		return i, nil
	})
	require.ErrorIs(t, err, firstErr)
}

func TestParallelInputGroupsPreCanceledContextDoesNotDispatchQueuedGroups(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var called atomic.Int64
	groups := []int{0, 1, 2, 3, 4}
	_, err := parallelInputGroups(ctx, groups, func() (func(), bool) {
		return func() {}, true
	}, func(ctx context.Context, _ int) (int, error) {
		called.Add(1)
		return 0, ctx.Err()
	})
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, called.Load(), "a canceled check must not dispatch any groups")
}

func TestParallelInputGroupsCancellationJoinsStartedWorkersAndReleasesSlots(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var slots, called, workers atomic.Int64
	var seen atomic.Uint32
	groups := []int{0, 1, 2, 3, 4, 5}
	_, err := parallelInputGroups(ctx, groups, func() (func(), bool) {
		slots.Add(1)
		return func() { slots.Add(-1) }, true
	}, func(ctx context.Context, i int) (int, error) {
		called.Add(1)
		seen.Or(uint32(1) << i)
		if i == 0 {
			return i, nil
		}
		if workers.Add(1) == maxParallelSubstitutionWorkers-1 {
			cancel()
		}
		<-ctx.Done()
		return i, ctx.Err()
	})
	require.ErrorIs(t, err, context.Canceled)
	require.GreaterOrEqual(t, called.Load(), int64(maxParallelSubstitutionWorkers))
	require.LessOrEqual(t, called.Load(), int64(maxParallelSubstitutionWorkers+1), "the caller's inline group may start before cancellation is observed")
	require.Zero(t, seen.Load()&(1<<5), "the queued final group must not start after cancellation")
	require.Zero(t, slots.Load(), "all started workers should release their slots before return")
}

func TestParallelInputGroupsSingleGroupCancellation(t *testing.T) {
	t.Run("canceled before dispatch", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := parallelInputGroups(ctx, []int{1}, nil, func(context.Context, int) (int, error) {
			t.Fatal("a canceled group must not start")
			return 0, nil
		})
		require.ErrorIs(t, err, context.Canceled)
	})
	t.Run("canceled by last group", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, err := parallelInputGroups(ctx, []int{1}, nil, func(context.Context, int) (int, error) {
			cancel()
			return 1, nil
		})
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestTraceProvesScalarSubstitutions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rule  string
		input string
	}{
		{
			name:  "unused leaf",
			rule:  `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if input.block.enabled == true`,
			input: `{"block":{"enabled":true,"unused":"${...}"}}`,
		},
		{
			name:  "count ignores map values",
			rule:  `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if count(input.block.tags) == 2`,
			input: `{"block":{"tags":{"unknown":"${...}","safe":"value"}}}`,
		},
		{
			name:  "known key lookup ignores sibling value",
			rule:  `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if input.block.tags.safe == "ok"`,
			input: `{"block":{"tags":{"unknown":"${...}","safe":"ok"}}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGate(t, testPlaceholder, "package datadog\n"+tc.rule)
			input := mustValue(t, tc.input)
			report := compareScopedAndFullStage2(t, g, input, blockScopeForProofTest(t, input))
			require.False(t, report.Verdicts[0].Uncertain)
			require.Zero(t, report.SubstitutionEvals, "the clean scalar proof should avoid stage 2")
		})
	}
}

func TestTraceProofRejectsUnknownIdentity(t *testing.T) {
	g := newTestGate(t, testPlaceholder, `package datadog

DatadogPolicy contains {"_dd_id": input.block.id, "path": []} if input.block.enabled == true
`)
	input := mustValue(t, `{"block":{"enabled":true,"id":"${...}"}}`)
	report := compareScopedAndFullStage2(t, g, input, blockScopeForProofTest(t, input))
	require.True(t, report.Verdicts[0].Uncertain)
	require.Greater(t, report.SubstitutionEvals, 0, "placeholder identity must retain stage 2")
}

func TestTraceProofRejectsDynamicObjectShapes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		rule        string
		input       string
		stage2Check bool
	}{
		{
			name:        "dynamic object key collapse",
			stage2Check: true,
			rule: `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if {
				obj := {input.block.key: true, "safe": true}
				count(obj) == 2
			}`,
			input: `{"block":{"key":"${...}"}}`,
		},
		{
			name:        "object comprehension key collapse",
			stage2Check: false,
			rule: `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if {
				dynamic := {input.block.key: true | true}
				obj := object.union(dynamic, {"safe": true})
				count(obj) == 2
			}`,
			input: `{"block":{"key":"${...}"}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGate(t, testPlaceholder, "package datadog\n"+tc.rule)
			input := mustValue(t, tc.input)
			report := compareScopedAndFullStage2(t, g, input, blockScopeForProofTest(t, input))
			require.True(t, report.Verdicts[0].Uncertain)
			if tc.stage2Check {
				require.Greater(t, report.SubstitutionEvals, 0)
			} else {
				require.Zero(t, report.SubstitutionEvals, "stage 1 already identifies the unknown dependency")
			}
		})
	}
}

func TestTraceProofMatchesFullStage2OnFailedBranches(t *testing.T) {
	for _, tc := range []struct {
		name, source string
	}{
		{
			name: "virtual document conflict",
			source: `value := 1
value := 2 if input.block.id == true
DatadogPolicy contains {"_dd_id":"fixed","path":[]} if value == 1`,
		},
		{
			name: "function conflict",
			source: `value(x) := 1
value(x) := 2 if x.id == true
DatadogPolicy contains {"_dd_id":"fixed","path":[]} if value(input.block) == 1`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGate(t, testPlaceholder, "package datadog\n"+tc.source)
			input := mustValue(t, `{"block":{"id":"${...}"}}`)
			results, err := g.Results(context.Background(), input)
			require.NoError(t, err)
			require.Len(t, results, 1)
			scope := blockScopeForProofTest(t, input)
			scoped, scopedErr := g.Check(context.Background(), input, []Candidate{{Result: results[0], Scope: []ast.Value{scope}}})
			full, fullErr := g.Check(context.Background(), input, []Candidate{{Result: results[0]}})
			require.Error(t, scopedErr)
			require.Error(t, fullErr)
			require.EqualError(t, scopedErr, fullErr.Error())
			require.Nil(t, scoped)
			require.Nil(t, full)
		})
	}
}

func TestTraceProofConfiguredSentinelComparisons(t *testing.T) {
	for _, tc := range []struct {
		name, policy, input                     string
		wantSentinel, wantUncertain, wantStage2 bool
		wantError                               bool
	}{
		{
			name: "empty iterator does not observe a sentinel",
			policy: `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if input.block.enabled == true
DatadogPolicy contains {"_dd_id":"unused","path":[]} if {
    some id in input.block.entries
    id == tf._placeholder
    false
}`,
			input:        `{"block":{"enabled":true,"entries":[],"unused":"${...}"}}`,
			wantSentinel: false, wantUncertain: false, wantStage2: false,
		},
		{
			name: "nonempty placeholder iterator remains observed",
			policy: `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if input.block.enabled == true
DatadogPolicy contains {"_dd_id":"unused","path":[]} if {
    some id in input.block.entries
    id == tf._placeholder
    false
}`,
			input:        `{"block":{"enabled":true,"entries":["${...}"],"unused":"${...}"}}`,
			wantSentinel: true, wantUncertain: false, wantStage2: true,
		},
		{
			name: "indexed unused function return retains conflict",
			policy: `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if {
    values := [tf.value(input.block.value)]
    ignored := values[0]
    input.block.enabled == true
}`,
			input:        `{"block":{"enabled":true,"value":"${...}"}}`,
			wantSentinel: true, wantError: true,
		},
		{
			name:         "direct placeholder",
			policy:       `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if input.block.value == tf._placeholder`,
			input:        `{"block":{"value":"${...}"}}`,
			wantSentinel: true, wantUncertain: true, wantStage2: true,
		},
		{
			name: "formal alias in failed alternative",
			policy: `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if input.block.enabled == true
DatadogPolicy contains {"_dd_id":"fixed","path":[]} if {
    alias := input.block.value
    tf.guard(alias)
    false
}`,
			input:        `{"block":{"enabled":true,"value":"${...}"}}`,
			wantSentinel: true, wantUncertain: false, wantStage2: true,
		},
		{
			name: "nested placeholder in failed alternative",
			policy: `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if input.block.enabled == true
DatadogPolicy contains {"_dd_id":"fixed","path":[]} if tf.guard(input.block.container)`,
			input:        `{"block":{"enabled":true,"container":{"nested":"${...}"}}}`,
			wantSentinel: true, wantUncertain: false, wantStage2: true,
		},
		{
			name: "concrete resolved ID",
			policy: `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if {
    tf.resolved(input.block.id) == "known"
    input.block.enabled == true
}`,
			input:        `{"block":{"id":"resource-id","enabled":true,"unused":"${...}"}}`,
			wantSentinel: false, wantUncertain: false, wantStage2: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modules := map[string]*ast.Module{
				"policy.rego": ast.MustParseModule("package datadog\nimport data.generic.terraform as tf\n" + tc.policy),
				"terraform.rego": ast.MustParseModule(`package generic.terraform
_placeholder := "${...}"
guard(v) if v == _placeholder
resolved(v) := "unknown" if v == _placeholder else := "known"
value(x) := _placeholder
value(x) := x
`),
			}
			g, err := New(Options{
				Placeholder: testPlaceholder,
				Modules:     modules,
				Query:       "data.datadog.DatadogPolicy",
				Sentinels:   []string{"data.generic.terraform._placeholder"},
			})
			require.NoError(t, err)
			input := mustValue(t, tc.input)
			results, err := g.Results(context.Background(), input)
			require.NoError(t, err)
			require.Len(t, results, 1)
			tr, err := g.trace(context.Background(), input)
			require.NoError(t, err)
			require.Equal(t, tc.wantSentinel, tr.sentinelRead)
			if tc.wantError {
				scope := blockScopeForProofTest(t, input)
				scoped, scopedErr := g.Check(context.Background(), input, []Candidate{{Result: results[0], Scope: []ast.Value{scope}}})
				full, fullErr := g.Check(context.Background(), input, []Candidate{{Result: results[0]}})
				require.Error(t, scopedErr)
				require.Error(t, fullErr)
				require.EqualError(t, scopedErr, fullErr.Error())
				require.Nil(t, scoped)
				require.Nil(t, full)
				return
			}
			scope := blockScopeForProofTest(t, input)
			report := compareScopedAndFullStage2(t, g, input, scope)
			require.Equal(t, tc.wantUncertain, report.Verdicts[0].Uncertain)
			require.Equal(t, tc.wantStage2, report.SubstitutionEvals > 0)
		})
	}
}

func TestTraceProofRetainsWithAndNondeterministicChecks(t *testing.T) {
	for _, tc := range []struct {
		name, rule string
	}{
		{
			name: "with override",
			rule: `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if input.block.enabled == true with input.block.enabled as true`,
		},
		{
			name: "nondeterministic builtin",
			rule: `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if time.now_ns() > 0`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGate(t, testPlaceholder, "package datadog\n"+tc.rule)
			input := mustValue(t, `{"block":{"enabled":false,"unused":"${...}"}}`)
			report := compareScopedAndFullStage2(t, g, input, blockScopeForProofTest(t, input))
			require.False(t, report.Verdicts[0].Uncertain)
			require.Greater(t, report.SubstitutionEvals, 0)
		})
	}
}

func TestUnstableCompositeShapeDetectsNestedInputSet(t *testing.T) {
	ph := newPlaceholder(testPlaceholder)
	block := mustValue(t, `{"value":"${...}"}`)
	set := ast.NewSet(ast.NewTerm(block))
	input := ast.NewObject(ast.Item(ast.StringTerm("members"), ast.NewTerm(set)))
	require.True(t, unstableCompositeShape(input, ph))
}

func TestObjectValueProofRejectsMixedSetAndUnknownKeyScopes(t *testing.T) {
	ph := newPlaceholder(testPlaceholder)
	result := mustValue(t, `{"_dd_id":"fixed","path":[]}`)
	for _, tc := range []struct {
		name  string
		input string
		set   bool
	}{
		{name: "nested set", input: `{"block":{"unused":"${...}"}}`, set: true},
		{name: "unknown key", input: `{"block":{"${...}":true,"unused":"${...}"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := mustValue(t, tc.input)
			if tc.set {
				members := ast.NewSet(ast.NewTerm(ast.String(testPlaceholder)))
				block := ast.NewObject(
					ast.Item(ast.StringTerm("unused"), ast.StringTerm(testPlaceholder)),
					ast.Item(ast.StringTerm("members"), ast.NewTerm(members)),
				)
				input = ast.NewObject(ast.Item(ast.StringTerm("block"), ast.NewTerm(block)))
			}
			scope := blockScopeForProofTest(t, input)
			candidate := Candidate{Result: result, Scope: []ast.Value{scope}}
			require.False(t, traceProvesObjectValueSubstitutions(&resultState{}, candidate, input, ph))
			require.False(t, onlyObjectValueUnknowns(candidate, input, ph))
		})
	}
}

func compareScopedAndFullStage2(t *testing.T, g *Gate, input, scope ast.Value) *Report {
	t.Helper()
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 1)
	scoped, err := g.Check(context.Background(), input, []Candidate{{Result: results[0], Scope: []ast.Value{scope}}})
	require.NoError(t, err)
	full, err := g.Check(context.Background(), input, []Candidate{{Result: results[0]}})
	require.NoError(t, err)
	require.Len(t, scoped.Verdicts, 1)
	require.Len(t, full.Verdicts, 1)
	require.Equal(t, full.Verdicts[0].Uncertain, scoped.Verdicts[0].Uncertain)
	return scoped
}

func blockScopeForProofTest(t *testing.T, input ast.Value) ast.Value {
	t.Helper()
	obj, ok := input.(ast.Object)
	require.True(t, ok)
	block := obj.Get(ast.StringTerm("block"))
	require.NotNil(t, block)
	return block.Value
}

func TestStructuralProofMatchesFullStage2(t *testing.T) {
	for _, tc := range []struct {
		name, source, input string
		uncertain, skip     bool
	}{
		{"vdoc head count", `items := input.block.items if true
DatadogPolicy contains {"_dd_id":"fixed","path":[]} if count(items) == 1`, `{"block":{"items":["${...}"]}}`, true, false},
		{"data alias", `arr := input.block.items
DatadogPolicy contains {"_dd_id":"fixed","path":[]} if not arr == []`, `{"block":{"items":["${...}"]}}`, true, false},
		{"bound get", `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if not object.get(input.block,"items",null,[])`, `{"block":{"items":["${...}"]}}`, true, false},
		{"unused mixed values", `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if input.block.enabled == true`, `{"block":{"enabled":true,"unused":"${...}","items":["${...}"]}}`, false, true},
		{"count", `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if count(input.block.items) == 1`, `{"block":{"items":["${...}"]}}`, true, false},
		{"index shift", `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if input.block.items[1] == "safe"`, `{"block":{"items":["${...}","safe"]}}`, true, false},
		{"get shift", `DatadogPolicy contains {"_dd_id":"fixed","path":[]} if object.get(input.block,["items",1],"no") == "safe"`, `{"block":{"items":["${...}","safe"]}}`, true, false},
		{"failed new element", `value(x) := 1 if true
value(x) := 2 if x.items[2] == true
DatadogPolicy contains {"_dd_id":"fixed","path":[]} if value(input.block) == 1`, `{"block":{"items":["${...}"]}}`, false, false},
		{"function shape", `value([x]) := 1 if true
DatadogPolicy contains {"_dd_id":"fixed","path":[]} if value(input.block.items) == 1`, `{"block":{"items":["${...}"]}}`, true, false},
		{"function returns array", `items(x) := x if true
DatadogPolicy contains {"_dd_id":"fixed","path":[]} if count(items(input.block.items)) == 1`, `{"block":{"items":["${...}"]}}`, true, false},
		{"vdoc alias chain", `items := input.block.items if true
alias := items if true
DatadogPolicy contains {"_dd_id":"fixed","path":[]} if count(alias) == 1`, `{"block":{"items":["${...}"]}}`, true, false},
		{"vdoc object get", `items := object.get(input.block,"items",[]) if true
DatadogPolicy contains {"_dd_id":"fixed","path":[]} if count(items) == 1`, `{"block":{"items":["${...}"]}}`, true, false},
		{"function head array length", `items([x]) := x if true
DatadogPolicy contains {"_dd_id":"fixed","path":items(input.block.items)} if true`, `{"block":{"items":["${...}"]}}`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGate(t, testPlaceholder, "package datadog\n"+tc.source)
			input := mustValue(t, tc.input)
			results, err := g.Results(context.Background(), input)
			require.NoError(t, err)
			require.Len(t, results, 1)
			scoped, se := g.Check(context.Background(), input, []Candidate{{Result: results[0], Scope: []ast.Value{blockScopeForProofTest(t, input)}}})
			full, fe := g.Check(context.Background(), input, []Candidate{{Result: results[0]}})
			if fe != nil {
				require.Equal(t, "failed new element", tc.name, "other cases must complete their certainty checks")
				require.EqualError(t, se, fe.Error())
				return
			}
			require.NoError(t, se)
			require.Equal(t, full.Verdicts[0].Uncertain, scoped.Verdicts[0].Uncertain)
			require.Equal(t, tc.uncertain, scoped.Verdicts[0].Uncertain)
			if tc.skip {
				require.Zero(t, scoped.SubstitutionEvals)
			} else {
				if !scoped.Verdicts[0].Uncertain {
					require.Positive(t, scoped.SubstitutionEvals)
				}
			}
		})
	}
}

func sentinelTypeProofGate(t *testing.T, rule string) *Gate {
	t.Helper()
	sources := map[string]string{
		"lib.rego": `package generic.lib
_placeholder := "${...}"
guard(x) if { is_string(x); x == _placeholder }
`,
		"rule.rego": `package datadog
import data.generic.lib as lib
` + rule,
	}
	modules := make(map[string]*ast.Module, len(sources))
	for name, src := range sources {
		m, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
		require.NoError(t, err)
		modules[name] = m
	}
	g, err := New(Options{
		Placeholder: testPlaceholder,
		Modules:     modules,
		Query:       "data.datadog.DatadogPolicy",
		Sentinels:   []string{"data.generic.lib._placeholder"},
	})
	require.NoError(t, err)
	return g
}

func TestKnownTypeCheckOnObjectDoesNotBlockObjectValueProof(t *testing.T) {
	g := sentinelTypeProofGate(t, `
DatadogPolicy contains {"_dd_id":"fixed","path":[]} if {
    not lib.guard(input.block)
    input.block.enabled == true
}`)
	input := mustValue(t, `{"block":{"enabled":true,"unused":"${...}"}}`)
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 1)
	scope := blockScopeForProofTest(t, input)
	scoped, err := g.Check(context.Background(), input, []Candidate{{Result: results[0], Scope: []ast.Value{scope}}})
	require.NoError(t, err)
	full, err := g.Check(context.Background(), input, []Candidate{{Result: results[0]}})
	require.NoError(t, err)
	require.Equal(t, full.Verdicts[0].Uncertain, scoped.Verdicts[0].Uncertain)
	require.False(t, scoped.Verdicts[0].Uncertain)
	require.Zero(t, scoped.SubstitutionEvals)
	require.Positive(t, full.SubstitutionEvals)
}

func TestActualPlaceholderTypeCheckRetainsSentinelRead(t *testing.T) {
	g := sentinelTypeProofGate(t, `
DatadogPolicy contains {"_dd_id":"fixed","path":[]} if lib.guard(input.block)
`)
	input := mustValue(t, `{"block":"${...}","other":"${...}"}`)
	results, err := g.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 1)
	tr, err := g.trace(context.Background(), input)
	require.NoError(t, err)
	require.True(t, tr.sentinelRead, "the exact placeholder operand must retain the sentinel-read flag")
	report, err := g.Check(context.Background(), input, []Candidate{{Result: results[0]}})
	require.NoError(t, err)
	require.Len(t, report.Verdicts, 1)
	require.True(t, report.Verdicts[0].Uncertain)
}

func TestParallelBatchRoundsPreserveVerdictsAndReasons(t *testing.T) {
	src := `package datadog
import rego.v1
DatadogPolicy contains {"rule": "x"} if count(input.block.items) == 2
`
	input := mustValue(t, `{"block":{"items":["${...}","${...}"]},"unused":"${...}"}`)
	sequential := newTestGate(t, testPlaceholder, src)
	parallel := newTestGate(t, testPlaceholder, src)
	results, err := sequential.Results(context.Background(), input)
	require.NoError(t, err)
	require.Len(t, results, 1)
	candidates := []Candidate{{Result: results[0], Scope: []ast.Value{input}}}
	before, err := sequential.Check(context.Background(), input, candidates)
	require.NoError(t, err)
	var active, maxActive, acquired atomic.Int32
	parallel.tryAcquireSubstitutionWorker = func() (func(), bool) {
		active.Add(1)
		acquired.Add(1)
		for {
			old := maxActive.Load()
			if active.Load() <= old || maxActive.CompareAndSwap(old, active.Load()) {
				break
			}
		}
		return func() { active.Add(-1) }, true
	}
	after, err := parallel.Check(context.Background(), input, candidates)
	require.NoError(t, err)
	require.Equal(t, before.Verdicts, after.Verdicts)
	require.Equal(t, before.Suppressed, after.Suppressed)
	require.Equal(t, before.Verdicts[0].Reason, after.Verdicts[0].Reason)
	require.Greater(t, acquired.Load(), int32(0), "the deterministic query should dispatch borrowed rounds")
	require.Zero(t, active.Load(), "all borrowed slots are returned")
}

func TestBatchRoundPurityGuardKeepsUnsafeQueriesSerial(t *testing.T) {
	for _, tc := range []struct {
		name, body string
	}{
		{"nondeterministic followed by deterministic", `time.now_ns() > 0; is_string("x")`},
		{"nested nondeterministic", `count([x | x := time.now_ns()]) > 0`},
		{"with modifier", `input.flag == "safe" with input.flag as "safe"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGate(t, testPlaceholder, `package datadog
DatadogPolicy contains {"rule": "x"} if { `+tc.body+` }
`)
			require.False(t, g.parallelBatchRounds)
		})
	}
	g := newTestGate(t, testPlaceholder, `package datadog
DatadogPolicy contains {"rule": "x"} if input.flag == "safe"
`)
	require.True(t, g.parallelBatchRounds)
	for rule := range g.rules.meta {
		logging, err := ast.ParseBody(`print("trace")`)
		require.NoError(t, err)
		rule.Body = append(rule.Body, logging...)
	}
	require.False(t, batchRoundsArePure(g.rules), "logging calls must disable speculative evaluation")
}

func TestParallelRoundWindowBoundsAndJoinsStartedWorkers(t *testing.T) {
	const extraSlots = 3
	var slots, active, maxActive atomic.Int32
	allRunning := make(chan struct{})
	var once atomic.Bool
	tryAcquire := func() (func(), bool) {
		for {
			current := slots.Load()
			if current >= extraSlots {
				return nil, false
			}
			if slots.CompareAndSwap(current, current+1) {
				return func() { slots.Add(-1) }, true
			}
		}
	}
	outcomes := parallelRoundWindow(context.Background(), 8, tryAcquire, func(i int) (int, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			old := maxActive.Load()
			if current <= old || maxActive.CompareAndSwap(old, current) {
				break
			}
		}
		if current == maxParallelSubstitutionWorkers && once.CompareAndSwap(false, true) {
			close(allRunning)
		}
		select {
		case <-allRunning:
		case <-time.After(2 * time.Second):
			return 0, errors.New("parallel rounds did not overlap")
		}
		return i, nil
	})
	require.Len(t, outcomes, maxParallelSubstitutionWorkers)
	for i, got := range outcomes {
		require.NoError(t, got.err)
		require.Equal(t, i, got.value)
	}
	require.EqualValues(t, maxParallelSubstitutionWorkers, maxActive.Load())
	require.Zero(t, slots.Load(), "all started workers return their CPU slots")
}

func TestParallelRoundWindowCancellationJoinsAndReleasesSlots(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var slots, started, finished atomic.Int32
	tryAcquire := func() (func(), bool) {
		slots.Add(1)
		cancel()
		return func() { slots.Add(-1) }, true
	}
	outcomes := parallelRoundWindow(ctx, 4, tryAcquire, func(i int) (int, error) {
		started.Add(1)
		<-ctx.Done()
		finished.Add(1)
		return i, ctx.Err()
	})
	require.NotEmpty(t, outcomes)
	require.ErrorIs(t, outcomes[0].err, context.Canceled)
	require.Equal(t, started.Load(), finished.Load(), "all started rounds have joined")
	require.Zero(t, slots.Load(), "all acquired slots are released")
}

func TestParallelRoundMergePreservesSerialErrorReachability(t *testing.T) {
	errLater := errors.New("later speculative error")
	jobs := []job{{index: 0}, {index: 1}}
	scope := ast.String("pending")
	verdict := Verdict{Uncertain: true, Stage: StageSubstitution, Reason: "removed"}

	t.Run("ignore error after all jobs are decided", func(t *testing.T) {
		scopes := [][]ast.Value{{scope}, {scope}}
		out := make([]Verdict, 2)
		window := []groupOutcome[parallelRoundResult]{
			{value: parallelRoundResult{scopes: [][]ast.Value{nil, nil}, verdicts: []Verdict{verdict, verdict}}},
			{err: errLater},
		}
		pending, err := mergeParallelRoundResults(jobs, scopes, out, 2, window)
		require.NoError(t, err)
		require.Zero(t, pending)
		require.Equal(t, []Verdict{verdict, verdict}, out)
	})

	t.Run("surface error while jobs remain", func(t *testing.T) {
		scopes := [][]ast.Value{{scope}, {scope}}
		out := make([]Verdict, 2)
		window := []groupOutcome[parallelRoundResult]{
			{value: parallelRoundResult{scopes: [][]ast.Value{nil, {scope}}, verdicts: []Verdict{verdict, verdict}}},
			{err: errLater},
		}
		pending, err := mergeParallelRoundResults(jobs, scopes, out, 2, window)
		require.ErrorIs(t, err, errLater)
		require.Equal(t, 1, pending)
		require.Equal(t, verdict, out[0])
		require.Empty(t, out[1])
	})
}
