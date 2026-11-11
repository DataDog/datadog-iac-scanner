// Package unknowngate decides whether a result of a rule holds whatever the unknown values of
// its input turn out to be. Unknown values are a placeholder string in the input. A result
// that may depend on one is uncertain, and the engine reports it as a pass.
//
// Guarantee: a finding is reported only when it is certain for every substitution of the
// unknowns in scope. Uncertain candidates are dropped (treated as a pass).
//
// The caller selects the candidates (stage 0): the results whose block or relations hold the
// placeholder. Every other result is certain. A candidate is certain only if it passes:
//
//   - stage 1, a traced re-evaluation of the rule: at least one derivation of the result reads
//     no unknown value in a way that could change it;
//   - stage 2, a substitution check: replacing each placeholder in the candidate's scope, one at
//     a time, by values taken from the rule does not remove the result.
//
// Known limitation: when a set-key derivation touches an unknown before the key is bound, the
// whole set can be marked uncertain (over-taint); see TestOrderDependentOvertaint.
//
// The package knows nothing about Terraform: it receives the placeholder, the rule modules,
// the input and the plain results.
package unknowngate

import (
	"context"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown"
)

// Options configures a gate for one rule.
type Options struct {
	// Placeholder is the unknown value, compared by exact match.
	Placeholder string
	// Modules are the parsed modules of the rule and its libraries. They are not modified.
	Modules map[string]*ast.Module
	// Query is the ref of the rule's result set, for example "data.datadog.DatadogPolicy".
	Query string
	// Capabilities restricts the builtins, as for the plain compile. Nil means all.
	Capabilities *ast.Capabilities
	// Store holds the base documents the rule reads under data. Nil means an empty store.
	Store storage.Store
	// Sentinels are refs to library rules whose value is the placeholder itself, for example
	// "data.generic.terraform._placeholder". Comparing a value with a sentinel tests whether
	// the value is unknown, not what it stands for, so it is not a touch.
	Sentinels []string
}

// Gate checks the results of one rule. It is safe for concurrent use.
type Gate struct {
	placeholder string
	query       ast.Ref
	plain       *ast.Compiler
	traced      *ast.Compiler
	plainBody   ast.Body
	tracedBody  ast.Body
	rules       *compiledRules
	flow        *flow
	store       storage.Store
	values      []ast.Value
	companions  []ast.Value
	// countExpands are list-cardinality substitutions driven by count(...)
	// comparisons in the reachable rules (always includes 1). Unrelated
	// numeric constants such as ports are not used.
	countExpands []int
	setDocs      map[string]bool
	renderSites  map[string]bool
	sentinels    []ast.Ref
	// sentinelVars holds, per rule, the variables bound to a sentinel.
	sentinelVars map[*ast.Rule]map[ast.Var]bool

	tracerOnly bool
}

const resultVar = ast.Var("unknowngate_result")

// New compiles the rule twice: once as the engine does, for the substitution check, and once
// for tracing, without comprehension indexes.
func New(opts Options) (*Gate, error) { //nolint:gocritic // the options are read once, at construction
	if opts.Placeholder == "" {
		return nil, errors.New("unknowngate: empty placeholder")
	}
	query, err := ast.ParseRef(opts.Query)
	if err != nil {
		return nil, fmt.Errorf("unknowngate: query: %w", err)
	}
	caps := opts.Capabilities
	if caps == nil {
		caps = ast.CapabilitiesForThisVersion()
	}
	g := &Gate{placeholder: opts.Placeholder, query: query, store: opts.Store}
	for _, s := range opts.Sentinels {
		ref, err := ast.ParseRef(s)
		if err != nil {
			return nil, fmt.Errorf("unknowngate: sentinel: %w", err)
		}
		g.sentinels = append(g.sentinels, ref)
	}
	if g.store == nil {
		g.store = inmem.New()
	}
	if g.plain, err = compile(opts.Modules, caps, false); err != nil {
		return nil, fmt.Errorf("unknowngate: %w", err)
	}
	if g.traced, err = compile(opts.Modules, caps, true); err != nil {
		return nil, fmt.Errorf("unknowngate: %w", err)
	}
	body := ast.NewBody(ast.Equality.Expr(ast.NewTerm(resultVar), ast.NewTerm(query)))
	if g.plainBody, err = g.plain.QueryCompiler().Compile(body); err != nil {
		return nil, fmt.Errorf("unknowngate: %w", err)
	}
	if g.tracedBody, err = g.traced.QueryCompiler().Compile(body); err != nil {
		return nil, fmt.Errorf("unknowngate: %w", err)
	}
	if g.rules, err = indexRules(g.traced, query); err != nil {
		return nil, fmt.Errorf("unknowngate: %w", err)
	}
	g.flow = analyzeFlow(g.rules)
	g.sentinelVars = sentinelVars(g.rules, g.sentinels)
	g.setDocs = map[string]bool{}
	for p, rs := range g.rules.byPath {
		if len(rs) > 0 && rs[0].Head.RuleKind() == ast.MultiValue {
			g.setDocs[p] = true
		}
	}
	g.values, g.companions, g.countExpands = substitutionValues(g.traced, g.rules, opts.Placeholder)
	g.renderSites = renderSites(g.plain)
	return g, nil
}

func (g *Gate) isSetDoc(ref ast.Ref) bool { return g.setDocs[ref.String()] }

// Candidate is a plain result to check.
type Candidate struct {
	// Result is one element of the rule's result set.
	Result ast.Value
	// Input, when set, is a minimal input for this result (its block and relations), an object.
	// Candidates that share a minimal input should share the value. If the rule does not
	// reproduce the result on it, the gate uses the whole input.
	Input ast.Value
	// Scope holds the composite subterms of the input whose placeholders the substitution
	// check replaces: the block and its relation lists. Empty means every placeholder of the
	// input.
	Scope []ast.Value
}

// Stage is the stage that decided a verdict.
type Stage uint8

const (
	StageNone Stage = iota
	StageTracer
	StageSubstitution
)

// Verdict is the decision on one candidate.
type Verdict struct {
	Uncertain bool
	Stage     Stage
	// Reason says, for an uncertain verdict, what made it uncertain.
	Reason string
}

// Report holds the verdicts, in the order of the candidates, and the counts the caller logs.
type Report struct {
	Verdicts          []Verdict
	Suppressed        int
	TracedEvals       int
	SubstitutionEvals int
}

// Check decides every candidate. input is the input the plain results came from.
func (g *Gate) Check(ctx context.Context, input ast.Value, cands []Candidate) (*Report, error) {
	rep := &Report{Verdicts: make([]Verdict, len(cands))}
	ph := newPlaceholder(g.placeholder)
	tr := &traces{g: g, ctx: ctx, input: input, minimal: map[ast.Value]*tracer{}}
	byInput := map[ast.Value][]job{}
	var order []ast.Value
	for i, c := range cands {
		id, mask := ph.identity(c.Result)
		st, used, err := tr.lookup(c, id)
		if err != nil {
			return nil, err
		}
		switch {
		case st == nil:
			rep.Verdicts[i] = Verdict{Uncertain: true, Stage: StageTracer, Reason: "the traced evaluation did not reproduce the result"}
		case !st.anyClean:
			rep.Verdicts[i] = Verdict{Uncertain: true, Stage: StageTracer, Reason: "every derivation reads an unknown value"}
		case g.tracerOnly:
		default:
			byInput[used] = append(byInput[used], job{index: i, cand: c, id: id, mask: mask})
			if len(byInput[used]) == 1 {
				order = append(order, used)
			}
		}
	}
	rep.TracedEvals = tr.evals
	for _, in := range order {
		s := &substitution{g: g, ctx: ctx, input: in, ph: ph}
		err := s.batch(byInput[in], rep.Verdicts)
		rep.SubstitutionEvals += s.evals
		if err != nil {
			return nil, err
		}
	}
	for _, v := range rep.Verdicts {
		if v.Uncertain {
			rep.Suppressed++
		}
	}
	return rep, nil
}

// traces runs stage 1 once per input.
type traces struct {
	g       *Gate
	ctx     context.Context
	input   ast.Value
	whole   *tracer
	minimal map[ast.Value]*tracer
	evals   int
}

// lookup returns the trace state of result id of c and the input that reproduced it: the
// minimal input of c, else the whole input. The state is nil if neither reproduced it.
func (t *traces) lookup(c Candidate, id ast.Value) (*resultState, ast.Value, error) {
	if c.Input != nil {
		tr, ok := t.minimal[c.Input]
		if !ok {
			var err error
			if tr, err = t.trace(c.Input); err != nil {
				return nil, nil, err
			}
			t.minimal[c.Input] = tr
		}
		if st, _ := tr.results.get(id); st != nil {
			return st, c.Input, nil
		}
	}
	if t.whole == nil {
		var err error
		if t.whole, err = t.trace(t.input); err != nil {
			return nil, nil, err
		}
	}
	st, _ := t.whole.results.get(id)
	return st, t.input, nil
}

func (t *traces) trace(input ast.Value) (*tracer, error) {
	t.evals++
	return t.g.trace(t.ctx, input)
}

// job is a candidate the tracer passed, waiting for the substitution check.
type job struct {
	index int
	cand  Candidate
	id    ast.Value
	mask  []string
}

func (g *Gate) trace(ctx context.Context, input ast.Value) (*tracer, error) {
	tr := newTracer(g, input)
	if _, err := g.eval(ctx, g.traced, g.tracedBody, input, tr); err != nil {
		return nil, err
	}
	return tr, nil
}

// eval evaluates the rule and returns its result set. A tracer turns rule indexing off, so
// every rule head is unified and traced.
func (g *Gate) eval(ctx context.Context, c *ast.Compiler, body ast.Body, input ast.Value, tr topdown.QueryTracer) (ast.Value, error) {
	return g.run(ctx, c, body, input, tr, nil)
}

// evalErrs evaluates the rule as the engine does and collects the builtin errors.
func (g *Gate) evalErrs(ctx context.Context, input ast.Value, errs *[]topdown.Error) (ast.Value, error) {
	return g.run(ctx, g.plain, g.plainBody, input, nil, errs)
}

func (g *Gate) run(
	ctx context.Context, c *ast.Compiler, body ast.Body, input ast.Value, tr topdown.QueryTracer, errs *[]topdown.Error,
) (ast.Value, error) {
	txn, err := g.store.NewTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer g.store.Abort(ctx, txn)
	q := topdown.NewQuery(body).
		WithCompiler(c).
		WithStore(g.store).
		WithTransaction(txn).
		WithInput(ast.NewTerm(input))
	if tr != nil {
		q = q.WithQueryTracer(tr).WithIndexing(false)
	}
	if errs != nil {
		q = q.WithBuiltinErrorList(errs)
	}
	var out ast.Value
	err = q.Iter(ctx, func(qr topdown.QueryResult) error {
		if t := qr[resultVar]; t != nil {
			out = t.Value
		}
		return nil
	})
	return out, err
}

// Results evaluates the rule as the engine does and returns its results, for callers and
// tests that do not have them.
func (g *Gate) Results(ctx context.Context, input ast.Value) ([]ast.Value, error) {
	v, err := g.eval(ctx, g.plain, g.plainBody, input, nil)
	if err != nil {
		return nil, err
	}
	return elements(v), nil
}

func elements(v ast.Value) []ast.Value {
	var out []ast.Value
	switch x := v.(type) {
	case ast.Set:
		_ = x.Iter(func(e *ast.Term) error {
			out = append(out, e.Value)
			return nil
		})
	case *ast.Array:
		for i := 0; i < x.Len(); i++ {
			out = append(out, x.Elem(i).Value)
		}
	case nil:
	default:
		out = append(out, v)
	}
	return out
}

// probe evaluates call, a call of a rule function on ground arguments, under a tracer of its
// own. It returns the value when the call has exactly one and no unknown value took part.
func (g *Gate) probe(parent *tracer, input ast.Value, call *ast.Term) (ast.Value, bool) {
	body := ast.NewBody(ast.Equality.Expr(ast.VarTerm("unknowngate_probe"), call))
	compiled, err := g.traced.QueryCompiler().Compile(body)
	if err != nil {
		return nil, false
	}
	tr := newTracer(g, input)
	tr.probeDepth = parent.probeDepth + 1
	ctx := context.Background()
	txn, err := g.store.NewTransaction(ctx)
	if err != nil {
		return nil, false
	}
	defer g.store.Abort(ctx, txn)
	var out ast.Value
	n := 0
	err = topdown.NewQuery(compiled).
		WithCompiler(g.traced).
		WithStore(g.store).
		WithTransaction(txn).
		WithInput(ast.NewTerm(input)).
		WithQueryTracer(tr).
		WithIndexing(false).
		Iter(ctx, func(qr topdown.QueryResult) error {
			if t := qr["unknowngate_probe"]; t != nil {
				if n == 0 || out.Compare(t.Value) != 0 {
					n++
				}
				out = t.Value
			}
			return nil
		})
	if err != nil || n != 1 || tr.rootTouched {
		return nil, false
	}
	return out, true
}
