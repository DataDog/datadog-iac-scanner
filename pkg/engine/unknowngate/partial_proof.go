package unknowngate

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown"
)

// resultProof belongs to one Check call; no result is cached across inputs or stores.
type resultProof struct {
	g           *Gate
	ctx         context.Context
	input       ast.Value
	placeholder *placeholder
	attempted   bool
	proven      bool
	evals       int
}

func (p *resultProof) check() (bool, error) {
	if !p.g.partialProof || p.g.nondeterministic || p.g.tracerOnly {
		return false, nil
	}
	if p.attempted {
		return p.proven, nil
	}
	p.attempted = true
	baselineErrors := []topdown.Error{}
	baseline, err := p.g.evalErrs(p.ctx, p.input, &baselineErrors)
	if err != nil {
		return false, fmt.Errorf("unknowngate: partial proof baseline: %w", err)
	}
	if len(baselineErrors) != 0 {
		return false, fmt.Errorf("unknowngate: partial proof baseline produced builtin errors: %v", baselineErrors)
	}
	p.evals++
	p.proven, err = p.g.proveFullResult(p.ctx, p.input, unknownInputRefs(p.input, p.placeholder), baseline)
	if err != nil {
		return false, fmt.Errorf("unknowngate: partial proof: %w", err)
	}
	return p.proven, nil
}

type partialSaveTracer struct{ saves int }

func (*partialSaveTracer) Enabled() bool { return true }
func (*partialSaveTracer) Config() topdown.TraceConfig {
	return topdown.TraceConfig{PlugLocalVars: false}
}
func (t *partialSaveTracer) TraceEvent(event topdown.Event) { //nolint:gocritic // topdown.QueryTracer requires an Event value.
	if event.Op == topdown.SaveOp {
		t.saves++
	}
}

// proveFullResult certifies the entire output rather than specializing one finding.
// Saved expressions also reject certification: set deduplication or a failing branch
// can otherwise discard residual work whose unknown resolution could cause an error.
func (g *Gate) proveFullResult(ctx context.Context, input ast.Value, unknowns []*ast.Term, baseline ast.Value) (bool, error) {
	if baseline == nil {
		return false, nil
	}
	body := ast.NewBody(ast.Equality.Expr(ast.NewTerm(g.query), ast.NewTerm(baseline)))
	compiled, err := g.plain.QueryCompiler().Compile(body)
	if err != nil {
		return false, fmt.Errorf("compile full-result equality query: %w", err)
	}
	txn, err := g.store.NewTransaction(ctx)
	if err != nil {
		return false, err
	}
	defer g.store.Abort(ctx, txn)
	errs := []topdown.Error{}
	tracer := &partialSaveTracer{}
	queries, support, err := topdown.NewQuery(compiled).
		WithCompiler(g.plain).
		WithStore(g.store).
		WithTransaction(txn).
		WithInput(ast.NewTerm(input)).
		WithUnknowns(unknowns).
		WithBuiltinErrorList(&errs).
		WithIndexing(false).
		WithEarlyExit(false).
		WithQueryTracer(tracer).
		WithCancel(contextCancel{ctx}).
		PartialRun(ctx)
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if len(errs) != 0 {
		return false, fmt.Errorf("partial evaluation produced builtin errors: %v", errs)
	}
	if len(support) != 0 || tracer.saves != 0 {
		return false, nil
	}
	if len(queries) == 0 {
		return false, nil
	}
	for _, query := range queries {
		if len(query) != 0 {
			return false, nil
		}
	}
	return true, nil
}

// unknownInputRefs over-approximates uncertain inputs, including the cardinality
// of open inventories and the keys of unknown-bearing objects and sets.
func unknownInputRefs(input ast.Value, placeholder *placeholder) []*ast.Term {
	refs := make([]*ast.Term, 0)
	seen := make(map[string]bool)
	root := ast.Ref{ast.InputRootDocument}
	var visit func(ast.Value, ast.Ref)
	add := func(ref ast.Ref) {
		term := ast.NewTerm(ref)
		if !seen[term.String()] {
			seen[term.String()] = true
			refs = append(refs, term)
		}
	}
	visit = func(value ast.Value, path ast.Ref) {
		if placeholder.is(value) {
			add(path)
			return
		}
		if text, ok := value.(ast.String); ok && placeholder.hasText(text) {
			add(path)
			return
		}
		switch x := value.(type) {
		case *ast.Array:
			for i := 0; i < x.Len(); i++ {
				child := x.Elem(i).Value
				if placeholder.is(child) {
					// A direct placeholder member represents an open inventory.
					add(path)
					return
				}
			}
			for i := 0; i < x.Len(); i++ {
				visit(x.Elem(i).Value, path.Append(ast.IntNumberTerm(i)))
			}
		case ast.Object:
			if hasUnknownObjectKey(x, placeholder) {
				add(path)
				return
			}
			_ = x.Iter(func(key, child *ast.Term) error {
				visit(child.Value, path.Append(key))
				return nil
			})
		case ast.Set:
			unknownMember := false
			_ = x.Iter(func(member *ast.Term) error {
				if placeholder.has(member.Value) || placeholder.hasText(member.Value) {
					unknownMember = true
					return errStop
				}
				return nil
			})
			if unknownMember {
				add(path)
			}
		}
	}
	visit(input, root)
	return refs
}

func hasUnknownObjectKey(object ast.Object, placeholder *placeholder) bool {
	unknown := false
	_ = object.Iter(func(key, _ *ast.Term) error {
		if placeholder.has(key.Value) || placeholder.hasText(key.Value) {
			unknown = true
			return errStop
		}
		return nil
	})
	return unknown
}
