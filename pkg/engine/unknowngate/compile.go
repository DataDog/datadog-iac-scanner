package unknowngate

import (
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
)

type ruleKind uint8

const (
	ruleVdoc ruleKind = iota
	rulePolicy
	ruleFunc
)

type ruleMeta struct {
	kind ruleKind
	// primary is false for else branches and default rules: their value is chosen because
	// other rules failed.
	primary bool
}

// unindexStage copies every comprehension term after the compiler indexed them. The
// comprehension index is keyed by term pointer, so the traced evaluation never reads it: a
// cached comprehension emits no events, and the tracer would not see the unknowns it compared.
func unindexStage(c *ast.Compiler) *ast.Error {
	for _, name := range sortedModuleNames(c) {
		ast.WalkExprs(c.Modules[name], func(e *ast.Expr) bool {
			if ts, ok := e.Terms.([]*ast.Term); ok {
				for i, t := range ts {
					if ast.IsComprehension(t.Value) {
						ts[i] = t.Copy()
					}
				}
			}
			return false
		})
	}
	return nil
}

func sortedModuleNames(c *ast.Compiler) []string {
	names := make([]string, 0, len(c.Modules))
	for n := range c.Modules {
		names = append(names, n)
	}
	return names
}

func compile(modules map[string]*ast.Module, caps *ast.Capabilities, traced bool) (*ast.Compiler, error) {
	c := ast.NewCompiler().WithCapabilities(caps)
	if traced {
		c = c.WithStageAfter("BuildComprehensionIndices", ast.CompilerStageDefinition{
			Name:       "UnknownGateUnindexComprehensions",
			MetricName: "compile_stage_unknowngate_unindex_comprehensions",
			Stage:      unindexStage,
		})
	}
	c.Compile(modules)
	if c.Failed() {
		return nil, fmt.Errorf("compile: %w", c.Errors)
	}
	return c, nil
}

// compiledRules indexes the rules of a compiled module set.
type compiledRules struct {
	meta   map[*ast.Rule]ruleMeta
	byPath map[string][]*ast.Rule
	defs   map[*ast.Rule]map[ast.Var]*ast.Term
	// callDefs maps the variables of each rule body to the call that binds them as its output:
	// the first expression that mentions the variable is `f(args, v)`.
	callDefs map[*ast.Rule]map[ast.Var]*ast.Expr
}

func indexRules(c *ast.Compiler, query ast.Ref) (*compiledRules, error) {
	cr := &compiledRules{meta: map[*ast.Rule]ruleMeta{}, byPath: map[string][]*ast.Rule{}}
	policies := 0
	for _, m := range c.Modules {
		for _, r := range m.Rules {
			kind := ruleVdoc
			switch {
			case len(r.Head.Args) > 0:
				kind = ruleFunc
			case r.Ref().GroundPrefix().Equal(query):
				kind = rulePolicy
				policies++
			}
			primary := !r.Default
			for x := r; x != nil; x = x.Else {
				cr.meta[x] = ruleMeta{kind: kind, primary: primary}
				p := x.Ref().GroundPrefix().String()
				cr.byPath[p] = append(cr.byPath[p], x)
				primary = false
			}
		}
	}
	if policies == 0 {
		return nil, errors.New("no rule defines the query " + query.String())
	}
	cr.defs = definitions(cr)
	cr.callDefs = callDefinitions(cr)
	return cr, nil
}

// definitions maps the variables of each rule body to the term of the assignment that binds
// them: the first expression that mentions the variable is `v = term`. The value of v is
// then known as soon as the variables of term are.
func definitions(cr *compiledRules) map[*ast.Rule]map[ast.Var]*ast.Term {
	out := map[*ast.Rule]map[ast.Var]*ast.Term{}
	for r := range cr.meta {
		defs := map[ast.Var]*ast.Term{}
		seen := ast.NewVarSet()
		for _, e := range r.Body {
			vars := e.Vars(ast.VarVisitorParams{SkipClosures: false})
			if e.IsEquality() && !e.Negated && len(e.With) == 0 {
				for i, o := range e.Operands() {
					v, ok := o.Value.(ast.Var)
					other := e.Operand(1 - i)
					if ok && !seen.Contains(v) && !other.Vars().Contains(v) {
						defs[v] = other
					}
				}
			}
			seen.Update(vars)
		}
		if len(defs) > 0 {
			out[r] = defs
		}
	}
	return out
}

func callDefinitions(cr *compiledRules) map[*ast.Rule]map[ast.Var]*ast.Expr {
	out := map[*ast.Rule]map[ast.Var]*ast.Expr{}
	for r := range cr.meta {
		defs := map[ast.Var]*ast.Expr{}
		seen := ast.NewVarSet()
		for _, e := range r.Body {
			vars := e.Vars(ast.VarVisitorParams{SkipClosures: false})
			if v, call, ok := callOutputBinding(cr, e, seen); ok {
				defs[v] = call
			}
			seen.Update(vars)
		}
		if len(defs) > 0 {
			out[r] = defs
		}
	}
	return out
}

func callOutputBinding(cr *compiledRules, e *ast.Expr, seen ast.VarSet) (ast.Var, *ast.Expr, bool) {
	if !e.IsCall() || e.IsEquality() || e.Negated || len(e.With) != 0 || !e.Operator().HasPrefix(ast.DefaultRootRef) {
		return "", nil, false
	}
	ops := e.Operands()
	n := cr.funcArity(e.Operator())
	if n < 0 || len(ops) != n+1 {
		return "", nil, false
	}
	v, ok := ops[n].Value.(ast.Var)
	if !ok || seen.Contains(v) {
		return "", nil, false
	}
	for _, o := range ops[:n] {
		if o.Vars().Contains(v) {
			return "", nil, false
		}
	}
	return v, e, true
}

func (cr *compiledRules) rules(ref ast.Ref) []*ast.Rule {
	return cr.byPath[ref.String()]
}

// funcArity returns the number of arguments of the function at ref, or -1.
func (cr *compiledRules) funcArity(ref ast.Ref) int {
	for _, r := range cr.rules(ref) {
		if len(r.Head.Args) > 0 {
			return len(r.Head.Args)
		}
	}
	return -1
}

// docRoot finds the virtual document a ground prefix of ref reads: the length of the shortest
// prefix whose rule tree node defines rules, or of the longest prefix inside the rule tree when
// the ref reads a key no rule defines. It returns 0 when ref reads no virtual document.
func docRoot(c *ast.Compiler, ref ast.Ref) int {
	node := c.RuleTree
	n := 0
	for i, t := range ref {
		if i > 0 && !t.IsGround() {
			break
		}
		child := node.Child(t.Value)
		if child == nil {
			break
		}
		node = child
		n = i + 1
		if len(node.Values) > 0 {
			return n
		}
	}
	if n <= 1 {
		return 0
	}
	return n
}

// sentinelVars maps each rule to the variables its body, closures included, binds to one of
// sentinels: the compiler moves refs out of calls into such variables.
func sentinelVars(cr *compiledRules, sentinels []ast.Ref) map[*ast.Rule]map[ast.Var]bool {
	out := map[*ast.Rule]map[ast.Var]bool{}
	if len(sentinels) == 0 {
		return out
	}
	for r := range cr.meta {
		ast.WalkExprs(r.Body, func(e *ast.Expr) bool {
			if !e.IsEquality() || e.Negated {
				return false
			}
			for i, o := range e.Operands() {
				v, ok := o.Value.(ast.Var)
				if !ok || !isSentinelRef(e.Operand(1-i).Value, sentinels) {
					continue
				}
				if out[r] == nil {
					out[r] = map[ast.Var]bool{}
				}
				out[r][v] = true
			}
			return false
		})
	}
	return out
}

func isSentinelRef(v ast.Value, sentinels []ast.Ref) bool {
	ref, ok := v.(ast.Ref)
	if !ok {
		return false
	}
	for _, s := range sentinels {
		if ref.Equal(s) {
			return true
		}
	}
	return false
}
