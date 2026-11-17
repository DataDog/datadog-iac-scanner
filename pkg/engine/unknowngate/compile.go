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
	for _, r := range queryRules(c, query) {
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
	if policies == 0 {
		return nil, errors.New("no rule defines the query " + query.String())
	}
	cr.defs = definitions(cr)
	cr.callDefs = callDefinitions(cr)
	return cr, nil
}

// queryRules returns the policy rules and their transitive data-rule and function
// dependencies. GetRules on each ref's ground prefix includes rules a dynamic
// nested key could select, along with else/default and function definitions.
func queryRules(c *ast.Compiler, query ast.Ref) []*ast.Rule {
	queue := c.GetRulesExact(query)
	seen := make(map[*ast.Rule]struct{}, len(queue))
	var out []*ast.Rule
	for len(queue) > 0 {
		rule := queue[0]
		queue = queue[1:]
		if _, ok := seen[rule]; ok {
			continue
		}
		seen[rule] = struct{}{}
		out = append(out, rule)
		ast.WalkRefs(rule, func(ref ast.Ref) bool {
			if ref.HasPrefix(ast.DefaultRootRef) {
				queue = append(queue, c.GetRules(ref.GroundPrefix())...)
			}
			return false
		})
	}
	return out
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

// constantSentinelVars identifies a direct marker temp only when its one
// binding is the variable's first definition and every later use is a direct
// equality predicate. Any alias, head use, call, modifier, or nested use fails
// closed to the broader sentinelVars behavior.
func constantSentinelVars(cr *compiledRules, sentinels []ast.Ref) map[*ast.Rule]map[ast.Var]bool {
	out := map[*ast.Rule]map[ast.Var]bool{}
	for r, vars := range definitions(cr) {
		for v, term := range vars {
			if !isSentinelRef(term.Value, sentinels) || sentinelTempUsedInHead(r, v) {
				continue
			}
			if !sentinelTempPredicateUsesOnly(r, v) {
				continue
			}
			if out[r] == nil {
				out[r] = map[ast.Var]bool{}
			}
			out[r][v] = true
		}
	}
	return out
}

func sentinelTempUsedInHead(r *ast.Rule, v ast.Var) bool {
	if occurs(r.Head.Key, v) || occurs(r.Head.Value, v) {
		return true
	}
	for _, term := range r.Head.Reference {
		if occurs(term, v) {
			return true
		}
	}
	for _, arg := range r.Head.Args {
		if occurs(arg, v) {
			return true
		}
	}
	return false
}

func sentinelTempPredicateUsesOnly(r *ast.Rule, v ast.Var) bool {
	definitionFound := false
	for i, e := range r.Body {
		if !occursExpr(e, v) {
			continue
		}
		if !definitionFound {
			// definitions() only records first-use, positive equality bindings and
			// term is the direct marker assigned by that binding.
			definitionFound = true
			continue
		}
		if !directSentinelPredicateUse(r, e, v, i) {
			return false
		}
	}
	return definitionFound
}

func directSentinelPredicateUse(r *ast.Rule, e *ast.Expr, v ast.Var, index int) bool {
	if e.Negated || len(e.With) != 0 {
		return false
	}
	if !e.IsEquality() && (!e.IsCall() || (e.Operator().String() != ast.Equal.Name && e.Operator().String() != ast.NotEqual.Name)) {
		return false
	}
	operands := e.Operands()
	if len(operands) != 2 {
		return false
	}
	found := false
	for _, operand := range operands {
		if variable, ok := operand.Value.(ast.Var); ok && variable == v {
			if found {
				return false
			}
			found = true
			continue
		}
		if occurs(operand, v) {
			return false
		}
		if other, ok := operand.Value.(ast.Var); ok && !boundBefore(r, other, index) {
			return false
		}
	}
	return found
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
