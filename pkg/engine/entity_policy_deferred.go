/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"sort"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/types"
)

// Structural comparisons, membership and type predicates stay in PE. Other
// ordinary builtins are deferred so their errors remain in native execution.
func entityPartialBuiltin(name string) bool {
	switch name {
	case "eq", "equal", "neq", "gt", "gte", "lt", "lte", ast.Member.Name, ast.MemberWithKey.Name,
		"is_null", "is_boolean", "is_number", "is_string", "is_array", "is_object", "is_set":
		return true
	}
	return false
}

type entityDeferredOp struct {
	Original, Private ast.Ref
	Decl              *types.Function
	Document          bool
}
type entityDeferredBoundary struct {
	compiler *ast.Compiler
	ops      map[string]entityDeferredOp
	original map[string]entityDeferredOp
	paths    []string
}

// Build a private PE compiler; native modules remain immutable, even when no
// operation needs deferring. Only complete functions with differing or computed
// outputs need opaque proxies to preserve their native errors and conflicts.
func prepareEntityDeferred(compiled *entityCompilation) (*entityDeferredBoundary, *entityCompilation, error) {
	original := compiled.compiler
	candidates, err := entityDeferredFunctions(original)
	if err != nil {
		return nil, nil, err
	}
	collectEntityDeferredBuiltins(original.Modules, candidates)
	p := &entityDeferredBoundary{ops: map[string]entityDeferredOp{}, original: map[string]entityDeferredOp{}}
	names := make([]string, 0, len(candidates))
	for name := range candidates {
		names = append(names, name)
	}
	sort.Strings(names)
	for index, name := range names {
		op := candidates[name]
		args := make([]types.Type, op.Decl.Arity())
		for i := range args {
			args[i] = types.A
		}
		op.Decl = types.NewFunction(args, types.A)
		op.Private = ast.MustParseRef(fmt.Sprintf("dd.__entity_deferred.op%d", index))
		p.ops[op.Private.String()] = op
		p.original[name] = op
		p.paths = append(p.paths, op.Private.String())
	}
	caps := *original.Capabilities()
	functions := append([]entityFunction{}, compiled.functions...)
	caps.Builtins = append([]*ast.Builtin{}, caps.Builtins...)
	for _, op := range p.ops {
		caps.Builtins = append(caps.Builtins, &ast.Builtin{Name: op.Private.String(), Decl: op.Decl, Nondeterministic: true})
		definition := &rego.Function{Name: op.Private.String(), Decl: op.Decl, Nondeterministic: true}
		functions = append(functions, entityFunction{definition, func(_ rego.BuiltinContext, _ []*ast.Term) (*ast.Term, error) {
			return nil, fmt.Errorf("private deferred operation executed during PE")
		}})
	}
	modules := copyEntityModules(original.Modules)
	for name, module := range modules {
		kept := []*ast.Rule{}
		for _, rule := range module.Rules {
			if op, ok := p.original[rule.Ref().String()]; ok && op.Original[0].Equal(ast.VarTerm("data")) {
				continue
			}
			kept = append(kept, rule)
		}
		module.Rules = kept
		lowered, err := p.lower(module, name != entityCoreModuleName)
		if err != nil {
			return nil, nil, err
		}
		modules[name] = lowered.(*ast.Module)
	}
	compiler := ast.NewCompiler().WithCapabilities(&caps)
	compiler.Compile(modules)
	attachEntityRuleModules(compiler.Modules)
	if compiler.Failed() {
		return nil, nil, fmt.Errorf("symbolic lowering: %s", compiler.Errors)
	}
	p.compiler = compiler
	lowered := &entityCompilation{compiler: compiler, capabilities: &caps, functions: functions, decisions: compiled.decisions}
	return p, lowered, nil
}

func entityDeferredFunctions(original *ast.Compiler) (map[string]entityDeferredOp, error) {
	groups := map[string][]*ast.Rule{}
	for name, module := range original.Modules {
		if name == entityCoreModuleName {
			continue
		}
		for _, rule := range module.Rules {
			if rule.Head.DocKind() == ast.CompleteDoc && rule.Head.RuleKind() == ast.SingleValue {
				groups[rule.Ref().String()] = append(groups[rule.Ref().String()], rule)
			}
		}
	}
	candidates := map[string]entityDeferredOp{}
	for key, rules := range groups {
		if entityIdenticalGroundHeads(rules) {
			continue
		}
		ref := rules[0].Ref().Copy()
		document := len(rules[0].Head.Args) == 0
		typ := original.TypeEnv.GetByRef(ref)
		var declaration *types.Function
		if document {
			declaration = types.NewFunction(types.Args(), typ)
		} else {
			var ok bool
			declaration, ok = typ.(*types.Function)
			if !ok {
				return nil, fmt.Errorf("missing original function type %s", key)
			}
		}
		candidates[key] = entityDeferredOp{Original: ref, Decl: declaration, Document: document}
	}
	return candidates, nil
}

// Identical concrete outputs cannot conflict. This only permits inlining;
// the original rule guards still decide whether the function is defined.
func entityIdenticalGroundHeads(rules []*ast.Rule) bool {
	var first *ast.Term
	for _, root := range rules {
		for rule := root; rule != nil; rule = rule.Else {
			if _, err := ast.JSON(rule.Head.Value.Value); err != nil {
				return false
			}
			if first == nil {
				first = rule.Head.Value
			} else if !first.Equal(rule.Head.Value) {
				return false
			}
		}
	}
	return first != nil
}

func collectEntityDeferredBuiltins(modules map[string]*ast.Module, candidates map[string]entityDeferredOp) {
	for name, module := range modules {
		if name == entityCoreModuleName {
			continue
		}
		ast.WalkExprs(module, func(expr *ast.Expr) bool {
			if !expr.IsCall() {
				return false
			}
			name := expr.Operator().String()
			if builtin := ast.BuiltinMap[name]; builtin != nil && !entityPartialBuiltin(name) {
				candidates[name] = entityDeferredOp{Original: expr.Operator().Copy(), Decl: builtin.Decl}
			}
			return false
		})
	}
}

func (p *entityDeferredBoundary) lower(x any, includeBuiltins bool) (any, error) {
	return ast.TransformRefs(x, func(ref ast.Ref) (ast.Value, error) {
		op, ok := p.original[ref.String()]
		if !ok || (!includeBuiltins && !op.Original[0].Equal(ast.VarTerm("data"))) {
			return ref, nil
		}
		if op.Document {
			return ast.Call{ast.NewTerm(op.Private.Copy())}, nil
		}
		return op.Private.Copy(), nil
	})
}
func (p *entityDeferredBoundary) closed(body ast.Body) bool {
	blocked := false
	symbols := ast.MustParseRef("input.__dd_symbols")
	partial := ast.MustParseRef("data." + entityPartialNamespace)
	ast.WalkRefs(body, func(ref ast.Ref) bool {
		prefix := ref.ConstantPrefix()
		if prefix.HasPrefix(symbols) || symbols.HasPrefix(prefix) && len(prefix) > 0 && prefix[0].Equal(ast.VarTerm("input")) {
			blocked = true
		}
		if ref.HasPrefix(partial) {
			blocked = true
		}
		if ref.HasPrefix(ast.MustParseRef("dd.__entity_deferred")) {
			if _, ok := p.ops[ref.String()]; !ok {
				blocked = true
			}
		}
		return false
	})
	return !blocked
}
func (p *entityDeferredBoundary) restore(body ast.Body) (ast.Body, bool, error) {
	if !p.closed(body) {
		return nil, false, nil
	}
	out := body.Copy()
	for _, expr := range out {
		if err := p.restoreCall(expr); err != nil {
			return nil, false, err
		}
	}
	restored, err := ast.Transform(ast.NewGenericTransformer(p.restoreNode), out)
	if err != nil {
		return nil, false, err
	}
	bodyOut := restored.(ast.Body)
	blocked := false
	ast.WalkRefs(bodyOut, func(ref ast.Ref) bool {
		if ref.HasPrefix(ast.MustParseRef("dd.__entity_deferred")) {
			blocked = true
		}
		return false
	})
	if blocked {
		return nil, false, nil
	}
	// OPA executes the whole restored body, preserving bindings and order.
	return bodyOut, true, nil
}

// An expression-level document proxy becomes either a read or a value binding.
func (p *entityDeferredBoundary) restoreCall(expr *ast.Expr) error {
	if !expr.IsCall() {
		return nil
	}
	op, ok := p.ops[expr.Operator().String()]
	if !ok {
		return nil
	}
	terms := expr.Terms.([]*ast.Term)
	if !op.Document {
		terms[0] = ast.NewTerm(op.Original.Copy())
		return nil
	}
	switch len(terms) {
	case 1:
		expr.Terms = ast.NewTerm(op.Original.Copy())
	case 2:
		expr.Terms = ast.Equality.Expr(terms[1].Copy(), ast.NewTerm(op.Original.Copy())).Terms
	default:
		return fmt.Errorf("unexpected document proxy arity")
	}
	return nil
}

// Restore references nested in operands after expression-level calls are fixed.
func (p *entityDeferredBoundary) restoreNode(node any) (any, error) {
	switch value := node.(type) {
	case ast.Call:
		if len(value) == 0 {
			return node, nil
		}
		ref, ok := value[0].Value.(ast.Ref)
		if !ok {
			return node, nil
		}
		if op, found := p.ops[ref.String()]; found && op.Document {
			if len(value) != 1 {
				return nil, fmt.Errorf("nested document proxy arity")
			}
			return op.Original.Copy(), nil
		}
	case ast.Ref:
		if op, ok := p.ops[value.String()]; ok && !op.Document {
			return op.Original.Copy(), nil
		}
	}
	return node, nil
}

// Compile under opaque Any declarations before restoring original operators.
// This prevents specialization from pruning errors before their native guards.
func (p *EntityProgram) nativeResidual(
	ctx context.Context, body ast.Body, input ast.Value, boundary *entityDeferredBoundary,
) ([]*ast.Term, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if !boundary.closed(body) {
		return nil, true, nil
	}
	qc := boundary.compiler.QueryCompiler()
	compiled, err := qc.Compile(body.Copy())
	if err != nil {
		return nil, false, err
	}
	restored, closed, err := boundary.restore(compiled)
	if err != nil {
		return nil, false, err
	}
	if !closed {
		return nil, true, nil
	}
	capture := ast.Var("result")
	for generated, source := range qc.RewrittenVars() {
		if source == "result" {
			capture = generated
		}
	}
	original, err := entitySessionFrom(ctx)
	if err != nil {
		return nil, false, err
	}
	session := &entitySession{reader: original.reader, targets: original.targets}
	ctx = context.WithValue(ctx, entitySessionKey{}, session)
	envelope := input.(ast.Object)
	nativeInput := ast.NewObject(
		ast.Item(ast.StringTerm("__dd_mode"), ast.StringTerm("native")),
		ast.Item(ast.StringTerm("arguments"), envelope.Get(ast.StringTerm("arguments"))),
		ast.Item(ast.StringTerm("__dd_symbols"), envelope.Get(ast.StringTerm("__dd_symbols"))),
		ast.Item(ast.StringTerm("__dd_focus"), ast.NullTerm()),
		ast.Item(ast.StringTerm("__dd_discovery"), ast.BooleanTerm(false)),
	)
	rows, err := p.runEntityResidual(ctx, restored, qc, nativeInput)
	if session.failure != nil {
		return nil, false, session.failure
	}
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	if session.symbolic {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("native residual evaluation: %w", err)
	}
	values := make([]*ast.Term, 0, len(rows))
	for _, row := range rows {
		value, ok := row[capture]
		if !ok {
			return nil, false, fmt.Errorf("missing native residual result")
		}
		values = append(values, value.Copy())
	}
	return values, false, nil
}

// Own the VM transaction and cancellation registration for one native replay.
func (p *EntityProgram) runEntityResidual(
	ctx context.Context, body ast.Body, compiler ast.QueryCompiler, input ast.Value,
) (topdown.QueryResultSet, error) {
	store := inmem.New()
	txn, err := store.NewTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer store.Abort(ctx, txn)
	vmCancel := topdown.NewCancel()
	stopCancellation := context.AfterFunc(ctx, vmCancel.Cancel)
	defer stopCancellation()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return topdown.NewQuery(body).
		WithCancel(vmCancel).
		WithCompiler(p.compilation.compiler).
		WithQueryCompiler(compiler).
		WithInput(ast.NewTerm(input)).
		WithStrictBuiltinErrors(true).
		WithBuiltins(p.compilation.builtins).
		WithStore(store).
		WithTransaction(txn).
		Run(ctx)
}
