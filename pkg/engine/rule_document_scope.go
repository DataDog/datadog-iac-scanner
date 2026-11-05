/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"fmt"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
)

// joiningQueries reports, by index in queries, whether each Terraform rule may
// read more than one document per finding. A rule is document-local only when
// every body of its entry rule iterates input.document exactly once, outside
// any comprehension, every or negation, and nothing else it reaches, library
// functions included, reads input. Anything the analysis cannot prove is
// joining.
func joiningQueries(queries []model.QueryMetadata, libraries ...string) map[int]bool {
	out := make(map[int]bool, len(queries))
	compiler, entries, err := compileForScope(queries, libraries)
	if err != nil {
		for i := range queries {
			out[i] = queryJoins(&queries[i], libraries...)
		}
		return out
	}
	s := &documentScope{compiler: compiler, reads: map[string]bool{}}
	for i := range queries {
		entry, ok := entries[i]
		out[i] = !ok || !s.local(compiler.GetRulesExact(entry))
	}
	return out
}

func queryJoins(query *model.QueryMetadata, libraries ...string) bool {
	compiler, entries, err := compileForScope([]model.QueryMetadata{*query}, libraries)
	if err != nil {
		return true
	}
	s := &documentScope{compiler: compiler, reads: map[string]bool{}}
	return !s.local(compiler.GetRulesExact(entries[0]))
}

func compileForScope(queries []model.QueryMetadata, libraries []string) (*ast.Compiler, map[int]ast.Ref, error) {
	opts := ast.ParserOptions{RegoVersion: ast.RegoV1}
	modules := make(map[string]*ast.Module, len(libraries)+len(queries))
	for i, library := range libraries {
		m, err := ast.ParseModuleWithOpts(fmt.Sprintf("library%d", i), library, opts)
		if err != nil {
			return nil, nil, err
		}
		modules[fmt.Sprintf("library%d", i)] = m
	}
	entries := make(map[int]ast.Ref, len(queries))
	for i := range queries {
		renamed := pkgDatadogDecl.ReplaceAllString(queries[i].Content, fmt.Sprintf("${1}package datadog.q%d", i))
		m, err := ast.ParseModuleWithOpts(fmt.Sprintf("rule%d", i), renamed, opts)
		if err != nil {
			if len(queries) == 1 {
				return nil, nil, err
			}
			continue
		}
		modules[fmt.Sprintf("rule%d", i)] = m
		entries[i] = m.Package.Path.Append(ast.StringTerm("DatadogPolicy"))
	}
	compiler := ast.NewCompiler().WithCapabilities(safeCapabilities())
	compiler.Compile(modules)
	if compiler.Failed() {
		return nil, nil, compiler.Errors
	}
	return compiler, entries, nil
}

type documentScope struct {
	compiler *ast.Compiler
	reads    map[string]bool
}

func (s *documentScope) local(entry []*ast.Rule) bool {
	if len(entry) == 0 {
		return false
	}
	for _, r := range entry {
		for ; r != nil; r = r.Else {
			if !s.localBody(r) {
				return false
			}
		}
	}
	return true
}

var inputDocumentPath = ast.MustParseRef("input.document")

// bodyScope tracks one entry body: the variables bound so far, those bound
// by iterating input.document, how many such iterations it has, and whether
// the visit is inside a comprehension, every or negation.
type bodyScope struct {
	*documentScope
	seen     ast.VarSet
	docIndex ast.VarSet
	loops    int
	nested   int
	ok       bool
}

// localBody reports whether the rule reads exactly one document: one
// iteration over input.document, re-indexed only by the variable it bound.
func (s *documentScope) localBody(rule *ast.Rule) bool {
	if len(rule.Head.Args) > 0 {
		return false
	}
	b := &bodyScope{documentScope: s, seen: ast.NewVarSet(), docIndex: ast.NewVarSet(), ok: true}
	vis := ast.NewGenericVisitor(b.visit)
	for _, expr := range rule.Body {
		vis.Walk(expr)
		b.seen.Update(expr.Vars(ast.VarVisitorParams{SkipClosures: true}))
	}
	if rule.Head.Key != nil {
		vis.Walk(rule.Head.Key)
	}
	if rule.Head.Value != nil {
		vis.Walk(rule.Head.Value)
	}
	return b.ok && b.loops == 1 && b.indexOnlyIndexes(rule)
}

// indexOnlyIndexes reports whether the document index variables are only
// used to index input.document: their value is a position in the evaluated
// documents, which batching changes.
func (b *bodyScope) indexOnlyIndexes(rule *ast.Rule) bool {
	if len(b.docIndex) == 0 {
		return true
	}
	ok := true
	var vis *ast.GenericVisitor
	vis = ast.NewGenericVisitor(func(x any) bool {
		if !ok {
			return true
		}
		switch t := x.(type) {
		case ast.Var:
			ok = !b.docIndex.Contains(t)
		case ast.Ref:
			if len(t) >= 3 && t.HasPrefix(inputDocumentPath) {
				for i, term := range t {
					if i != 2 {
						vis.Walk(term)
					}
				}
				return true
			}
		case *ast.Expr:
			if ops := t.Operands(); t.IsCall() && t.Operator().String() == ast.MemberWithKey.Name &&
				ops[2].Equal(ast.NewTerm(inputDocumentPath)) {
				vis.Walk(ops[1])
				return true
			}
		}
		return !ok
	})
	vis.Walk(rule.Body)
	vis.Walk(rule.Head)
	return ok
}

// opensScope reports whether x evaluates its body over values it binds
// itself, so an iteration over input.document inside it aggregates documents.
func opensScope(x any) bool {
	switch t := x.(type) {
	case *ast.ArrayComprehension, *ast.SetComprehension, *ast.ObjectComprehension, *ast.Every:
		return true
	case *ast.Expr:
		return t.Negated
	}
	return false
}

func (b *bodyScope) visit(x any) bool {
	if !b.ok {
		return true
	}
	if b.nested == 0 && opensScope(x) {
		b.nested++
		ast.NewGenericVisitor(b.visit).Walk(x)
		b.nested--
		return true
	}
	switch t := x.(type) {
	case *ast.Expr:
		if len(t.With) > 0 {
			b.ok = false
		} else if t.IsCall() {
			return b.member(t.Operator().String(), t.Operands())
		}
	case ast.Ref:
		if t[0].Equal(ast.InputRootDocument) {
			b.ok = b.documentRef(t)
		} else if t.HasPrefix(ast.DefaultRootRef) && b.dataReadsInput(t) {
			b.ok = false
		}
	}
	return !b.ok
}

// member counts `some ... in input.document` as an iteration when it binds
// fresh variables, and reports whether the call needs no further visiting.
func (b *bodyScope) member(op string, ops []*ast.Term) bool {
	if op != ast.Member.Name && op != ast.MemberWithKey.Name {
		return false
	}
	last := len(ops) - 1
	if ref, isRef := ops[last].Value.(ast.Ref); !isRef || !ref.Equal(inputDocumentPath) {
		return false
	}
	if b.nested > 0 {
		b.ok = false
		return true
	}
	for _, t := range ops[:last] {
		if len(t.Vars().Intersect(b.seen)) > 0 {
			b.ok = false
			return true
		}
	}
	b.loops++
	if v, isVar := ops[0].Value.(ast.Var); isVar && last == 2 {
		b.docIndex.Add(v)
	}
	for _, t := range ops[:last] {
		b.seen.Update(t.Vars())
	}
	return true
}

func (b *bodyScope) documentRef(ref ast.Ref) bool {
	if readsArguments(ref) {
		return true
	}
	if len(ref) < 3 || !ref[1].Equal(ast.StringTerm("document")) {
		return false
	}
	v, isVar := ref[2].Value.(ast.Var)
	switch {
	case isVar && b.docIndex.Contains(v):
		return true
	case isVar && !b.seen.Contains(v) && b.nested == 0:
		b.loops++
		b.docIndex.Add(v)
		b.seen.Add(v)
		return true
	}
	return false
}

// readsArguments reports whether ref reads input.arguments, the rule
// arguments every evaluation of a rule is given unchanged.
func readsArguments(ref ast.Ref) bool {
	return len(ref) >= 2 && ref[0].Equal(ast.InputRootDocument) && ref[1].Equal(ast.StringTerm("arguments"))
}

// dataReadsInput reports whether any rule ref may evaluate reads input,
// directly or through the rules and functions it reaches.
func (s *documentScope) dataReadsInput(ref ast.Ref) bool {
	rules := s.compiler.GetRules(ref.ConstantPrefix())
	if len(rules) == 0 {
		rules = s.compiler.GetRulesExact(ref)
	}
	for _, rule := range rules {
		if s.ruleReadsInput(rule) {
			return true
		}
	}
	return false
}

func (s *documentScope) ruleReadsInput(rule *ast.Rule) bool {
	key := rule.Location.String() + rule.Head.Ref().String()
	if found, done := s.reads[key]; done {
		return found
	}
	s.reads[key] = false
	found := false
	vis := ast.NewGenericVisitor(func(x any) bool {
		if found {
			return true
		}
		switch t := x.(type) {
		case *ast.Expr:
			found = len(t.With) > 0
		case ast.Ref:
			found = (t[0].Equal(ast.InputRootDocument) && !readsArguments(t)) ||
				(t.HasPrefix(ast.DefaultRootRef) && s.dataReadsInput(t))
		}
		return found
	})
	for r := rule; r != nil && !found; r = r.Else {
		vis.Walk(r.Head)
		vis.Walk(r.Body)
	}
	s.reads[key] = found
	return found
}
