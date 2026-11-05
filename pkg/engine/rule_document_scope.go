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

// terraformQueryAnalysis is what the engine derives once per Terraform
// ruleset: whether each rule may read more than one document per finding, and
// the block types each rule can read (nil when they cannot be bounded). A rule
// is document-local only when every body of its entry rule iterates
// input.document exactly once and nothing else it reaches reads input;
// anything the analysis cannot prove is cross-document. Both maps are keyed
// by the rule's index in the analyzed slice: rule names are directory base
// names and repeat across providers.
type terraformQueryAnalysis struct {
	cross   map[int]bool
	targets map[int]*ruleTargets
}

func analyzeTerraformQueries(queries []model.QueryMetadata, libraries ...string) terraformQueryAnalysis {
	out := terraformQueryAnalysis{
		cross:   make(map[int]bool, len(queries)),
		targets: make(map[int]*ruleTargets, len(queries)),
	}
	compiler, entries, err := compileForScope(queries, libraries)
	if err != nil {
		for i := range queries {
			out.cross[i] = crossDocument(&queries[i], libraries...)
		}
		return out
	}
	s := &documentScope{compiler: compiler, reads: map[string]bool{}}
	for i := range queries {
		entry, ok := entries[i]
		if !ok {
			out.cross[i] = true
			continue
		}
		rules := compiler.GetRulesExact(entry)
		out.cross[i] = !s.local(rules)
		out.targets[i] = blockTypesRead(compiler, rules)
	}
	return out
}

func crossDocument(query *model.QueryMetadata, libraries ...string) bool {
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
// by iterating input.document, and how many such iterations it has.
type bodyScope struct {
	*documentScope
	seen     ast.VarSet
	docIndex ast.VarSet
	loops    int
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
	return b.ok && b.loops == 1
}

func (b *bodyScope) visit(x any) bool {
	if !b.ok {
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
	if op != "internal.member_2" && op != "internal.member_3" {
		return false
	}
	last := len(ops) - 1
	if ref, isRef := ops[last].Value.(ast.Ref); !isRef || !ref.Equal(inputDocumentPath) {
		return false
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
	if len(ref) < 3 || !ref[1].Equal(ast.StringTerm("document")) {
		return false
	}
	v, isVar := ref[2].Value.(ast.Var)
	switch {
	case isVar && b.docIndex.Contains(v):
		return true
	case isVar && !b.seen.Contains(v):
		b.loops++
		b.docIndex.Add(v)
		b.seen.Add(v)
		return true
	}
	return false
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

// typedSections are the document sections whose blocks are keyed by type;
// the per-root type index holds their types under the same prefixes.
var typedSections = map[string]string{
	"resource":       "",
	"data":           dataTypePrefix,
	ephemeralSection: ephemeralPrefix,
}

// untypedSections hold blocks a root can have without any resource, data or
// ephemeral block, so a rule reading them cannot be bounded by type.
var untypedSections = map[string]bool{
	"module": true, "provider": true, "variable": true, "output": true,
	"locals": true, "terraform": true, "moved": true, "import": true, "check": true,
}

// blockTypesRead returns the block types the given rule bodies, and every rule
// and function they reach, can read off a document. It returns nil when that
// set is not bounded: a section indexed by a non-constant type, a section used
// whole, a section named as a plain string, an untyped section, or a walk.
func blockTypesRead(compiler *ast.Compiler, rules []*ast.Rule) *ruleTargets {
	r := &typeReads{compiler: compiler, seen: map[string]bool{}, types: map[string]bool{}}
	for _, rule := range rules {
		r.rule(rule)
	}
	if r.unbounded || len(r.types) == 0 {
		return nil
	}
	return &ruleTargets{types: r.types}
}

type typeReads struct {
	compiler  *ast.Compiler
	seen      map[string]bool
	types     map[string]bool
	unbounded bool
}

func (r *typeReads) rule(rule *ast.Rule) {
	key := rule.Location.String() + rule.Head.Ref().String()
	if r.seen[key] {
		return
	}
	r.seen[key] = true
	vis := ast.NewGenericVisitor(r.visit)
	for x := rule; x != nil && !r.unbounded; x = x.Else {
		vis.Walk(x.Head)
		vis.Walk(x.Body)
	}
}

func (r *typeReads) visit(x any) bool {
	if r.unbounded {
		return true
	}
	switch t := x.(type) {
	case *ast.Expr:
		if t.IsCall() && t.Operator().String() == "walk" {
			r.unbounded = true
		}
	case ast.Call:
		if len(t) > 0 && t[0].Value.Compare(ast.WalkBuiltin.Ref()) == 0 {
			r.unbounded = true
		}
	case ast.Ref:
		r.ref(t)
		// Section names inside the ref are handled by ref; only nested
		// expressions (index variables, calls) still need visiting.
		vis := ast.NewGenericVisitor(r.visit)
		for _, term := range t[1:] {
			if _, isString := term.Value.(ast.String); !isString {
				vis.Walk(term)
			}
		}
		return true
	case *ast.Term:
		if s, ok := t.Value.(ast.String); ok {
			if _, typed := typedSections[string(s)]; typed || untypedSections[string(s)] {
				r.unbounded = true
			}
		}
	}
	return r.unbounded
}

func (r *typeReads) ref(ref ast.Ref) {
	if ref.HasPrefix(ast.DefaultRootRef) {
		r.follow(ref)
		return
	}
	for i := 1; i < len(ref); i++ {
		s, ok := ref[i].Value.(ast.String)
		if !ok {
			continue
		}
		if untypedSections[string(s)] {
			r.unbounded = true
			return
		}
		prefix, typed := typedSections[string(s)]
		if !typed {
			continue
		}
		if i+1 == len(ref) {
			r.unbounded = true
			return
		}
		typ, ok := ref[i+1].Value.(ast.String)
		if !ok {
			r.unbounded = true
			return
		}
		r.types[prefix+string(typ)] = true
		i++
	}
}

// follow visits the rules and functions a data ref may evaluate.
func (r *typeReads) follow(ref ast.Ref) {
	rules := r.compiler.GetRules(ref.ConstantPrefix())
	if len(rules) == 0 {
		rules = r.compiler.GetRulesExact(ref)
	}
	for _, rule := range rules {
		if r.unbounded {
			return
		}
		r.rule(rule)
	}
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
			found = t[0].Equal(ast.InputRootDocument) || (t.HasPrefix(ast.DefaultRootRef) && s.dataReadsInput(t))
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
