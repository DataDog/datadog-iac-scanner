/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"sort"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// A rule is evaluated against every scanned document, and nearly every rule
// only ever reads documents holding one or two resource types: a module
// instantiated per count or for_each instance adds a document per instance,
// which every rule then walks past. documentSelection works out, from a rule's
// Rego, which documents it can read anything from, so that it is evaluated
// against those alone.
//
// The selection must not change a finding, so it is derived only from what
// makes that provably so. A document is reached through input.document[v]; a
// reference that goes on to a named block, as input.document[v].resource.T or
// input.document[v].module, is undefined on a document without that block, so
// such a document can neither satisfy it nor, under not, make it fail.
// Anything else read from input.document[v] is only safe when the same body
// also requires v to reach a named block, since v then only ranges over
// selected documents. Every other use of the documents, such as counting them,
// indexing them by position, iterating them with every, or handing input to a
// function, selects every document.

// docSelector says which documents a rule reads. A document is read when it
// holds any of keys, see documentKeys.
type docSelector struct {
	all  bool
	keys map[string]bool
}

const (
	anyBlockType   = "*"
	documentsField = "document"
	opAssign       = "assign"
	opEq           = "eq"
)

// blockSections are the document fields keyed by block type.
var blockSections = map[string]bool{"resource": true, "data": true}

// everyDocumentField are the fields every document has, which select nothing.
var everyDocumentField = map[string]bool{"id": true, "file": true}

// documentKeys lists the keys a document is selected by: each of its fields,
// and each block type of its resource and data fields, as "resource.T", with
// "resource.*" for a section holding any block.
func documentKeys(doc ast.Object) []string {
	var keys []string
	_ = doc.Iter(func(k, v *ast.Term) error {
		field, ok := k.Value.(ast.String)
		if !ok {
			return nil
		}
		keys = append(keys, string(field))
		if !blockSections[string(field)] {
			return nil
		}
		blocks, ok := v.Value.(ast.Object)
		if !ok || blocks.Len() == 0 {
			return nil
		}
		keys = append(keys, string(field)+"."+anyBlockType)
		_ = blocks.Iter(func(t, _ *ast.Term) error {
			if typ, ok := t.Value.(ast.String); ok {
				keys = append(keys, string(field)+"."+string(typ))
			}
			return nil
		})
		return nil
	})
	return keys
}

// regoFunction is what one rule or function of a package reads, before the
// functions it calls are followed.
type regoFunction struct {
	all  bool
	keys map[string]bool
	// typeParams are the parameters naming the block type a reference selects
	// by, with the sections they name it in.
	typeParams map[int][]string
	calls      []regoCall
}

// regoCall is a use of another rule or function, with the string constants it
// passes.
type regoCall struct {
	name string
	args map[int]string
	// dynamicArgs are the positions given anything but a string constant.
	dynamicArgs map[int]bool
}

// regoFunctions indexes the rules and functions of a set of modules by their
// full name, as in "generic.terraform.has_target_resource".
type regoFunctions map[string][]*regoFunction

func (fs regoFunctions) addModule(mod *ast.Module) {
	pkg := packageName(mod)
	scope := moduleScope{pkg: pkg, imports: moduleImports(mod), local: map[string]bool{}, readsInput: importsInput(mod)}
	for _, rule := range mod.Rules {
		scope.local[ruleName(rule)] = true
	}
	for _, rule := range mod.Rules {
		name := pkg + "." + ruleName(rule)
		for r := rule; r != nil; r = r.Else {
			fs[name] = append(fs[name], analyzeRule(r, &scope))
		}
	}
}

// selector follows the calls of the named rules and reports what they read in
// all. A call that cannot be followed selects every document.
func (fs regoFunctions) selector(entry []string) docSelector {
	sel := docSelector{keys: map[string]bool{}}
	type visit struct {
		name string
		args string
	}
	seen := map[visit]bool{}
	var follow func(name string, args map[int]string, dynamic map[int]bool)
	follow = func(name string, args map[int]string, dynamic map[int]bool) {
		if sel.all {
			return
		}
		v := visit{name: name, args: argsKey(args)}
		if seen[v] {
			return
		}
		seen[v] = true
		defs, ok := fs.resolve(name)
		if !ok {
			// Either base data, which cannot read the documents, or a rule
			// that is not known.
			if fs.inRulePackage(name) {
				sel.all = true
			}
			return
		}
		for _, def := range defs {
			if def.all {
				sel.all = true
				return
			}
			for k := range def.keys {
				sel.keys[k] = true
			}
			for param, sections := range def.typeParams {
				typ, constant := args[param]
				if !constant || dynamic[param] {
					sel.all = true
					return
				}
				for _, section := range sections {
					sel.keys[section+"."+typ] = true
				}
			}
			for _, call := range def.calls {
				follow(call.name, call.args, call.dynamicArgs)
			}
		}
	}
	for _, name := range entry {
		follow(name, nil, nil)
	}
	if sel.all {
		sel.keys = nil
	}
	return sel
}

// resolve finds the rule a name reads from, which may be a path into the
// rule's value, as in generic.common.policy_types.aws.
func (fs regoFunctions) resolve(name string) ([]*regoFunction, bool) {
	for {
		if defs, ok := fs[name]; ok {
			return defs, true
		}
		cut := strings.LastIndexByte(name, '.')
		if cut < 0 {
			return nil, false
		}
		name = name[:cut]
	}
}

// inRulePackage reports whether name falls in, or holds, a package of rules.
func (fs regoFunctions) inRulePackage(name string) bool {
	for known := range fs {
		pkg := known[:strings.LastIndexByte(known, '.')+1]
		if strings.HasPrefix(name+".", pkg) || strings.HasPrefix(pkg, name+".") {
			return true
		}
	}
	return false
}

func argsKey(args map[int]string) string {
	if len(args) == 0 {
		return ""
	}
	parts := make([]string, 0, len(args))
	for i, a := range args {
		parts = append(parts, string(rune('0'+i))+"="+a)
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x00")
}

// querySelector derives the documents a query reads, given the functions of
// the libraries it is compiled with. A query that cannot be parsed reads every
// document.
func querySelector(content string, libraries regoFunctions) docSelector {
	mod, err := ast.ParseModuleWithOpts("query", content, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil || mod == nil {
		return docSelector{all: true}
	}
	own := make(regoFunctions, len(libraries)+len(mod.Rules))
	for name, defs := range libraries {
		own[name] = defs
	}
	pkg := packageName(mod)
	for _, rule := range mod.Rules {
		// A query's package is shared by every query; its own rules replace
		// whatever another query defined there.
		delete(own, pkg+"."+ruleName(rule))
	}
	own.addModule(mod)
	entry := make([]string, 0, len(mod.Rules))
	for _, rule := range mod.Rules {
		entry = append(entry, pkg+"."+ruleName(rule))
	}
	return own.selector(entry)
}

// libraryFunctions analyzes the rule libraries once for every query.
func libraryFunctions(modules ...*ast.Module) regoFunctions {
	out := regoFunctions{}
	for _, mod := range modules {
		if mod != nil {
			out.addModule(mod)
		}
	}
	return out
}

type moduleScope struct {
	pkg     string
	imports map[string]string
	local   map[string]bool
	// readsInput is set when the module imports from input, which its rules
	// then read under another name.
	readsInput bool
}

// ruleAnalysis carries the state of analyzing one rule definition.
type ruleAnalysis struct {
	scope  *moduleScope
	out    *regoFunction
	params map[ast.Var]int
	// aliases maps a variable bound to a document to the variable indexing it.
	aliases map[ast.Var]ast.Var
	// indexUses counts the occurrences of each variable indexing the
	// documents directly, as in input.document[i].
	indexUses map[ast.Var]int
	// fresh numbers the wildcards indexing documents, each its own variable.
	fresh int
}

func analyzeRule(rule *ast.Rule, scope *moduleScope) *regoFunction {
	if scope.readsInput {
		return &regoFunction{all: true}
	}
	a := &ruleAnalysis{
		scope:     scope,
		out:       &regoFunction{keys: map[string]bool{}, typeParams: map[int][]string{}},
		params:    map[ast.Var]int{},
		aliases:   map[ast.Var]ast.Var{},
		indexUses: map[ast.Var]int{},
	}
	for i, arg := range rule.Head.Args {
		if v, ok := arg.Value.(ast.Var); ok {
			a.params[v] = i
		} else {
			a.terms(nil, arg)
		}
	}
	a.collectAliases(rule.Body)
	constrained := a.constrainedIn(rule.Body, nil)
	a.body(rule.Body, constrained)
	head := []*ast.Term{rule.Head.Key, rule.Head.Value}
	if ref := rule.Head.Reference; len(ref) > 1 {
		head = append(head, ref[1:]...)
	}
	for _, t := range head {
		if t != nil {
			a.terms(constrained, t)
		}
	}
	a.checkIndexUses(rule)
	if a.out.all {
		a.out.keys = nil
		a.out.typeParams = nil
		a.out.calls = nil
	}
	return a.out
}

// collectAliases records the variables bound to a document anywhere in the
// rule, as by `d := input.document[i]` or `some i, d in input.document`.
//
// A variable is only taken for an alias when nothing else binds it: a name
// bound again, as in a comprehension of its own, could stand for something
// else there.
func (a *ruleAnalysis) collectAliases(body ast.Body) {
	bindings := map[ast.Var]int{}
	ast.WalkExprs(body, func(e *ast.Expr) bool {
		for _, t := range boundTerms(e) {
			if v, ok := t.Value.(ast.Var); ok && !v.IsWildcard() {
				bindings[v]++
			}
		}
		switch terms := e.Terms.(type) {
		case []*ast.Term:
			if len(terms) == 3 && (terms[0].String() == opAssign || terms[0].String() == opEq) {
				a.aliasPair(terms[1], terms[2])
				a.aliasPair(terms[2], terms[1])
			}
		case *ast.SomeDecl:
			for _, sym := range terms.Symbols {
				if call, ok := sym.Value.(ast.Call); ok {
					a.aliasMember(call)
				}
			}
		}
		return false
	})
	for v := range a.aliases {
		if _, isParam := a.params[v]; isParam || bindings[v] > 1 {
			a.out.all = true
		}
	}
}

// boundTerms are the terms an expression may bind a variable to.
func boundTerms(e *ast.Expr) []*ast.Term {
	var out []*ast.Term
	switch terms := e.Terms.(type) {
	case []*ast.Term:
		if len(terms) == 3 && (terms[0].String() == opAssign || terms[0].String() == opEq) {
			out = append(out, terms[1], terms[2])
		}
	case *ast.SomeDecl:
		for _, sym := range terms.Symbols {
			switch decl := sym.Value.(type) {
			case ast.Call:
				out = append(out, decl[1:len(decl)-1]...)
			case ast.Var:
				out = append(out, sym)
			}
		}
	case *ast.Every:
		for _, t := range []*ast.Term{terms.Key, terms.Value} {
			if t != nil {
				out = append(out, t)
			}
		}
	}
	return out
}

// aliasMember records the alias `some d in input.document` or
// `some i, d in input.document` binds.
func (a *ruleAnalysis) aliasMember(call ast.Call) {
	operands := call[1:]
	if len(operands) < 2 || !isDocumentsRef(operands[len(operands)-1]) {
		return
	}
	v, ok := operands[len(operands)-2].Value.(ast.Var)
	if !ok || v.IsWildcard() {
		return
	}
	index := a.freshVar()
	if len(operands) == 3 {
		if key, isVar := operands[0].Value.(ast.Var); isVar && !key.IsWildcard() {
			index = key
		}
	}
	a.aliases[v] = index
}

func (a *ruleAnalysis) aliasPair(target, source *ast.Term) {
	v, ok := target.Value.(ast.Var)
	if !ok || v.IsWildcard() {
		return
	}
	if index, ok := documentIndex(source); ok {
		a.aliases[v] = a.indexVar(index)
	}
}

// freshVar names a variable no rule can spell.
func (a *ruleAnalysis) freshVar() ast.Var {
	a.fresh++
	return ast.Var("document#" + strconv.Itoa(a.fresh))
}

// indexVar names the variable a document index term stands for. A position
// is not a variable, and selects every document when it is read.
func (a *ruleAnalysis) indexVar(t *ast.Term) ast.Var {
	v, ok := t.Value.(ast.Var)
	if !ok {
		a.out.all = true
		return a.freshVar()
	}
	if v.IsWildcard() {
		return a.freshVar()
	}
	return v
}

// isDocumentsRef reports whether t is input.document.
func isDocumentsRef(t *ast.Term) bool {
	ref, ok := t.Value.(ast.Ref)
	return ok && len(ref) == 2 && ref[0].Equal(ast.InputRootDocument) && ref[1].Equal(ast.StringTerm(documentsField))
}

// documentIndex returns the index term of input.document[x].
func documentIndex(t *ast.Term) (*ast.Term, bool) {
	ref, ok := t.Value.(ast.Ref)
	if !ok || len(ref) != 3 || !ref[0].Equal(ast.InputRootDocument) || !ref[1].Equal(ast.StringTerm(documentsField)) {
		return nil, false
	}
	return ref[2], true
}

// fieldKey is the key a reference into a document is selected by: a block
// type, the block type a parameter names, or a plain field.
type fieldKey struct {
	key     string
	param   int
	section string
	// rank orders keys from the most selective: a block type, any block of a
	// section, a field, a field of every document.
	rank int
}

// fieldKeyOf returns the key reading rest from a document is selected by: a
// document without it leaves the reference undefined.
func (a *ruleAnalysis) fieldKeyOf(rest ast.Ref) (fieldKey, bool) {
	if len(rest) == 0 {
		return fieldKey{}, false
	}
	field, ok := rest[0].Value.(ast.String)
	if !ok {
		return fieldKey{}, false
	}
	if !blockSections[string(field)] || len(rest) < 2 {
		rank := 2
		if everyDocumentField[string(field)] {
			rank = 3
		}
		return fieldKey{key: string(field), param: -1, rank: rank}, true
	}
	switch typ := rest[1].Value.(type) {
	case ast.String:
		return fieldKey{key: string(field) + "." + string(typ), param: -1}, true
	case ast.Var:
		if param, isParam := a.params[typ]; isParam {
			return fieldKey{param: param, section: string(field)}, true
		}
	}
	return fieldKey{key: string(field) + "." + anyBlockType, param: -1, rank: 1}, true
}

func (a *ruleAnalysis) selectKey(k fieldKey) {
	if k.param >= 0 {
		a.out.typeParams[k.param] = append(a.out.typeParams[k.param], k.section)
		return
	}
	a.out.keys[k.key] = true
}

// constrainedIn returns the document variables the body's own positive
// expressions only bind to documents holding some field, together with
// inherited. The documents holding one of those fields are selected, which is
// all such a variable can range over.
func (a *ruleAnalysis) constrainedIn(body ast.Body, inherited map[ast.Var]bool) map[ast.Var]bool {
	best := map[ast.Var]fieldKey{}
	for _, e := range body {
		if e.Negated {
			continue
		}
		a.walkOwnRefs(e, func(ref ast.Ref) {
			index, rest, ok := a.documentRef(ref)
			if !ok {
				return
			}
			v, isVar := index.Value.(ast.Var)
			if !isVar || v.IsWildcard() || inherited[v] {
				return
			}
			k, ok := a.fieldKeyOf(rest)
			if !ok {
				return
			}
			if cur, seen := best[v]; !seen || k.rank < cur.rank || (k.rank == cur.rank && k.key < cur.key) {
				best[v] = k
			}
		})
	}
	out := make(map[ast.Var]bool, len(inherited)+len(best))
	for v := range inherited {
		out[v] = true
	}
	for v, k := range best {
		a.selectKey(k)
		out[v] = true
	}
	return out
}

// walkOwnRefs visits the references of an expression outside of the
// comprehensions and every bodies it holds, which are bodies of their own.
func (a *ruleAnalysis) walkOwnRefs(e *ast.Expr, f func(ast.Ref)) {
	vis := ast.NewGenericVisitor(func(x interface{}) bool {
		switch x := x.(type) {
		case *ast.ArrayComprehension, *ast.SetComprehension, *ast.ObjectComprehension, *ast.Every:
			return true
		case ast.Ref:
			f(x)
		}
		return false
	})
	vis.Walk(e)
}

// documentRef splits a reference into a document, input.document[x] or an
// alias of one, and the path read from it.
func (a *ruleAnalysis) documentRef(ref ast.Ref) (*ast.Term, ast.Ref, bool) {
	if head, ok := ref[0].Value.(ast.Var); ok {
		if index, isAlias := a.aliases[head]; isAlias {
			return ast.VarTerm(string(index)), ref[1:], true
		}
	}
	if len(ref) < 3 || !ref[0].Equal(ast.InputRootDocument) || !ref[1].Equal(ast.StringTerm(documentsField)) {
		return nil, nil, false
	}
	return ref[2], ref[3:], true
}

// body analyzes the expressions of a body in which the variables of
// constrained only range over selected documents.
func (a *ruleAnalysis) body(body ast.Body, constrained map[ast.Var]bool) {
	for _, e := range body {
		if a.out.all {
			return
		}
		for _, w := range e.With {
			if ref, ok := w.Target.Value.(ast.Ref); ok && ref[0].Equal(ast.InputRootDocument) {
				a.out.all = true
				return
			}
			a.terms(constrained, w.Value)
		}
		switch terms := e.Terms.(type) {
		case *ast.Term:
			a.terms(constrained, terms)
		case []*ast.Term:
			a.call(constrained, terms)
		case *ast.SomeDecl:
			for _, sym := range terms.Symbols {
				if call, ok := sym.Value.(ast.Call); ok {
					a.someDecl(constrained, call)
				}
			}
		case *ast.Every:
			// Every document has to pass, so leaving any out changes the result.
			if isDocumentsRef(terms.Domain) {
				a.out.all = true
				return
			}
			a.terms(constrained, terms.Domain)
			a.body(terms.Body, a.constrainedIn(terms.Body, constrained))
		}
	}
}

// someDecl analyzes `some x in coll` and `some k, x in coll`. Iterating the
// documents binds an alias rather than using them as a value.
func (a *ruleAnalysis) someDecl(constrained map[ast.Var]bool, call ast.Call) {
	operands := call[1:]
	if len(operands) > 0 && isDocumentsRef(operands[len(operands)-1]) {
		alias, ok := operands[len(operands)-2].Value.(ast.Var)
		if !ok || alias.IsWildcard() {
			// Iterated without binding a document: a use of them all.
			a.out.all = true
			return
		}
		if len(operands) == 3 {
			if v, ok := operands[0].Value.(ast.Var); ok && !v.IsWildcard() {
				a.indexUses[v]++
			}
		}
		return
	}
	for _, t := range operands {
		a.terms(constrained, t)
	}
}

// call analyzes an expression calling an operator.
func (a *ruleAnalysis) call(constrained map[ast.Var]bool, terms []*ast.Term) {
	if len(terms) == 0 {
		return
	}
	op := terms[0].String()
	args := terms[1:]
	if (op == opAssign || op == opEq) && len(args) == 2 {
		// Binding a document to an alias is not a use of it.
		for i, t := range args {
			if v, ok := args[1-i].Value.(ast.Var); ok && !v.IsWildcard() {
				if index, isDoc := documentIndex(t); isDoc {
					a.countIndex(index)
					continue
				}
			}
			a.terms(constrained, t)
		}
		return
	}
	a.callee(terms[0], args)
	for _, t := range args {
		a.terms(constrained, t)
	}
}

// callee records a call of a rule or function.
func (a *ruleAnalysis) callee(op *ast.Term, args []*ast.Term) {
	name, ok := a.ruleNameOf(op)
	if !ok {
		return
	}
	call := regoCall{name: name, args: map[int]string{}, dynamicArgs: map[int]bool{}}
	for i, arg := range args {
		if s, ok := arg.Value.(ast.String); ok {
			call.args[i] = string(s)
		} else {
			call.dynamicArgs[i] = true
		}
	}
	a.out.calls = append(a.out.calls, call)
}

// ruleNameOf resolves a reference to the full name of what it reads, or
// reports false for builtins and variables. The name stops at the first part
// that is not a constant.
func (a *ruleAnalysis) ruleNameOf(t *ast.Term) (string, bool) {
	ref, ok := t.Value.(ast.Ref)
	if !ok {
		if v, isVar := t.Value.(ast.Var); isVar && a.scope.local[string(v)] {
			return a.scope.pkg + "." + string(v), true
		}
		return "", false
	}
	head, ok := ref[0].Value.(ast.Var)
	if !ok {
		return "", false
	}
	var parts []string
	switch {
	case ref[0].Equal(ast.DefaultRootDocument):
	case a.scope.imports[string(head)] != "":
		parts = []string{a.scope.imports[string(head)]}
	case a.scope.local[string(head)]:
		return a.scope.pkg + "." + string(head), true
	default:
		return "", false
	}
	for _, term := range ref[1:] {
		s, ok := term.Value.(ast.String)
		if !ok {
			break
		}
		parts = append(parts, string(s))
	}
	if len(parts) == 0 {
		// The whole of data.
		a.out.all = true
		return "", false
	}
	return strings.Join(parts, "."), true
}

// terms analyzes a term used as a value.
//
//nolint:gocyclo // one case per kind of term
func (a *ruleAnalysis) terms(constrained map[ast.Var]bool, t *ast.Term) {
	if a.out.all || t == nil {
		return
	}
	switch v := t.Value.(type) {
	case ast.Var:
		switch {
		case v.Equal(ast.InputRootDocument.Value):
			a.out.all = true
		case a.isAlias(v):
			// A whole document, used as a value.
			a.requireConstrained(constrained, a.aliases[v])
		case a.scope.local[string(v)]:
			// A rule of the package, or a variable of the same name: following
			// it only ever selects more.
			a.callee(t, nil)
		}
	case ast.Ref:
		a.ref(constrained, v)
	case ast.Call:
		a.call(constrained, v)
	case *ast.Array:
		v.Foreach(func(x *ast.Term) { a.terms(constrained, x) })
	case ast.Set:
		v.Foreach(func(x *ast.Term) { a.terms(constrained, x) })
	case ast.Object:
		v.Foreach(func(k, x *ast.Term) {
			a.terms(constrained, k)
			a.terms(constrained, x)
		})
	case *ast.ArrayComprehension:
		inner := a.constrainedIn(v.Body, constrained)
		a.body(v.Body, inner)
		a.terms(inner, v.Term)
	case *ast.SetComprehension:
		inner := a.constrainedIn(v.Body, constrained)
		a.body(v.Body, inner)
		a.terms(inner, v.Term)
	case *ast.ObjectComprehension:
		inner := a.constrainedIn(v.Body, constrained)
		a.body(v.Body, inner)
		a.terms(inner, v.Key)
		a.terms(inner, v.Value)
	}
}

func (a *ruleAnalysis) isAlias(v ast.Var) bool {
	_, ok := a.aliases[v]
	return ok
}

// ref analyzes a reference used as a value.
func (a *ruleAnalysis) ref(constrained map[ast.Var]bool, ref ast.Ref) {
	if ref[0].Equal(ast.InputRootDocument) {
		if len(ref) == 1 {
			a.out.all = true
			return
		}
		if !ref[1].Equal(ast.StringTerm(documentsField)) {
			if _, ok := ref[1].Value.(ast.String); !ok {
				a.out.all = true
				return
			}
			// Rule arguments and the like, not the documents.
			a.refTerms(constrained, ref[2:])
			return
		}
		if len(ref) == 2 {
			// The documents as a whole: counted, iterated, handed on.
			a.out.all = true
			return
		}
	}
	index, rest, ok := a.documentRef(ref)
	if !ok {
		if _, isRule := a.ruleNameOf(ast.NewTerm(ref)); isRule {
			a.callee(ast.NewTerm(ref), nil)
		}
		a.refTerms(constrained, ref[1:])
		return
	}
	if ref[0].Equal(ast.InputRootDocument) {
		a.countIndex(index)
	}
	a.document(constrained, index, rest)
	a.refTerms(constrained, rest)
}

// document analyzes reading rest from the document indexed by index.
func (a *ruleAnalysis) document(constrained map[ast.Var]bool, index *ast.Term, rest ast.Ref) {
	v, isVar := index.Value.(ast.Var)
	if !isVar {
		// A document picked by position: leaving any out moves the others.
		a.out.all = true
		return
	}
	if !v.IsWildcard() && constrained[v] {
		return
	}
	k, ok := a.fieldKeyOf(rest)
	if !ok {
		// The whole document, or a field picked by a variable.
		a.out.all = true
		return
	}
	a.selectKey(k)
}

// countIndex accounts for an occurrence of a document index variable.
func (a *ruleAnalysis) countIndex(index *ast.Term) {
	if v, ok := index.Value.(ast.Var); ok && !v.IsWildcard() {
		a.indexUses[v]++
	}
}

func (a *ruleAnalysis) refTerms(constrained map[ast.Var]bool, terms ast.Ref) {
	for _, t := range terms {
		if _, isVar := t.Value.(ast.Var); isVar {
			continue // a variable iterating the value, not a use of a document
		}
		a.terms(constrained, t)
	}
}

func (a *ruleAnalysis) requireConstrained(constrained map[ast.Var]bool, v ast.Var) {
	if constrained[v] {
		return
	}
	a.out.all = true
}

// checkIndexUses selects every document when a variable indexing the
// documents is used for anything but indexing them: the position of a
// document changes once others are left out.
func (a *ruleAnalysis) checkIndexUses(rule *ast.Rule) {
	if a.out.all || len(a.indexUses) == 0 {
		return
	}
	occurrences := map[ast.Var]int{}
	ast.WalkVars(rule, func(v ast.Var) bool {
		if _, ok := a.indexUses[v]; ok {
			occurrences[v]++
		}
		return false
	})
	declared := map[ast.Var]int{}
	ast.WalkExprs(rule, func(e *ast.Expr) bool {
		if some, ok := e.Terms.(*ast.SomeDecl); ok {
			for _, sym := range some.Symbols {
				if v, isVar := sym.Value.(ast.Var); isVar {
					declared[v]++
				}
			}
		}
		return false
	})
	for v, uses := range a.indexUses {
		if _, isParam := a.params[v]; isParam {
			a.out.all = true
			return
		}
		if occurrences[v] > uses+declared[v] {
			a.out.all = true
			return
		}
	}
}

// packageName is a module's package path without the leading data, as in
// "generic.common".
func packageName(mod *ast.Module) string {
	parts := make([]string, 0, len(mod.Package.Path))
	for _, term := range mod.Package.Path[1:] {
		if str, ok := term.Value.(ast.String); ok {
			parts = append(parts, string(str))
		}
	}
	return strings.Join(parts, ".")
}

func ruleName(rule *ast.Rule) string {
	if name := rule.Head.Name; name != "" {
		return string(name)
	}
	ref := rule.Head.Ref()
	if len(ref) > 0 {
		return strings.TrimPrefix(ref[0].String(), "data.")
	}
	return ""
}

// moduleImports maps the name an import is used by to the package it names.
func moduleImports(mod *ast.Module) map[string]string {
	out := make(map[string]string, len(mod.Imports))
	for _, imp := range mod.Imports {
		ref, ok := imp.Path.Value.(ast.Ref)
		if !ok || len(ref) < 2 || !ref[0].Equal(ast.DefaultRootDocument) {
			continue
		}
		parts := make([]string, 0, len(ref)-1)
		for _, term := range ref[1:] {
			str, ok := term.Value.(ast.String)
			if !ok {
				parts = nil
				break
			}
			parts = append(parts, string(str))
		}
		if len(parts) == 0 {
			continue
		}
		name := string(imp.Alias)
		if name == "" {
			name = parts[len(parts)-1]
		}
		out[name] = strings.Join(parts, ".")
	}
	return out
}

func importsInput(mod *ast.Module) bool {
	for _, imp := range mod.Imports {
		if ref, ok := imp.Path.Value.(ast.Ref); ok && ref[0].Equal(ast.InputRootDocument) {
			return true
		}
		if v, ok := imp.Path.Value.(ast.Var); ok && v.Equal(ast.InputRootDocument.Value) {
			return true
		}
	}
	return false
}
