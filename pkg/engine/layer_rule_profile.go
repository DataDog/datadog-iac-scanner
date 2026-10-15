/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// layerProfile says which top-level Terraform block types a rule can read from
// the documents it is given. The later documents of an expanded file (see
// converter.BuildLayers) differ from the first only in the blocks of the
// expanded types, so a rule that cannot read those types gives the same
// findings there, and is not evaluated against them.
//
// The profile errs towards reading more: anything the analysis cannot follow
// makes the rule read every type.
type layerProfile struct {
	// all is set when the rule may read any type.
	all bool
	// types are the resource, data and module types the rule names. A module
	// block is named "module".
	types map[string]bool
}

// reads reports whether the rule can see a difference in any of changed.
func (p *layerProfile) reads(changed map[string]bool) bool {
	if p == nil || p.all {
		return true
	}
	for t := range changed {
		if p.types[t] {
			return true
		}
	}
	return false
}

const (
	moduleBlockType = "module"
	documentSection = "document"
	resourceSection = "resource"
	// mustExist marks a use that names a library rule, which has to be known
	// for the profile to be complete.
	mustExist = "!"
)

// ruleSummary is what a single Rego rule or function reads directly, and which
// other rules it uses.
type ruleSummary struct {
	all   bool
	types map[string]bool
	// typedByName is set when the rule reads a block type held in a variable.
	// The variable is taken to hold one of the strings the rules in play spell out.
	typedByName bool
	// readsData is set when the rule reads the library's base data, which can
	// list block types.
	readsData bool
	// strings are the string constants of the rule.
	strings map[string]bool
	uses    []string
}

// regoSummaries indexes every rule of a set of modules by its full name, as in
// "generic.terraform.resource_name".
type regoSummaries map[string]*ruleSummary

// addModule adds the rules of an already parsed module.
func (s regoSummaries) addModule(mod *ast.Module) {
	pkg := packageName(mod)
	imports := moduleImports(mod)
	local := make(map[string]bool, len(mod.Rules))
	for _, rule := range mod.Rules {
		local[ruleName(rule)] = true
	}
	for _, rule := range mod.Rules {
		key := pkg + "." + ruleName(rule)
		summary := s[key]
		if summary == nil {
			summary = &ruleSummary{types: map[string]bool{}, strings: map[string]bool{}}
			s[key] = summary
		}
		for r := rule; r != nil; r = r.Else {
			summarizeRule(r, pkg, imports, local, summary)
		}
	}
}

func packageName(mod *ast.Module) string {
	parts := make([]string, 0, len(mod.Package.Path))
	for i, term := range mod.Package.Path {
		if i == 0 {
			continue // the leading "data"
		}
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

//nolint:gocyclo // one pass over the reference kinds a rule can use
func summarizeRule(
	rule *ast.Rule, pkg string, imports map[string]string, local map[string]bool, out *ruleSummary,
) {
	aliases, declarations := documentAliases(rule)
	typeVars := map[ast.Var]bool{}
	aliasHeads := map[string]int{}
	documentRefs := 0
	ast.WalkRefs(rule, func(ref ast.Ref) bool {
		head, ok := ref[0].Value.(ast.Var)
		if !ok {
			return false
		}
		switch {
		case head.Equal(ast.InputRootDocument.Value):
			if isDocumentsRef(ref) {
				documentRefs++
			} else {
				summarizeInputRef(ref, out, typeVars)
			}
		case head.Equal(ast.DefaultRootDocument.Value):
			if use, ok := dataRuleRef(ref); ok {
				out.uses = append(out.uses, use)
				if !isRulePackage(use) {
					out.readsData = true
				}
			}
		case imports[string(head)] != "":
			if len(ref) > 1 {
				if name, ok := ref[1].Value.(ast.String); ok {
					out.uses = append(out.uses, mustExist+imports[string(head)]+"."+string(name))
				}
			}
		case aliases[string(head)]:
			aliasHeads[string(head)]++
			summarizeBlockRef(ref[1:], out, typeVars)
		case local[string(head)]:
			out.uses = append(out.uses, pkg+"."+string(head))
		default:
			// A variable that may hold a document, such as a function argument.
			summarizeBlockRef(ref[1:], out, typeVars)
		}
		return false
	})
	if unconstrainedTypeVars(rule, typeVars) {
		out.all = true
	}
	// A document used as a value, rather than reached into by a reference,
	// may be searched in ways the references do not show.
	if documentRefs > declarations.refs {
		out.all = true
	}
	uses := map[string]int{}
	ast.WalkVars(rule, func(v ast.Var) bool {
		if aliases[string(v)] {
			uses[string(v)]++
		}
		// A rule used by its bare name is a variable, not a reference.
		if local[string(v)] {
			out.uses = append(out.uses, pkg+"."+string(v))
		}
		return false
	})
	for name := range aliases {
		if uses[name] > aliasHeads[name]+declarations.vars[name] {
			out.all = true
		}
	}
	ast.WalkTerms(rule, func(t *ast.Term) bool {
		if str, ok := t.Value.(ast.String); ok {
			out.strings[string(str)] = true
		}
		return false
	})
}

// aliasDeclarations counts the places a document is bound to a variable, which
// are not uses of it.
type aliasDeclarations struct {
	refs int
	vars map[string]int
}

// documentAliases finds the variables a rule binds to a scanned document, as
// in `some i in input.document` or `doc := input.document[_]`.
func documentAliases(rule *ast.Rule) (map[string]bool, aliasDeclarations) {
	aliases := map[string]bool{}
	decl := aliasDeclarations{vars: map[string]int{}}
	bind := func(target, source *ast.Term) {
		name, ok := target.Value.(ast.Var)
		ref, isRef := source.Value.(ast.Ref)
		if !ok || !isRef || !isDocumentsRef(ref) {
			return
		}
		aliases[string(name)] = true
		decl.vars[string(name)]++
		decl.refs++
	}
	forEachBinding(rule, false, bind)
	return aliases, decl
}

// isDocumentsRef reports whether ref is input.document or one of its elements.
func isDocumentsRef(ref ast.Ref) bool {
	if len(ref) < 2 || len(ref) > 3 {
		return false
	}
	name, ok := ref[1].Value.(ast.String)
	return ok && name == documentSection
}

// dataRuleRef reads a reference written out in full, as in
// data.generic.terraform.resource_name, as "generic.terraform.resource_name".
func dataRuleRef(ref ast.Ref) (string, bool) {
	parts := make([]string, 0, len(ref)-1)
	for _, term := range ref[1:] {
		str, ok := term.Value.(ast.String)
		if !ok {
			break
		}
		parts = append(parts, string(str))
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, "."), true
}

// summarizeInputRef records what a reference into the scanned documents reads:
// input.document[_].resource.<type> and its data and module variants name a
// type.
func summarizeInputRef(ref ast.Ref, out *ruleSummary, vars map[ast.Var]bool) {
	if name, ok := ref[1].Value.(ast.String); !ok || name != documentSection {
		return // rule arguments and the like, not a document
	}
	if len(ref) < minDocumentRefLen {
		out.all = true
		return
	}
	summarizeBlockRef(ref[3:], out, vars)
}

// summarizeBlockRef records what reaching into a document through rest reads.
func summarizeBlockRef(rest ast.Ref, out *ruleSummary, vars map[ast.Var]bool) {
	if len(rest) == 0 {
		return
	}
	section, ok := rest[0].Value.(ast.String)
	if !ok {
		return
	}
	switch section {
	case resourceSection, "data":
		if len(rest) < 2 {
			out.all = true
			return
		}
		switch blockType := rest[1].Value.(type) {
		case ast.String:
			out.types[string(blockType)] = true
		case ast.Var:
			out.typedByName = true
			vars[blockType] = true
		default:
			out.typedByName = true
			out.all = true
		}
	case moduleBlockType:
		out.types[moduleBlockType] = true
	}
}

// profile follows the rules the named rules use and reports what they read in
// all.
func (s regoSummaries) profile(entry []string) *layerProfile {
	p := &layerProfile{types: map[string]bool{}}
	seen := map[string]bool{}
	var visited []*ruleSummary
	typedByName, readsData := false, false
	stack := append([]string(nil), entry...)
	for len(stack) > 0 {
		key := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		required := strings.HasPrefix(key, mustExist)
		key = strings.TrimPrefix(key, mustExist)
		if seen[key] {
			continue
		}
		seen[key] = true
		summary := s[key]
		if summary == nil {
			// A library rule that is not known could read anything.
			p.all = p.all || required
			continue
		}
		p.all = p.all || summary.all
		for t := range summary.types {
			p.types[t] = true
		}
		typedByName = typedByName || summary.typedByName
		readsData = readsData || summary.readsData
		visited = append(visited, summary)
		stack = append(stack, summary.uses...)
	}
	if typedByName && readsData {
		// The base data can list the types a variable takes.
		p.all = true
	}
	if typedByName {
		for _, summary := range visited {
			for str := range summary.strings {
				p.types[str] = true
			}
		}
	}
	return p
}

// queryLayerProfile profiles a query against the libraries it can call. A query
// that cannot be parsed reads everything.
func queryLayerProfile(content string, libraries regoSummaries) *layerProfile {
	mod, err := ast.ParseModuleWithOpts("query", content, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil || mod == nil {
		return &layerProfile{all: true}
	}
	own := regoSummaries{}
	for key, summary := range libraries {
		own[key] = summary
	}
	own.addModule(mod)
	pkg := packageName(mod)
	entry := make([]string, 0, len(mod.Rules))
	for _, rule := range mod.Rules {
		entry = append(entry, pkg+"."+ruleName(rule))
	}
	return own.profile(entry)
}

// librarySummaries parses rule libraries once for profiling queries.
func librarySummaries(libraries ...string) regoSummaries {
	out := regoSummaries{}
	for _, code := range libraries {
		mod, err := ast.ParseModuleWithOpts("library", code, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil || mod == nil {
			continue
		}
		out.addModule(mod)
	}
	return out
}

// isRulePackage tells a reference to a rule, such as generic.common.valid_key,
// from one into the base data, such as common_lib.aws_resource_policy_types.
func isRulePackage(use string) bool {
	return strings.HasPrefix(use, "generic.") || strings.HasPrefix(use, "datadog.")
}

// unconstrainedTypeVars reports whether a variable that picks a block type is
// left to range over every type: it is neither a parameter of the rule nor
// bound to something other than a document by a membership or an assignment.
func unconstrainedTypeVars(rule *ast.Rule, vars map[ast.Var]bool) bool {
	if len(vars) == 0 {
		return false
	}
	params := map[ast.Var]bool{}
	for _, arg := range rule.Head.Args {
		if v, ok := arg.Value.(ast.Var); ok {
			params[v] = true
		}
	}
	constrained := map[ast.Var]bool{}
	bind := func(target, source *ast.Term) {
		v, ok := target.Value.(ast.Var)
		if !ok || !vars[v] {
			return
		}
		if ref, isRef := source.Value.(ast.Ref); isRef && ref[0].Equal(ast.InputRootDocument) {
			return
		}
		constrained[v] = true
	}
	forEachBinding(rule, true, bind)
	for v := range vars {
		if !params[v] && !constrained[v] {
			return true
		}
	}
	return false
}

// forEachBinding calls bind for every pair of terms an expression of the rule
// equates, assigns or tests for membership.
func forEachBinding(rule *ast.Rule, skipNegated bool, bind func(target, source *ast.Term)) {
	fromCall := func(call ast.Call) {
		if len(call) < 3 {
			return
		}
		switch call[0].String() {
		case "assign", "eq":
			bind(call[1], call[2])
			bind(call[2], call[1])
		case "member", "internal.member_2":
			bind(call[1], call[2])
		case "member_3", "internal.member_3":
			if len(call) > 3 {
				bind(call[2], call[3])
			}
		}
	}
	ast.WalkExprs(rule, func(e *ast.Expr) bool {
		if skipNegated && e.Negated {
			return false
		}
		switch terms := e.Terms.(type) {
		case []*ast.Term:
			fromCall(ast.Call(terms))
		case *ast.SomeDecl:
			for _, sym := range terms.Symbols {
				if call, ok := sym.Value.(ast.Call); ok {
					fromCall(call)
				}
			}
		}
		return false
	})
}

const minDocumentRefLen = 4
