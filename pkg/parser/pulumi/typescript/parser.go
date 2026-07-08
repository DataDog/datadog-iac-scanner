/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package typescript implements a static Pulumi-TypeScript/JavaScript parser.
//
// It walks the TypeScript AST to extract resource constructor calls of the form:
//
//	const bucket = new aws.s3.BucketV2("my-bucket", { acl: "public-read" });
//
// and produces a model.Document matching the Pulumi YAML schema.
package typescript

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_typescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	pulumi "github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi"
)

var lang = sitter.NewLanguage(tree_sitter_typescript.LanguageTypescript())

// Parser implements parser.kindParser for Pulumi TypeScript programs.
type Parser struct{}

func (p *Parser) GetKind() model.FileKind        { return model.KindPulumiTypeScript }
func (p *Parser) GetCommentToken() string         { return "//" }
func (p *Parser) SupportedExtensions() []string   { return []string{".ts"} }
func (p *Parser) SupportedTypes() map[string]bool { return map[string]bool{"pulumi": true} }

func (p *Parser) StringifyContent(content []byte) (string, error) {
	return string(content), nil
}

func (p *Parser) Parse(
	ctx context.Context,
	fileContent []byte,
	filename string,
	ignoreComments bool, startLine int,
) ([]byte, []model.Document, []int, map[string]model.ResolvedFile, error) {
	return ParseWithLanguage(ctx, lang, "pulumi typescript parser", fileContent, filename)
}

// ParseWithLanguage is the shared implementation used by both the TypeScript
// and JavaScript parsers.
func ParseWithLanguage(
	ctx context.Context,
	language *sitter.Language,
	parserLabel string,
	fileContent []byte,
	filename string,
) ([]byte, []model.Document, []int, map[string]model.ResolvedFile, error) {
	p := sitter.NewParser()
	defer p.Close()
	if err := p.SetLanguage(language); err != nil {
		return fileContent, nil, nil, nil, fmt.Errorf("%s: set language: %w", parserLabel, err)
	}

	tree := p.Parse(fileContent, nil)
	if tree == nil {
		return fileContent, nil, nil, nil, fmt.Errorf("%s: failed to parse file", parserLabel)
	}
	defer tree.Close()

	root := tree.RootNode()

	aliases := buildImportAliases(root, fileContent)
	if len(aliases) == 0 {
		return fileContent, nil, nil, nil, nil
	}

	localVars := buildLocalVars(root, fileContent)

	// Merge symbols from relative imports (cross-file analysis).
	if idx := pulumi.ProjectIndexFromContext(ctx); idx != nil {
		for k, v := range buildCrossFileVars(root, fileContent, filename, idx) {
			localVars[k] = v
		}
	}

	resources := extractResources(root, fileContent, aliases, localVars)
	if len(resources) == 0 {
		return fileContent, nil, nil, nil, nil
	}

	resourcesMap := map[string]interface{}{}
	resourcesDDLines := map[string]int{}
	for name, r := range resources {
		resourcesMap[name] = r.toMap()
		resourcesDDLines[name] = r.line
	}
	resourcesMap["_dd_lines"] = pulumi.BuildDDLines(0, resourcesDDLines)

	doc := model.Document{
		"runtime":   "nodejs",
		"resources": resourcesMap,
		"_dd_lines": pulumi.BuildDDLines(0, map[string]int{"resources": 0}),
	}

	return fileContent, []model.Document{doc}, nil, nil, nil
}

// ── import alias resolution ──────────────────────────────────────────────────

type aliasEntry struct {
	provider string
	module   string // non-empty for named imports like `import { s3 } from "@pulumi/aws"`
}

func buildImportAliases(root *sitter.Node, src []byte) map[string]aliasEntry {
	aliases := map[string]aliasEntry{}

	cursor := root.Walk()
	defer cursor.Close()

	var walk func()
	walk = func() {
		node := cursor.Node()
		switch node.Kind() {
		case "import_statement":
			handleImport(node, src, aliases)
		case "variable_declarator":
			handleRequire(node, src, aliases)
		}
		if cursor.GotoFirstChild() {
			for {
				walk()
				if !cursor.GotoNextSibling() {
					break
				}
			}
			cursor.GotoParent()
		}
	}
	walk()
	return aliases
}

// handleImport processes TypeScript import statements.
//
//	import * as aws from "@pulumi/aws"       → aliases["aws"] = {provider:"aws"}
//	import { s3 } from "@pulumi/aws"         → aliases["s3"] = {provider:"aws", module:"s3"}
//	import { s3 as s3mod } from "@pulumi/aws"→ aliases["s3mod"] = {provider:"aws", module:"s3"}
func handleImport(node *sitter.Node, src []byte, out map[string]aliasEntry) {
	// Find the source string: the last string_fragment child gives the module path.
	pkg := importSource(node, src)
	if pkg == "" {
		return
	}
	provider, ok := pulumi.NpmPkgToProvider(pkg)
	if !ok {
		return
	}

	// Find the import clause.
	clause := firstChildByKind(node, "import_clause")
	if clause == nil {
		return
	}

	// namespace import: * as aws
	if ns := firstChildByKind(clause, "namespace_import"); ns != nil {
		alias := identifierText(ns, src)
		if alias != "" {
			out[alias] = aliasEntry{provider: provider}
		}
		return
	}

	// named imports: { s3, ec2 as ec2mod }
	if named := firstChildByKind(clause, "named_imports"); named != nil {
		for i := uint(0); i < named.NamedChildCount(); i++ {
			spec := named.NamedChild(i)
			if spec == nil || spec.Kind() != "import_specifier" {
				continue
			}
			// name: what it is in the module; alias: local name (may differ)
			nameNode := spec.ChildByFieldName("name")
			aliasNode := spec.ChildByFieldName("alias")
			if nameNode == nil {
				continue
			}
			originalName := nameNode.Utf8Text(src)
			localName := originalName
			if aliasNode != nil {
				localName = aliasNode.Utf8Text(src)
			}
			out[localName] = aliasEntry{provider: provider, module: originalName}
		}
		return
	}

	// default import: import aws from "@pulumi/aws"  (uncommon for Pulumi)
	if id := firstChildByKind(clause, "identifier"); id != nil {
		alias := id.Utf8Text(src)
		out[alias] = aliasEntry{provider: provider}
	}
}

// handleRequire processes CommonJS require() assignments:
//
//	const aws = require("@pulumi/aws")         → aliases["aws"] = {provider:"aws"}
//	const { s3, ec2 } = require("@pulumi/aws") → aliases["s3"]={…}, aliases["ec2"]={…}
func handleRequire(node *sitter.Node, src []byte, out map[string]aliasEntry) {
	valueNode := node.ChildByFieldName("value")
	if valueNode == nil || valueNode.Kind() != "call_expression" {
		return
	}
	// The call must be `require("@pulumi/…")`.
	fn := valueNode.ChildByFieldName("function")
	if fn == nil || fn.Utf8Text(src) != "require" {
		return
	}
	args := valueNode.ChildByFieldName("arguments")
	if args == nil {
		return
	}
	pkg := ""
	for i := uint(0); i < args.NamedChildCount(); i++ {
		child := args.NamedChild(i)
		if child != nil && child.Kind() == "string" {
			pkg = strings.Trim(child.Utf8Text(src), `"'`)
			break
		}
	}
	provider, ok := pulumi.NpmPkgToProvider(pkg)
	if !ok {
		return
	}

	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	switch nameNode.Kind() {
	case "identifier":
		// const aws = require("@pulumi/aws")
		out[nameNode.Utf8Text(src)] = aliasEntry{provider: provider}
	case "object_pattern":
		// const { s3, ec2 as myEc2 } = require("@pulumi/aws")
		for i := uint(0); i < nameNode.NamedChildCount(); i++ {
			spec := nameNode.NamedChild(i)
			if spec == nil {
				continue
			}
			switch spec.Kind() {
			case "shorthand_property_identifier_pattern":
				name := spec.Utf8Text(src)
				out[name] = aliasEntry{provider: provider, module: name}
			case "pair_pattern":
				keyNode := spec.ChildByFieldName("key")
				valNode := spec.ChildByFieldName("value")
				if keyNode != nil && valNode != nil {
					out[valNode.Utf8Text(src)] = aliasEntry{provider: provider, module: keyNode.Utf8Text(src)}
				}
			}
		}
	}
}

func importSource(node *sitter.Node, src []byte) string {
	// The module specifier is a string literal at the end of the import.
	for i := int(node.ChildCount()) - 1; i >= 0; i-- {
		child := node.Child(uint(i))
		if child == nil {
			continue
		}
		if child.Kind() == "string" {
			// Strip quotes.
			return strings.Trim(child.Utf8Text(src), `"'`)
		}
	}
	return ""
}

// ── local variable resolution ────────────────────────────────────────────────

func buildLocalVars(root *sitter.Node, src []byte) map[string]interface{} {
	vars := map[string]interface{}{}

	cursor := root.Walk()
	defer cursor.Close()

	var walk func()
	walk = func() {
		node := cursor.Node()
		// const/let/var x = <literal>  or  x = config.get*(…) ?? default
		if node.Kind() == "variable_declarator" {
			nameNode := node.ChildByFieldName("name")
			valueNode := node.ChildByFieldName("value")
			if nameNode != nil && valueNode != nil && nameNode.Kind() == "identifier" {
				name := nameNode.Utf8Text(src)
				if val, ok := extractLiteral(valueNode, src, nil); ok {
					vars[name] = val
				} else if val, ok := extractConfigDefault(valueNode, src); ok {
					vars[name] = val
				}
			}
		}
		// function foo() { return "literal"; } — index the return value.
		if node.Kind() == "function_declaration" {
			nameNode := node.ChildByFieldName("name")
			if nameNode != nil && nameNode.Kind() == "identifier" {
				if v, ok := extractFnBodyLiteral(node, src, nil); ok {
					vars[nameNode.Utf8Text(src)] = v
				}
			}
		}
		if cursor.GotoFirstChild() {
			for {
				walk()
				if !cursor.GotoNextSibling() {
					break
				}
			}
			cursor.GotoParent()
		}
	}
	walk()
	return vars
}

// extractFnBodyLiteral returns the single literal value returned by a zero-arg
// arrow_function, function expression, or function_declaration node, enabling
// calls like getDefaultAcl() to be inlined into property values.
func extractFnBodyLiteral(node *sitter.Node, src []byte, localVars map[string]interface{}) (interface{}, bool) {
	body := node.ChildByFieldName("body")
	if body == nil {
		return nil, false
	}
	// Concise arrow body: () => "val"
	if body.Kind() != "statement_block" {
		return extractLiteral(body, src, localVars)
	}
	// Block body: find first (or only) return_statement.
	for i := uint(0); i < body.NamedChildCount(); i++ {
		stmt := body.NamedChild(i)
		if stmt == nil || stmt.Kind() != "return_statement" {
			continue
		}
		// return_statement has one named child: the return value.
		if stmt.NamedChildCount() > 0 {
			return extractLiteral(stmt.NamedChild(0), src, localVars)
		}
	}
	return nil, false
}

// buildCrossFileVars resolves relative imports against the ProjectIndex and
// returns a variable map that is merged into the file's local variable table.
//
// Supported import forms:
//
//	import { x, y as z } from "./config"   → vars["x"]=symbols["x"], vars["z"]=symbols["y"]
//	import * as cfg      from "./config"   → vars["cfg"]=symbols (whole map)
//	const cfg            = require("./c")  → vars["cfg"]=symbols
//	const { x }          = require("./c")  → vars["x"]=symbols["x"]
func buildCrossFileVars(root *sitter.Node, src []byte, filename string, idx *pulumi.ProjectIndex) map[string]interface{} {
	out := map[string]interface{}{}
	cursor := root.Walk()
	defer cursor.Close()

	var walk func()
	walk = func() {
		node := cursor.Node()
		switch node.Kind() {
		case "import_statement":
			handleLocalImport(node, src, filename, idx, out)
		case "variable_declarator":
			handleLocalRequire(node, src, filename, idx, out)
		}
		if cursor.GotoFirstChild() {
			for {
				walk()
				if !cursor.GotoNextSibling() {
					break
				}
			}
			cursor.GotoParent()
		}
	}
	walk()
	return out
}

func handleLocalImport(node *sitter.Node, src []byte, filename string, idx *pulumi.ProjectIndex, out map[string]interface{}) {
	pkg := importSource(node, src)
	if !strings.HasPrefix(pkg, ".") {
		return // external (Pulumi SDK etc.) — handled by buildImportAliases
	}
	syms := resolveModule(filename, pkg, idx)
	if syms == nil {
		return
	}

	clause := firstChildByKind(node, "import_clause")
	if clause == nil {
		return
	}

	if ns := firstChildByKind(clause, "namespace_import"); ns != nil {
		alias := identifierText(ns, src)
		if alias != "" {
			out[alias] = syms.Values
		}
		return
	}

	if named := firstChildByKind(clause, "named_imports"); named != nil {
		for i := uint(0); i < named.NamedChildCount(); i++ {
			spec := named.NamedChild(i)
			if spec == nil || spec.Kind() != "import_specifier" {
				continue
			}
			nameNode := spec.ChildByFieldName("name")
			aliasNode := spec.ChildByFieldName("alias")
			if nameNode == nil {
				continue
			}
			exportedName := nameNode.Utf8Text(src)
			localName := exportedName
			if aliasNode != nil {
				localName = aliasNode.Utf8Text(src)
			}
			if v, ok := syms.Values[exportedName]; ok {
				out[localName] = v
			}
		}
		return
	}

	// Default import: `import cfg from "./config"` — resolve the "default" export
	// if present, otherwise fall back to the whole symbols map.
	if id := firstChildByKind(clause, "identifier"); id != nil {
		name := id.Utf8Text(src)
		if defaultVal, ok := syms.Values["default"]; ok {
			out[name] = defaultVal
		} else {
			out[name] = syms.Values
		}
	}
}

func handleLocalRequire(node *sitter.Node, src []byte, filename string, idx *pulumi.ProjectIndex, out map[string]interface{}) {
	valueNode := node.ChildByFieldName("value")
	if valueNode == nil || valueNode.Kind() != "call_expression" {
		return
	}
	fn := valueNode.ChildByFieldName("function")
	if fn == nil || fn.Utf8Text(src) != "require" {
		return
	}
	args := valueNode.ChildByFieldName("arguments")
	if args == nil {
		return
	}
	pkg := ""
	for i := uint(0); i < args.NamedChildCount(); i++ {
		child := args.NamedChild(i)
		if child != nil && child.Kind() == "string" {
			pkg = strings.Trim(child.Utf8Text(src), `"'`)
			break
		}
	}
	if !strings.HasPrefix(pkg, ".") {
		return
	}
	syms := resolveModule(filename, pkg, idx)
	if syms == nil {
		return
	}

	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	switch nameNode.Kind() {
	case "identifier":
		out[nameNode.Utf8Text(src)] = syms.Values
	case "object_pattern":
		for i := uint(0); i < nameNode.NamedChildCount(); i++ {
			spec := nameNode.NamedChild(i)
			if spec == nil {
				continue
			}
			switch spec.Kind() {
			case "shorthand_property_identifier_pattern":
				name := spec.Utf8Text(src)
				if v, ok := syms.Values[name]; ok {
					out[name] = v
				}
			case "pair_pattern":
				keyNode := spec.ChildByFieldName("key")
				valNode := spec.ChildByFieldName("value")
				if keyNode != nil && valNode != nil {
					if v, ok := syms.Values[keyNode.Utf8Text(src)]; ok {
						out[valNode.Utf8Text(src)] = v
					}
				}
			}
		}
	}
}

// resolveModule resolves a relative module specifier to the matching entry in
// the ProjectIndex by trying common file extensions.
func resolveModule(currentFile, specifier string, idx *pulumi.ProjectIndex) *pulumi.FileSymbols {
	dir := filepath.ToSlash(filepath.Dir(currentFile))
	base := filepath.ToSlash(filepath.Join(dir, specifier))
	candidates := []string{
		base + ".ts",
		base + ".js",
		base + ".tsx",
		base + ".jsx",
		base, // specifier already carries an extension
		base + "/index.ts",
		base + "/index.js",
	}
	for _, c := range candidates {
		if syms := idx.Lookup(c); syms != nil {
			return syms
		}
	}
	return nil
}

// ── resource extraction ──────────────────────────────────────────────────────

type resource struct {
	typeToken  string
	line       int
	properties map[string]propValue
}

type propValue struct {
	value interface{}
	line  int
}

func (r *resource) toMap() map[string]interface{} {
	props := map[string]interface{}{}
	propsLines := map[string]int{}
	for k, pv := range r.properties {
		props[k] = pv.value
		propsLines[k] = pv.line
	}
	props["_dd_lines"] = pulumi.BuildDDLines(r.line, propsLines)

	return map[string]interface{}{
		"type":       r.typeToken,
		"properties": props,
		"_dd_lines": pulumi.BuildDDLines(r.line, map[string]int{
			"type":       r.line,
			"properties": r.line,
		}),
	}
}

func extractResources(
	root *sitter.Node,
	src []byte,
	aliases map[string]aliasEntry,
	localVars map[string]interface{},
) map[string]*resource {
	resources := map[string]*resource{}

	cursor := root.Walk()
	defer cursor.Close()

	var walk func()
	walk = func() {
		node := cursor.Node()
		// new aws.s3.BucketV2("name", { ... })
		if node.Kind() == "new_expression" {
			if r, name, ok := extractNewExpression(node, src, aliases, localVars); ok && name != "" {
				resources[name] = r
			}
		}
		if cursor.GotoFirstChild() {
			for {
				walk()
				if !cursor.GotoNextSibling() {
					break
				}
			}
			cursor.GotoParent()
		}
	}
	walk()
	return resources
}

func extractNewExpression(
	node *sitter.Node,
	src []byte,
	aliases map[string]aliasEntry,
	localVars map[string]interface{},
) (*resource, string, bool) {
	constructor := node.ChildByFieldName("constructor")
	if constructor == nil {
		return nil, "", false
	}

	chain := memberChain(constructor, src)
	if len(chain) < 2 {
		return nil, "", false
	}

	entry, ok := aliases[chain[0]]
	if !ok {
		return nil, "", false
	}

	var typeToken string
	rest := chain[1:]
	if entry.module != "" {
		segments := append(strings.Split(entry.module, "."), rest...)
		typeToken = buildTypeToken(entry.provider, segments)
	} else {
		typeToken = buildTypeToken(entry.provider, rest)
	}

	line := int(node.StartPosition().Row) + 1

	args := node.ChildByFieldName("arguments")
	if args == nil {
		return nil, "", false
	}

	logicalName, props := extractArguments(args, src, localVars)

	return &resource{
		typeToken:  typeToken,
		line:       line,
		properties: props,
	}, logicalName, true
}

func extractArguments(args *sitter.Node, src []byte, localVars map[string]interface{}) (string, map[string]propValue) {
	props := map[string]propValue{}
	var logicalName string

	positionalIdx := 0
	for i := uint(0); i < args.NamedChildCount(); i++ {
		child := args.NamedChild(i)
		if child == nil {
			continue
		}
		// Unwrap TypeScript type assertions: expr as Type
		// NamedChild(0) is always the expression; ChildByFieldName("value") is
		// unreliable in some tree-sitter-typescript Go binding versions.
		actual := child
		if child.Kind() == "as_expression" && child.NamedChildCount() > 0 {
			actual = child.NamedChild(0)
		}
		switch positionalIdx {
		case 0:
			if actual.Kind() == "string" {
				logicalName = strings.Trim(actual.Utf8Text(src), `"'`)
			} else if val, ok := resolveValue(actual, src, localVars); ok {
				if s, isStr := val.(string); isStr {
					logicalName = s
				}
			}
		case 1:
			if actual.Kind() == "object" {
				props = extractObjectProps(actual, src, localVars)
			} else if val, ok := resolveValue(actual, src, localVars); ok {
				// Identifier or member expression resolving to a props map.
				if m, ok := val.(map[string]interface{}); ok {
					propLine := int(child.StartPosition().Row) + 1
					for k, v := range m {
						if k != "_dd_lines" {
							props[k] = propValue{value: v, line: propLine}
						}
					}
				}
			}
		}
		positionalIdx++
	}
	return logicalName, props
}

func extractObjectProps(node *sitter.Node, src []byte, localVars map[string]interface{}) map[string]propValue {
	props := map[string]propValue{}
	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "pair":
			keyNode := child.ChildByFieldName("key")
			valNode := child.ChildByFieldName("value")
			if keyNode == nil || valNode == nil {
				continue
			}
			key := propertyKey(keyNode, src)
			if key == "" {
				continue
			}
			propLine := int(child.StartPosition().Row) + 1
			if val, ok := resolveValue(valNode, src, localVars); ok {
				props[key] = propValue{value: val, line: propLine}
			}
		case "shorthand_property_identifier":
			// { acl } shorthand — resolve from local vars
			name := child.Utf8Text(src)
			propLine := int(child.StartPosition().Row) + 1
			if val, ok := localVars[name]; ok {
				props[name] = propValue{value: val, line: propLine}
			}
		case "spread_element":
			// { ...defaults, acl: "public-read" } — expand if the spread target is
			// a known local variable holding a plain object.
			if child.NamedChildCount() > 0 {
				inner := child.NamedChild(0)
				if inner != nil && inner.Kind() == "identifier" {
					if val, ok := localVars[inner.Utf8Text(src)]; ok {
						if m, ok := val.(map[string]interface{}); ok {
							propLine := int(child.StartPosition().Row) + 1
							for k, v := range m {
								if _, exists := props[k]; !exists {
									props[k] = propValue{value: v, line: propLine}
								}
							}
						}
					}
				}
			}
		}
	}
	return props
}

// ── value resolution ─────────────────────────────────────────────────────────

func resolveValue(node *sitter.Node, src []byte, localVars map[string]interface{}) (interface{}, bool) {
	return extractLiteral(node, src, localVars)
}

func extractLiteral(node *sitter.Node, src []byte, localVars map[string]interface{}) (interface{}, bool) {
	if node == nil {
		return nil, false
	}
	switch node.Kind() {
	case "string":
		s := node.Utf8Text(src)
		// Strip quotes and template literal backticks.
		s = strings.Trim(s, "`\"'")
		return s, true
	case "number":
		text := node.Utf8Text(src)
		var n float64
		fmt.Sscanf(text, "%f", &n)
		return n, true
	case "true":
		return true, true
	case "false":
		return false, true
	case "null", "undefined":
		return nil, true
	case "identifier":
		name := node.Utf8Text(src)
		if localVars != nil {
			if val, ok := localVars[name]; ok {
				return val, true
			}
		}
		return nil, false
	case "object":
		return extractObject(node, src, localVars), true
	case "array":
		return extractArray(node, src, localVars), true
	case "template_string":
		// Collect string fragments.
		var parts []string
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child != nil && child.Kind() == "string_fragment" {
				parts = append(parts, child.Utf8Text(src))
			}
		}
		return strings.Join(parts, ""), true
	case "ternary_expression":
		// Try both branches.
		consequence := node.ChildByFieldName("consequence")
		if v, ok := extractLiteral(consequence, src, localVars); ok {
			return v, true
		}
		alternative := node.ChildByFieldName("alternative")
		if v, ok := extractLiteral(alternative, src, localVars); ok {
			return v, true
		}
		return nil, false
	case "member_expression":
		// Resolve cfg.key where cfg is a namespace import stored as a map.
		obj := node.ChildByFieldName("object")
		prop := node.ChildByFieldName("property")
		if obj != nil && prop != nil && localVars != nil {
			if objVal, ok := localVars[obj.Utf8Text(src)]; ok {
				if m, ok := objVal.(map[string]interface{}); ok {
					key := prop.Utf8Text(src)
					if v, exists := m[key]; exists {
						return v, true
					}
				}
			}
		}
		return nil, false
	case "as_expression":
		// expr as Type — NamedChild(0) is the expression being cast.
		if node.NamedChildCount() > 0 {
			return extractLiteral(node.NamedChild(0), src, localVars)
		}
		return nil, false
	case "type_assertion":
		// <Type>expr (older TS prefix syntax) — last named child is the expression.
		if node.NamedChildCount() > 0 {
			return extractLiteral(node.NamedChild(node.NamedChildCount()-1), src, localVars)
		}
		return nil, false
	case "binary_expression":
		// Handle `config.getBoolean("x") ?? false` — nullish coalescing.
		op := node.ChildByFieldName("operator")
		if op != nil && op.Utf8Text(src) == "??" {
			right := node.ChildByFieldName("right")
			if v, ok := extractLiteral(right, src, localVars); ok {
				return v, true
			}
		}
		return nil, false
	case "arrow_function", "function":
		// Zero-arg arrow/function expression: () => "val"  or  () => { return "val"; }
		if v, ok := extractFnBodyLiteral(node, src, localVars); ok {
			return v, true
		}
		return nil, false
	case "call_expression":
		// If the callee is a zero-arg function already indexed in localVars, use
		// its stored return value (e.g. const acl = getDefaultAcl()).
		fn := node.ChildByFieldName("function")
		if fn != nil && fn.Kind() == "identifier" && localVars != nil {
			if v, ok := localVars[fn.Utf8Text(src)]; ok {
				return v, true
			}
		}
		// Delegate to config-default extraction.
		return extractConfigDefault(node, src)
	}
	return nil, false
}

// extractConfigDefault resolves a config.get*/require* call to its nullish
// coalescing default (right side of ??) or the getter's zero value by type.
//
// Patterns handled:
//
//	config.getBoolean("key") ?? false          → false   (via binary_expression above)
//	config.get("key") ?? "us-east-1"           → "us-east-1"
//	config.requireBoolean("key")               → false (zero value)
func extractConfigDefault(node *sitter.Node, src []byte) (interface{}, bool) {
	if node == nil || node.Kind() != "call_expression" {
		return nil, false
	}
	fn := node.ChildByFieldName("function")
	if fn == nil {
		return nil, false
	}
	fnText := fn.Utf8Text(src)
	if !isConfigGetter(fnText) {
		return nil, false
	}
	zv, _ := configZeroValue(fnText)
	return zv, true
}

var tsConfigGetterSuffixes = []string{
	".getBoolean", ".getNumber", ".getSecret", ".getSecretBoolean",
	".getSecretNumber", ".getSecretObject", ".getObject",
	".get", ".requireBoolean", ".requireNumber", ".requireSecret",
	".requireSecretBoolean", ".requireObject", ".require",
}

func isConfigGetter(fnText string) bool {
	for _, s := range tsConfigGetterSuffixes {
		if strings.HasSuffix(fnText, s) {
			return true
		}
	}
	return false
}

func configZeroValue(fnText string) (interface{}, bool) {
	switch {
	case strings.Contains(fnText, "Boolean") || strings.Contains(fnText, "Bool"):
		return false, true
	case strings.Contains(fnText, "Number") || strings.Contains(fnText, "Int") || strings.Contains(fnText, "Float"):
		return 0, true
	default:
		return "", true
	}
}

func extractObject(node *sitter.Node, src []byte, localVars map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	ddLines := map[string]int{}
	line := int(node.StartPosition().Row) + 1

	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if child == nil || child.Kind() != "pair" {
			continue
		}
		keyNode := child.ChildByFieldName("key")
		valNode := child.ChildByFieldName("value")
		if keyNode == nil || valNode == nil {
			continue
		}
		key := propertyKey(keyNode, src)
		propLine := int(child.StartPosition().Row) + 1
		if val, ok := extractLiteral(valNode, src, localVars); ok {
			out[key] = val
			ddLines[key] = propLine
		}
	}
	out["_dd_lines"] = pulumi.BuildDDLines(line, ddLines)
	return out
}

func extractArray(node *sitter.Node, src []byte, localVars map[string]interface{}) []interface{} {
	var out []interface{}
	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if child == nil {
			continue
		}
		if val, ok := extractLiteral(child, src, localVars); ok {
			out = append(out, val)
		}
	}
	return out
}

// ── helpers ──────────────────────────────────────────────────────────────────

func memberChain(node *sitter.Node, src []byte) []string {
	switch node.Kind() {
	case "identifier":
		return []string{node.Utf8Text(src)}
	case "member_expression":
		obj := node.ChildByFieldName("object")
		prop := node.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return nil
		}
		return append(memberChain(obj, src), prop.Utf8Text(src))
	}
	return nil
}

func propertyKey(node *sitter.Node, src []byte) string {
	switch node.Kind() {
	case "property_identifier", "identifier":
		return node.Utf8Text(src)
	case "string":
		return strings.Trim(node.Utf8Text(src), `"'`)
	}
	return ""
}

func firstChildByKind(node *sitter.Node, kind string) *sitter.Node {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == kind {
			return child
		}
	}
	return nil
}

func identifierText(node *sitter.Node, src []byte) string {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "identifier" {
			return child.Utf8Text(src)
		}
	}
	return ""
}

func buildTypeToken(provider string, segments []string) string {
	if len(segments) == 0 {
		return provider
	}
	class := segments[len(segments)-1]
	moduleParts := segments[:len(segments)-1]
	module := strings.Join(moduleParts, "/")
	if module == "" {
		return provider + "::" + class
	}
	return provider + ":" + module + ":" + class
}
