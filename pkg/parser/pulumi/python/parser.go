/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package python implements a static Pulumi-Python parser.
//
// It walks the Python AST (via tree-sitter) to extract resource constructor
// calls of the form:
//
//	bucket = aws.s3.BucketV2("my-bucket", acl="public-read", ...)
//
// and produces a model.Document whose shape matches the Pulumi YAML schema so
// that existing Rego rules apply without modification.
package python

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_python "github.com/tree-sitter/tree-sitter-python/bindings/go"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	pulumi "github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi"
)

var lang = sitter.NewLanguage(tree_sitter_python.Language())

// Parser implements parser.kindParser for Pulumi Python programs.
type Parser struct{}

func (p *Parser) GetKind() model.FileKind       { return model.KindPulumiPython }
func (p *Parser) GetCommentToken() string        { return "#" }
func (p *Parser) SupportedExtensions() []string  { return []string{".py"} }
func (p *Parser) SupportedTypes() map[string]bool { return map[string]bool{"pulumi": true} }

func (p *Parser) StringifyContent(content []byte) (string, error) {
	return string(content), nil
}

func (p *Parser) Parse(
	ctx context.Context,
	fileContent []byte,
	filename string,
	_ bool, _ int,
) ([]byte, []model.Document, []int, map[string]model.ResolvedFile, error) {
	parser := sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(lang); err != nil {
		return fileContent, nil, nil, nil, fmt.Errorf("pulumi python parser: set language: %w", err)
	}

	tree := parser.Parse(fileContent, nil)
	if tree == nil {
		return fileContent, nil, nil, nil, fmt.Errorf("pulumi python parser: failed to parse file")
	}
	defer tree.Close()

	root := tree.RootNode()

	aliases := buildImportAliases(root, fileContent)
	if len(aliases) == 0 {
		// No Pulumi SDK imports — not a Pulumi program.
		return fileContent, nil, nil, nil, nil
	}

	localVars := buildLocalVars(root, fileContent)

	// Merge symbols from local module imports (cross-file analysis).
	if idx := pulumi.ProjectIndexFromContext(ctx); idx != nil {
		for k, v := range buildPyCrossFileVars(root, fileContent, filename, idx) {
			localVars[k] = v
		}
	}

	resources := extractResources(root, fileContent, aliases, localVars)
	if len(resources) == 0 {
		return fileContent, nil, nil, nil, nil
	}

	// Build the resources map with _dd_lines entries.
	resourcesDD := make(map[string]interface{})
	resourcesDDLines := map[string]int{}
	for name, r := range resources {
		resourcesDD[name] = r.toMap()
		resourcesDDLines[name] = r.line
	}
	resourcesMap := map[string]interface{}{}
	for k, v := range resourcesDD {
		resourcesMap[k] = v
	}
	resourcesMap["_dd_lines"] = pulumi.BuildDDLines(0, resourcesDDLines)

	doc := model.Document{
		"runtime": "python",
		"resources": resourcesMap,
		"_dd_lines": pulumi.BuildDDLines(0, map[string]int{"resources": 0}),
	}

	return fileContent, []model.Document{doc}, nil, nil, nil
}

// ── import alias resolution ──────────────────────────────────────────────────

// aliasEntry maps a local Python name to a (provider, optional module) pair.
// When module is empty the alias covers the whole provider.
type aliasEntry struct {
	provider string // e.g. "aws"
	module   string // e.g. "s3", or "" for root
}

// buildImportAliases scans all import/import-from statements and builds a map
// from local alias → aliasEntry.  Only Pulumi provider packages are recorded.
func buildImportAliases(root *sitter.Node, src []byte) map[string]aliasEntry {
	aliases := map[string]aliasEntry{}

	cursor := root.Walk()
	defer cursor.Close()

	var walk func()
	walk = func() {
		node := cursor.Node()
		switch node.Kind() {
		case "import_statement":
			// import pulumi_aws as aws
			// import pulumi_aws
			handleImportStatement(node, src, aliases)
		case "import_from_statement":
			// from pulumi_aws import s3
			// from pulumi_aws.s3 import BucketV2
			handleImportFrom(node, src, aliases)
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

func handleImportStatement(node *sitter.Node, src []byte, out map[string]aliasEntry) {
	// children: "import" name [("as" alias) …]
	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "dotted_name":
			pkgName := child.Utf8Text(src)
			provider, ok := pulumi.PythonPkgToProvider(pkgName)
			if !ok {
				continue
			}
			// No alias: register under the raw package name.
			out[pkgName] = aliasEntry{provider: provider}
		case "aliased_import":
			// aliased_import: dotted_name AS identifier
			namePart := namedChildByKind(child, "dotted_name", src)
			aliasPart := namedChildByKind(child, "identifier", src)
			if namePart == "" || aliasPart == "" {
				continue
			}
			provider, ok := pulumi.PythonPkgToProvider(namePart)
			if !ok {
				continue
			}
			out[aliasPart] = aliasEntry{provider: provider}
		}
	}
}

func handleImportFrom(node *sitter.Node, src []byte, out map[string]aliasEntry) {
	// from <module> import <name> [as <alias>] [, ...]
	// The first dotted_name child is the module.
	var fromPkg string
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "dotted_name" && fromPkg == "" {
			fromPkg = child.Utf8Text(src)
			break
		}
	}
	if fromPkg == "" {
		return
	}

	// Resolve fromPkg: could be "pulumi_aws" or "pulumi_aws.s3"
	parts := strings.SplitN(fromPkg, ".", 2)
	provider, ok := pulumi.PythonPkgToProvider(parts[0])
	if !ok {
		return
	}
	parentModule := ""
	if len(parts) == 2 {
		parentModule = parts[1]
	}

	// Collect imported names/aliases.
	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "dotted_name", "identifier":
			localName := child.Utf8Text(src)
			mod := joinModule(parentModule, localName)
			out[localName] = aliasEntry{provider: provider, module: mod}
		case "aliased_import":
			namePart := namedChildByKind(child, "dotted_name", src)
			if namePart == "" {
				namePart = namedChildByKind(child, "identifier", src)
			}
			aliasPart := namedChildByKind(child, "identifier", src)
			if namePart == "" || aliasPart == "" {
				continue
			}
			mod := joinModule(parentModule, namePart)
			out[aliasPart] = aliasEntry{provider: provider, module: mod}
		}
	}
}

// ── local variable resolution ────────────────────────────────────────────────

// buildLocalVars collects top-level simple assignments:
//
//   - literal values:          acl = "public-read"
//   - config defaults:         flag = config.get_bool("x", default=False)
//   - config or-default:       flag = config.get_bool("x") or False
func buildLocalVars(root *sitter.Node, src []byte) map[string]interface{} {
	vars := map[string]interface{}{}

	cursor := root.Walk()
	defer cursor.Close()

	var walk func()
	walk = func() {
		node := cursor.Node()
		if node.Kind() == "assignment" {
			left := node.ChildByFieldName("left")
			right := node.ChildByFieldName("right")
			if left != nil && right != nil && left.Kind() == "identifier" {
				name := left.Utf8Text(src)
				// Pass vars so earlier assignments can be referenced (e.g. b = a + "x").
				if val, ok := extractLiteral(right, src, vars); ok {
					vars[name] = val
				} else if val, ok := extractConfigDefault(right, src); ok {
					vars[name] = val
				}
			}
		}
		// def get_acl(): return "private"  — index the return value.
		if node.Kind() == "function_definition" {
			nameNode := node.ChildByFieldName("name")
			if nameNode != nil {
				if v, ok := extractPyFnBodyLiteral(node, src, vars); ok {
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

// extractPyFnBodyLiteral returns the single literal value returned by a
// zero-arg function_definition node so that calls like get_acl() can be
// inlined as property values.
func extractPyFnBodyLiteral(node *sitter.Node, src []byte, localVars map[string]interface{}) (interface{}, bool) {
	body := node.ChildByFieldName("body")
	if body == nil {
		return nil, false
	}
	for i := uint(0); i < body.NamedChildCount(); i++ {
		stmt := body.NamedChild(i)
		if stmt == nil || stmt.Kind() != "return_statement" {
			continue
		}
		for j := uint(0); j < stmt.NamedChildCount(); j++ {
			child := stmt.NamedChild(j)
			if child == nil {
				continue
			}
			if v, ok := extractLiteral(child, src, localVars); ok {
				return v, true
			}
		}
	}
	return nil, false
}

// buildPyCrossFileVars resolves local module imports against the ProjectIndex.
//
// Supported forms:
//
//	from config import defaults           → vars["defaults"] = symbols["defaults"]
//	from config import DEFAULT_ACL as acl → vars["acl"] = symbols["DEFAULT_ACL"]
//	import config                         → vars["config"] = symbols (whole map)
//	from . import config                  → vars["config"] = symbols (relative package)
func buildPyCrossFileVars(root *sitter.Node, src []byte, filename string, idx *pulumi.ProjectIndex) map[string]interface{} {
	out := map[string]interface{}{}
	dir := filepath.ToSlash(filepath.Dir(filename))

	cursor := root.Walk()
	defer cursor.Close()

	var walk func()
	walk = func() {
		node := cursor.Node()
		switch node.Kind() {
		case "import_from_statement":
			resolvePyFromImport(node, src, dir, idx, out)
		case "import_statement":
			resolvePyImport(node, src, dir, idx, out)
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

func resolvePyFromImport(node *sitter.Node, src []byte, dir string, idx *pulumi.ProjectIndex, out map[string]interface{}) {
	// Extract the module name (first dotted_name or relative_import child).
	modName := ""
	isRelative := false
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "dotted_name":
			if modName == "" {
				modName = child.Utf8Text(src)
			}
		case "relative_import":
			// from . import ... or from .config import ...
			isRelative = true
			for j := uint(0); j < child.ChildCount(); j++ {
				sub := child.Child(j)
				if sub != nil && sub.Kind() == "dotted_name" {
					modName = sub.Utf8Text(src)
				}
			}
		}
	}
	if modName == "" && !isRelative {
		return
	}
	// Skip known Pulumi provider packages.
	if _, ok := pulumi.PythonPkgToProvider(modName); ok {
		return
	}

	syms := resolvePyModule(dir, modName, idx)
	if syms == nil {
		return
	}

	// Collect imported names.
	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "dotted_name", "identifier":
			name := child.Utf8Text(src)
			if name == modName {
				continue // this is the module, not an imported name
			}
			if v, ok := syms.Values[name]; ok {
				out[name] = v
			}
		case "aliased_import":
			origNode := child.ChildByFieldName("name")
			aliasNode := child.ChildByFieldName("alias")
			if origNode == nil {
				continue
			}
			orig := origNode.Utf8Text(src)
			local := orig
			if aliasNode != nil {
				local = aliasNode.Utf8Text(src)
			}
			if v, ok := syms.Values[orig]; ok {
				out[local] = v
			}
		case "wildcard_import":
			// from config import * — merge all
			for k, v := range syms.Values {
				out[k] = v
			}
		}
	}
}

func resolvePyImport(node *sitter.Node, src []byte, dir string, idx *pulumi.ProjectIndex, out map[string]interface{}) {
	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "dotted_name":
			modName := child.Utf8Text(src)
			if _, ok := pulumi.PythonPkgToProvider(modName); ok {
				continue // Pulumi SDK — handled by buildImportAliases
			}
			if syms := resolvePyModule(dir, modName, idx); syms != nil {
				out[modName] = syms.Values
			}
		case "aliased_import":
			nameNode := child.ChildByFieldName("name")
			aliasNode := child.ChildByFieldName("alias")
			if nameNode == nil {
				continue
			}
			modName := nameNode.Utf8Text(src)
			if _, ok := pulumi.PythonPkgToProvider(modName); ok {
				continue
			}
			localName := modName
			if aliasNode != nil {
				localName = aliasNode.Utf8Text(src)
			}
			if syms := resolvePyModule(dir, modName, idx); syms != nil {
				out[localName] = syms.Values
			}
		}
	}
}

// resolvePyModule looks up the ProjectIndex entry for a local Python module.
func resolvePyModule(dir, modName string, idx *pulumi.ProjectIndex) *pulumi.FileSymbols {
	// Convert dotted module path to file path: "config" → "config.py",
	// "utils.helpers" → "utils/helpers.py"
	rel := strings.ReplaceAll(modName, ".", "/")
	base := filepath.ToSlash(filepath.Join(dir, rel))
	candidates := []string{
		base + ".py",
		base + "/__init__.py",
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
		// Look for assignment: name = SomeProvider.Module.Class("logical-name", ...)
		// or bare calls (e.g. inside a function).
		if node.Kind() == "call" {
			typeToken, ok := resolveCallType(node, src, aliases)
			if ok {
				logicalName, props, line := extractCallArgs(node, src, localVars, aliases)
				if logicalName != "" {
					resources[logicalName] = &resource{
						typeToken:  typeToken,
						line:       line,
						properties: props,
					}
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
	return resources
}

// resolveCallType resolves a call node's function to a Pulumi type token.
// Returns ("", false) if not a Pulumi constructor.
func resolveCallType(node *sitter.Node, src []byte, aliases map[string]aliasEntry) (string, bool) {
	fn := node.ChildByFieldName("function")
	if fn == nil {
		return "", false
	}
	// Walk the attribute chain and collect the dotted path.
	chain := attributeChain(fn, src)
	if len(chain) == 0 {
		return "", false
	}

	entry, ok := aliases[chain[0]]
	if !ok {
		return "", false
	}

	// Direct type import: `from pulumi_aws.s3 import BucketV2` then `BucketV2(...)`
	// The chain has length 1; the alias module already encodes "s3.BucketV2".
	if len(chain) == 1 {
		if entry.module == "" {
			return "", false
		}
		return buildTypeToken(entry.provider, strings.Split(entry.module, ".")), true
	}

	// Build type token: provider + remaining chain segments joined by ":"
	// For `aws.s3.BucketV2` with alias aws→{provider:aws, module:""}:
	//   token = "aws:s3:BucketV2"
	// For `s3.BucketV2` with alias s3→{provider:aws, module:"s3"}:
	//   token = "aws:s3:BucketV2"
	rest := chain[1:] // segments after the alias
	if entry.module != "" {
		// alias already has a module baked in, e.g. from `from pulumi_aws import s3`
		// rest = ["BucketV2"]  → "aws:s3:BucketV2"
		segments := append(strings.Split(entry.module, "."), rest...)
		return buildTypeToken(entry.provider, segments), true
	}
	// alias is the root provider, rest contains module(s) + class.
	return buildTypeToken(entry.provider, rest), true
}

func buildTypeToken(provider string, segments []string) string {
	if len(segments) == 0 {
		return provider
	}
	// Last segment is the resource class name; everything before is the module.
	class := segments[len(segments)-1]
	moduleParts := segments[:len(segments)-1]
	module := strings.Join(moduleParts, "/")
	if module == "" {
		return provider + "::" + class
	}
	return provider + ":" + module + ":" + class
}

func extractCallArgs(
	node *sitter.Node,
	src []byte,
	localVars map[string]interface{},
	aliases map[string]aliasEntry,
) (logicalName string, props map[string]propValue, line int) {
	line = int(node.StartPosition().Row) + 1
	props = map[string]propValue{}

	argList := node.ChildByFieldName("arguments")
	if argList == nil {
		return "", props, line
	}

	// First positional argument is the logical resource name.
	firstPosIdx := uint(0)
	for i := uint(0); i < argList.NamedChildCount(); i++ {
		child := argList.NamedChild(i)
		if child == nil {
			continue
		}
		if child.Kind() == "keyword_argument" {
			break
		}
		// First non-keyword named child.
		if firstPosIdx == 0 {
			firstPosIdx = i
			if val, ok := resolveValue(child, src, localVars, aliases); ok {
				if s, isStr := val.(string); isStr {
					logicalName = s
				}
			}
			break
		}
	}

	// Keyword arguments → properties.
	for i := uint(0); i < argList.NamedChildCount(); i++ {
		child := argList.NamedChild(i)
		if child == nil {
			continue
		}
		propLine := int(child.StartPosition().Row) + 1
		switch child.Kind() {
		case "keyword_argument":
			nameNode := child.ChildByFieldName("name")
			valueNode := child.ChildByFieldName("value")
			if nameNode == nil || valueNode == nil {
				continue
			}
			key := pulumi.SnakeToCamel(nameNode.Utf8Text(src))
			if key == "opts" || key == "options" {
				continue // ResourceOptions — skip
			}
			if val, ok := resolveValue(valueNode, src, localVars, aliases); ok {
				props[key] = propValue{value: val, line: propLine}
			}
		case "dictionary_splat":
			// **defaults — expand if the target resolves to a known dict.
			for j := uint(0); j < child.NamedChildCount(); j++ {
				inner := child.NamedChild(j)
				if inner == nil {
					continue
				}
				if val, ok := extractLiteral(inner, src, localVars); ok {
					if m, ok := val.(map[string]interface{}); ok {
						for k, v := range m {
							if k != "_dd_lines" {
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
	return logicalName, props, line
}

// ── value resolution ─────────────────────────────────────────────────────────

// resolveValue resolves a tree-sitter node to a Go value.  It handles literals,
// local variable references, dicts, lists, booleans, and typed Args constructors.
func resolveValue(node *sitter.Node, src []byte, localVars map[string]interface{}, aliases map[string]aliasEntry) (interface{}, bool) {
	if node != nil && node.Kind() == "call" {
		// Zero-arg helper functions indexed in localVars take priority.
		if v, ok := extractLiteral(node, src, localVars); ok {
			return v, true
		}
		// Typed argument constructors like aws.ec2.InstanceRootBlockDeviceArgs(...)
		// are treated as plain dicts — extract their keyword arguments.
		m, _ := extractCallAsDict(node, src, localVars)
		return m, true
	}
	return extractLiteral(node, src, localVars)
}

// extractCallAsDict extracts keyword arguments from a call node and returns
// them as a map, enabling typed Pulumi Args constructors to be treated the
// same as dict literals for property value resolution.
func extractCallAsDict(node *sitter.Node, src []byte, localVars map[string]interface{}) (map[string]interface{}, bool) {
	argList := node.ChildByFieldName("arguments")
	if argList == nil {
		return nil, false
	}
	out := map[string]interface{}{}
	ddLines := map[string]int{}
	defLine := int(node.StartPosition().Row) + 1

	for i := uint(0); i < argList.NamedChildCount(); i++ {
		child := argList.NamedChild(i)
		if child == nil || child.Kind() != "keyword_argument" {
			continue
		}
		nameNode := child.ChildByFieldName("name")
		valueNode := child.ChildByFieldName("value")
		if nameNode == nil || valueNode == nil {
			continue
		}
		key := pulumi.SnakeToCamel(nameNode.Utf8Text(src))
		propLine := int(child.StartPosition().Row) + 1
		if val, ok := extractLiteral(valueNode, src, localVars); ok {
			out[key] = val
			ddLines[key] = propLine
		}
	}
	out["_dd_lines"] = pulumi.BuildDDLines(defLine, ddLines)
	return out, true
}

func extractLiteral(node *sitter.Node, src []byte, localVars map[string]interface{}) (interface{}, bool) {
	if node == nil {
		return nil, false
	}
	switch node.Kind() {
	case "string":
		return pyExtractString(node, src, localVars)
	case "integer":
		text := node.Utf8Text(src)
		var n int
		fmt.Sscanf(text, "%d", &n)
		return n, true
	case "float":
		text := node.Utf8Text(src)
		var f float64
		fmt.Sscanf(text, "%f", &f)
		return f, true
	case "true":
		return true, true
	case "false":
		return false, true
	case "none":
		return nil, true
	case "identifier":
		name := node.Utf8Text(src)
		if localVars != nil {
			if val, ok := localVars[name]; ok {
				return val, true
			}
		}
		return nil, false
	case "attribute":
		// Resolve obj.attr where obj is a known local variable holding a dict.
		obj := node.ChildByFieldName("object")
		attr := node.ChildByFieldName("attribute")
		if obj != nil && attr != nil && localVars != nil {
			if objVal, ok := localVars[obj.Utf8Text(src)]; ok {
				if m, ok := objVal.(map[string]interface{}); ok {
					key := attr.Utf8Text(src)
					if v, exists := m[key]; exists {
						return v, true
					}
				}
			}
		}
		return nil, false
	case "dictionary":
		return extractDict(node, src, localVars), true
	case "list":
		return extractList(node, src, localVars), true
	case "concatenated_string":
		// Best-effort: concatenate all string parts.
		var parts []string
		for i := uint(0); i < node.NamedChildCount(); i++ {
			child := node.NamedChild(i)
			if child == nil {
				continue
			}
			if v, ok := extractLiteral(child, src, localVars); ok {
				parts = append(parts, fmt.Sprintf("%v", v))
			}
		}
		return strings.Join(parts, ""), true
	case "conditional_expression":
		// Resolve whichever branch is a literal.
		body := node.ChildByFieldName("body")
		if v, ok := extractLiteral(body, src, localVars); ok {
			return v, true
		}
		alt := node.ChildByFieldName("alternative")
		if v, ok := extractLiteral(alt, src, localVars); ok {
			return v, true
		}
		return nil, false
	case "subscript":
		// DEFAULTS["key"] — resolve when DEFAULTS is a known local dict.
		obj := node.ChildByFieldName("value")
		key := node.ChildByFieldName("subscript")
		if obj != nil && key != nil && localVars != nil {
			if objVal, ok := localVars[obj.Utf8Text(src)]; ok {
				if m, ok := objVal.(map[string]interface{}); ok {
					keyStr := strings.Trim(key.Utf8Text(src), `"'`)
					if v, exists := m[keyStr]; exists {
						return v, true
					}
				}
			}
		}
		return nil, false
	case "boolean_operator":
		// `config.get_bool("x") or False` — take the right side as default.
		right := node.ChildByFieldName("right")
		if v, ok := extractLiteral(right, src, localVars); ok {
			return v, true
		}
		return nil, false
	case "binary_operator":
		// String concatenation: "prefix-" + name
		op := node.ChildByFieldName("operator")
		if op == nil || op.Utf8Text(src) != "+" {
			return nil, false
		}
		left := node.ChildByFieldName("left")
		right := node.ChildByFieldName("right")
		lv, lok := extractLiteral(left, src, localVars)
		rv, rok := extractLiteral(right, src, localVars)
		if lok && rok {
			if ls, ok := lv.(string); ok {
				if rs, ok := rv.(string); ok {
					return ls + rs, true
				}
			}
		}
		return nil, false
	case "call":
		// If the callee is a zero-arg function already in localVars, use its
		// stored return value (e.g. acl=get_default_acl()).
		fn := node.ChildByFieldName("function")
		if fn != nil && fn.Kind() == "identifier" && localVars != nil {
			if v, ok := localVars[fn.Utf8Text(src)]; ok {
				return v, true
			}
		}
		// Delegate to config-default extraction so vars set from config are usable.
		return extractConfigDefault(node, src)
	}
	return nil, false
}

// pyExtractString handles Python string nodes including regular strings,
// triple-quoted strings, and f-strings.
//
// For f-strings with interpolations, static parts are collected and dynamic
// parts resolved from localVars when possible; unresolvable interpolations
// cause the whole f-string to be skipped (returns false) to avoid storing
// misleading partial values.
func pyExtractString(node *sitter.Node, src []byte, localVars map[string]interface{}) (interface{}, bool) {
	text := node.Utf8Text(src)

	// Detect f-strings: any string starting with f/F (possibly after r/R).
	lower := strings.ToLower(text)
	isFString := strings.HasPrefix(lower, "f\"") || strings.HasPrefix(lower, "f'") ||
		strings.HasPrefix(lower, "rf\"") || strings.HasPrefix(lower, "rf'") ||
		strings.HasPrefix(lower, "fr\"") || strings.HasPrefix(lower, "fr'")

	if isFString {
		var parts []string
		hasUnresolved := false
		for i := uint(0); i < node.NamedChildCount(); i++ {
			child := node.NamedChild(i)
			if child == nil {
				continue
			}
			switch child.Kind() {
			case "string_fragment", "string_content":
				parts = append(parts, child.Utf8Text(src))
			case "interpolation":
				if child.NamedChildCount() > 0 {
					inner := child.NamedChild(0)
					if v, ok := extractLiteral(inner, src, localVars); ok {
						parts = append(parts, fmt.Sprintf("%v", v))
						continue
					}
				}
				hasUnresolved = true
			}
		}
		if hasUnresolved {
			return nil, false
		}
		return strings.Join(parts, ""), true
	}

	// Regular / raw / bytes string. Find the first quote character to skip any
	// prefix letters (r, b, u, rb, etc.) safely — this avoids accidentally
	// stripping content characters that happen to be r/b/u.
	s := text
	if idx := strings.IndexAny(s, `"'`); idx > 0 {
		s = s[idx:]
	}
	// Strip triple quotes then single/double.
	s = strings.TrimPrefix(s, `"""`)
	s = strings.TrimSuffix(s, `"""`)
	s = strings.TrimPrefix(s, `'''`)
	s = strings.TrimSuffix(s, `'''`)
	s = strings.Trim(s, `"'`)
	return s, true
}

// extractConfigDefault resolves a pulumi.Config.get_*/require_* call to its
// declared default value (keyword arg `default=`) or zero value by type, so
// that scanner rules can conservatively evaluate whether a resource property
// might be insecure even when the real value comes from the stack config.
//
// Patterns handled:
//
//	config.get_bool("key", default=False)        → False
//	config.get_int("key", default=0)             → 0
//	config.get("key", default="us-east-1")       → "us-east-1"
//	config.get_bool("key") or False              → handled in boolean_operator above
func extractConfigDefault(node *sitter.Node, src []byte) (interface{}, bool) {
	if node == nil || node.Kind() != "call" {
		return nil, false
	}
	fn := node.ChildByFieldName("function")
	if fn == nil {
		return nil, false
	}

	// Verify the callee ends in a recognised config getter: .get, .get_bool,
	// .get_int, .get_float, .get_secret, .require, etc.
	fnText := fn.Utf8Text(src)
	if !isConfigGetter(fnText) {
		return nil, false
	}

	argList := node.ChildByFieldName("arguments")
	if argList == nil {
		return configZeroValue(fnText)
	}

	// Look for a keyword argument named "default".
	for i := uint(0); i < argList.NamedChildCount(); i++ {
		child := argList.NamedChild(i)
		if child == nil || child.Kind() != "keyword_argument" {
			continue
		}
		kw := child.ChildByFieldName("name")
		val := child.ChildByFieldName("value")
		if kw != nil && kw.Utf8Text(src) == "default" && val != nil {
			if v, ok := extractLiteral(val, src, nil); ok {
				return v, true
			}
		}
	}

	return configZeroValue(fnText)
}

var configGetterSuffixes = []string{
	".get_bool", ".get_int", ".get_float", ".get_secret_bool",
	".get_secret_int", ".get_secret_float", ".get_object", ".get_secret_object",
	".get_secret", ".get", ".require_bool", ".require_int", ".require_float",
	".require_secret", ".require_object", ".require",
}

func isConfigGetter(fnText string) bool {
	for _, suffix := range configGetterSuffixes {
		if strings.HasSuffix(fnText, suffix) {
			return true
		}
	}
	return false
}

func configZeroValue(fnText string) (interface{}, bool) {
	switch {
	case strings.Contains(fnText, "_bool"):
		return false, true
	case strings.Contains(fnText, "_int"):
		return 0, true
	case strings.Contains(fnText, "_float"):
		return 0.0, true
	default:
		return "", true
	}
}

func extractDict(node *sitter.Node, src []byte, localVars map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	ddLines := map[string]int{}
	line := int(node.StartPosition().Row) + 1

	for i := uint(0); i < node.NamedChildCount(); i++ {
		pair := node.NamedChild(i)
		if pair == nil || pair.Kind() != "pair" {
			continue
		}
		keyNode := pair.ChildByFieldName("key")
		valNode := pair.ChildByFieldName("value")
		if keyNode == nil || valNode == nil {
			continue
		}
		key, _ := extractLiteral(keyNode, src, nil)
		keyStr := pulumi.SnakeToCamel(fmt.Sprintf("%v", key))
		propLine := int(pair.StartPosition().Row) + 1
		if val, ok := extractLiteral(valNode, src, localVars); ok {
			out[keyStr] = val
			ddLines[keyStr] = propLine
		}
	}
	out["_dd_lines"] = pulumi.BuildDDLines(line, ddLines)
	return out
}

func extractList(node *sitter.Node, src []byte, localVars map[string]interface{}) []interface{} {
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

// attributeChain extracts a dotted chain of names from an attribute node.
// e.g. `aws.s3.BucketV2` → ["aws", "s3", "BucketV2"]
func attributeChain(node *sitter.Node, src []byte) []string {
	switch node.Kind() {
	case "identifier":
		return []string{node.Utf8Text(src)}
	case "attribute":
		obj := node.ChildByFieldName("object")
		attr := node.ChildByFieldName("attribute")
		if obj == nil || attr == nil {
			return nil
		}
		return append(attributeChain(obj, src), attr.Utf8Text(src))
	}
	return nil
}

func namedChildByKind(node *sitter.Node, kind string, src []byte) string {
	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if child != nil && child.Kind() == kind {
			return child.Utf8Text(src)
		}
	}
	return ""
}

func joinModule(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}
