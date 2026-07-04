/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package projectindex builds a conservative cross-file symbol index for Pulumi
// projects. It performs a lightweight AST scan of each source file looking only
// for top-level exported constants, variables, and simple zero-arg functions
// that return a literal value.  Dynamic, computed, or non-literal exports are
// silently skipped — parsers fall back to their existing single-file behaviour.
package projectindex

import (
	"fmt"
	goast "go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	tree_sitter_python "github.com/tree-sitter/tree-sitter-python/bindings/go"
	tree_sitter_typescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"

	pulumi "github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi"
)

var (
	tsLang = sitter.NewLanguage(tree_sitter_typescript.LanguageTypescript())
	jsLang = sitter.NewLanguage(tree_sitter_javascript.Language())
	pyLang = sitter.NewLanguage(tree_sitter_python.Language())
)

// Build creates a ProjectIndex from the given file list and content cache.
// Files not present in contentCache are read from disk.  Files with
// unrecognised extensions are silently skipped.
func Build(paths []string, contentCache map[string][]byte) *pulumi.ProjectIndex {
	idx := &pulumi.ProjectIndex{
		ByFile: make(map[string]*pulumi.FileSymbols, len(paths)),
	}

	// Collect Go files by directory so we can do same-package analysis.
	goDirs := map[string][]string{} // dir → []absPath

	for _, p := range paths {
		norm := filepath.ToSlash(p)
		ext := strings.ToLower(filepath.Ext(norm))
		src := content(norm, contentCache)
		if src == nil {
			continue
		}

		switch ext {
		case ".ts":
			if syms := extractTSSymbols(src, tsLang); len(syms) > 0 {
				idx.ByFile[norm] = &pulumi.FileSymbols{Values: syms}
			}
		case ".js":
			if syms := extractTSSymbols(src, jsLang); len(syms) > 0 {
				idx.ByFile[norm] = &pulumi.FileSymbols{Values: syms}
			}
		case ".py":
			if syms := extractPySymbols(src); len(syms) > 0 {
				idx.ByFile[norm] = &pulumi.FileSymbols{Values: syms}
			}
		case ".go":
			dir := filepath.ToSlash(filepath.Dir(norm))
			goDirs[dir] = append(goDirs[dir], norm)
		}
	}

	// For Go, build per-package symbol tables by parsing all files in each dir.
	for dir, goPaths := range goDirs {
		syms := extractGoPackageSymbols(dir, goPaths, contentCache)
		for _, p := range goPaths {
			norm := filepath.ToSlash(p)
			if idx.ByFile[norm] == nil {
				idx.ByFile[norm] = &pulumi.FileSymbols{Values: make(map[string]interface{})}
			}
			// Each Go file in the package shares the whole package's symbol table —
			// the parser only has one file's AST so it needs access to sibling consts.
			for k, v := range syms {
				idx.ByFile[norm].Values[k] = v
			}
		}
		_ = dir
	}

	return idx
}

// content returns the byte content for path from the cache or disk.
func content(path string, cache map[string][]byte) []byte {
	if cache != nil {
		if b, ok := cache[path]; ok {
			return b
		}
	}
	b, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		return nil
	}
	return b
}

// ── TypeScript / JavaScript ───────────────────────────────────────────────────

// extractTSSymbols extracts top-level exported symbols using the given
// tree-sitter grammar (TypeScript or JavaScript).
func extractTSSymbols(src []byte, lang *sitter.Language) map[string]interface{} {
	p := sitter.NewParser()
	defer p.Close()
	if err := p.SetLanguage(lang); err != nil {
		return nil
	}
	tree := p.Parse(src, nil)
	if tree == nil {
		return nil
	}
	defer tree.Close()

	out := map[string]interface{}{}
	root := tree.RootNode()

	cursor := root.Walk()
	defer cursor.Close()

	var walk func()
	walk = func() {
		node := cursor.Node()
		switch node.Kind() {
		case "export_statement":
			extractTSExport(node, src, out)
		case "expression_statement":
			extractModuleExports(node, src, out)
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

// extractTSExport handles:
//
//	export const NAME = <literal>
//	export const NAME = () => <literal>
//	export function NAME() { return <literal>; }
//	export default <literal>
func extractTSExport(node *sitter.Node, src []byte, out map[string]interface{}) {
	decl := node.ChildByFieldName("declaration")
	if decl == nil {
		// `export { NAME }` re-export, OR `export default expr` where the
		// field binding is unreliable. Look for a non-clause named child.
		for i := uint(0); i < node.NamedChildCount(); i++ {
			child := node.NamedChild(i)
			if child == nil {
				continue
			}
			switch child.Kind() {
			case "export_clause", "namespace_export", "from_clause":
				return // re-export — no value to extract
			default:
				if v, ok := tsValueOrArrow(child, src); ok {
					out["default"] = v
				}
				return
			}
		}
		return
	}
	switch decl.Kind() {
	case "lexical_declaration", "variable_declaration":
		for i := uint(0); i < decl.NamedChildCount(); i++ {
			vd := decl.NamedChild(i)
			if vd == nil || vd.Kind() != "variable_declarator" {
				continue
			}
			name := vd.ChildByFieldName("name")
			value := vd.ChildByFieldName("value")
			if name == nil || value == nil {
				continue
			}
			if v, ok := tsValueOrArrow(value, src); ok {
				out[name.Utf8Text(src)] = v
			}
		}
	case "function_declaration":
		name := decl.ChildByFieldName("name")
		body := decl.ChildByFieldName("body")
		if name == nil || body == nil {
			return
		}
		if v, ok := tsSingleReturnValue(body, src); ok {
			out[name.Utf8Text(src)] = v
		}
	default:
		// export default <expr> — store under the "default" key so that
		// `import x from "./mod"` can resolve it.
		if v, ok := tsLiteralValue(decl, src); ok {
			out["default"] = v
		}
	}
}

// tsValueOrArrow extracts a literal value from a node that is either a direct
// literal/object or a zero-arg arrow function returning one.
func tsValueOrArrow(node *sitter.Node, src []byte) (interface{}, bool) {
	if node.Kind() != "arrow_function" {
		return tsLiteralValue(node, src)
	}
	body := node.ChildByFieldName("body")
	if body == nil {
		return nil, false
	}
	// Expression body: () => "value"
	if body.Kind() != "statement_block" {
		return tsLiteralValue(body, src)
	}
	// Block body: () => { return "value"; }
	return tsSingleReturnValue(body, src)
}

// extractModuleExports handles:
//
//	module.exports = { key: value, ... }
//	module.exports.NAME = <literal>
func extractModuleExports(node *sitter.Node, src []byte, out map[string]interface{}) {
	if node.NamedChildCount() == 0 {
		return
	}
	expr := node.NamedChild(0)
	if expr == nil || expr.Kind() != "assignment_expression" {
		return
	}
	left := expr.ChildByFieldName("left")
	right := expr.ChildByFieldName("right")
	if left == nil || right == nil {
		return
	}
	leftText := left.Utf8Text(src)

	if leftText == "module.exports" {
		// module.exports = { k: v, ... }
		if right.Kind() == "object" {
			mergeTSObject(right, src, out)
		}
		return
	}
	// module.exports.NAME = <literal>
	if strings.HasPrefix(leftText, "module.exports.") {
		name := leftText[len("module.exports."):]
		if name != "" {
			if v, ok := tsLiteralValue(right, src); ok {
				out[name] = v
			}
		}
	}
}

func mergeTSObject(node *sitter.Node, src []byte, out map[string]interface{}) {
	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if child == nil || child.Kind() != "pair" {
			continue
		}
		k := child.ChildByFieldName("key")
		v := child.ChildByFieldName("value")
		if k == nil || v == nil {
			continue
		}
		key := strings.Trim(k.Utf8Text(src), `"'`)
		if val, ok := tsLiteralValue(v, src); ok {
			out[key] = val
		}
	}
}

// tsSingleReturnValue extracts the literal value from the last return statement
// in a function body. Any number of preceding statements is tolerated so that
// functions with logging or early setup are not excluded, as long as the final
// statement is an unconditional return of a literal expression.
func tsSingleReturnValue(body *sitter.Node, src []byte) (interface{}, bool) {
	if body.NamedChildCount() == 0 {
		return nil, false
	}
	last := body.NamedChild(body.NamedChildCount() - 1)
	if last == nil || last.Kind() != "return_statement" {
		return nil, false
	}
	if last.NamedChildCount() == 0 {
		return nil, false
	}
	return tsLiteralValue(last.NamedChild(0), src)
}

// tsLiteralValue resolves a tree-sitter node to a Go primitive/map/slice.
func tsLiteralValue(node *sitter.Node, src []byte) (interface{}, bool) {
	if node == nil {
		return nil, false
	}
	switch node.Kind() {
	case "string":
		text := node.Utf8Text(src)
		text = strings.TrimPrefix(text, "`")
		text = strings.TrimSuffix(text, "`")
		text = strings.Trim(text, `"'`)
		return text, true
	case "number":
		var n float64
		fmt.Sscanf(node.Utf8Text(src), "%f", &n)
		return n, true
	case "true":
		return true, true
	case "false":
		return false, true
	case "null", "undefined":
		return nil, true
	case "template_string":
		// Extract only the static string_fragment parts; interpolations are skipped.
		var parts []string
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child != nil && child.Kind() == "string_fragment" {
				parts = append(parts, child.Utf8Text(src))
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, ""), true
		}
		return nil, false
	case "object":
		m := map[string]interface{}{}
		for i := uint(0); i < node.NamedChildCount(); i++ {
			child := node.NamedChild(i)
			if child == nil || child.Kind() != "pair" {
				continue
			}
			k := child.ChildByFieldName("key")
			v := child.ChildByFieldName("value")
			if k == nil || v == nil {
				continue
			}
			key := strings.Trim(k.Utf8Text(src), `"'`)
			if val, ok := tsLiteralValue(v, src); ok {
				m[key] = val
			}
		}
		return m, true
	case "array":
		var arr []interface{}
		for i := uint(0); i < node.NamedChildCount(); i++ {
			child := node.NamedChild(i)
			if child == nil {
				continue
			}
			if v, ok := tsLiteralValue(child, src); ok {
				arr = append(arr, v)
			}
		}
		return arr, true
	}
	return nil, false
}

// ── Python ────────────────────────────────────────────────────────────────────

// extractPySymbols extracts module-level assignments and simple def-return functions.
func extractPySymbols(src []byte) map[string]interface{} {
	p := sitter.NewParser()
	defer p.Close()
	if err := p.SetLanguage(pyLang); err != nil {
		return nil
	}
	tree := p.Parse(src, nil)
	if tree == nil {
		return nil
	}
	defer tree.Close()

	out := map[string]interface{}{}
	root := tree.RootNode()

	// Only top-level nodes (direct children of module root).
	// In tree-sitter-python, plain assignments are wrapped in expression_statement.
	for i := uint(0); i < root.NamedChildCount(); i++ {
		node := root.NamedChild(i)
		if node == nil {
			continue
		}
		// Unwrap expression_statement → assignment.
		target := node
		if node.Kind() == "expression_statement" && node.NamedChildCount() == 1 {
			target = node.NamedChild(0)
		}
		if target == nil {
			continue
		}
		switch target.Kind() {
		case "assignment":
			left := target.ChildByFieldName("left")
			right := target.ChildByFieldName("right")
			if left == nil || right == nil || left.Kind() != "identifier" {
				continue
			}
			if v, ok := pyLiteralValue(right, src); ok {
				out[left.Utf8Text(src)] = v
			}
		case "function_definition":
			name := target.ChildByFieldName("name")
			body := target.ChildByFieldName("body")
			if name == nil || body == nil {
				continue
			}
			if v, ok := pySingleReturnValue(body, src); ok {
				out[name.Utf8Text(src)] = v
			}
		}
		// function_definition at the top level (not wrapped in expression_statement).
		if node.Kind() == "function_definition" {
			name := node.ChildByFieldName("name")
			body := node.ChildByFieldName("body")
			if name != nil && body != nil {
				if v, ok := pySingleReturnValue(body, src); ok {
					out[name.Utf8Text(src)] = v
				}
			}
		}
	}
	return out
}

// pySingleReturnValue extracts the literal value from the last return statement
// in a Python function body, tolerating any number of preceding statements.
func pySingleReturnValue(body *sitter.Node, src []byte) (interface{}, bool) {
	if body.NamedChildCount() == 0 {
		return nil, false
	}
	last := body.NamedChild(body.NamedChildCount() - 1)
	if last == nil || last.Kind() != "return_statement" {
		return nil, false
	}
	if last.NamedChildCount() == 0 {
		return nil, false
	}
	return pyLiteralValue(last.NamedChild(0), src)
}

func pyLiteralValue(node *sitter.Node, src []byte) (interface{}, bool) {
	if node == nil {
		return nil, false
	}
	switch node.Kind() {
	case "string":
		return pyIndexExtractString(node, src)
	case "binary_operator":
		// String concatenation: "a" + "b"
		op := node.ChildByFieldName("operator")
		if op != nil && op.Utf8Text(src) == "+" {
			left := node.ChildByFieldName("left")
			right := node.ChildByFieldName("right")
			lv, lok := pyLiteralValue(left, src)
			rv, rok := pyLiteralValue(right, src)
			if lok && rok {
				if ls, ok := lv.(string); ok {
					if rs, ok := rv.(string); ok {
						return ls + rs, true
					}
				}
			}
		}
		return nil, false
	case "integer":
		var n int
		fmt.Sscanf(node.Utf8Text(src), "%d", &n)
		return n, true
	case "float":
		var f float64
		fmt.Sscanf(node.Utf8Text(src), "%f", &f)
		return f, true
	case "true":
		return true, true
	case "false":
		return false, true
	case "none":
		return nil, true
	case "dictionary":
		m := map[string]interface{}{}
		for i := uint(0); i < node.NamedChildCount(); i++ {
			pair := node.NamedChild(i)
			if pair == nil || pair.Kind() != "pair" {
				continue
			}
			k := pair.ChildByFieldName("key")
			v := pair.ChildByFieldName("value")
			if k == nil || v == nil {
				continue
			}
			keyVal, ok := pyLiteralValue(k, src)
			if !ok {
				continue
			}
			key := fmt.Sprintf("%v", keyVal)
			if val, ok := pyLiteralValue(v, src); ok {
				m[key] = val
			}
		}
		return m, true
	case "list":
		var arr []interface{}
		for i := uint(0); i < node.NamedChildCount(); i++ {
			child := node.NamedChild(i)
			if v, ok := pyLiteralValue(child, src); ok {
				arr = append(arr, v)
			}
		}
		return arr, true
	}
	return nil, false
}

// pyIndexExtractString handles Python string nodes in the index (no localVars).
// f-strings without resolvable interpolations are skipped entirely to avoid
// producing misleading partial values in the symbol table.
func pyIndexExtractString(node *sitter.Node, src []byte) (interface{}, bool) {
	text := node.Utf8Text(src)
	lower := strings.ToLower(text)
	isFString := strings.HasPrefix(lower, "f\"") || strings.HasPrefix(lower, "f'") ||
		strings.HasPrefix(lower, "rf\"") || strings.HasPrefix(lower, "rf'") ||
		strings.HasPrefix(lower, "fr\"") || strings.HasPrefix(lower, "fr'")

	if isFString {
		// Without localVars we cannot resolve interpolations; skip to avoid
		// emitting partial values that could mislead security rules.
		for i := uint(0); i < node.NamedChildCount(); i++ {
			child := node.NamedChild(i)
			if child != nil && child.Kind() == "interpolation" {
				return nil, false
			}
		}
		// No interpolations — collect static fragments.
		var parts []string
		for i := uint(0); i < node.NamedChildCount(); i++ {
			child := node.NamedChild(i)
			if child != nil && (child.Kind() == "string_fragment" || child.Kind() == "string_content") {
				parts = append(parts, child.Utf8Text(src))
			}
		}
		return strings.Join(parts, ""), true
	}

	s := text
	if idx := strings.IndexAny(s, `"'`); idx > 0 {
		s = s[idx:]
	}
	s = strings.TrimPrefix(s, `"""`)
	s = strings.TrimSuffix(s, `"""`)
	s = strings.TrimPrefix(s, `'''`)
	s = strings.TrimSuffix(s, `'''`)
	s = strings.Trim(s, `"'`)
	return s, true
}

// ── Go ────────────────────────────────────────────────────────────────────────

// extractGoPackageSymbols builds a symbol table from all Go files in a directory.
// It collects package-level const/var declarations and simple zero-arg functions
// that return a single literal.
func extractGoPackageSymbols(dir string, paths []string, contentCache map[string][]byte) map[string]interface{} {
	out := map[string]interface{}{}
	fset := token.NewFileSet()

	for _, p := range paths {
		src := content(filepath.ToSlash(p), contentCache)
		if src == nil {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.FromSlash(p), src, 0)
		if err != nil && f == nil {
			continue
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *goast.GenDecl:
				if d.Tok != token.CONST && d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					vs, ok := spec.(*goast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range vs.Names {
						if i >= len(vs.Values) {
							break
						}
						// Pass out so earlier consts can be referenced (e.g. const b = a + "x").
						if v := goLiteralValue(vs.Values[i], out); v != nil {
							out[name.Name] = v
						}
					}
				}
			case *goast.FuncDecl:
				if d.Name == nil || d.Body == nil {
					continue
				}
				// Only zero-arg functions.
				if d.Type.Params != nil && d.Type.Params.NumFields() > 0 {
					continue
				}
				if v := goSingleReturnValue(d.Body); v != nil {
					out[d.Name.Name] = v
				}
			}
		}
	}
	return out
}

// goSingleReturnValue extracts a literal from the last return statement in body.
// Accepts any number of preceding statements. Handles both single-result and
// two-result (value, nil) returns common in Go Pulumi helpers.
func goSingleReturnValue(body *goast.BlockStmt) interface{} {
	if body == nil || len(body.List) == 0 {
		return nil
	}
	ret, ok := body.List[len(body.List)-1].(*goast.ReturnStmt)
	if !ok {
		return nil
	}
	switch len(ret.Results) {
	case 1:
		return goLiteralValue(ret.Results[0], nil)
	case 2:
		// Accept (value, nil) — the (*TypeArgs, error) pattern.
		if ident, ok := ret.Results[1].(*goast.Ident); ok && ident.Name == "nil" {
			return goLiteralValue(ret.Results[0], nil)
		}
	}
	return nil
}

// goLiteralValue resolves a Go AST expression to a primitive value.
// syms is an optional symbol map used to resolve identifier references
// (e.g. constants defined earlier in the same package).
func goLiteralValue(expr goast.Expr, syms ...map[string]interface{}) interface{} {
	var s map[string]interface{}
	if len(syms) > 0 {
		s = syms[0]
	}
	return goLiteralValueCtx(expr, s)
}

func goLiteralValueCtx(expr goast.Expr, syms map[string]interface{}) interface{} {
	switch e := expr.(type) {
	case *goast.BasicLit:
		switch e.Kind {
		case token.STRING:
			s := e.Value
			s = strings.TrimPrefix(s, "`")
			s = strings.TrimSuffix(s, "`")
			s = strings.Trim(s, `"`)
			return s
		case token.INT:
			var n int
			fmt.Sscanf(e.Value, "%d", &n)
			return n
		case token.FLOAT:
			var f float64
			fmt.Sscanf(e.Value, "%f", &f)
			return f
		}
	case *goast.Ident:
		switch e.Name {
		case "true":
			return true
		case "false":
			return false
		case "nil":
			return nil
		}
		if syms != nil {
			if v, ok := syms[e.Name]; ok {
				return v
			}
		}
	case *goast.CompositeLit:
		// Determine whether this is a map/struct literal (KV pairs) or a
		// slice/array literal (positional elements).
		hasKV := false
		for _, elt := range e.Elts {
			if _, ok := elt.(*goast.KeyValueExpr); ok {
				hasKV = true
				break
			}
		}
		if !hasKV {
			var arr []interface{}
			for _, elt := range e.Elts {
				if v := goLiteralValueCtx(elt, syms); v != nil {
					arr = append(arr, v)
				}
			}
			return arr
		}
		m := map[string]interface{}{}
		for _, elt := range e.Elts {
			kv, ok := elt.(*goast.KeyValueExpr)
			if !ok {
				continue
			}
			// Keys can be Ident (struct literals) or BasicLit string (map literals).
			key := ""
			switch k := kv.Key.(type) {
			case *goast.Ident:
				key = k.Name
			case *goast.BasicLit:
				if k.Kind == token.STRING {
					key = strings.Trim(k.Value, `"`)
				}
			}
			if key == "" {
				continue
			}
			if v := goLiteralValueCtx(kv.Value, syms); v != nil {
				m[key] = v
			}
		}
		return m
	case *goast.BinaryExpr:
		// String concatenation: "prefix-" + "suffix" or const1 + const2
		if e.Op == token.ADD {
			left := goLiteralValueCtx(e.X, syms)
			right := goLiteralValueCtx(e.Y, syms)
			if ls, ok := left.(string); ok {
				if rs, ok := right.(string); ok {
					return ls + rs
				}
			}
		}
	case *goast.CallExpr:
		// Unwrap single-arg Pulumi input wrappers: pulumi.String("x"), pulumi.Bool(true), etc.
		if len(e.Args) == 1 {
			return goLiteralValueCtx(e.Args[0], syms)
		}
	case *goast.UnaryExpr:
		return goLiteralValueCtx(e.X, syms)
	}
	return nil
}
