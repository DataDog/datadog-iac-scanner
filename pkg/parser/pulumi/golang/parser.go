/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package golang implements a static Pulumi-Go parser using the standard
// go/ast library.
//
// It extracts resource constructor calls of the form:
//
//	bucket, _ := s3.NewBucketV2(ctx, "my-bucket", &s3.BucketV2Args{
//	    Acl: pulumi.String("public-read"),
//	})
//
// and produces a model.Document matching the Pulumi YAML schema.
package golang

import (
	"context"
	"fmt"
	goast "go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	pulumi "github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi"
)

// Parser implements parser.kindParser for Pulumi Go programs.
type Parser struct{}

func (p *Parser) GetKind() model.FileKind        { return model.KindPulumiGo }
func (p *Parser) GetCommentToken() string         { return "//" }
func (p *Parser) SupportedExtensions() []string   { return []string{".go"} }
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
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, fileContent, 0)
	if err != nil {
		// Tolerate partial parse errors; go/parser still returns what it could.
		if f == nil {
			return fileContent, nil, nil, nil, nil
		}
	}

	pkgInfos := buildImportMap(f)
	if len(pkgInfos) == 0 {
		return fileContent, nil, nil, nil, nil
	}

	// Load package-level symbols from sibling files via the project index.
	var pkgSyms map[string]interface{}
	if idx := pulumi.ProjectIndexFromContext(ctx); idx != nil {
		if syms := idx.Lookup(filepath.ToSlash(filename)); syms != nil {
			pkgSyms = syms.Values
		}
	}

	resources := extractResources(f, fset, pkgInfos, pkgSyms)
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
		"runtime":   "go",
		"resources": resourcesMap,
		"_dd_lines": pulumi.BuildDDLines(0, map[string]int{"resources": 0}),
	}

	return fileContent, []model.Document{doc}, nil, nil, nil
}

// ── import resolution ────────────────────────────────────────────────────────

// pkgInfo holds the resolved provider and module for a Go import.
type pkgInfo struct {
	provider string // e.g. "aws"
	module   string // e.g. "s3"
	localPkg string // local package alias used in the file
}

// buildImportMap scans import declarations and returns a map from local package
// name → pkgInfo for Pulumi provider imports.
func buildImportMap(f *goast.File) map[string]*pkgInfo {
	out := map[string]*pkgInfo{}
	for _, imp := range f.Imports {
		if imp.Path == nil {
			continue
		}
		importPath := strings.Trim(imp.Path.Value, `"`)

		provider, module := pulumi.GoImportToProviderModule(importPath)
		if provider == "" {
			continue
		}

		// Determine the local package name used in the file.
		localName := module
		if imp.Name != nil && imp.Name.Name != "_" && imp.Name.Name != "." {
			localName = imp.Name.Name
		}

		out[localName] = &pkgInfo{
			provider: provider,
			module:   module,
			localPkg: localName,
		}
	}
	return out
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

func extractResources(f *goast.File, fset *token.FileSet, pkgInfos map[string]*pkgInfo, pkgSyms map[string]interface{}) map[string]*resource {
	resources := map[string]*resource{}

	goast.Inspect(f, func(n goast.Node) bool {
		callExpr, ok := n.(*goast.CallExpr)
		if !ok {
			return true
		}

		// Looking for pkg.NewTypeName(ctx, "name", &pkg.TypeNameArgs{...})
		sel, ok := callExpr.Fun.(*goast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*goast.Ident)
		if !ok {
			return true
		}

		localPkg := ident.Name
		constructorName := sel.Sel.Name

		// Constructor must start with "New".
		if !strings.HasPrefix(constructorName, "New") {
			return true
		}

		info, ok := pkgInfos[localPkg]
		if !ok {
			return true
		}

		resourceType := constructorName[len("New"):] // strip "New"
		typeToken := info.provider + ":" + info.module + ":" + resourceType

		line := fset.Position(callExpr.Pos()).Line

		// args: (ctx, "logical-name", &pkg.TypeArgs{...}, opts...)
		logicalName, props := extractCallArgs(callExpr, fset, pkgSyms)
		if logicalName == "" {
			return true
		}

		resources[logicalName] = &resource{
			typeToken:  typeToken,
			line:       line,
			properties: props,
		}
		return true
	})
	return resources
}

// extractCallArgs extracts the logical name and properties from a Pulumi Go
// constructor call.  Pulumi Go constructors follow the signature:
//
//	New<Type>(ctx, name string, args *TypeArgs, opts ...ResourceOption) (*Type, error)
func extractCallArgs(call *goast.CallExpr, fset *token.FileSet, pkgSyms map[string]interface{}) (string, map[string]propValue) {
	props := map[string]propValue{}
	var logicalName string

	if len(call.Args) < 2 {
		return "", props
	}

	// arg[1] is the logical name — string literal or a named constant.
	switch a := call.Args[1].(type) {
	case *goast.BasicLit:
		if a.Kind == token.STRING {
			logicalName = strings.Trim(a.Value, `"`)
		}
	case *goast.Ident:
		if pkgSyms != nil {
			if v, ok := pkgSyms[a.Name]; ok {
				logicalName, _ = v.(string)
			}
		}
	}
	if logicalName == "" {
		return "", props
	}

	// arg[2] is &pkg.TypeArgs{...} — extract the composite literal.
	if len(call.Args) < 3 {
		return logicalName, props
	}
	argsArg := call.Args[2]

	// Unwrap & if present.
	if unary, ok := argsArg.(*goast.UnaryExpr); ok {
		argsArg = unary.X
	}

	// Resolve identifier (variable) or zero-arg call from pkgSyms.
	if pkgSyms != nil {
		var symName string
		if ident, ok := argsArg.(*goast.Ident); ok {
			symName = ident.Name
		} else if callExpr, ok := argsArg.(*goast.CallExpr); ok && len(callExpr.Args) == 0 {
			if ident, ok := callExpr.Fun.(*goast.Ident); ok {
				symName = ident.Name
			}
		}
		if symName != "" {
			if v, ok := pkgSyms[symName]; ok {
				if m, ok := v.(map[string]interface{}); ok {
					for k, val := range m {
						if k == "_dd_lines" {
							continue
						}
						key := lowerFirst(k)
						props[key] = propValue{value: val, line: 0}
					}
				}
			}
			return logicalName, props
		}
	}

	compLit, ok := argsArg.(*goast.CompositeLit)
	if !ok {
		return logicalName, props
	}

	for _, elt := range compLit.Elts {
		kv, ok := elt.(*goast.KeyValueExpr)
		if !ok {
			continue
		}
		keyIdent, ok := kv.Key.(*goast.Ident)
		if !ok {
			continue
		}
		key := lowerFirst(keyIdent.Name)
		propLine := fset.Position(kv.Pos()).Line

		val := extractValue(kv.Value, fset, pkgSyms)
		if val != nil {
			props[key] = propValue{value: val, line: propLine}
		}
	}
	return logicalName, props
}

// extractValue resolves a Go AST expression to a Go value.
// Handles pulumi.String("x"), pulumi.Bool(true), pulumi.Int(n), literals,
// composite literals, and slice literals.
func extractValue(expr goast.Expr, fset *token.FileSet, pkgSyms map[string]interface{}) interface{} {
	switch e := expr.(type) {
	case *goast.BasicLit:
		switch e.Kind {
		case token.STRING:
			return strings.Trim(e.Value, `"`)
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
		// Resolve package-level constants and variables from sibling files.
		if pkgSyms != nil {
			if v, ok := pkgSyms[e.Name]; ok {
				return v
			}
		}
	case *goast.BinaryExpr:
		// String concatenation: "prefix-" + region or "a" + "b"
		if e.Op == token.ADD {
			left := extractValue(e.X, fset, pkgSyms)
			right := extractValue(e.Y, fset, pkgSyms)
			if ls, ok := left.(string); ok {
				if rs, ok := right.(string); ok {
					return ls + rs
				}
			}
		}
	case *goast.CallExpr:
		// pulumi.String("x"), pulumi.Bool(true), pulumi.Int(42), pulumi.Float64(3.14)
		if isPulumiWrap(e) && len(e.Args) == 1 {
			return extractValue(e.Args[0], fset, pkgSyms)
		}
		// cfg.GetBool("key"), cfg.GetString("key"), cfg.Require("key"), etc.
		if v, ok := extractConfigGetterValue(e); ok {
			return v
		}
		// Zero-arg function call whose return value is indexed in pkgSyms
		// (e.g. opts := getDefaultArgs()).
		if len(e.Args) == 0 && pkgSyms != nil {
			if ident, ok := e.Fun.(*goast.Ident); ok {
				if v, ok := pkgSyms[ident.Name]; ok {
					return v
				}
			}
		}
	case *goast.CompositeLit:
		return extractCompositeLit(e, fset, pkgSyms)
	case *goast.UnaryExpr:
		// &pkg.TypeArgs{...}
		return extractValue(e.X, fset, pkgSyms)
	}
	return nil
}

// isPulumiWrap reports whether a call is a pulumi.String / pulumi.Bool / … wrapper.
func isPulumiWrap(call *goast.CallExpr) bool {
	sel, ok := call.Fun.(*goast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*goast.Ident)
	if !ok {
		return false
	}
	return pkg.Name == "pulumi"
}

func extractCompositeLit(lit *goast.CompositeLit, fset *token.FileSet, pkgSyms map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	ddLines := map[string]int{}
	defLine := fset.Position(lit.Pos()).Line

	for _, elt := range lit.Elts {
		kv, ok := elt.(*goast.KeyValueExpr)
		if !ok {
			continue
		}
		keyIdent, ok := kv.Key.(*goast.Ident)
		if !ok {
			continue
		}
		key := lowerFirst(keyIdent.Name)
		propLine := fset.Position(kv.Pos()).Line
		val := extractValue(kv.Value, fset, pkgSyms)
		if val != nil {
			out[key] = val
			ddLines[key] = propLine
		}
	}
	out["_dd_lines"] = pulumi.BuildDDLines(defLine, ddLines)
	return out
}

// extractConfigGetterValue recognises Pulumi config getter calls such as
// cfg.GetBool("key") and returns the zero value for that type, allowing the
// scanner to evaluate security rules conservatively when config values are used
// directly as resource properties.
func extractConfigGetterValue(call *goast.CallExpr) (interface{}, bool) {
	sel, ok := call.Fun.(*goast.SelectorExpr)
	if !ok {
		return nil, false
	}
	method := sel.Sel.Name
	switch method {
	case "GetBool", "RequireBool":
		return false, true
	case "GetInt", "RequireInt":
		return 0, true
	case "GetFloat64", "RequireFloat64":
		return 0.0, true
	case "Get", "Require", "GetSecret", "RequireSecret",
		"GetObject", "RequireObject":
		return "", true
	}
	return nil, false
}

// lowerFirst lowercases the first rune of s (Go struct fields are PascalCase
// but Pulumi property names are camelCase).
func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}
