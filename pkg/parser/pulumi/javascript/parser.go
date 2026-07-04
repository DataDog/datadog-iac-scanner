/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package javascript implements a static Pulumi-JavaScript parser.
//
// It delegates to the TypeScript parser's shared AST walking logic using the
// tree-sitter JavaScript grammar, so all import forms (require() and ESM) and
// resource extraction patterns supported for TypeScript are also supported here.
package javascript

import (
	"context"

	sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi/typescript"
)

var lang = sitter.NewLanguage(tree_sitter_javascript.Language())

// Parser implements parser.kindParser for Pulumi JavaScript programs.
type Parser struct{}

func (p *Parser) GetKind() model.FileKind        { return model.KindPulumiJS }
func (p *Parser) GetCommentToken() string         { return "//" }
func (p *Parser) SupportedExtensions() []string   { return []string{".js"} }
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
	return typescript.ParseWithLanguage(ctx, lang, "pulumi javascript parser", fileContent, filename)
}
