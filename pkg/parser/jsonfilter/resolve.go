/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package jsonfilter parses CloudWatch Logs filter patterns.
package jsonfilter

import (
	"encoding/json"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/jsonfilter/parser"
	"github.com/antlr4-go/antlr/v4"
)

// Resolve returns the JSON form of a filter pattern: an object whose
// _dd_filter_expr key holds the expression tree. A pattern that does not
// parse is returned unchanged, so a caller can tell the two apart by the key.
func Resolve(pattern string) string {
	is := antlr.NewInputStream(pattern)

	lexer := parser.NewJSONFilterLexer(is)
	lexer.RemoveErrorListeners()
	stream := antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel)
	errorListener := parser.NewCustomErrorListener()
	lexer.AddErrorListener(errorListener)

	p := parser.NewJSONFilterParser(stream)
	p.RemoveErrorListeners()
	p.AddErrorListener(errorListener)
	p.BuildParseTrees = true
	tree := p.Awsjsonfilter()

	visitor := parser.NewJSONFilterPrinterVisitor()
	if errorListener.HasErrors() {
		return pattern
	}

	out, err := json.Marshal(visitor.VisitAll(tree))
	if err != nil {
		return pattern
	}
	return string(out)
}
