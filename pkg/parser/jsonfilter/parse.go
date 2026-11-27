/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package jsonfilter

import (
	"encoding/json"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/jsonfilter/parser"
	"github.com/antlr4-go/antlr/v4"
)

// Parse parses an AWS CloudWatch metric filter pattern into a structured map
// representation. Returns (nil, false) when the pattern is invalid or uses
// syntax not modeled by the grammar.
func Parse(pattern string) (map[string]any, bool) {
	if pattern == "" {
		return nil, false
	}
	is := antlr.NewInputStream(pattern)
	lexer := parser.NewJSONFilterLexer(is)
	lexer.RemoveErrorListeners()
	errorListener := parser.NewCustomErrorListener()
	lexer.AddErrorListener(errorListener)
	stream := antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel)

	p := parser.NewJSONFilterParser(stream)
	p.RemoveErrorListeners()
	p.AddErrorListener(errorListener)
	p.BuildParseTrees = true
	tree := p.Awsjsonfilter()
	if errorListener.HasErrors() {
		return nil, false
	}
	visitor := parser.NewJSONFilterPrinterVisitor()
	parsed := visitor.VisitAll(tree)
	raw, err := json.Marshal(parsed)
	if err != nil {
		return nil, false
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil || len(out) == 0 {
		return nil, false
	}
	return out, true
}
