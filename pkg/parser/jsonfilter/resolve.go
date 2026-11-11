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

// Status is how far Interpret understood a filter pattern.
type Status int

const (
	// StatusOK means the pattern was parsed into an expression tree the
	// rules can evaluate.
	StatusOK Status = iota
	// StatusUnsupported means the pattern is known text the parser cannot
	// interpret (for example a regex clause). Rules must treat it as
	// uncertain, not as a proven failure.
	StatusUnsupported
)

// Interpretation is the derived reading of a filter pattern: the expression
// tree when Status is StatusOK, otherwise nothing the rules can prove from.
type Interpretation struct {
	Status Status
	// Expr is the object Resolve would serialize, with an _dd_filter_expr
	// tree, when Status is StatusOK.
	Expr map[string]any
}

// Interpret parses pattern. A pattern that does not parse, or that uses
// syntax this package does not model, is StatusUnsupported.
func Interpret(pattern string) Interpretation {
	resolved := Resolve(pattern)
	if resolved == pattern {
		return Interpretation{Status: StatusUnsupported}
	}
	var expr map[string]any
	if err := json.Unmarshal([]byte(resolved), &expr); err != nil {
		return Interpretation{Status: StatusUnsupported}
	}
	if _, ok := expr["_dd_filter_expr"]; !ok {
		return Interpretation{Status: StatusUnsupported}
	}
	return Interpretation{Status: StatusOK, Expr: expr}
}

// Resolve returns the JSON form of a filter pattern: an object whose
// _dd_filter_expr key holds the expression tree. A pattern that does not
// parse is returned unchanged, so a caller can tell the two apart by the key.
// Prefer Interpret when the caller needs an explicit status.
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
