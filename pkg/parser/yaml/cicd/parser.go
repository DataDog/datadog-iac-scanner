/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package cicd

import (
	"context"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	yamlParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml"
)

// Parser defines a parser type
type Parser struct{}

// ParsedCommand represents a parsed shell command
type ParsedCommand struct {
	Type     string          `json:"type"`    // "command", "pipeline", "redirected_statement"
	Command  string          `json:"command"` // Command name (e.g., "echo", "cargo")
	Args     []ParsedArg     `json:"args"`    // Command arguments
	Redirect *ParsedRedirect `json:"redirect,omitempty"`
	Pipeline []ParsedCommand `json:"pipeline,omitempty"`
}

// ParsedArg represents a command argument
type ParsedArg struct {
	Type  string `json:"type"`          // "literal", "expansion", "command_substitution"
	Value string `json:"value"`         // The text content
	Var   string `json:"var,omitempty"` // Variable name if type is expansion
}

// ParsedRedirect represents a file redirection
type ParsedRedirect struct {
	Operator string    `json:"operator"` // ">>", ">", etc.
	Target   ParsedArg `json:"target"`   // Redirect target
}

// ParsedRun represents a fully parsed run block
type ParsedRun struct {
	Shell    string          `json:"shell"`           // "bash", "pwsh", etc.
	Commands []ParsedCommand `json:"commands"`        // All commands found
	ParseOK  bool            `json:"parse_ok"`        // Whether parsing succeeded
	Error    error           `json:"error,omitempty"` // Parse error if any
}

// Span represents a text span
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// ExpressionMatch represents a found expression in text
type ExpressionMatch struct {
	Full       string `json:"full"`       // Full match including ${{ }}
	Expression string `json:"expression"` // Just the expression inside
	FullSpan   Span   `json:"full_span"`  // Span of full match
	ExprSpan   Span   `json:"expr_span"`  // Span of expression
}

// ParsedExpression represents a parsed GitHub Actions expression
type ParsedExpression struct {
	Raw                   string                `json:"raw"`                      // Original expression text
	AST                   ASTNode               `json:"ast,omitempty"`            // Parsed AST
	ParseOK               bool                  `json:"parse_ok"`                 // Whether parsing succeeded
	Error                 error                 `json:"error,omitempty"`          // Parse error if any
	ConstantReducible     bool                  `json:"constant_reducible"`       // Can be evaluated at parse time
	ConstantSubexprs      []ParsedSubExpression `json:"constant_subexprs"`        // Sub-expressions that are constant
	ComputedIndices       []ParsedSubExpression `json:"computed_indices"`         // Dynamic array/object accesses
	HasSecretsExpansion   bool                  `json:"has_secrets_expansion"`    // Uses toJSON(secrets) pattern
	SecretsExpansionNodes []ParsedSubExpression `json:"secrets_expansion_nodes"`  // Nodes with secrets expansion
	HasDynamicSecretKey   bool                  `json:"has_dynamic_secret_key"`   // Uses secrets[variable]
	DynamicSecretKeyNodes []ParsedSubExpression `json:"dynamic_secret_key_nodes"` // Nodes with dynamic secret access
}

// ParsedSubExpression represents a sub-expression in the AST
type ParsedSubExpression struct {
	Type  string `json:"type"`  // Type of sub-expression
	Value string `json:"value"` // Text value
}

// ASTNode represents a simplified AST node
type ASTNode struct {
	Type     string    `json:"type"`               // Node type from tree-sitter
	Value    string    `json:"value,omitempty"`    // Text content
	Children []ASTNode `json:"children,omitempty"` // Child nodes
}

// Parse parses yaml/yml file and returns it as a Document
func (p *Parser) Parse(ctx context.Context, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	resolved, documents, ignoreLines, resolvedFiles, err = yamlParser.Parse(ctx, fileContent, filePath, resolveReferences, maxResolverDepth)

	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Convert keys to string format
	documents = yamlParser.ConvertKeysToString(documents)

	// Enhance documents with parsed run blocks
	p.enhanceWithParsedRuns(ctx, documents)

	// Enhance documents with parsed expressions
	p.enhanceWithParsedExpressions(ctx, documents)

	// UnmarshalYAML already adds line tracking, so we can use documents directly
	return resolved, documents, ignoreLines, resolvedFiles, nil
}

// SupportedExtensions returns extensions supported by this parser, which are yaml and yml extension
func (p *Parser) SupportedExtensions() []string {
	return yamlParser.SupportedExtensions()
}

// SupportedTypes returns types supported by this parser, which are ansible, cloudFormation, k8s
func (p *Parser) SupportedTypes() map[string]bool {
	return map[string]bool{
		"cicd": true,
	}
}

// GetKind returns YAML constant kind
func (p *Parser) GetKind() model.FileKind {
	return model.KindYAML
}

// GetCommentToken return the comment token of YAML - #
func (p *Parser) GetCommentToken() string {
	return "#"
}

// StringifyContent converts original content into string formatted version
func (p *Parser) StringifyContent(content []byte) (string, error) {
	return string(content), nil
}

// enhanceWithParsedRuns walks through documents and parses run blocks with tree-sitter
func (p *Parser) enhanceWithParsedRuns(ctx context.Context, documents []model.Document) {
	contextLogger := logger.FromContext(ctx)
	for _, doc := range documents {
		// Look for jobs in the workflow
		jobs, ok := doc["jobs"]
		if !ok {
			continue
		}

		jobsMap, ok := jobs.(map[string]interface{})
		if !ok {
			continue
		}

		for _, j := range jobsMap {
			job, ok := j.(map[string]interface{})
			if !ok {
				continue
			}

			// Look for steps in the job
			steps, ok := job["steps"]
			if !ok {
				continue
			}

			stepsSlice, ok := steps.([]interface{})
			if !ok {
				continue
			}

			for _, s := range stepsSlice {
				step, ok := s.(map[string]interface{})
				if !ok {
					continue
				}

				// Check if step has a run block
				runScript, ok := step["run"].(string)
				if !ok {
					continue
				}

				// Determine shell (default to bash)
				shell := "bash"
				if shellVal, ok := step["shell"].(string); ok {
					shell = shellVal
				}

				// Parse the run block
				parsed := parseRunBlock(runScript, shell)
				if parsed.Error != nil {
					contextLogger.Err(parsed.Error).Msg("Failed to parse shell expressions in run block")
				}

				// Add parsed structure to step
				step["_parsed_run"] = parsed
			}
		}
	}
}

// enhanceWithParsedExpressions walks through documents and parses GitHub Actions expressions
func (p *Parser) enhanceWithParsedExpressions(ctx context.Context, documents []model.Document) {
	for _, doc := range documents {
		p.parseExpressionsInValue(ctx, doc)
	}
}

// parseExpressionsInValue recursively walks a value and parses any expressions found
func (p *Parser) parseExpressionsInValue(ctx context.Context, value interface{}) {
	contextLogger := logger.FromContext(ctx)
	switch v := value.(type) {
	case model.Document, map[string]interface{}:
		// Handle maps (documents, jobs, steps, env, with blocks, etc.)
		// Convert to map for uniform handling
		var m map[string]interface{}
		if doc, ok := v.(model.Document); ok {
			m = doc
		} else {
			m = v.(map[string]interface{})
		}

		for key, val := range m {
			// Collect all expressions found in this value (string or array)
			var allExpressions []ExpressionMatch

			// Check if the value is a string with expressions
			switch typedValue := val.(type) {
			case string:
				allExpressions = extractExpressionsFromString(typedValue)
			case []interface{}:
				for _, elem := range typedValue {
					if strElem, ok := elem.(string); ok {
						expressions := extractExpressionsFromString(strElem)
						allExpressions = append(allExpressions, expressions...)
					}
				}
			}

			// If we found any expressions, parse and store them
			if len(allExpressions) > 0 {
				parsedExprs := make([]ParsedExpression, 0, len(allExpressions))
				for _, expr := range allExpressions {
					parsed := parseExpression(ctx, expr)
					if parsed.Error != nil {
						contextLogger.Err(parsed.Error).Msg("Failed to parse ghaction expression")
					}
					parsedExprs = append(parsedExprs, *parsed)
				}
				// Add parsed expressions to the map under a special key
				exprKey := "_parsed_expressions_" + strings.ReplaceAll(key, "-", "_")
				m[exprKey] = parsedExprs
			}

			// Recurse into nested structures
			p.parseExpressionsInValue(ctx, val)
		}

	case []interface{}:
		for _, item := range v {
			p.parseExpressionsInValue(ctx, item)
		}
	}
}
