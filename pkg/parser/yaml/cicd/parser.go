/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package cicd

import (
	"context"
	"reflect"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser"
	yamlParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/cicd/provider"
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
	ParseOK  bool            `json:"parse_ok"`        // Whether parser facts are available (Error may report recovery)
	Error    error           `json:"error,omitempty"` // Parse error if any
}

// Span represents a text span
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// ExpressionMatch represents a found expression in text
type ExpressionMatch struct {
	Terminated bool   // Set by lexical extraction, or by the implicit-condition context.
	Full       string `json:"full"`       // Full match including ${{ }}
	Expression string `json:"expression"` // Just the expression inside
	FullSpan   Span   `json:"full_span"`  // Span of full match
	ExprSpan   Span   `json:"expr_span"`  // Span of expression
}

// ParsedExpression represents a parsed GitHub Actions expression
type ParsedExpression struct {
	Raw                   string                `json:"raw"`                      // Original expression text
	AST                   ASTNode               `json:"ast,omitempty"`            // Parsed AST
	ParseOK               bool                  `json:"parse_ok"`                 // Facts are available; Error may report recovery
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

// ParseContract separates declaration-only GitLab parses from legacy enrichment.
func (p *Parser) ParseContract(path string) string {
	if provider.Entrypoint(path) == provider.GitLab {
		return provider.GitLabDeclarations
	}
	return provider.LegacyEnriched
}

// Parse parses yaml/yml file and returns it as a Document
func (p *Parser) Parse(ctx context.Context, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	// CI providers own file composition. A scalar naming YAML is a literal,
	// never a generic reference to inline into the rule document.
	documents, ignoreLines, err = yamlParser.ParseStrictNoResolve(ctx, fileContent, filePath)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	resolved = fileContent
	if provider.Entrypoint(filePath) == provider.GitLab {
		return resolved, documents, ignoreLines, nil, nil
	}

	// Convert keys to string format
	documents = yamlParser.ConvertKeysToString(documents)

	if parser.IsLineInfoOnly(ctx) {
		return resolved, documents, ignoreLines, resolvedFiles, nil
	}

	// Keep generic expression extraction separate from provider declarations.
	p.enhanceWithParsedExpressions(ctx, documents)
	for _, doc := range documents {
		enhanceGitHub(ctx, doc)
	}

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

// enhanceWithParsedExpressions walks through documents and parses GitHub Actions expressions
func (p *Parser) enhanceWithParsedExpressions(ctx context.Context, documents []model.Document) {
	for _, doc := range documents {
		p.parseExpressionsInValue(ctx, doc, make(map[uintptr]bool))
	}
}

// parseExpressionsInValue recursively walks a value and parses any expressions found.
// seen prevents revisiting maps during enrichment. CI source values remain
// literal; this walk never resolves or reads sibling files.
func (p *Parser) parseExpressionsInValue(ctx context.Context, value interface{}, seen map[uintptr]bool) {
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
		ptr := reflect.ValueOf(m).Pointer()
		if seen[ptr] {
			return
		}
		seen[ptr] = true

		var parsedByKey map[string][]ParsedExpression
		for key, val := range m {
			allExpressions := expressionsInValue(val)

			// If we found any expressions, parse and store them
			if len(allExpressions) > 0 {
				parsedExprs := make([]ParsedExpression, 0, len(allExpressions))
				for _, expr := range allExpressions {
					parsed := parseExpression(ctx, expr)
					if parsed.Error != nil {
						event := contextLogger.Debug()
						if !expr.Terminated {
							event = contextLogger.Error()
						}
						event.Err(parsed.Error).Msg("Incomplete GitHub expression analysis")
					}
					parsedExprs = append(parsedExprs, *parsed)
				}
				if parsedByKey == nil {
					parsedByKey = make(map[string][]ParsedExpression)
				}
				parsedByKey[key] = parsedExprs
			}

			// Recurse into nested structures
			p.parseExpressionsInValue(ctx, val, seen)
		}

		// The map is only written once its iteration is over.
		for exprKey, parsedExprs := range parsedExpressionKeys(m, parsedByKey) {
			m[exprKey] = parsedExprs
		}

	case []interface{}:
		for _, item := range v {
			p.parseExpressionsInValue(ctx, item, seen)
		}
	}
}

// expressionsInValue collects the expressions found in a value: a string, or
// the strings of an array.
func expressionsInValue(value interface{}) []ExpressionMatch {
	switch typedValue := value.(type) {
	case string:
		return extractExpressionsFromString(typedValue)
	case []interface{}:
		var allExpressions []ExpressionMatch
		for _, elem := range typedValue {
			if strElem, ok := elem.(string); ok {
				allExpressions = append(allExpressions, extractExpressionsFromString(strElem)...)
			}
		}
		return allExpressions
	}
	return nil
}

// parsedExpressionsKeyPrefix prefixes the map key under which the parsed expressions
// of a sibling value are stored.
const parsedExpressionsKeyPrefix = "_parsed_expressions_"

// parsedExpressionKeys returns the entries to add to the map m for the parsed
// expressions of its values, parsedByKey being keyed by the original key of each value.
//
// Keys starting with "_parsed_expressions_" belong to the scanner: an entry the
// workflow writes under such a name is overwritten, so that it cannot hide the
// parsed expressions of another value from the rules.
//
// The parsed expressions of key K are always stored under "_parsed_expressions_" + K,
// the exact key. When K contains '-', they are also stored under the legacy alias
// "_parsed_expressions_" + K with every '-' replaced by '_' ("runs-on" gives
// "_parsed_expressions_runs_on"), which rules read under fixed names. Only workflow
// keys, the keys of m that do not start with "_parsed_expressions_", get an alias, and
// only they are considered when deciding whether an alias is ambiguous. The alias is
// left out when:
//   - its mangled name is itself a workflow key ("A_B" next to "A-B"): the exact key of
//     that value wins, whether or not that value has expressions;
//   - another workflow key has the same mangled name ("A-B_C" and "A_B-C"), whether or
//     not that key has expressions: none of them gets the alias;
//   - it is also the exact key of another value: the exact key wins.
//
// The result only depends on the keys and values of m and parsedByKey, not on map
// iteration order.
func parsedExpressionKeys(m map[string]interface{}, parsedByKey map[string][]ParsedExpression) map[string][]ParsedExpression {
	if len(parsedByKey) == 0 {
		return nil
	}

	additions := make(map[string][]ParsedExpression, len(parsedByKey))
	for key, parsedExprs := range parsedByKey {
		additions[parsedExpressionsKeyPrefix+key] = parsedExprs
	}

	mangledKeyCount := make(map[string]int)
	for key := range m {
		if !isWorkflowKey(key) {
			continue
		}
		if mangled := strings.ReplaceAll(key, "-", "_"); mangled != key {
			mangledKeyCount[mangled]++
		}
	}

	for key, parsedExprs := range parsedByKey {
		mangled := strings.ReplaceAll(key, "-", "_")
		if !isWorkflowKey(key) || mangled == key || mangledKeyCount[mangled] > 1 {
			continue
		}
		if _, mangledIsKey := m[mangled]; mangledIsKey && isWorkflowKey(mangled) {
			continue
		}
		if _, aliasIsExactKey := parsedByKey[mangled]; aliasIsExactKey {
			continue
		}
		additions[parsedExpressionsKeyPrefix+mangled] = parsedExprs
	}
	return additions
}

// isWorkflowKey reports whether key was written by the workflow rather than reserved
// for the parsed expressions stored by the scanner.
func isWorkflowKey(key string) bool {
	return !strings.HasPrefix(key, parsedExpressionsKeyPrefix)
}
