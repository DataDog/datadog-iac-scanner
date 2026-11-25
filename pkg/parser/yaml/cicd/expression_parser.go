/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package cicd

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	ghactions "github.com/rmuir/tree-sitter-ghactions/bindings/go"
	sitter "github.com/tree-sitter/go-tree-sitter"
)

// Regular expression to find GitHub Actions expressions: ${{ ... }}
var exprRegex = regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`)

const (
	// Node kinds
	call_expression      = "call_expression"
	function_call        = "function_call"
	argument_list        = "argument_list"
	subscript_expression = "subscript_expression"
	index_expression     = "index_expression"
	constant_reducible   = "constant_reducible"
	identifier           = "identifier"
	member_expression    = "member_expression"
	binary_expression    = "binary_expression"
	unary_expression     = "unary_expression"
	string_content       = "string_content"
	string_literal       = "string_literal"

	// Types
	secrets_expansion    = "secrets_expansion" //nolint:gosec
	dynamic_secret_index = "dynamic_secret_index"
	computed_index       = "computed_index"

	fullMatchLen = 4
)

var ghactionsLang = sitter.NewLanguage(ghactions.Language())

// ParseExpression parses a GitHub Actions expression and returns structured information
func parseExpression(ctx context.Context, expr ExpressionMatch) *ParsedExpression {
	contextLogger := logger.FromContext(ctx)
	result := &ParsedExpression{
		Raw:                 expr.Expression,
		ParseOK:             false,
		ConstantReducible:   false,
		ConstantSubexprs:    []ParsedSubExpression{},
		ComputedIndices:     []ParsedSubExpression{},
		HasSecretsExpansion: false,
		HasDynamicSecretKey: false,
	}

	// Create parser
	parser := sitter.NewParser()
	defer parser.Close()
	err := parser.SetLanguage(ghactionsLang)

	if err != nil {
		contextLogger.Err(err).Msgf("Failed to load ghaction tree-sitter language")
		return result
	}

	// Tree-sitter-ghactions requires the ${{ }} wrapper to parse correctly
	exprBytes := []byte(expr.Full)
	tree := parser.Parse(exprBytes, nil)
	if tree == nil {
		result.Error = fmt.Errorf("failed to parse expression '%s': invalid syntax", expr.Expression)
		return result
	}
	defer tree.Close()

	// Walk the AST and extract information
	rootNode := tree.RootNode()
	result.AST = buildAST(rootNode, exprBytes)
	result.ParseOK = true

	// Analyze the AST for patterns
	// Start analysis from root which will recursively check all children
	analyzeExpression(rootNode, exprBytes, result)

	// Check if entire expression is constant-reducible
	// The root is always "source", so check if all its children are constant
	allChildrenConstant := true
	if rootNode.NamedChildCount() > 0 {
		for i := uint(0); i < rootNode.NamedChildCount(); i++ {
			child := rootNode.NamedChild(i)
			if child != nil && !isConstantReducible(child) {
				allChildrenConstant = false
				break
			}
		}
		if allChildrenConstant {
			result.ConstantReducible = true
		}
	}

	return result
}

// ExtractExpressionsFromString finds all ${{ ... }} expressions in a string
func extractExpressionsFromString(input string) []ExpressionMatch {
	matches := exprRegex.FindAllStringSubmatchIndex(input, -1)
	results := make([]ExpressionMatch, 0, len(matches))

	for _, match := range matches {
		// match[0], match[1] are the full match (${{ ... }})
		// match[2], match[3] are the captured group (the expression inside)
		if len(match) < fullMatchLen {
			continue
		}
		fullStart := match[0]
		fullEnd := match[1]
		exprStart := match[2]
		exprEnd := match[3]

		results = append(results, ExpressionMatch{
			Full:       input[fullStart:fullEnd],
			Expression: input[exprStart:exprEnd],
			FullSpan: Span{
				Start: fullStart,
				End:   fullEnd,
			},
			ExprSpan: Span{
				Start: exprStart,
				End:   exprEnd,
			},
		})
	}

	return results
}

// buildAST recursively builds a simplified AST representation
func buildAST(node *sitter.Node, source []byte) ASTNode {
	ast := ASTNode{
		Type:     node.Kind(),
		Value:    node.Utf8Text(source),
		Children: []ASTNode{},
	}

	childCount := node.NamedChildCount()
	for i := uint(0); i < childCount; i++ {
		child := node.NamedChild(i)
		if child != nil {
			ast.Children = append(ast.Children, buildAST(child, source))
		}
	}

	return ast
}

// analyzeExpression walks the AST and detects security-relevant patterns
func analyzeExpression(node *sitter.Node, source []byte, result *ParsedExpression) { //nolint:gocyclo
	nodeKind := node.Kind()
	nodeText := node.Utf8Text(source)

	switch nodeKind {
	case call_expression, function_call:
		// Check for toJSON(secrets) pattern
		funcName := getFunctionName(node, source)
		if strings.EqualFold(funcName, "toJSON") {
			// Look for argument_list child, then check its children for bare "secrets"
			for i := uint(0); i < node.NamedChildCount(); i++ {
				child := node.NamedChild(i)
				if child != nil && child.Kind() == argument_list {
					// Check arguments inside the argument_list
					for j := uint(0); j < child.NamedChildCount(); j++ {
						arg := child.NamedChild(j)
						if arg != nil && isBareSecretsContext(arg, source) {
							result.HasSecretsExpansion = true
							result.SecretsExpansionNodes = append(result.SecretsExpansionNodes, ParsedSubExpression{
								Type:  secrets_expansion,
								Value: nodeText,
							})
						}
					}
				}
			}
		}

	case subscript_expression, index_expression:
		// Check for secrets[dynamic_key] pattern
		// Note: tree-sitter-ghactions uses "argument" field for the object being indexed
		objectNode := node.ChildByFieldName("argument")
		if objectNode == nil {
			// Fallback to "object" in case grammar changes
			objectNode = node.ChildByFieldName("object")
		}
		indexNode := node.ChildByFieldName("index")

		if objectNode != nil && indexNode != nil {
			objectText := objectNode.Utf8Text(source)
			if strings.EqualFold(objectText, "secrets") && !isLiteralString(indexNode) {
				result.HasDynamicSecretKey = true
				result.DynamicSecretKeyNodes = append(result.DynamicSecretKeyNodes, ParsedSubExpression{
					Type:  dynamic_secret_index,
					Value: nodeText,
				})
			}
		}

		// Check for any computed index (for obfuscation rule)
		if indexNode != nil && isComputedIndex(indexNode) {
			result.ComputedIndices = append(result.ComputedIndices, ParsedSubExpression{
				Type:  computed_index,
				Value: nodeText,
			})
		}
	}

	// Check if this node is constant-reducible and add to subexprs list
	if isConstantReducible(node) {
		result.ConstantSubexprs = append(result.ConstantSubexprs, ParsedSubExpression{
			Type:  constant_reducible,
			Value: nodeText,
		})
	}

	// Recurse to children
	childCount := node.NamedChildCount()
	for i := uint(0); i < childCount; i++ {
		child := node.NamedChild(i)
		if child != nil {
			analyzeExpression(child, source, result)
		}
	}
}

// getFunctionName extracts the function name from a call expression
func getFunctionName(node *sitter.Node, source []byte) string {
	// Look for function name child
	funcNode := node.ChildByFieldName("function")
	if funcNode != nil {
		return funcNode.Utf8Text(source)
	}

	// Fallback: look for identifier child
	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if child != nil && child.Kind() == identifier {
			return child.Utf8Text(source)
		}
	}

	return ""
}

// isBareSecretsContext checks if a node is a bare "secrets" context reference
func isBareSecretsContext(node *sitter.Node, source []byte) bool {
	if node.Kind() == identifier {
		return strings.EqualFold(node.Utf8Text(source), "secrets")
	}
	return false
}

// isLiteralString checks if a node is a string literal (not a variable or expression)
func isLiteralString(node *sitter.Node) bool {
	kind := node.Kind()
	return kind == string_kind || kind == string_literal || kind == string_content
}

// isComputedIndex checks if an index expression uses runtime values
func isComputedIndex(node *sitter.Node) bool {
	// If it's a literal string, it's not computed
	if isLiteralString(node) {
		return false
	}

	kind := node.Kind()
	// Function calls, member expressions, identifiers (variables) are all computed
	return kind == call_expression ||
		kind == function_call ||
		kind == member_expression ||
		kind == subscript_expression ||
		kind == identifier
}

// isConstantReducible checks if an expression can be evaluated at parse time
func isConstantReducible(node *sitter.Node) bool {
	kind := node.Kind()

	// Literals are constant
	if kind == string_kind || kind == string_literal || kind == "number" || kind == "boolean" ||
		kind == "true" || kind == "false" || kind == "null" {
		return true
	}

	// Binary operations on constants are constant
	if kind == binary_expression {
		leftNode := node.ChildByFieldName("left")
		rightNode := node.ChildByFieldName("right")
		if leftNode != nil && rightNode != nil {
			return isConstantReducible(leftNode) && isConstantReducible(rightNode)
		}
	}

	// Unary operations on constants are constant
	if kind == unary_expression {
		operandNode := node.ChildByFieldName("operand")
		if operandNode != nil {
			return isConstantReducible(operandNode)
		}
	}

	// Identifiers, member expressions, etc. are NOT constant
	return false
}
