package terraform

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// Remove the whitespaces at the beginning of a line
var indentRegex = regexp.MustCompile(`^\s+`)

// Remove the whitespaces but the newlines
var whitespaceRegex = regexp.MustCompile(`\s+`)

// nolint:gocyclo,gocritic
func GenerateSubstrings(
	ctx context.Context,
	key string,
	extracted [][]string,
	lines []string,
	currentLine int,
	fileOriginalData []byte,
) (string, string, int) {
	var substr1, substr2 string
	var idx int

	// Replace placeholders back to bracketed values
	for idx, str := range extracted {
		placeholder := fmt.Sprintf("{{%d}}", idx)
		key = strings.Replace(key, placeholder, str[0], 1)
	}

	// Handle [something] or ["key"]
	if strings.Contains(key, "[") && strings.HasSuffix(key, "]") {
		start := strings.Index(key, "[")
		end := strings.LastIndex(key, "]")
		if start > 0 && end > start {
			base := key[:start]
			bracketValue := key[start+1 : end]

			// Strip quotes from map-style keys like ["Name"]
			bracketValue = strings.Trim(bracketValue, `"'`)

			// Handle placeholders like [{{label}}]
			if strings.HasPrefix(bracketValue, "{{") && strings.HasSuffix(bracketValue, "}}") {
				bracketValue = strings.TrimPrefix(bracketValue, "{{")
				bracketValue = strings.TrimSuffix(bracketValue, "}}")
			}

			// Handle numeric index
			if index, err := strconv.Atoi(bracketValue); err == nil {
				substr1 = base
				substr2, idx = resolveListIndex(ctx, base, index, currentLine, lines, fileOriginalData)
				return substr1, substr2, idx
			}

			// Resource label or map key
			substr1 = base
			substr2 = bracketValue
			return substr1, substr2, 0
		}
	}

	parts := strings.SplitN(key, "=", 2)
	substr1 = strings.TrimSpace(parts[0])
	if len(parts) > 1 {
		substr2 = strings.TrimSpace(parts[1])
	}

	return substr1, substr2, 0
}

func resolveListIndex(
	ctx context.Context,
	attrName string,
	index, currentLine int,
	lines []string,
	fullFileContent []byte,
) (substr string, linenum int) {
	contextLogger := logger.FromContext(ctx)
	// Parse the entire file once (HCL parser handles ALL edge cases)
	hclFile, diags := hclsyntax.ParseConfig(fullFileContent, "temp.tf", hcl.InitialPos)
	if diags.HasErrors() {
		// Fallback to string-based if parsing fails
		contextLogger.Warn().Msg("Array detection falling back to resolveListIndex string based")
		return resolveListIndexStringBased(attrName, index, currentLine, lines)
	}

	body := hclFile.Body.(*hclsyntax.Body)

	// Search for the attribute in the parsed tree
	result, lineNum := findInHCLBody(body, attrName, index, currentLine)
	return result, lineNum
}

func findInHCLBody(body *hclsyntax.Body, attrName string, index, contextLine int) (substr string, lineNum int) {
	// If contextLine is provided (>= 0), first scope the search to the block containing that line
	// Note: contextLine is 0-indexed, so 0 is a valid line (first line of file)
	if contextLine >= 0 {
		// Find the block that contains the contextLine (HCL lines are 1-indexed)
		for _, block := range body.Blocks {
			start := block.TypeRange.Start.Line
			end := block.Body.SrcRange.End.Line

			// Convert 0-indexed contextLine to 1-indexed for comparison with HCL positions
			contextLineHCL := contextLine + 1

			if contextLineHCL >= start && contextLineHCL <= end {
				// We're inside this block - search within it (without contextLine, since we've already scoped to the right block)
				result, line := findInHCLBodyScoped(block.Body, attrName, index)
				if line > 0 || result != "" {
					return result, line
				}
			}
		}
	}

	// If contextLine is not provided or block not found, search globally
	return findInHCLBodyScoped(body, attrName, index)
}

// findInHCLBodyScoped searches for an attribute or block in the given body without recursion beyond immediate nested blocks
func findInHCLBodyScoped(body *hclsyntax.Body, attrName string, index int) (substr string, lineNum int) {
	// Case 1: Array attribute (e.g., container = [{}, {}])
	if attr, exists := body.Attributes[attrName]; exists {
		if tupleExpr, ok := attr.Expr.(*hclsyntax.TupleConsExpr); ok {
			// This is an array! Get the Nth element
			if index < len(tupleExpr.Exprs) {
				targetElement := tupleExpr.Exprs[index]

				// Check if this element is single-line (starts and ends on the same line)
				elementStartLine := targetElement.Range().Start.Line
				elementEndLine := targetElement.Range().End.Line

				if elementStartLine == elementEndLine {
					// Single-line element - return the line number where it's located
					return "", elementStartLine - 1
				}

				// Multi-line element - return line number
				return "", targetElement.Range().Start.Line - 1
			}
		}
	}

	// Case 2: Repeated blocks (e.g., binding { } binding { })
	matchingBlocks := []hclsyntax.Block{}
	for _, block := range body.Blocks {
		if block.Type == attrName {
			matchingBlocks = append(matchingBlocks, *block)
		}
	}
	if index < len(matchingBlocks) {
		return "", matchingBlocks[index].TypeRange.Start.Line - 1
	}

	// Case 3: Search in nested blocks recursively (without contextLine)
	for _, block := range body.Blocks {
		if result, line := findInHCLBodyScoped(block.Body, attrName, index); line > 0 || result != "" {
			return result, line
		}
	}

	return "", 0
}

func resolveListIndexStringBased(attrName string, index, currentLine int, lines []string) (substr string, lineNum int) {
	if index < 0 {
		return "", 0
	}

	countAttr := 0
	for i := currentLine; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		// Case 1: This is an actual array
		if strings.HasPrefix(trimmed, attrName+" = [") || strings.HasPrefix(trimmed, attrName+"=[") {
			// Check if it's a single-line array
			start := strings.Index(trimmed, "[")
			end := strings.Index(trimmed, "]")
			if start >= 0 && end > start {
				// Single-line array - extract the value using simple parsing
				value, err := getSingleLineArrayValue(trimmed, start, end, index)
				if err == nil {
					return value, 0
				}
			}

			// Multi-line array or single-line array with complex content - use HCL parser
			j, err := getArrayElementLine(attrName, index, lines, i)
			if err != nil {
				return "", 0
			}
			return "", j
		}

		// Case 2: The attribute appears several times
		if strings.Contains(trimmed, attrName+" {") {
			countAttr++
			if countAttr == index+1 {
				return trimmed, i
			}
		}
	}
	return "", 0
}

// getSingleLineArrayValue extracts a value from a single-line array
func getSingleLineArrayValue(line string, start, end, index int) (string, error) {
	// Extract array content
	arrayContent := line[start : end+1]

	// Parse with HCL to properly handle strings, heredocs, etc.
	expr, diags := hclsyntax.ParseExpression([]byte(arrayContent), "", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return "", fmt.Errorf("parse error: %s", diags.Error())
	}

	// Check if it's a tuple (array)
	tuple, ok := expr.(*hclsyntax.TupleConsExpr)
	if !ok {
		return "", fmt.Errorf("not an array expression")
	}

	if index < 0 || index >= len(tuple.Exprs) {
		return "", fmt.Errorf("index out of bounds")
	}

	// Get the string representation of the element
	elemExpr := tuple.Exprs[index]

	// Handle string literals
	if strLit, ok := elemExpr.(*hclsyntax.LiteralValueExpr); ok {
		// Return the string value without quotes
		return strLit.Val.AsString(), nil
	}

	// For other types, return the source text
	elemBytes := elemExpr.Range().SliceBytes([]byte(arrayContent))
	return strings.Trim(string(elemBytes), `"`), nil
}

// getArrayElementLine parses the attribute and returns the line number of the element at the given index
func getArrayElementLine(attrName string, index int, lines []string, startLine int) (int, error) {
	// Find and extract the full array expression from the lines
	arrayContent := extractArrayContent(attrName, lines, startLine)
	if arrayContent == "" {
		return 0, fmt.Errorf("array not found")
	}

	// Parse the array expression, telling HCL that the content starts at line startLine+1 (1-indexed)
	expr, diags := hclsyntax.ParseExpression([]byte(arrayContent), "", hcl.Pos{Line: startLine + 1, Column: 1})
	if diags.HasErrors() {
		return 0, fmt.Errorf("parse error: %s", diags.Error())
	}

	// Check if it's a tuple (array)
	tuple, ok := expr.(*hclsyntax.TupleConsExpr)
	if !ok {
		return 0, fmt.Errorf("not an array expression")
	}

	if index < 0 || index >= len(tuple.Exprs) {
		return 0, fmt.Errorf("index %d out of bounds (array has %d elements)", index, len(tuple.Exprs))
	}

	// Get the line number of the element (1-indexed from HCL)
	// Convert to 0-indexed for consistency with the detector's expectations
	return tuple.Exprs[index].Range().Start.Line - 1, nil
}

// extractArrayContent extracts the array content from the attribute definition
// This function supposes that the file is properly formatted
func extractArrayContent(attrName string, lines []string, startLine int) string {
	var result strings.Builder
	baseIndent := -1
	arrayStarted := false

	for i := startLine; i < len(lines); i++ {
		line := lines[i]

		// Find the attribute definition
		if !arrayStarted {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(whitespaceRegex.ReplaceAllString(trimmed, ""), attrName+"=[") {
				// Found the array start - determine base indentation
				indentMatch := indentRegex.FindString(line)
				baseIndent = len(indentMatch)

				// Extract from the '[' onwards
				idx := strings.Index(line, "[")
				if idx >= 0 {
					arrayStarted = true
					result.WriteString(line[idx:])

					// Check if array closes on same line
					if strings.Contains(line[idx:], "]") {
						// Single line array - extract just the array part
						endIdx := strings.Index(line[idx:], "]")
						return line[idx : idx+endIdx+1]
					}
					result.WriteString("\n")
				}
			}
			continue
		}

		// Array has started - collect lines based on indentation
		currentIndentMatch := indentRegex.FindString(line)
		currentIndent := len(currentIndentMatch)
		trimmed := strings.TrimSpace(line)

		// Check if array is closed
		if strings.Contains(line, "]") {
			result.WriteString(line)
			// Verify this is the closing bracket at our level
			if currentIndent <= baseIndent || trimmed == "]" {
				return result.String()
			}
			result.WriteString("\n")
			continue
		}

		// Continue collecting if:
		// 1. Line is more indented than base
		// 2. Line is empty (preserve structure)
		// 3. Line starts with comma (continuation)
		if currentIndent > baseIndent || trimmed == "" || strings.HasPrefix(trimmed, ",") {
			result.WriteString(line)
			result.WriteString("\n")
		} else {
			// Less indentation means we've left the array block without proper closing
			break
		}
	}

	return ""
}
