package terraform

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
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
	fileOriginalData string,
) (string, string, int) {
	// No expansion cache: the callers of this shape read JSON documents, whose
	// bodies never reach the HCL expansion.
	return generateSubstrings(ctx, key, extracted, lines, currentLine, func() (*hclsyntax.Body, error) {
		return parseBody([]byte(fileOriginalData))
	}, unknownBlocks, nil)
}

// nolint:gocyclo,gocritic
func generateSubstrings(
	ctx context.Context,
	key string,
	extracted [][]string,
	lines []string,
	currentLine int,
	parse func() (*hclsyntax.Body, error),
	repeated repeatedBlocks,
	expansions *sync.Map,
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
				substr2, idx = resolveListIndex(ctx, base, index, currentLine, lines, parse, repeated, expansions)
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

func parseBody(src []byte) (*hclsyntax.Body, error) {
	hclFile, diags := hclsyntax.ParseConfig(src, "temp.tf", hcl.InitialPos)
	if diags.HasErrors() {
		return nil, diags
	}
	return hclFile.Body.(*hclsyntax.Body), nil
}

func resolveListIndex(
	ctx context.Context,
	attrName string,
	index, currentLine int,
	lines []string,
	parse func() (*hclsyntax.Body, error),
	repeated repeatedBlocks,
	expansions *sync.Map,
) (substr string, linenum int) {
	contextLogger := logger.FromContext(ctx)
	body, err := parse()
	if err != nil {
		contextLogger.Warn().Msg("Array detection falling back to resolveListIndex string based")
		return resolveListIndexStringBased(attrName, index, currentLine, lines)
	}

	// Search for the attribute in the parsed tree
	result, lineNum := findInHCLBody(ctx, body, attrName, index, currentLine, repeated, expansions)
	if result == "" && lineNum == 0 {
		if line, ok := findTupleElementLineInJsonencodeArgs(body, attrName, index, currentLine); ok {
			return "", line
		}
		return resolveListIndexStringBased(attrName, index, currentLine, lines)
	}
	return result, lineNum
}

// findTupleElementLineInJsonencodeArgs finds attrName = [ ... ] tuple element index inside jsonencode({...})
// (or nested merge/...) when it is not a top-level block attribute.
func findTupleElementLineInJsonencodeArgs(body *hclsyntax.Body, attrName string, index, contextLine int) (int, bool) {
	contextLineHCL := contextLine + 1
	for _, block := range body.Blocks {
		start := block.TypeRange.Start.Line
		end := block.Body.SrcRange.End.Line
		if contextLineHCL < start || contextLineHCL > end {
			continue
		}
		for _, attr := range block.Body.Attributes {
			if line := findTupleElementLineInExpr(attr.Expr, attrName, index); line >= 0 {
				return line, true
			}
		}
	}
	return 0, false
}

func findTupleElementLineInExpr(expr hclsyntax.Expression, attrName string, index int) int {
	switch e := expr.(type) {
	case *hclsyntax.FunctionCallExpr:
		if e.Name == "jsonencode" && len(e.Args) > 0 {
			if line := findTupleElementLineInObject(e.Args[0], attrName, index); line >= 0 {
				return line
			}
		}
		for _, arg := range e.Args {
			if line := findTupleElementLineInExpr(arg, attrName, index); line >= 0 {
				return line
			}
		}
	case *hclsyntax.ObjectConsExpr:
		if line := findTupleElementLineInObject(e, attrName, index); line >= 0 {
			return line
		}
	}
	return -1
}

func findTupleElementLineInObject(expr hclsyntax.Expression, attrName string, index int) int {
	obj, ok := expr.(*hclsyntax.ObjectConsExpr)
	if !ok {
		return -1
	}
	for _, item := range obj.Items {
		if hcl.ExprAsKeyword(item.KeyExpr) != attrName {
			continue
		}
		tup, ok := item.ValueExpr.(*hclsyntax.TupleConsExpr)
		if !ok || index < 0 || index >= len(tup.Exprs) {
			return -1
		}
		return tup.Exprs[index].Range().Start.Line - 1
	}
	return -1
}

func findInHCLBody(
	ctx context.Context, body *hclsyntax.Body, attrName string, index, contextLine int, repeated repeatedBlocks,
	expansions *sync.Map,
) (substr string, lineNum int) {
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
				result, line := findInHCLBodyScoped(ctx, block.Body, attrName, index, contextLine, repeated, expansions)
				if line > 0 || result != "" {
					return result, line
				}
			}
		}
	}

	// If contextLine is not provided or block not found, search globally
	return findInHCLBodyScoped(ctx, body, attrName, index, contextLine, repeated, expansions)
}

type blockSlots []int

func (s blockSlots) len() int { return len(s) }

// repeatedBlockSlots lists the line of the block each repeated attrName block of
// the document stands for, in order.
//
// The document is the authority: it records, for every block it holds, the line
// of the source block it was generated from (a dynamic block's blocks all carry
// the dynamic block's line), which stays exact however many dynamic blocks the
// body has and however the converter, with the scan's variables, resolved them.
// Those lines are used when each is the line of a block of the body that can
// generate attrName, and the count matches the document's.
//
// Without them (a document that records no lines, or one from another source),
// the slots are worked out from the body alone: a dynamic block stands for as
// many blocks as its for_each yields without variables. One dynamic block that
// cannot be resolved that way stands for those the document's total leaves, if
// the total is known. With several of them the total cannot be split between
// them, so they stand for none, as the converter keeps them as written when it
// cannot expand them.
// nolint:gocyclo
func repeatedBlockSlots(
	ctx context.Context, body *hclsyntax.Body, attrName string, repeated repeatedBlocks, expansions *sync.Map,
) blockSlots {
	if ctx.Err() != nil {
		// A canceled lookup stops before any slot work, memo hits included.
		return nil
	}
	// The document's recorded lines answer the lookup without expanding any
	// dynamic block, so they are checked before the expansion work below; the
	// blocks' source lines are all the lookup needs from them.
	sourceLines := make(map[int]bool)
	for _, block := range body.Blocks {
		if block.Type == attrName || (dynamicblock.Is(block) && dynamicblock.GeneratedType(block) == attrName) {
			sourceLines[block.TypeRange.Start.Line-1] = true
		}
	}
	if slots, ok := documentSlots(repeated, sourceLines); ok {
		return slots
	}

	// Without usable document lines, every dynamic block of attrName stands
	// for as many slots as its for_each yields. The expansion of one block is
	// memoized for the duration of line detection: line detection revisits
	// the same bodies once per finding, and re-expanding a large for_each per
	// visit would multiply the expansion work by the number of lookups.
	type entry struct {
		line  int
		count int
	}
	var entries []entry
	fixed, unresolved := 0, -1
	unresolvedBlocks := 0
	for _, block := range body.Blocks {
		line := block.TypeRange.Start.Line - 1
		switch {
		case block.Type == attrName:
			entries = append(entries, entry{line, 1})
			fixed++
		case dynamicblock.Is(block) && dynamicblock.GeneratedType(block) == attrName:
			count, resolved := expansionCount(ctx, block, expansions)
			if ctx.Err() != nil {
				// The expansion was interrupted: its count is partial, and
				// treating it as an unresolved for_each would fill the
				// document's total and grow the slots unchecked. Stop before
				// either; a healthy lookup re-expands.
				return nil
			}
			if resolved {
				entries = append(entries, entry{line, count})
				fixed += count
			} else {
				unresolved = len(entries)
				unresolvedBlocks++
				entries = append(entries, entry{line, 0})
			}
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	if unresolvedBlocks == 1 && !repeated.nested && repeated.total != unknownTotal && repeated.total > fixed {
		entries[unresolved].count = repeated.total - fixed
	}
	var slots blockSlots
	for _, e := range entries {
		for i := 0; i < e.count; i++ {
			if ctx.Err() != nil {
				// Cancellation during materialization: stop appending and
				// return nothing, like the other cancellation paths — a
				// partial slot list must not come back as a result.
				return nil
			}
			slots = append(slots, e.line)
		}
	}
	return slots
}

// expansionCount is how many blocks a dynamic block generates for line
// detection, memoized by the block's identity. The parsed bodies live in the
// detector's per-file cache, so one block keeps its identity across the
// lookups of a scan. ok is false when the for_each does not resolve, which
// the slots then treat as a block standing for the document's remaining
// total, exactly as an unresolved expansion did.
func expansionCount(ctx context.Context, block *hclsyntax.Block, expansions *sync.Map) (count int, ok bool) {
	if ctx.Err() != nil {
		return 0, false
	}
	if expansions != nil {
		if cached, hit := expansions.Load(block); hit {
			e := cached.(expansionCount_)
			return e.count, e.resolved
		}
	}
	expansion := dynamicblock.Expand(ctx, block, dynamicForEachContext)
	if ctx.Err() != nil {
		// The expansion stopped mid-walk, so its count is partial. It is not
		// memoized: a later lookup on a healthy context re-expands the block
		// and gets the complete count.
		return 0, false
	}
	result := expansionCount_{resolved: expansion.Resolved, count: len(expansion.Iterators)}
	if expansions != nil {
		expansions.Store(block, result)
	}
	return result.count, result.resolved
}

// expansionCount_ is the memoized result of one dynamic block's expansion.
type expansionCount_ struct {
	resolved bool
	count    int
}

// documentSlots takes the source lines the document records for its blocks, if
// they are consistent with the body: as many as the document holds, each the
// line of a block of the body that can generate them.
func documentSlots(repeated repeatedBlocks, sourceLines map[int]bool) (blockSlots, bool) {
	if len(repeated.lines) == 0 || len(repeated.lines) != repeated.total {
		return nil, false
	}
	for _, line := range repeated.lines {
		if !sourceLines[line] {
			return nil, false
		}
	}
	return blockSlots(repeated.lines), true
}

// enclosingFirst orders blocks so the ones spanning contextLine (0-indexed, or
// negative for none) come first, each group in source order.
func enclosingFirst(blocks hclsyntax.Blocks, contextLine int) hclsyntax.Blocks {
	if contextLine < 0 {
		return blocks
	}
	ordered := make(hclsyntax.Blocks, 0, len(blocks))
	for _, block := range blocks {
		if blockSpansLine(block, contextLine+1) {
			ordered = append(ordered, block)
		}
	}
	for _, block := range blocks {
		if !blockSpansLine(block, contextLine+1) {
			ordered = append(ordered, block)
		}
	}
	return ordered
}

// dynamicForEachContext evaluates a dynamic block's for_each with functions only.
var dynamicForEachContext = &hcl.EvalContext{Functions: functions.TerraformFuncs}

// findInHCLBodyScoped searches for an attribute or block in the given body without recursion beyond immediate nested blocks
func findInHCLBodyScoped(
	ctx context.Context, body *hclsyntax.Body, attrName string, index, contextLine int, repeated repeatedBlocks,
	expansions *sync.Map,
) (substr string, lineNum int) {
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

	// Case 2: Repeated blocks (e.g., binding { } binding { }).
	if slots := repeatedBlockSlots(ctx, body, attrName, repeated, expansions); index < slots.len() {
		return "", slots[index]
	}

	// Case 3: Search in nested blocks recursively, those around contextLine first:
	// the position the search has reached names the nested block the key is in,
	// and the document's slots only fit the body that holds the blocks.
	for _, block := range enclosingFirst(body.Blocks, contextLine) {
		if result, line := findInHCLBodyScoped(ctx, block.Body, attrName, index, contextLine,
			repeated.inNestedBody(), expansions); line > 0 || result != "" {
			return result, line
		}
	}

	return "", 0
}

func lineDeclaresJSONArray(trimmed, attrName string) bool {
	norm := whitespaceRegex.ReplaceAllString(trimmed, "")
	return strings.HasPrefix(norm, attrName+"=[") ||
		strings.HasPrefix(norm, `"`+attrName+`":[`)
}

func resolveListIndexStringBased(attrName string, index, currentLine int, lines []string) (substr string, lineNum int) {
	if index < 0 {
		return "", 0
	}

	countAttr := 0
	for i := currentLine; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		// Case 1: This is an actual array (HCL or JSON key inside heredoc / string)
		if lineDeclaresJSONArray(trimmed, attrName) {
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
		if s, ok := ctyutil.ConcreteString(strLit.Val); ok {
			return s, nil
		}
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
	if !diags.HasErrors() {
		if tuple, ok := expr.(*hclsyntax.TupleConsExpr); ok {
			if index < 0 || index >= len(tuple.Exprs) {
				return 0, fmt.Errorf("index %d out of bounds (array has %d elements)", index, len(tuple.Exprs))
			}
			// Get the line number of the element (1-indexed from HCL)
			// Convert to 0-indexed for consistency with the detector's expectations
			return tuple.Exprs[index].Range().Start.Line - 1, nil
		}
	}

	jsonLine, errJSON := getArrayElementLineJSON(arrayContent, index, startLine)
	if errJSON == nil {
		return jsonLine, nil
	}

	if diags.HasErrors() {
		return 0, fmt.Errorf("parse error: %s; json fallback: %v", diags.Error(), errJSON)
	}
	return 0, fmt.Errorf("not an array expression; json fallback: %v", errJSON)
}

// getArrayElementLineJSON resolves array element line for JSON array syntax (e.g. inside heredocs).
func getArrayElementLineJSON(arrayContent string, index, arrayStartLine0 int) (int, error) {
	dec := json.NewDecoder(strings.NewReader(arrayContent))
	tok, err := dec.Token()
	if err != nil {
		return 0, err
	}
	d, ok := tok.(json.Delim)
	if !ok || d != '[' {
		return 0, fmt.Errorf("expected JSON array")
	}
	for i := 0; dec.More(); i++ {
		offsetBefore := int(dec.InputOffset())
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return 0, err
		}
		if i == index {
			suffix := arrayContent[offsetBefore:]
			trimmed := strings.TrimLeft(suffix, " \t\n\r,")
			pos := offsetBefore + (len(suffix) - len(trimmed))
			if pos < len(arrayContent) {
				newlines := strings.Count(arrayContent[:pos], "\n")
				return arrayStartLine0 + newlines, nil
			}
			return 0, fmt.Errorf("empty element position")
		}
	}
	return 0, fmt.Errorf("index %d out of bounds", index)
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
			if lineDeclaresJSONArray(trimmed, attrName) {
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

		// Check if array is closed at our indentation level
		if strings.Contains(line, "]") && currentIndent <= baseIndent {
			result.WriteString(line)
			return result.String()
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
