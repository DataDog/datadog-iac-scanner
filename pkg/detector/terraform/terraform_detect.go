/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

const strBlockBody = "block-body"
const strBlockStart = "block-start"
const strNestedEnd = "nested-end"
const strNestedStart = "nested-start"
const strNestedBody = "nested-body"

// DetectKindLine holds a per-scan HCL parse cache. Multiple findings in the
// same file reuse the parsed body instead of re-running hclsyntax.ParseConfig
// for each one, which is the dominant cost when a single rule fires thousands
// of times across a large repo.
type DetectKindLine struct {
	// hclCache maps file path → *hclsyntax.Body, populated on first parse.
	hclCache sync.Map
}

// cachedParseBody parses src as HCL and returns the body, reusing a previously
// parsed result for the same filePath within this scan.
func (d *DetectKindLine) cachedParseBody(src []byte, filePath string) (*hclsyntax.Body, error) {
	if cached, ok := d.hclCache.Load(filePath); ok {
		return cached.(*hclsyntax.Body), nil
	}
	hclFile, diagnostics := hclsyntax.ParseConfig(src, filePath, hcl.InitialPos)
	if diagnostics.HasErrors() {
		return nil, fmt.Errorf("failed to parse HCL: %v", diagnostics.Errs())
	}
	body, ok := hclFile.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("unexpected HCL body type")
	}
	d.hclCache.Store(filePath, body)
	return body, nil
}

const undetectedVulnerabilityLine = -1

// DetectLine searches vulnerability line in terraform files
func (d *DetectKindLine) DetectLine(ctx context.Context, file *model.FileMetadata,
	searchKey string, outputLines int) model.VulnerabilityLines {
	contextLogger := logger.FromContext(ctx)
	searchKey = sanitizeSearchKey(searchKey)

	detection := &detector.DefaultDetectLineResponse{
		CurrentLine:     0,
		IsBreak:         false,
		FoundAtLeastOne: false,
		ResolvedFile:    file.FilePath,
		ResolvedFiles:   make(map[string]model.ResolvedFileSplit),
	}

	extracted := detector.GetBracketValues(searchKey, [][]string{}, "")
	normalizedKey := searchKey
	for i, match := range extracted {
		if !strings.Contains(match[0], "{{") {
			normalizedKey = strings.ReplaceAll(normalizedKey, match[0], `{{`+strconv.Itoa(i)+`}}`)
		}
	}

	keyParts := strings.FieldsFunc(normalizedKey, func(r rune) bool {
		return r == '.' || r == '/'
	})
	for i, part := range keyParts {
		if strings.Contains(part, "$ref") {
			keyParts = append(keyParts[:i+1], keyParts[i+1:]...)
			break
		}
	}

	lines := *file.LinesOriginalData

	if tfpath.IsJSONConfig(file.FilePath) {
		return detectJSONConfigLine(ctx, file, keyParts, extracted, outputLines)
	}

	for _, part := range keyParts {
		// Parse the entire file in case of array detection, thus the file.OriginalData
		s1, s2, idx := GenerateSubstrings(ctx, part, extracted, lines, detection.CurrentLine, []byte(file.OriginalData))

		// Jumps to line in case of multiline Array
		if idx != 0 {
			detection.CurrentLine = idx
			continue
		}
		detection, _, _, _ = detection.DetectCurrentLine(s1, s2, 0, lines, file.Kind)
		if detection.IsBreak {
			break
		}
	}

	if detection.FoundAtLeastOne {
		line := detection.CurrentLine + 1
		body, parseErr := d.cachedParseBody([]byte(file.OriginalData), file.FilePath)
		if parseErr != nil {
			contextLogger.Error().Err(parseErr).Msgf("Failed to parse block at line %d in file %s", line, file.FilePath)
			return buildEmptyVulnerabilityLines(file)
		}
		vulnLines, err := locateTerraformBlock(ctx, body, line, lines)
		if err != nil {
			contextLogger.Error().Err(err).Msgf("Failed to locate block at line %d in file %s", line, file.FilePath)
			return buildEmptyVulnerabilityLines(file)
		}
		vulnLines.Line = line
		vulnLines.VulnLines = detector.GetAdjacentVulnLines(detection.CurrentLine, outputLines, lines)
		vulnLines.ResolvedFile = file.FilePath
		vulnLines.FileSource = lines
		return vulnLines
	}

	contextLogger.Warn().Msgf("Failed to detect Terraform line, query response %s", normalizedKey)
	return buildEmptyVulnerabilityLines(file)
}

func detectJSONConfigLine(
	ctx context.Context, file *model.FileMetadata, keyParts []string, extracted [][]string, outputLines int,
) model.VulnerabilityLines {
	lines := *file.LinesOriginalData
	current := 0
	found := false
	for _, part := range keyParts {
		s1, s2, idx := GenerateSubstrings(ctx, part, extracted, lines, current, []byte(file.OriginalData))
		if idx != 0 {
			current = idx
			found = true
			continue
		}
		if line, ok := findJSONKeyLine(lines, current, s1); ok {
			current = line
			found = true
		}
		if s2 != "" {
			if line, ok := findJSONKeyLine(lines, current, s2); ok {
				current = line
				found = true
			}
		}
	}
	if !found {
		return buildEmptyVulnerabilityLines(file)
	}
	line := current + 1
	if line < 1 || line > len(lines) {
		return buildEmptyVulnerabilityLines(file)
	}
	got := syntheticVulnerabilityLines(line, lines)
	got.Line = line
	got.VulnLines = detector.GetAdjacentVulnLines(current, outputLines, lines)
	got.ResolvedFile = file.FilePath
	got.FileSource = lines
	return got
}

func findJSONKeyLine(lines []string, from int, key string) (int, bool) {
	if key == "" {
		return from, false
	}
	quoted := `"` + key + `"`
	for i := from; i < len(lines); i++ {
		if jsonLineDeclaresKey(lines[i], quoted) {
			return i, true
		}
	}
	return from, false
}

func jsonLineDeclaresKey(line, quoted string) bool {
	start := 0
	for {
		rel := strings.Index(line[start:], quoted)
		if rel < 0 {
			return false
		}
		idx := start + rel
		rest := strings.TrimLeft(line[idx+len(quoted):], " \t")
		if strings.HasPrefix(rest, ":") {
			return true
		}
		start = idx + len(quoted)
	}
}

func buildEmptyVulnerabilityLines(file *model.FileMetadata) model.VulnerabilityLines {
	return model.VulnerabilityLines{
		Line:           undetectedVulnerabilityLine,
		VulnLines:      &[]model.CodeLine{},
		ResolvedFile:   file.FilePath,
		ResourceSource: "",
		FileSource:     *file.LinesOriginalData,
	}
}

func sanitizeSearchKey(key string) string {
	re := regexp.MustCompile(`\[%!s\(int=(\d+)\)\]`)
	return re.ReplaceAllString(key, "[$1]")
}

// locateTerraformBlock finds the block containing identifyingLine in a pre-parsed
// HCL body and returns its location metadata. The caller is responsible for
// parsing (and optionally caching) the body via cachedParseBody.
func locateTerraformBlock(
	ctx context.Context,
	body *hclsyntax.Body,
	identifyingLine int,
	strLines []string,
) (model.VulnerabilityLines, error) {
	contextLogger := logger.FromContext(ctx)

	if len(strLines) == 0 {
		err := fmt.Errorf("line %d is out of range", identifyingLine)
		contextLogger.Error().Msg(err.Error())
		return model.VulnerabilityLines{}, err
	}
	if identifyingLine <= 0 || identifyingLine > len(strLines) {
		identifyingLine = min(max(identifyingLine, 1), len(strLines))
	}

	if block := blockContainingLine(body.Blocks, identifyingLine); block != nil {
		return vulnerabilityLinesFromBlock(block, identifyingLine, strLines), nil
	}
	if block := nearestBlock(body.Blocks, identifyingLine); block != nil {
		return vulnerabilityLinesFromBlock(block, identifyingLine, strLines), nil
	}

	contextLogger.Warn().Msgf("using line %d as location because no HCL block was found", identifyingLine)
	return syntheticVulnerabilityLines(identifyingLine, strLines), nil
}

func blockContainingLine(blocks hclsyntax.Blocks, line int) *hclsyntax.Block {
	for _, block := range blocks {
		if line >= block.TypeRange.Start.Line && line <= block.Body.SrcRange.End.Line {
			return block
		}
	}
	return nil
}

func nearestBlock(blocks hclsyntax.Blocks, line int) *hclsyntax.Block {
	var nearest *hclsyntax.Block
	best := -1
	for _, block := range blocks {
		dist := lineDistance(line, block.TypeRange.Start.Line, block.Body.SrcRange.End.Line)
		if nearest == nil || dist < best {
			nearest = block
			best = dist
		}
	}
	return nearest
}

func lineDistance(line, start, end int) int {
	if line < start {
		return start - line
	}
	if line > end {
		return line - end
	}
	return 0
}

func vulnerabilityLinesFromBlock(block *hclsyntax.Block, identifyingLine int, strLines []string) model.VulnerabilityLines {
	start := block.TypeRange.Start
	end := block.Body.SrcRange.End
	anchor := identifyingLine
	if identifyingLine < start.Line || identifyingLine > end.Line {
		anchor = start.Line
	}
	insertionLine, insertionCol := calculateInsertionPoint(block, anchor, strLines)
	return model.VulnerabilityLines{
		VulnerablilityLocation: model.ResourceLocation{
			Start: toResourceLine(start),
			End:   toResourceLine(end),
		},
		RemediationLocation: model.ResourceLocation{
			Start: model.ResourceLine{Line: insertionLine, Col: insertionCol},
			End:   model.ResourceLine{Line: insertionLine, Col: insertionCol},
		},
		BlockLocation: model.ResourceLocation{
			Start: toResourceLine(start),
			End:   toResourceLine(end),
		},
		LineWithVulnerability: strLines[identifyingLine-1],
		ResourceSource:        extractBlockSource(strLines, start.Line, end.Line),
	}
}

func syntheticVulnerabilityLines(line int, strLines []string) model.VulnerabilityLines {
	loc := model.ResourceLocation{
		Start: model.ResourceLine{Line: line, Col: 1},
		End:   model.ResourceLine{Line: line, Col: len(strLines[line-1]) + 1},
	}
	return model.VulnerabilityLines{
		VulnerablilityLocation: loc,
		RemediationLocation:    loc,
		BlockLocation:          loc,
		LineWithVulnerability:  strLines[line-1],
		ResourceSource:         strLines[line-1] + "\n",
	}
}

func toResourceLine(pos hcl.Pos) model.ResourceLine {
	return model.ResourceLine{Line: pos.Line, Col: pos.Column}
}

func extractBlockSource(lines []string, start, end int) string {
	return strings.Join(lines[start-1:end], "\n") + "\n"
}

// nolint:gocyclo
func calculateInsertionPoint(block *hclsyntax.Block, line int, lines []string) (insertionLine, col int) {
	name, nestedStart, nestedEnd, isAttr := findContainingStructure(block, line)

	var caseType string

	if name != "" {
		// When the containing attribute is a function-call wrapper (e.g. jsonencode(...),
		// merge(..., { ... })), we only push the anchor past the wrapper on the degenerate
		// boundary where the identifying line coincides with the wrapper's closing line —
		// otherwise injected HCL could corrupt a single-line wrapped expression. For every
		// other case the identifying line lies inside the wrapped body, which is where both
		// SARIF regions and attribute-level remediations should anchor.
		lineText := strings.TrimSpace(lines[nestedStart.Line-1])
		isFunctionCallWrapper := isAttr && strings.Contains(lineText, "(") && strings.Contains(lineText, "{")
		switch {
		case line == nestedEnd.Line && isFunctionCallWrapper:
			insertionLine = nestedEnd.Line + 1
			caseType = strBlockBody
		case line == nestedEnd.Line:
			insertionLine = nestedEnd.Line - 1
			caseType = strNestedEnd
		case line == nestedStart.Line:
			insertionLine = nestedStart.Line + 1
			caseType = strNestedStart
		default:
			insertionLine = line
			caseType = strNestedBody
		}
	} else if line == block.TypeRange.Start.Line {
		insertionLine = block.Body.SrcRange.End.Line - 1
		for i := insertionLine; i >= block.TypeRange.Start.Line; i-- {
			_, s, e, attr := findContainingStructure(block, i)
			if attr && e.Line >= insertionLine {
				insertionLine = s.Line - 1
			} else {
				break
			}
		}
		if insertionLine < block.TypeRange.Start.Line {
			insertionLine = block.TypeRange.Start.Line
		}
		caseType = strBlockStart
	} else {
		insertionLine = line
		caseType = strBlockBody
	}

	insertionLine = min(max(insertionLine, 1), len(lines))
	col = determineInsertionIndent(lines, insertionLine, caseType, nestedStart.Line, nestedEnd.Line) + 1
	trimmed := strings.TrimSpace(lines[insertionLine-1])
	if caseType == "block-start" && (strings.Contains(trimmed, "}") || isHeredocTerminator(trimmed, lines, insertionLine-1)) {
		col = len(lines[insertionLine-1]) + 1
	}
	return insertionLine, col
}

// nolint:gocritic
func findContainingStructure(block *hclsyntax.Block, line int) (string, hcl.Pos, hcl.Pos, bool) {
	for _, nested := range block.Body.Blocks {
		if line >= nested.TypeRange.Start.Line && line <= nested.Body.SrcRange.End.Line {
			if name, s, e, isAttr := findContainingStructure(nested, line); name != "" {
				return name, s, e, isAttr
			}
			return nested.Type, nested.TypeRange.Start, nested.Body.SrcRange.End, false
		}
	}

	for name, attr := range block.Body.Attributes {
		start := attr.SrcRange.Start
		end := attr.SrcRange.End
		if line >= start.Line && line <= end.Line {
			switch attr.Expr.(type) {
			case *hclsyntax.ObjectConsExpr:
				return name, start, end, true
			case *hclsyntax.FunctionCallExpr:
				return name, start, end, true // allow insertion logic to handle function call detection
			}
		}
	}

	return "", hcl.Pos{}, hcl.Pos{}, false
}

func determineInsertionIndent(lines []string, insertionLine int, caseType string, nestedStart, nestedEnd int) int {
	switch caseType {
	case strNestedEnd:
		for i := nestedEnd - 2; i >= nestedStart-1; i-- {
			if trimmed := strings.TrimSpace(lines[i]); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				return countLeadingSpacesOrTabs([]byte(lines[i]))
			}
		}
	case strNestedStart:
		return countLeadingSpacesOrTabs([]byte(lines[nestedStart-1])) + 2
	case strNestedBody, strBlockBody:
		return countLeadingSpacesOrTabs([]byte(lines[insertionLine-1]))
	case strBlockStart:
		if strings.TrimSpace(lines[insertionLine-1]) != "}" {
			if idx := firstNonWhitespaceIndex(lines[insertionLine-1]); idx != -1 {
				return idx
			}
		}
		return 1
	}
	return 0
}

func countLeadingSpacesOrTabs(line []byte) int {
	count := 0
	for _, b := range line {
		if b == ' ' || b == '\t' {
			count++
		} else {
			break
		}
	}
	return count
}

func firstNonWhitespaceIndex(line string) int {
	for i, r := range line {
		if r != ' ' && r != '\t' {
			return i
		}
	}
	return -1
}

func isHeredocTerminator(line string, lines []string, idx int) bool {
	for i := idx - 1; i >= 0; i-- {
		text := strings.TrimSpace(lines[i])
		if strings.Contains(text, "<<") {
			parts := strings.Split(text, "<<")
			if len(parts) == 2 {
				marker := strings.TrimSpace(parts[1])
				return line == marker
			}
		}
	}
	return false
}
