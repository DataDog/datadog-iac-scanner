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
	"sort"
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
const blockTypeResource = "resource"
const blockTypeData = "data"

// DetectKindLine holds a per-scan HCL parse cache. Multiple findings in the
// same file reuse the parsed body instead of re-running hclsyntax.ParseConfig
// for each one, which is the dominant cost when a single rule fires thousands
// of times across a large repo.
type DetectKindLine struct {
	// hclCache maps file path → *hclsyntax.Body, populated on first parse.
	hclCache sync.Map
	// blockLines memoizes the source lines of repeated blocks, which every
	// finding indexing one of them would otherwise reread in full.
	blockLines blockLinesMemo
	// namedBlocks maps a parsed body → namedBlocks, its top-level blocks by
	// type and labels, so finding the block a search key names does not read
	// every block of the file.
	namedBlocks sync.Map
}

// namedBlocks indexes the top-level blocks of a body by blockKey, in order.
type namedBlocks map[string][]*hclsyntax.Block

func blockKey(blockType string, labels ...string) string {
	return blockType + "\x00" + strings.Join(labels, "\x00")
}

// blocksByName returns the index of body's top-level blocks, built once.
func (d *DetectKindLine) blocksByName(body *hclsyntax.Body) namedBlocks {
	if cached, ok := d.namedBlocks.Load(body); ok {
		return cached.(namedBlocks)
	}
	index := make(namedBlocks, len(body.Blocks))
	for _, block := range body.Blocks {
		key := blockKey(block.Type, block.Labels...)
		index[key] = append(index[key], block)
	}
	d.namedBlocks.Store(body, index)
	return index
}

// cachedParseBody parses src as HCL and returns the body, reusing a previously
// parsed result for the same filePath within this scan.
func (d *DetectKindLine) cachedParseBody(src, filePath string) (*hclsyntax.Body, error) {
	if cached, ok := d.hclCache.Load(filePath); ok {
		return cached.(*hclsyntax.Body), nil
	}
	hclFile, diagnostics := hclsyntax.ParseConfig([]byte(src), filePath, hcl.InitialPos)
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
		File:            file,
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

	lines := file.Lines()

	if tfpath.IsJSONConfig(file.FilePath) {
		return detectJSONConfigLine(ctx, file, keyParts, extracted, outputLines)
	}

	parse := func() (*hclsyntax.Body, error) {
		return d.cachedParseBody(file.OriginalData, file.FilePath)
	}
	detection = detectKeyParts(ctx, detection, keyParts, extracted, lines, file.Kind, file.Document, file.LineInfoDocument, parse, d)

	if detection.FoundAtLeastOne {
		line := detection.CurrentLine + 1
		body, parseErr := d.cachedParseBody(file.OriginalData, file.FilePath)
		if parseErr != nil {
			contextLogger.Error().Err(parseErr).Msgf("Failed to parse block at line %d in file %s", line, file.FilePath)
			return buildEmptyVulnerabilityLines(file)
		}
		heredocs, ok := file.LinesContaining("<<")
		if ok && heredocs == nil {
			heredocs = []int{}
		}
		vulnLines, err := locateTerraformBlock(ctx, body, line, lines, heredocs)
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

// detectKeyParts walks the search key part by part. A search key names one
// block, so once the search is inside it, a part only matching text past it
// (inside a heredoc, say) is skipped and the search goes on from the last line
// found within it.
func detectKeyParts(
	ctx context.Context,
	detection *detector.DefaultDetectLineResponse,
	keyParts []string,
	extracted [][]string,
	lines []string,
	kind model.FileKind,
	doc, lineDoc model.Document,
	parse func() (*hclsyntax.Body, error),
	d *DetectKindLine,
) *detector.DefaultDetectLineResponse {
	var scope *hclsyntax.Block
	if body, err := parse(); err == nil {
		scope = searchKeyBlock(body, keyParts, extracted, d.blocksByName(body))
	}
	inScope := false
	cursor := newDocCursor(doc, extracted)
	lineCursor := newDocCursor(lineDoc, extracted)
	cursor.memo, lineCursor.memo = &d.blockLines, &d.blockLines
	for _, part := range keyParts {
		prevLine, prevFound := detection.CurrentLine, detection.FoundAtLeastOne
		repeated := withSourceLines(cursor.advance(part), lineCursor.advance(part))
		s1, s2, idx := generateSubstrings(ctx, part, extracted, lines, detection.CurrentLine, parse, repeated)

		// Jumps to line in case of multiline Array
		if idx != 0 {
			detection.CurrentLine = idx
		} else {
			detection, _, _, _ = detection.DetectCurrentLine(s1, s2, 0, lines, kind)
		}
		if scope != nil && detection.FoundAtLeastOne {
			within := blockSpansLine(scope, detection.CurrentLine+1)
			if inScope && !within {
				detection.CurrentLine, detection.FoundAtLeastOne = prevLine, prevFound
				continue
			}
			inScope = within
		}
		if detection.IsBreak {
			break
		}
	}
	return detection
}

func detectJSONConfigLine(
	ctx context.Context, file *model.FileMetadata, keyParts []string, extracted [][]string, outputLines int,
) model.VulnerabilityLines {
	lines := file.Lines()
	current := 0
	found := false
	for _, part := range keyParts {
		s1, s2, idx := GenerateSubstrings(ctx, part, extracted, lines, current, file.OriginalData)
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
		FileSource:     file.Lines(),
	}
}

var formattedIntIndexRegex = regexp.MustCompile(`\[%!s\(int=(\d+)\)\]`)

func sanitizeSearchKey(key string) string {
	if !strings.Contains(key, "%!s(int=") {
		return key
	}
	return formattedIntIndexRegex.ReplaceAllString(key, "[$1]")
}

// locateTerraformBlock finds the block containing identifyingLine in a pre-parsed
// HCL body and returns its location metadata. The caller is responsible for
// parsing (and optionally caching) the body via cachedParseBody.
func locateTerraformBlock(
	ctx context.Context,
	body *hclsyntax.Body,
	identifyingLine int,
	strLines []string,
	heredocs []int,
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
		return vulnerabilityLinesFromBlock(block, identifyingLine, strLines, heredocs), nil
	}
	if block := nearestBlock(body.Blocks, identifyingLine); block != nil {
		return vulnerabilityLinesFromBlock(block, identifyingLine, strLines, heredocs), nil
	}

	contextLogger.Warn().Msgf("using line %d as location because no HCL block was found", identifyingLine)
	return syntheticVulnerabilityLines(identifyingLine, strLines), nil
}

func blockContainingLine(blocks hclsyntax.Blocks, line int) *hclsyntax.Block {
	for _, block := range blocks {
		if blockSpansLine(block, line) {
			return block
		}
	}
	return nil
}

var searchKeyBlockPart = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_-]*)\[(.+)\]$`)

var labelOnlyBlockTypes = map[string]bool{"module": true, "variable": true, "output": true}

// searchKeyBlock returns the top-level block a search key names, as in
// resource.aws_s3_bucket[name] or data.aws_ami[name], or nil when the key
// names none unambiguously.
func searchKeyBlock(body *hclsyntax.Body, keyParts []string, extracted [][]string, index namedBlocks) *hclsyntax.Block {
	if len(keyParts) == 0 {
		return nil
	}
	parts, blockType := keyParts, ""
	if parts[0] == blockTypeResource || parts[0] == blockTypeData {
		blockType, parts = parts[0], parts[1:]
	}
	if len(parts) == 0 {
		return nil
	}
	m := searchKeyBlockPart.FindStringSubmatch(parts[0])
	if m == nil {
		return nil
	}
	typ, name := m[1], m[2]
	if strings.HasPrefix(name, "{{") && strings.HasSuffix(name, "}}") {
		name = name[2 : len(name)-2]
		if i, err := strconv.Atoi(name); err == nil && i >= 0 && i < len(extracted) {
			name = extracted[i][1]
		}
	}
	if index != nil {
		return uniqueBlock(namedCandidates(index, blockType, typ, name))
	}
	var found *hclsyntax.Block
	for _, block := range body.Blocks {
		if !blockNamed(block, blockType, typ, name) {
			continue
		}
		if found != nil {
			return nil
		}
		found = block
	}
	return found
}

// namedCandidates lists the blocks of the index blockNamed accepts.
func namedCandidates(index namedBlocks, blockType, typ, name string) [][]*hclsyntax.Block {
	switch {
	case blockType == "" && labelOnlyBlockTypes[typ]:
		return [][]*hclsyntax.Block{index[blockKey(typ, name)]}
	case blockType == "":
		return [][]*hclsyntax.Block{index[blockKey(blockTypeResource, typ, name)], index[blockKey(blockTypeData, typ, name)]}
	default:
		return [][]*hclsyntax.Block{index[blockKey(blockType, typ, name)]}
	}
}

// uniqueBlock returns the only block of the lists, or nil when there is not
// exactly one.
func uniqueBlock(lists [][]*hclsyntax.Block) *hclsyntax.Block {
	var found *hclsyntax.Block
	for _, list := range lists {
		for _, block := range list {
			if found != nil {
				return nil
			}
			found = block
		}
	}
	return found
}

func blockNamed(block *hclsyntax.Block, blockType, typ, name string) bool {
	if blockType == "" && labelOnlyBlockTypes[typ] {
		return block.Type == typ && len(block.Labels) == 1 && block.Labels[0] == name
	}
	if blockType == "" && block.Type != blockTypeResource && block.Type != blockTypeData {
		return false
	}
	if blockType != "" && block.Type != blockType {
		return false
	}
	return len(block.Labels) == 2 && block.Labels[0] == typ && block.Labels[1] == name
}

func blockSpansLine(block *hclsyntax.Block, line int) bool {
	return line >= block.TypeRange.Start.Line && line <= block.Body.SrcRange.End.Line
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

func vulnerabilityLinesFromBlock(block *hclsyntax.Block, identifyingLine int, strLines []string, heredocs []int) model.VulnerabilityLines {
	start := block.TypeRange.Start
	end := block.Body.SrcRange.End
	anchor := identifyingLine
	if identifyingLine < start.Line || identifyingLine > end.Line {
		anchor = start.Line
	}
	insertionLine, insertionCol := calculateInsertionPoint(block, anchor, strLines, heredocs)
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
func calculateInsertionPoint(block *hclsyntax.Block, line int, lines []string, heredocs []int) (insertionLine, col int) {
	name, nestedStart, nestedEnd, isAttr := findContainingStructure(block, line)

	var caseType string

	if name != "" {
		// When the containing attribute is a function-call wrapper (e.g. jsonencode(...),
		// merge(..., { ... })), we only push the anchor past the wrapper on the degenerate
		// boundary where the identifying line coincides with the wrapper's closing line —
		// otherwise injected HCL could corrupt a single-line wrapped expression. For every
		// other case the identifying line lies inside the wrapped body, which is where both
		// SARIF regions and attribute-level remediations should anchor.
		// Single-line calls (file(), including "${...}" interpolation) share start and end;
		// keep that line before the wrapper heuristic, which also matches `{`.
		lineText := strings.TrimSpace(lines[nestedStart.Line-1])
		isFunctionCallWrapper := isAttr && strings.Contains(lineText, "(") && strings.Contains(lineText, "{")
		switch {
		case nestedStart.Line == nestedEnd.Line:
			insertionLine = line
			caseType = strNestedBody
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
	if caseType == "block-start" && (strings.Contains(trimmed, "}") || isHeredocTerminator(trimmed, lines, insertionLine-1, heredocs)) {
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

// isHeredocTerminator reports whether line ends the heredoc opened by the
// nearest line above idx with one "<<". heredocs, when not nil, lists the lines
// containing "<<" in ascending order, so only those are read.
func isHeredocTerminator(line string, lines []string, idx int, heredocs []int) bool {
	if heredocs != nil {
		return isHeredocTerminatorAt(line, lines, heredocs[:sort.SearchInts(heredocs, idx)])
	}
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

// isHeredocTerminatorAt is isHeredocTerminator reading only the lines above
// idx that contain "<<" (heredocs, ascending), the only ones its search stops
// at: each block of a file would otherwise read every line above it.
func isHeredocTerminatorAt(line string, lines []string, heredocs []int) bool {
	for k := len(heredocs) - 1; k >= 0; k-- {
		parts := strings.Split(strings.TrimSpace(lines[heredocs[k]]), "<<")
		if len(parts) == 2 {
			return line == strings.TrimSpace(parts[1])
		}
	}
	return false
}
