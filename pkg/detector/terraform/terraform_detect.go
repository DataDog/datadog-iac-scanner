/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
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

// hclCacheCap bounds the bodies a detector keeps for files with no line-info
// source.
const hclCacheCap = 256

// DetectKindLine finds a finding's lines in a Terraform file. The file's HCL
// body is the one its line-info reparse built, when that reparse parsed the
// file's own content. A file with no line-info source has no lease to bound
// a cached body on, so its parse is kept in a capped cache keyed by a hash of
// its path and content: module copies of one file share a parse, and two
// contents at one path do not. A failed parse is kept too.
type DetectKindLine struct {
	mu       sync.Mutex
	hclCache map[[sha256.Size]byte]hclCacheEntry
	// parseBody parses HCL source; nil means parseHCLBody.
	parseBody func(src, filePath string) (*hclsyntax.Body, error)
}

type hclCacheEntry struct {
	body *hclsyntax.Body
	err  error
}

func (d *DetectKindLine) parse(src, filePath string) (*hclsyntax.Body, error) {
	if d.parseBody != nil {
		return d.parseBody(src, filePath)
	}
	return parseHCLBody(src, filePath)
}

func (d *DetectKindLine) cachedParseBody(file *model.FileMetadata) (*hclsyntax.Body, error) {
	if !file.HasLineInfoSource() {
		return d.parseFile(file)
	}
	body, err := file.Derived(model.HCLBodyKey, func() (any, error) {
		return d.parse(file.OriginalData, file.FilePath)
	})
	if err != nil || body == nil {
		return nil, err
	}
	parsed, ok := body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("unexpected HCL body type")
	}
	return parsed, nil
}

// parseFile parses a file that has no line-info source to hold a Derived
// body on, through the detector's capped cache.
func (d *DetectKindLine) parseFile(file *model.FileMetadata) (*hclsyntax.Body, error) {
	key := hclCacheKey(file.FilePath, file.OriginalData)
	d.mu.Lock()
	cached, ok := d.hclCache[key]
	d.mu.Unlock()
	if ok {
		return cached.body, cached.err
	}

	body, err := d.parse(file.OriginalData, file.FilePath)

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.hclCache == nil {
		d.hclCache = make(map[[sha256.Size]byte]hclCacheEntry)
	}
	if _, ok := d.hclCache[key]; !ok && len(d.hclCache) >= hclCacheCap {
		for evict := range d.hclCache {
			delete(d.hclCache, evict)
			break
		}
	}
	d.hclCache[key] = hclCacheEntry{body: body, err: err}
	return body, err
}

func hclCacheKey(filePath, src string) [sha256.Size]byte {
	h := sha256.New()
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], uint64(len(filePath)))
	h.Write(n[:])
	h.Write([]byte(filePath))
	h.Write([]byte(src))
	var key [sha256.Size]byte
	h.Sum(key[:0])
	return key
}

func parseHCLBody(src, filePath string) (*hclsyntax.Body, error) {
	hclFile, diagnostics := hclsyntax.ParseConfig([]byte(src), filePath, hcl.InitialPos)
	if diagnostics.HasErrors() {
		return nil, fmt.Errorf("failed to parse HCL: %v", diagnostics.Errs())
	}
	body, ok := hclFile.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("unexpected HCL body type")
	}
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

	// A file without a line-info source has no lease to keep the body on, so
	// the body is parsed at most once here and handed to every step.
	var body *hclsyntax.Body
	var parseErr error
	parsed := false
	parse := func() (*hclsyntax.Body, error) {
		if !parsed {
			body, parseErr = d.cachedParseBody(file)
			parsed = true
		}
		return body, parseErr
	}
	detection = detectKeyParts(ctx, detection, keyParts, extracted, lines, file.Kind, file.Document, file.LineInfoDocument, parse)

	if detection.FoundAtLeastOne {
		line := detection.CurrentLine + 1
		body, parseErr := parse()
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

// detectKeyParts walks the search key part by part. A search key names one
// block, so once a part has matched inside it, a later part only matching text
// past it (inside a heredoc, say) is skipped. If nothing matches inside the
// block, the search falls back to the whole file.
func detectKeyParts(
	ctx context.Context,
	detection *detector.DefaultDetectLineResponse,
	keyParts []string,
	extracted [][]string,
	lines []string,
	kind model.FileKind,
	doc, lineDoc model.Document,
	parse func() (*hclsyntax.Body, error),
) *detector.DefaultDetectLineResponse {
	var scope *hclsyntax.Block
	if body, err := parse(); err == nil {
		scope = searchKeyBlock(detection.File, body, keyParts, extracted)
	}
	startLine := detection.CurrentLine
	detection = walkKeyParts(ctx, detection, keyParts, extracted, lines, kind, doc, lineDoc, parse, scope)
	if scope != nil && !detection.FoundAtLeastOne {
		detection.CurrentLine = startLine
		detection.IsBreak = false
		detection.SetSearchEnd(0)
		detection = walkKeyParts(ctx, detection, keyParts, extracted, lines, kind, doc, lineDoc, parse, nil)
	}
	return detection
}

// walkKeyParts searches keyParts from detection.CurrentLine. When scope is set,
// the search starts at that block and only keeps matches on lines it spans.
func walkKeyParts(
	ctx context.Context,
	detection *detector.DefaultDetectLineResponse,
	keyParts []string,
	extracted [][]string,
	lines []string,
	kind model.FileKind,
	doc, lineDoc model.Document,
	parse func() (*hclsyntax.Body, error),
	scope *hclsyntax.Block,
) *detector.DefaultDetectLineResponse {
	if scope != nil && scope.TypeRange.Start.Line > 0 {
		detection.CurrentLine = scope.TypeRange.Start.Line - 1
		if scope.Body != nil && scope.Body.SrcRange.End.Line > detection.CurrentLine {
			detection.SetSearchEnd(scope.Body.SrcRange.End.Line)
		}
	}
	cursor := newDocCursor(doc, extracted)
	lineCursor := newDocCursor(lineDoc, extracted)
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
		// Do not treat the search as inside the block until a part matches on
		// a line it spans; out-of-block hits are only kept on the full-file pass.
		if scope != nil && detection.FoundAtLeastOne && !blockSpansLine(scope, detection.CurrentLine+1) {
			detection.CurrentLine, detection.FoundAtLeastOne = prevLine, prevFound
			continue
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

// blockIndexAfter is the first block whose header is past line. Blocks come
// from the parser in source order, so their start lines only increase.
func blockIndexAfter(blocks hclsyntax.Blocks, line int) int {
	return sort.Search(len(blocks), func(i int) bool {
		return blocks[i].TypeRange.Start.Line > line
	})
}

func blockContainingLine(blocks hclsyntax.Blocks, line int) *hclsyntax.Block {
	i := blockIndexAfter(blocks, line)
	if i == 0 {
		return nil
	}
	if blockSpansLine(blocks[i-1], line) {
		return blocks[i-1]
	}
	return nil
}

var searchKeyBlockPart = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_-]*)\[(.+)\]$`)

var labelOnlyBlockTypes = map[string]bool{"module": true, "variable": true, "output": true}

// searchKeyBlock returns the top-level block a search key names, as in
// resource.aws_s3_bucket[name] or data.aws_ami[name], or nil when the key
// names none unambiguously.
func searchKeyBlock(file *model.FileMetadata, body *hclsyntax.Body, keyParts []string, extracted [][]string) *hclsyntax.Block {
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
	return blocksOf(file, body).get(blockType, typ, name)
}

// terraformBlockIndexKey keeps one name-to-block map for the file's HCL body
// while a lease holds the parse. Building it per finding walks every earlier
// block again.
var terraformBlockIndexKey = model.NewDerivedKey("terraform.blockIndex")

// blockIndex maps a block's type and labels to that block. A nil value means
// more than one block has those labels, which the search treats as no block.
type blockIndex struct {
	unique map[string]*hclsyntax.Block
}

func (idx *blockIndex) add(key string, block *hclsyntax.Block) {
	if prev, ok := idx.unique[key]; ok && prev != nil {
		idx.unique[key] = nil
		return
	}
	if _, ok := idx.unique[key]; ok {
		return
	}
	idx.unique[key] = block
}

func (idx *blockIndex) get(blockType, typ, name string) *hclsyntax.Block {
	if idx == nil {
		return nil
	}
	var key string
	switch {
	case blockType == "" && labelOnlyBlockTypes[typ]:
		key = typ + "\x00" + name
	case blockType == "":
		key = "\x00" + typ + "\x00" + name
	default:
		key = blockType + "\x00" + typ + "\x00" + name
	}
	return idx.unique[key]
}

func indexBlocks(body *hclsyntax.Body) *blockIndex {
	idx := &blockIndex{unique: map[string]*hclsyntax.Block{}}
	if body == nil {
		return idx
	}
	for _, block := range body.Blocks {
		switch {
		case (block.Type == blockTypeResource || block.Type == blockTypeData) && len(block.Labels) == 2:
			labels := block.Labels[0] + "\x00" + block.Labels[1]
			idx.add(block.Type+"\x00"+labels, block)
			idx.add("\x00"+labels, block)
		case labelOnlyBlockTypes[block.Type] && len(block.Labels) == 1:
			idx.add(block.Type+"\x00"+block.Labels[0], block)
		}
	}
	return idx
}

func blocksOf(file *model.FileMetadata, body *hclsyntax.Body) *blockIndex {
	if file == nil {
		return indexBlocks(body)
	}
	v, err := file.Derived(terraformBlockIndexKey, func() (any, error) {
		return indexBlocks(body), nil
	})
	idx, ok := v.(*blockIndex)
	if err != nil || !ok || idx == nil {
		return indexBlocks(body)
	}
	return idx
}

func blockSpansLine(block *hclsyntax.Block, line int) bool {
	return line >= block.TypeRange.Start.Line && line <= block.Body.SrcRange.End.Line
}

func nearestBlock(blocks hclsyntax.Blocks, line int) *hclsyntax.Block {
	if len(blocks) == 0 {
		return nil
	}
	i := blockIndexAfter(blocks, line)
	if i == 0 {
		return blocks[0]
	}
	if i == len(blocks) {
		return blocks[len(blocks)-1]
	}
	prev, next := blocks[i-1], blocks[i]
	prevDist := lineDistance(line, prev.TypeRange.Start.Line, prev.Body.SrcRange.End.Line)
	nextDist := lineDistance(line, next.TypeRange.Start.Line, next.Body.SrcRange.End.Line)
	// An equal distance keeps the earlier block, matching the old scan.
	if nextDist < prevDist {
		return next
	}
	return prev
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
	heredocEnd := isHeredocTerminator(trimmed, lines, insertionLine-1, block.TypeRange.Start.Line-1)
	if caseType == "block-start" && (strings.Contains(trimmed, "}") || heredocEnd) {
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

func isHeredocTerminator(line string, lines []string, idx, floor int) bool {
	if floor < 0 {
		floor = 0
	}
	for i := idx - 1; i >= floor; i-- {
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
