/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package detector

import (
	"context"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

const (
	undetectedVulnerabilityLine = -1
	// resource, type, and name; the resource block's own header line is now
	// injected into the remapped plan document (see pkg/parser/json/tfplan.go),
	// so a bare resource-level searchKey can resolve structurally too.
	tfPlanMinAttributePathLen = 3
)

type defaultDetectLine struct {
}

// DetectLine searches vulnerability line if kindDetectLine is not in detectors
func (d defaultDetectLine) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string,
	outputLines int) model.VulnerabilityLines {
	contextLogger := logger.FromContext(ctx)
	detector := &DefaultDetectLineResponse{
		CurrentLine:     0,
		IsBreak:         false,
		FoundAtLeastOne: false,
		ResolvedFile:    file.FilePath,
		ResolvedFiles:   d.prepareResolvedFiles(file.ResolvedFiles),
		File:            file,
	}

	lines := file.Lines()

	// Terraform plan JSON is remapped under a top-level "resource" key, so the
	// resource block has no source text to match. Resolve the searchKey path
	// structurally (mirroring the legacy searchLine) before any text matching.
	if file.Kind == model.KindTerraformPlan {
		if result := detectTerraformPlanLine(searchKey, file, detector.ResolvedFile, outputLines, lines); result != nil {
			return *result
		}
	}

	// Deep anchored keys (e.g. Ansible's "name={{task}}.{{module}}.policy.Statement[0].Principal")
	// resolve structurally: the text matcher cannot advance through bracket indices.
	if result := detectAnchoredLine(searchKey, file, detector.ResolvedFile, outputLines, lines); result != nil {
		return *result
	}

	var extractedString [][]string
	extractedString = GetBracketValues(searchKey, extractedString, "")
	sanitizedSubstring := searchKey
	for idx, str := range extractedString {
		sanitizedSubstring = strings.ReplaceAll(sanitizedSubstring, str[0], `{{`+strconv.Itoa(idx)+`}}`)
	}
	splitSanitized := strings.Split(sanitizedSubstring, ".")

	// Re-join $ref segments split by dot (e.g. "$ref=#/schemas/v1.0.Foo" → ["v1","0","Foo"])
	// before the numeric-index check runs.
	for index, split := range splitSanitized {
		if strings.Contains(split, "$ref") {
			splitSanitized[index] = strings.Join(splitSanitized[index:], ".")
			splitSanitized = splitSanitized[:index+1]
			break
		}
	}

	// Numeric segments (e.g. "0" in "rules.0.apiGroups") have no literal text in the
	// source file, so the text-matcher cannot advance through them. handleArrayIndex
	// tries a structured gjson lookup first; on failure it strips numerics and falls
	// back to the text-matcher.
	if result, remaining := handleArrayIndex(
		splitSanitized,
		extractedString,
		file,
		detector.ResolvedFile,
		outputLines,
		lines,
		file.Kind == model.KindTerraformPlan,
	); result != nil {
		return *result
	} else if remaining != nil {
		splitSanitized = remaining
	}

	start, end := model.ResourceLine{}, model.ResourceLine{}
	for _, key := range splitSanitized {
		substr1, substr2 := GenerateSubstrings(ctx, key, extractedString, lines, detector.CurrentLine)

		// BICEP-specific tweaks in order to make bicep files compatible with ARM queries
		if file.Kind == "BICEP" {
			substr1 = strings.ReplaceAll(substr1, "resources", "resource")
			substr1 = strings.ReplaceAll(substr1, "parameters", "param")
			substr1 = strings.ReplaceAll(substr1, "variables", "variable")
		}
		detector, start, end, lines = detector.DetectCurrentLine(substr1, substr2, 0, lines, file.Kind)

		if detector.IsBreak {
			break
		}
	}

	if detector.FoundAtLeastOne {
		return model.VulnerabilityLines{
			Line:         detector.CurrentLine + 1,
			VulnLines:    GetAdjacentVulnLines(detector.CurrentLine, outputLines, lines),
			ResolvedFile: detector.ResolvedFile,
			VulnerablilityLocation: model.ResourceLocation{
				Start: start,
				End:   end,
			},
		}
	}

	var filePathSplit = strings.Split(file.FilePath, "/")
	contextLogger.Warn().Msgf("Failed to detect line associated with identified result in file %s", filePathSplit[len(filePathSplit)-1])

	return model.VulnerabilityLines{
		Line:         undetectedVulnerabilityLine,
		VulnLines:    &[]model.CodeLine{},
		ResolvedFile: detector.ResolvedFile,
	}
}

// detectTerraformPlanLine resolves a plan searchKey (e.g. "type[name].attr")
// against the remapped "resource.type.name" document. Returns nil when the path
// cannot be resolved so the caller can fall back to text matching.
func detectTerraformPlanLine(
	searchKey string,
	file *model.FileMetadata,
	resolvedFile string,
	outputLines int,
	lines []string,
) *model.VulnerabilityLines {
	path, explicitResourcePath := terraformPlanPath(searchKey)
	if len(path) < tfPlanMinAttributePathLen && !explicitResourcePath {
		return nil
	}
	lineNr := GetLineBySearchLine(path, file)
	if lineNr < 1 {
		lineNr = planBlockLine(file.LineInfoDocument, path)
	}
	// lineNr == 1 means _dd_lines were computed from minified (single-line) JSON;
	// the plan opening "{" sits on line 1 so that value is never a real attribute
	// line. Fall through to text matching, which runs on the pretty-printed content.
	if lineNr <= 1 || lineNr > len(lines) {
		return nil
	}
	return &model.VulnerabilityLines{
		Line:         lineNr,
		VulnLines:    GetAdjacentVulnLines(lineNr-1, outputLines, lines),
		ResolvedFile: resolvedFile,
		VulnerablilityLocation: model.ResourceLocation{
			Start: model.ResourceLine{Line: lineNr},
			End:   model.ResourceLine{Line: lineNr},
		},
	}
}

// expandSearchKeyPath turns a search key into structural path components:
// dropping any value anchor ("key=value"), splitting on top-level dots, and
// expanding bracket groups ("group[name]" -> group, name), stripping the
// "{{ }}" templating some Rego rules wrap the name in.
//
// Bracket contents can contain dots (module-prefixed keys, e.g.
// "type[module.foo.name]") and/or a count/for_each suffix bracket (e.g.
// "type[this[0]]"), so the top-level dot-split ignores dots inside an
// unclosed "[...]" (see splitTopLevelDots), and a group's closing bracket is
// found by findMatchingBracket, which is quote- and nesting-aware since a
// for_each key can itself contain a literal "]" (e.g. module.secrets["prod]eu"]).
func expandSearchKeyPath(searchKey string) []string {
	// Drop the value anchor (key=value) up front; the value may contain dots.
	if eq := strings.Index(searchKey, "="); eq >= 0 {
		searchKey = searchKey[:eq]
	}
	var comps []string
	for _, seg := range splitTopLevelDots(searchKey) {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		for seg != "" {
			open := strings.Index(seg, "[")
			if open < 0 {
				if seg != "" {
					comps = append(comps, seg)
				}
				break
			}
			if head := seg[:open]; head != "" {
				comps = append(comps, head)
			}
			closeIdx := findMatchingBracket(seg, open)
			if closeIdx < 0 {
				break
			}
			inner := seg[open+1 : closeIdx]
			inner = strings.TrimPrefix(inner, "{{")
			inner = strings.TrimSuffix(inner, "}}")
			if inner != "" {
				comps = append(comps, inner)
			}
			seg = seg[closeIdx+1:]
		}
	}
	return comps
}

// terraformPlanPath turns a plan searchKey into structural path components for
// GetLineBySearchLine, rooted at the plan's top-level "resource" key; see
// expandSearchKeyPath for the expansion rules.
func terraformPlanPath(searchKey string) ([]string, bool) {
	comps := expandSearchKeyPath(searchKey)
	explicitResourcePath := len(comps) > 0 && comps[0] == "resource"
	if explicitResourcePath {
		comps = comps[1:]
	}
	return append([]string{"resource"}, comps...), explicitResourcePath
}

// findMatchingBracket finds the "]" closing the "[" at open in s, tracking
// nested brackets and quoting so a quoted for_each key's own "]" isn't mistaken
// for the group's close.
func findMatchingBracket(s string, open int) int {
	inQuotes := false
	depth := 0
	for i := open + 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if inQuotes {
				i++ // skip the escaped character
			}
		case '"':
			inQuotes = !inQuotes
		case '[':
			if !inQuotes {
				depth++
			}
		case ']':
			if inQuotes {
				continue
			}
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}

// splitTopLevelDots splits s on "." like strings.Split, except dots inside an
// unclosed "[...]" group aren't treated as separators, e.g.
// "type[module.foo.name].attr" splits into ["type[module.foo.name]", "attr"].
// Quote-aware like findMatchingBracket.
func splitTopLevelDots(s string) []string {
	var segs []string
	depth, start := 0, 0
	inQuotes := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			if inQuotes {
				i++
			}
		case '"':
			inQuotes = !inQuotes
		case '[':
			if !inQuotes {
				depth++
			}
		case ']':
			if !inQuotes && depth > 0 {
				depth--
			}
		case '.':
			if depth == 0 && !inQuotes {
				segs = append(segs, s[start:i])
				start = i + 1
			}
		}
	}
	return append(segs, s[start:])
}

// handleArrayIndex handles paths that contain numeric segments. It first attempts a
// structured gjson lookup (precise, handles array indices and numeric map keys). On
// failure it strips numerics and returns the remainder for the text-matcher fallback.
// Returns (nil, nil) when no numeric segment is present.
func handleArrayIndex(
	splitSanitized []string,
	extractedString [][]string,
	file *model.FileMetadata,
	resolvedFile string,
	outputLines int,
	lines []string,
	skipStructuredLookup bool,
) (result *model.VulnerabilityLines, remaining []string) {
	hasNumeric := false
	for _, seg := range splitSanitized {
		if _, err := strconv.Atoi(seg); err == nil {
			hasNumeric = true
			break
		}
	}
	if !hasNumeric {
		return nil, nil
	}

	if !skipStructuredLookup {
		// Strip value anchors (key=value → key) so gjson receives a pure key path.
		// Paths with mid-path anchors (e.g. "meta.name={{pod}}.spec...") resolve to a
		// nonexistent gjson path and return -1, falling through to the text-matcher.
		structPath := extractStructuralPath(splitSanitized, extractedString)
		if lineNr := GetLineBySearchLine(structPath, file); lineNr > 0 && lineNr <= len(lines) {
			result := model.VulnerabilityLines{
				Line:         lineNr,
				VulnLines:    GetAdjacentVulnLines(lineNr-1, outputLines, lines),
				ResolvedFile: resolvedFile,
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: lineNr},
					End:   model.ResourceLine{Line: lineNr},
				},
			}
			return &result, nil
		}
	}

	filtered := splitSanitized[:0]
	for _, s := range splitSanitized {
		if _, err := strconv.Atoi(s); err != nil {
			filtered = append(filtered, s)
		}
	}
	return nil, filtered
}

// extractStructuralPath converts a sanitized segment list into a plain key path for
// GetLineBySearchLine: resolves {{N}} placeholders, strips value anchors (key=value →
// key), and preserves numeric indices.
func extractStructuralPath(segments []string, extracted [][]string) []string {
	result := make([]string, 0, len(segments))
	for _, seg := range segments {
		for i, ext := range extracted {
			seg = strings.ReplaceAll(seg, `{{`+strconv.Itoa(i)+`}}`, ext[1])
		}
		if idx := strings.Index(seg, "="); idx >= 0 {
			seg = seg[:idx]
		}
		if seg != "" {
			result = append(result, seg)
		}
	}
	return result
}

func (d defaultDetectLine) prepareResolvedFiles(resFiles map[string]model.ResolvedFile) map[string]model.ResolvedFileSplit {
	resolvedFiles := make(map[string]model.ResolvedFileSplit)
	for f, res := range resFiles {
		resolvedFiles[f] = model.ResolvedFileSplit{
			Path:  res.Path,
			Lines: *res.LinesContent,
		}
	}
	return resolvedFiles
}

// planBlockLine resolves a resource.<type>.<name>.<attr>... path through plan
// line info. Plan JSON wraps every nested block in a one-element array, whose
// element line info lives in the parent's _dd_<key>._dd_arr rather than in the
// element, so it walks the document and its line map together. Blocks without
// an explicit index resolve only when the array has a single element. Returns
// -1 when the path does not resolve.
func planBlockLine(doc interface{}, path []string) int {
	const resourcePathLen = 3
	if len(path) <= resourcePathLen {
		return -1
	}
	node, ok := resolvePath(doc, path[:resourcePathLen])
	if !ok {
		return -1
	}
	lineMap, ok := childAt(node, "_dd_lines")
	if !ok {
		return -1
	}
	for i := resourcePathLen; i < len(path); i++ {
		entry, ok := childAt(lineMap, "_dd_"+path[i])
		if !ok {
			return -1
		}
		if i == len(path)-1 {
			return lineAtPath(entry, []string{"_dd_line"})
		}
		child, ok := childAt(node, path[i])
		if !ok {
			return -1
		}
		switch c := child.(type) {
		case []interface{}:
			element, elementLines, consumed, ok := planArrayElement(c, entry, path, i)
			if !ok {
				return -1
			}
			i += consumed
			if i == len(path)-1 {
				return lineAtPath(elementLines, []string{"_dd__default", "_dd_line"})
			}
			node, lineMap = element, elementLines
		case map[string]interface{}:
			node = c
			if lineMap, ok = childAt(c, "_dd_lines"); !ok {
				return -1
			}
		default:
			return -1
		}
	}
	return -1
}

// planArrayElement selects the element of a plan block array that path[i]
// addresses. A numeric path[i+1] is the explicit index and counts as consumed;
// without one the array must hold exactly one element. It returns the element,
// its line info and the number of extra path segments consumed.
func planArrayElement(arr []interface{}, entry interface{}, path []string, i int) (element, lines interface{}, consumed int, ok bool) {
	idx := 0
	if n, err := strconv.Atoi(path[i+1]); err == nil {
		idx = n
		consumed = 1
	} else if len(arr) != 1 {
		return nil, nil, 0, false
	}
	if idx < 0 || idx >= len(arr) {
		return nil, nil, 0, false
	}
	lines, ok = resolvePath(entry, []string{"_dd_arr", strconv.Itoa(idx)})
	if !ok {
		return nil, nil, 0, false
	}
	return arr[idx], lines, consumed, true
}
