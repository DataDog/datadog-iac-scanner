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
	lineInfoKey                 = "_dd_lines"
	sourcePathKey               = "_path"
	sourceDocumentIDKey         = "id"
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
	if result, ok := compiledLegacyLines(ctx, file, searchKey, outputLines); ok {
		return result
	}
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

	if result, ok := detectCloudFormationLoopLine(file, searchKey, outputLines); ok {
		return result
	}

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

	splitSanitized, extractedString := splitLegacySearchKey(searchKey, splitLiteralDots)

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
	if declaration, ok := terraformPlanDeclarationPath(searchKey, file.LineInfoDocument); ok {
		path, explicitResourcePath = declaration, true
	}
	if len(path) < tfPlanMinAttributePathLen && !explicitResourcePath {
		return nil
	}
	lineNr := GetLineBySearchLine(path, file)
	if lineNr <= 0 {
		// A path into a JSON-encoded attribute (a policy document, which rules
		// read decoded) ends on the line holding the encoded value.
		if encoded, ok := encodedAttributePath(path, file.LineInfoDocument); ok {
			lineNr = GetLineBySearchLine(encoded, file)
		}
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

// LineInfoSections returns the sections of a file's line-info document, beyond
// the ones it always holds, that line detection reads to locate searchKey:
// for a Terraform plan, prior-state data or changes under an explicit path,
// and both sections for deep anchors, which search the document as a whole.
func LineInfoSections(kind model.FileKind, searchKey string) []string {
	if kind != model.KindTerraformPlan {
		return nil
	}
	// Classify the anchored syntax before expanding an explicit path:
	// expandSearchKeyPath drops the value anchor, so its key alone can look
	// like a section name even when the selected object lives elsewhere.
	segments, extracted := splitSearchKeySegments(searchKey)
	if _, rest, anchored := parseAnchoredPrefix(segments, extracted); anchored {
		if hasNumericIndex(expandKeyPath(rest, extracted)) {
			return []string{"data", "resource_changes"}
		}
		return nil
	}
	if comps := expandSearchKeyPath(searchKey); len(comps) > 0 {
		switch comps[0] {
		case "resource_changes", "data":
			return []string{comps[0]}
		}
	}
	return nil
}

// terraformPlanDeclarationPath returns the plan path of a searchKey on a
// declaration that only the plan's configuration holds: a path rooted at
// "configuration" as it is, and an HCL-style "output[name]" or
// "variable[name]" key as the path of the only module declaring it.
func terraformPlanDeclarationPath(searchKey string, doc map[string]interface{}) ([]string, bool) {
	comps := expandSearchKeyPath(searchKey)
	if len(comps) == 0 {
		return nil, false
	}
	if comps[0] == "configuration" {
		return comps, true
	}
	section, ok := map[string]string{"output": "outputs", "variable": "variables"}[comps[0]]
	if !ok || len(comps) < 2 {
		return nil, false
	}
	var declarations [][]string
	var walk func(module interface{}, path []string)
	walk = func(module interface{}, path []string) {
		if declared, ok := childAt(module, section); ok {
			if _, ok := childAt(declared, comps[1]); ok {
				declarations = append(declarations, append(append([]string{}, path...), section, comps[1]))
			}
		}
		calls, _ := childAt(module, "module_calls")
		callMap, _ := calls.(map[string]interface{})
		for name, call := range callMap {
			if child, ok := childAt(call, "module"); ok && name != lineInfoKey {
				walk(child, append(append([]string{}, path...), "module_calls", name, "module"))
			}
		}
	}
	if root, ok := resolvePath(doc, []string{"configuration", "root_module"}); ok {
		walk(root, []string{"configuration", "root_module"})
	}
	if len(declarations) != 1 {
		return nil, false
	}
	return append(declarations[0], comps[2:]...), true
}

// encodedAttributePath returns the prefix of a plan path ending at a string
// attribute when the path continues inside it: the attribute holds a JSON
// document the rule decoded, such as an IAM policy.
func encodedAttributePath(path []string, doc map[string]interface{}) ([]string, bool) {
	var node interface{} = doc
	for i, seg := range path {
		child, ok := childAt(node, seg)
		if !ok {
			return nil, false
		}
		if _, isString := child.(string); isString {
			return path[:i+1], i+1 < len(path)
		}
		node = child
	}
	return nil, false
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
		seg = resolvePlaceholders(seg, extracted)
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

func nativeSourceDocument(file *model.FileMetadata) model.Document {
	if file.Document != nil {
		return file.Document
	}
	return file.LineInfoDocument
}
func compiledLegacyLines(
	ctx context.Context, file *model.FileMetadata, searchKey string, outputLines int,
) (model.VulnerabilityLines, bool) {
	if file.LineOverlay != nil {
		var path []string
		document := nativeSourceDocument(file)
		if document != nil {
			var value SourceValue = NativeSourceValue{Value: document}
			if file.DocumentDialect == model.GitLabDialect {
				value = WrittenSourceValue(value)
			}
			if concrete, err := ResolveLegacySourcePath(ctx, value, searchKey); err == nil {
				path = concrete.Components()
			}
		} else {
			path = SourceSearchPath(searchKey)
		}
		if path != nil {
			position := file.LineOverlay.LookupSource(path)
			source := file
			if snapshot := position.Snapshot; snapshot != nil {
				source = &model.FileMetadata{Kind: file.Kind, FilePath: snapshot.Path,
					OriginalData: snapshot.Content, LinesOriginalData: snapshot.Lines()}
			}
			if position.Line > 0 {
				if result, err := sourceLines(source, position.Line, outputLines); err == nil {
					return result, true
				}
			}
		}
	}
	return model.VulnerabilityLines{}, false
}
