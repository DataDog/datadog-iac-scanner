/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package helm

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/agnivade/levenshtein"
)

// DetectKindLine defines a kindDetectLine type
type DetectKindLine struct {
}

type detectCurlLine struct {
	foundRes   bool
	lineRes    int
	breakRes   bool
	lastUnique dupHistory
}

// dupHistory keeps the history of uniques
type dupHistory struct {
	unique         bool
	lastUniqueLine int
}

const (
	undetectedVulnerabilityLine = -1
)

// DetectLine is used to detect line on the helm template,
// it looks only at the keys of the template and will make use of the auxiliary added
// lines (ex: "# KICS_HELM_ID_")
func (d DetectKindLine) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string,
	outputLines int) model.VulnerabilityLines {
	contextLogger := logger.FromContext(ctx)
	if file.HelmID != "" {
		searchKey = fmt.Sprintf("%s.%s", strings.TrimRight(strings.TrimLeft(file.HelmID, "# "), ":"), searchKey)
	}

	lines := make([]string, len(file.Lines()))
	copy(lines, file.Lines())

	curLineRes := detectCurlLine{
		foundRes: false,
		lineRes:  0,
		breakRes: false,
	}
	var extractedString [][]string
	extractedString = detector.GetBracketValues(searchKey, extractedString, "")
	sanitizedSubstring := searchKey
	for idx, str := range extractedString {
		sanitizedSubstring = strings.ReplaceAll(sanitizedSubstring, str[0], `{{`+strconv.Itoa(idx)+`}}`)
	}

	helmID, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(file.HelmID, "# KICS_HELM_ID_"), ":"))
	if err != nil {
		helmID = -1
	}

	curLineRes, start, end := curLineRes.walkSearchKey(ctx, lines, sanitizedSubstring, extractedString, file.IDInfo, helmID)

	if curLineRes.foundRes {
		unstamped, index := unstampedLines(lines)
		at := index(curLineRes.lineRes)
		adjustedLine := at + 1
		return model.VulnerabilityLines{
			Line:                  adjustedLine,
			VulnLines:             detector.GetAdjacentVulnLines(at, outputLines, unstamped),
			LineWithVulnerability: strings.Split(unstamped[at], ": ")[0],
			ResolvedFile:          file.FilePath,
			VulnerablilityLocation: model.ResourceLocation{
				Start: model.ResourceLine{Line: adjustedLine, Col: start.Col},
				End:   model.ResourceLine{Line: adjustedLine, Col: end.Col},
			},
		}
	}

	// Helm attributes named-template output to the file that invoked it. The
	// resolver records the action that actually executed, so wrappers with
	// conditional or repeated invocations can still point to the right source.
	invocation := emittingInvocation(ctx, file, sanitizedSubstring, extractedString, helmID)
	if found, ok := invocationLines(file, invocation, lines, outputLines); ok {
		return found
	}

	var filePathSplit = strings.Split(file.FilePath, "/")
	contextLogger.Warn().Msgf("Failed to detect line associated with identified result in file %s", filePathSplit[len(filePathSplit)-1])

	return model.VulnerabilityLines{
		Line:         undetectedVulnerabilityLine,
		VulnLines:    &[]model.CodeLine{},
		ResolvedFile: file.FilePath,
	}
}

// invocationLines locates a finding at the include-like action whose output
// produced it. The recorded position counts the "# KICS_HELM_ID_" lines stamped
// above it, which are left out of the reported line and snippet.
func invocationLines(
	file *model.FileMetadata, invocation model.ResourceLine, lines []string, outputLines int,
) (model.VulnerabilityLines, bool) {
	if invocation.Line < 1 || invocation.Line > len(lines) || isHelmIDLine(lines[invocation.Line-1]) {
		return model.VulnerabilityLines{}, false
	}
	unstamped, index := unstampedLines(lines)
	at := index(invocation.Line - 1)
	reported := model.ResourceLine{Line: at + 1, Col: invocation.Col}
	return model.VulnerabilityLines{
		Line:                  reported.Line,
		VulnLines:             detector.GetAdjacentVulnLines(at, outputLines, unstamped),
		LineWithVulnerability: unstamped[at],
		ResolvedFile:          file.FilePath,
		VulnerablilityLocation: model.ResourceLocation{
			Start: reported,
			End:   model.ResourceLine{Line: reported.Line, Col: len(unstamped[at])},
		},
	}, true
}

// walkSearchKey matches the keys of the sanitized search key one after the
// other in lines, each below the previous one. Since we are only looking at
// keys we can ignore the second value passed through '=' and '[]'.
func (d detectCurlLine) walkSearchKey(ctx context.Context, lines []string, sanitizedSubstring string,
	extractedString [][]string, idInfo map[int]interface{}, helmID int,
) (walked detectCurlLine, start, end model.ResourceLine) {
	for _, key := range strings.Split(sanitizedSubstring, ".") {
		substr1, _ := detector.GenerateSubstrings(ctx, key, extractedString, lines, d.lineRes)
		var iterStart, iterEnd model.ResourceLine
		d, iterStart, iterEnd = d.detectCurrentLine(lines, fmt.Sprintf("%s:", substr1), "", true, idInfo, helmID)

		if d.breakRes {
			break
		}
		start = iterStart
		end = iterEnd
	}

	// Look at dupHistory to see if the last element was duplicate, if so
	// change the line to the last unique key
	if !d.lastUnique.unique {
		d.lineRes = d.lastUnique.lastUniqueLine
	}
	return d, start, end
}

// emittingInvocation returns the invocation whose output holds the finding.
// When several invocations emitted parts of the document, the search key is
// matched in the rendered output, where those parts are, and the invocation
// emitting that line is chosen.
func emittingInvocation(ctx context.Context, file *model.FileMetadata, sanitizedSubstring string,
	extractedString [][]string, helmID int) model.ResourceLine {
	if len(file.HelmInvocations) < 2 || file.HelmRenderedContent == "" {
		return file.HelmInvocations.First()
	}
	rendered := strings.Split(file.HelmRenderedContent, "\n")
	found, _, _ := detectCurlLine{}.walkSearchKey(ctx, rendered, sanitizedSubstring, extractedString, nil, helmID)
	if !found.foundRes {
		return file.HelmInvocations.First()
	}
	return file.HelmInvocations.At(found.lineRes + 1)
}

func isHelmIDLine(line string) bool {
	return strings.Contains(line, "# KICS_HELM_ID_")
}

// unstampedLines drops the "# KICS_HELM_ID_" lines the resolver stamped into
// the rendered output. index maps a position in lines to its position in kept;
// a stamp line maps to the line that follows it.
func unstampedLines(lines []string) (kept []string, index func(int) int) {
	kept = make([]string, 0, len(lines))
	keptBefore := make([]int, len(lines))
	for i, line := range lines {
		keptBefore[i] = len(kept)
		if !isHelmIDLine(line) {
			kept = append(kept, line)
		}
	}
	return kept, func(i int) int { return keptBefore[i] }
}

func containsHelmKey(line, key string) bool {
	if isHelmIDLine(line) {
		// A stamp only stands for its own ID; "0:" must not match "# KICS_HELM_ID_40:".
		return strings.TrimSpace(line) == "# "+key
	}
	if strings.Contains(line, key) {
		return true
	}
	key = strings.TrimSuffix(key, ":")
	return strings.Contains(line, `"`+key+`":`) || strings.Contains(line, `'`+key+`':`)
}

// nolint:gocritic
func (d detectCurlLine) detectCurrentLine(lines []string, str1,
	str2 string, byKey bool, idInfo map[int]interface{}, id int) (detectCurlLine, model.ResourceLine, model.ResourceLine) {
	distances := make(map[int]int)
	starts, ends := make(map[int]model.ResourceLine), make(map[int]model.ResourceLine)
	for i := d.lineRes; i < len(lines); i++ {
		if str1 != "" && str2 != "" {
			if strings.Contains(lines[i], str1) && strings.Contains(lines[i], str2) {
				distances[i] = levenshtein.ComputeDistance(detector.ExtractLineFragment(lines[i], str2, byKey), str2)
				starts[i] = model.ResourceLine{Line: i + 1, Col: 0}
				ends[i] = model.ResourceLine{Line: i + 1, Col: len(lines[i])}
			}
		} else if str1 != "" {
			if containsHelmKey(lines[i], str1) {
				distances[i] = levenshtein.ComputeDistance(
					detector.ExtractLineFragment(strings.TrimSpace(lines[i]), str1, byKey), str1)
				starts[i] = model.ResourceLine{Line: i + 1, Col: 0}
				ends[i] = model.ResourceLine{Line: i + 1, Col: len(lines[i])}
			}
		}
	}

	lastSingle := d.lastUnique.lastUniqueLine

	if len(distances) == 0 {
		return detectCurlLine{
			foundRes: d.foundRes,
			lineRes:  d.lineRes,
			breakRes: true,
			lastUnique: dupHistory{
				lastUniqueLine: lastSingle,
				unique:         d.lastUnique.unique,
			},
		}, model.ResourceLine{}, model.ResourceLine{}
	}

	lineResponse := detector.SelectLineWithMinimumDistance(distances, d.lineRes)
	// if lineResponse is unique
	unique := detectLastSingle(lineResponse, distances, idInfo, id)
	if unique {
		lastSingle = lineResponse
	}

	return detectCurlLine{
			foundRes: true,
			lineRes:  lineResponse,
			breakRes: false,
			lastUnique: dupHistory{
				unique:         unique,
				lastUniqueLine: lastSingle,
			},
		},
		starts[lineResponse],
		ends[lineResponse]
}

// detectLastSingle checks if the line is unique or a duplicate
func detectLastSingle(line int, dis map[int]int, idInfo map[int]interface{}, id int) bool {
	if idInfo == nil {
		return true
	}
	var containsLine func(int) bool
	switch originalLines := idInfo[id].(type) {
	case model.HelmIDLineRange:
		containsLine = func(line int) bool {
			return line >= originalLines.Start && line <= originalLines.End
		}
	case map[int]int:
		containsLine = func(line int) bool {
			_, ok := originalLines[line]
			return ok
		}
	default:
		return true
	}
	for key, value := range dis {
		if value == dis[line] && key != line {
			// check if we are only looking at original data equivalent to the vulnerability
			if containsLine(key) {
				return false
			}
		}
	}
	return true
}
