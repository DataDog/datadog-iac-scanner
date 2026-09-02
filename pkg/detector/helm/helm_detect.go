/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package helm

import (
	"context"
	"fmt"
	"sort"
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

	lines := make([]string, len(*file.LinesOriginalData))
	copy(lines, *file.LinesOriginalData)

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

	start, end := model.ResourceLine{}, model.ResourceLine{}
	// Since we are only looking at keys we can ignore the second value passed through '=' and '[]'
	for _, key := range strings.Split(sanitizedSubstring, ".") {
		substr1, _ := detector.GenerateSubstrings(ctx, key, extractedString, lines, curLineRes.lineRes)
		var iterStart, iterEnd model.ResourceLine
		curLineRes, iterStart, iterEnd = curLineRes.detectCurrentLine(lines, fmt.Sprintf("%s:", substr1), "", true, file.IDInfo, helmID)

		if curLineRes.breakRes {
			break
		}
		start = iterStart
		end = iterEnd
	}

	// Look at dupHistory to see if the last element was duplicate, if so
	// change the line to the last unique key
	if !curLineRes.lastUnique.unique {
		curLineRes.lineRes = curLineRes.lastUnique.lastUniqueLine
	}

	if curLineRes.foundRes {
		lineRemove := make(map[int]int)
		count := 0
		for i, line := range lines { // Remove auxiliary lines
			if strings.Contains(line, "# KICS_HELM_ID_") {
				count++
				lineRemove[i] = count
				lines = append(lines[:i], lines[i+1:]...)
			}
		}
		// Update found line
		curLineRes.lineRes = removeLines(curLineRes.lineRes, lineRemove)
		adjustedLine := curLineRes.lineRes + 1
		return model.VulnerabilityLines{
			Line:                  adjustedLine,
			VulnLines:             detector.GetAdjacentVulnLines(curLineRes.lineRes, outputLines, lines),
			LineWithVulnerability: strings.Split(lines[curLineRes.lineRes], ": ")[0],
			ResolvedFile:          file.FilePath,
			VulnerablilityLocation: model.ResourceLocation{
				Start: model.ResourceLine{Line: adjustedLine, Col: start.Col},
				End:   model.ResourceLine{Line: adjustedLine, Col: end.Col},
			},
		}
	}

	var filePathSplit = strings.Split(file.FilePath, "/")
	contextLogger.Warn().Msgf("Failed to detect line associated with identified result in file %s", filePathSplit[len(filePathSplit)-1])

	return model.VulnerabilityLines{
		Line:         undetectedVulnerabilityLine,
		VulnLines:    &[]model.CodeLine{},
		ResolvedFile: file.FilePath,
	}
}

// removeLines is used to update the vulnerability line after removing the "# KICS_HELM_ID_"
func removeLines(current int, lineRemove map[int]int) int {
	orderByKey := make([]int, len(lineRemove))
	i := 0
	for k := range lineRemove {
		orderByKey[i] = k
		i++
	}
	remove := 0
	sort.Ints(orderByKey)
	for _, k := range orderByKey {
		if current > k {
			remove = lineRemove[k]
		} else {
			break
		}
	}
	current -= remove
	return current
}

func containsHelmKey(line, key string) bool {
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
