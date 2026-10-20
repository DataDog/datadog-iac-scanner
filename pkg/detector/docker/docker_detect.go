package docker

import (
	"context"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/dockerfile"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/moby/buildkit/frontend/dockerfile/command"
)

// DetectKindLine defines a kindDetectLine type
type DetectKindLine struct {
}

const (
	undetectedVulnerabilityLine = -1
)

// DetectLine searches vulnerability line in docker files
func (d DetectKindLine) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string,
	outputLines int) model.VulnerabilityLines {
	var extractedString [][]string
	extractedString = detector.GetBracketValues(searchKey, extractedString, "")
	sKey := searchKey
	for idx, str := range extractedString {
		sKey = strings.ReplaceAll(sKey, str[0], `{{`+strconv.Itoa(idx)+`}}`)
	}

	unchangedText := file.Lines()
	source := file.DetectionLines(dockerfile.SourceViewKey, dockerfile.InstructionLines)
	normalized := file.DetectionLines("docker.instructions", func(_ []string) []string {
		var lines []string
		for i, line := range source {
			normalized := normalizeInstruction(line)
			if normalized != line {
				if lines == nil {
					lines = slices.Clone(source)
				}
				lines[i] = normalized
			}
		}
		if lines == nil {
			return source
		}
		return lines
	})
	// When no transformation was needed, keep the original file's index and
	// avoid retaining a second FileMetadata and lazy cache for identical lines.
	match := file
	if len(normalized) > 0 && &normalized[0] != &unchangedText[0] {
		match = file.DetectionView("docker.instructions", func([]string) []string { return normalized })
	}
	lines := match.Lines()
	search := instructionKeySearch{view: match, lines: lines, starts: stageStartLines(match)}
	for _, key := range strings.Split(sKey, ".") {
		first, second := detector.GenerateSubstrings(ctx, key, extractedString, lines, 0)
		search.keys = append(search.keys, instructionKey{first, second})
	}
	// Multiple explicit stage selectors can revisit the same suffix during
	// backtracking. Memoize those states to avoid combinatorial searches.
	fromKeys := 0
	for _, key := range search.keys {
		if isFromInstruction(key.first) {
			fromKeys++
		}
	}
	if fromKeys > 1 {
		search.attempts = make(map[stageSearch]instructionMatch)
	}
	result := search.find(0, len(lines), instructionMatch{})

	if result.matched > 0 {
		return model.VulnerabilityLines{
			Line:                  result.line + 1,
			LineWithVulnerability: source[result.line],
			VulnLines:             detector.GetAdjacentVulnLines(result.line, outputLines, unchangedText),
			ResolvedFile:          file.FilePath,
			VulnerablilityLocation: model.ResourceLocation{
				Start: result.start,
				End:   result.end,
			},
		}
	}

	return model.VulnerabilityLines{
		Line:                  undetectedVulnerabilityLine,
		VulnLines:             &[]model.CodeLine{},
		LineWithVulnerability: "",
		ResolvedFile:          file.FilePath,
	}
}

func isFromInstruction(line string) bool {
	word := dockerWordAt(line, 0)
	return strings.EqualFold(line[word.start:word.end], command.From)
}

type instructionKey struct{ first, second string }
type instructionMatch struct {
	line, matched int
	start, end    model.ResourceLine
}
type stageSearch struct{ key, line, end int }

type instructionKeySearch struct {
	view     *model.FileMetadata
	lines    []string
	starts   []int
	keys     []instructionKey
	attempts map[stageSearch]instructionMatch
}

// find retries a FROM selection when its remaining keys fail. Each attempt has
// its own stage bound. If no attempt completes, keep the longest matched prefix
// (and the earliest attempt on ties), preserving partial-location fallback.
func (s *instructionKeySearch) find(keyIndex, end int, result instructionMatch) (found instructionMatch) {
	if s.attempts != nil {
		state := stageSearch{keyIndex, result.line, end}
		if previous, ok := s.attempts[state]; ok {
			return previous
		}
		defer func() { s.attempts[state] = found }()
	}
	for ; keyIndex < len(s.keys); keyIndex++ {
		key := s.keys[keyIndex]
		stage := isFromInstruction(key.first)
		limit := end
		if stage {
			limit = len(s.lines)
		}
		first, second, accept := instructionSearch(s.view, s.starts, key.first, key.second, result.line)
		det := &detector.DefaultDetectLineResponse{File: s.view, CurrentLine: result.line, AcceptLine: accept, EndLine: limit}
		best := result
		for det.CurrentLine < limit {
			_, start, finish, _ := det.DetectCurrentLine(first, second, 0, s.lines, model.KindDOCKER)
			if det.IsBreak {
				return best
			}
			found := instructionMatch{line: det.CurrentLine, matched: result.matched + 1, start: start, end: finish}
			// Global ARG selectors do not select a stage. A match at or after the
			// first FROM selects its containing stage, including literal selectors.
			next := sort.SearchInts(s.starts, det.CurrentLine+1)
			bound := len(s.lines)
			if next > 0 && next < len(s.starts) {
				bound = s.starts[next]
			}
			if !stage {
				result, end = found, bound
				break
			}
			attempt := s.find(keyIndex+1, bound, found)
			if attempt.matched > best.matched {
				best = attempt
			}
			if best.matched == len(s.keys) {
				return best
			}
			if next == len(s.starts) {
				return best
			}
			det.CurrentLine = s.starts[next]
		}
		if stage {
			return best
		}
	}
	return result
}
