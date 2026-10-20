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
	search := instructionKeySearch{view: match, lines: lines, starts: stageStartLines(match), exactStages: make(map[string][]int)}
	// O(S) setup: all keys share the same stage argument index.
	for stage, line := range search.starts {
		args := dockerfile.FromArguments(lines[line])
		search.exactStages[args] = append(search.exactStages[args], stage)
	}
	for _, key := range strings.Split(sKey, ".") {
		first, second := detector.GenerateSubstrings(ctx, key, extractedString, lines, 0)
		search.keys = append(search.keys, search.prepareKey(first, second))
	}
	search.attempts = make(map[stageSearch]instructionMatch)
	result := search.find(0, -1, instructionMatch{})

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

type instructionKey struct {
	first, second string
	accept        func(int, string) bool
	from          bool
	exact         []int
}
type instructionMatch struct {
	line, matched int
	start, end    model.ResourceLine
}
type stageSearch struct{ key, line, stage int }

type instructionKeySearch struct {
	view        *model.FileMetadata
	lines       []string
	starts      []int
	exactStages map[string][]int
	keys        []instructionKey
	attempts    map[stageSearch]instructionMatch
}

// prepareKey does normalization and exact-stage lookup once per key, independent
// of how many candidate stages must be searched.
func (s *instructionKeySearch) prepareKey(first, second string) instructionKey {
	first, second, accept := instructionSearch(s.view, first, second)
	key := instructionKey{first: first, second: second, accept: accept, from: accept != nil && isFromInstruction(first)}
	if first == "FROM" && second != "" {
		key.exact = s.exactStages[second]
	}
	return key
}

// find tries stage selections in source order, including selections made by
// ordinary keys after a global ARG. Ordinary keys stay in the selected stage;
// an explicit FROM may select a later one. Failed attempts retain the longest
// matched prefix, with the earliest attempt winning ties.
func (s *instructionKeySearch) find(keyIndex, stage int, result instructionMatch) (found instructionMatch) {
	if keyIndex == len(s.keys) {
		return result
	}
	state := stageSearch{keyIndex, result.line, stage}
	if previous, ok := s.attempts[state]; ok {
		return previous
	}
	defer func() { s.attempts[state] = found }()
	key := s.keys[keyIndex]
	firstStage, lastStage := stage, stage
	if key.from || stage < 0 {
		firstStage = sort.Search(len(s.starts), func(i int) bool { return s.starts[i] >= result.line })
		if !key.from {
			firstStage = -1 // The preamble has not selected a build stage yet.
		}
		lastStage = len(s.starts) - 1
	}
	exact := sort.SearchInts(key.exact, firstStage)
	useExact := key.from && exact < len(key.exact)
	best := result
	for candidate := firstStage; candidate <= lastStage; candidate++ {
		if useExact {
			if exact == len(key.exact) {
				break
			}
			candidate = key.exact[exact]
			exact++
		}
		match, ok := s.matchInStage(key, candidate, result)
		if !ok {
			continue
		}
		attempt := s.find(keyIndex+1, candidate, match)
		if attempt.matched > best.matched {
			best = attempt
		}
		if best.matched == len(s.keys) {
			return best
		}
	}
	return best
}

func (s *instructionKeySearch) matchInStage(key instructionKey, stage int, result instructionMatch) (instructionMatch, bool) {
	start, end := result.line, len(s.lines)
	if stage >= 0 {
		start = max(start, s.starts[stage])
	}
	if stage+1 < len(s.starts) {
		end = s.starts[stage+1]
	}
	if key.from {
		end = start + 1
	} // FROM candidates are tried in source order.
	if start >= end {
		return instructionMatch{}, false
	}
	det := &detector.DefaultDetectLineResponse{File: s.view, CurrentLine: start, AcceptLine: key.accept, EndLine: end}
	_, begin, finish, _ := det.DetectCurrentLine(key.first, key.second, 0, s.lines, model.KindDOCKER)
	if det.IsBreak {
		return instructionMatch{}, false
	}
	return instructionMatch{line: det.CurrentLine, matched: result.matched + 1, start: begin, end: finish}, true
}
