package docker

import (
	"context"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
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
	source := file.DetectionLines(sourceViewKey, instructionLines)
	normalized := file.DetectionLines("docker.instructions", func(_ []string) []string {
		var lines []string
		for i, line := range source {
			norm := normalizeInstruction(line)
			if norm != line {
				if lines == nil {
					lines = slices.Clone(source)
				}
				lines[i] = norm
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
		args := fromArguments(lines[line])
		search.exactStages[args] = append(search.exactStages[args], stage)
	}
	for _, key := range strings.Split(sKey, ".") {
		first, second := detector.GenerateSubstrings(ctx, key, extractedString, lines, 0)
		search.keys = append(search.keys, search.prepareKey(first, second))
	}
	result := search.solve()

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

type instructionKey struct {
	rawFirst, rawSecond   string
	normFirst, normSecond string
	instFirst, instSecond bool
	from                  bool
	exact                 []int
}

type instructionMatch struct {
	line, matched, instructions int
	start, end                  model.ResourceLine
}

type instructionKeySearch struct {
	view        *model.FileMetadata
	lines       []string
	starts      []int
	exactStages map[string][]int
	keys        []instructionKey
}

// prepareKey precomputes normalized instruction forms and exact-stage indexes
// while deferring stage-dependent instruction-vs-literal selection to solve().
func (s *instructionKeySearch) prepareKey(first, second string) instructionKey {
	normFirst := normalizeInstruction(first)
	instFirst := startsAtInstruction(normFirst, normFirst)
	normSecond := second
	instSecond := false
	if instFirst && (strings.EqualFold(normFirst, command.Onbuild) || strings.EqualFold(normFirst, command.Healthcheck)) {
		normSecond = normalizeInstruction(second)
		instSecond = startsAtInstruction(normFirst+" "+normSecond, normSecond)
	}
	key := instructionKey{
		rawFirst:   first,
		rawSecond:  second,
		normFirst:  normFirst,
		normSecond: normSecond,
		instFirst:  instFirst,
		instSecond: instSecond,
	}
	if instFirst && isFromInstruction(normFirst) {
		args := strings.TrimSpace(second)
		if args == "" {
			args = fromArguments(normFirst)
		}
		exact := s.exactStages[args]
		if len(exact) > 0 || s.hasMatchingStageHeader(args) {
			key.from = true
			key.normSecond = args
			if args != "" {
				key.exact = exact
			}
		}
	}
	return key
}

func (s *instructionKeySearch) hasMatchingStageHeader(args string) bool {
	for _, line := range s.starts {
		if args == "" || strings.Contains(fromArguments(s.lines[line]), args) {
			return true
		}
	}
	return false
}

type instructionOption struct {
	line, distance int
	result         instructionMatch
}
type instructionOptions []instructionOption

func (options instructionOptions) lookup(line int) instructionMatch {
	i := sort.Search(len(options), func(i int) bool { return options[i].line >= line })
	if i < len(options) {
		return options[i].result
	}
	return instructionMatch{}
}

func betterOption(a, b instructionOption, rankDistance bool) bool {
	if b.result.matched != a.result.matched {
		return b.result.matched > a.result.matched
	}
	if b.result.instructions != a.result.instructions {
		return b.result.instructions > a.result.instructions
	}
	return rankDistance && b.distance < a.distance
}

// bestSuffix keeps each threshold line while selecting its best reachable
// result in one backward pass. Distance ranks alternatives within a stage;
// stage choices retain source order when prefixes and instruction counts tie.
func (options instructionOptions) bestSuffix(rankDistance bool) {
	for i := len(options) - 2; i >= 0; i-- {
		a, b := &options[i], &options[i+1]
		if betterOption(*a, *b, rankDistance) {
			a.result, a.distance = b.result, b.distance
		}
	}
}

type instructionLayer struct {
	stages      []instructionOptions
	from, exact instructionOptions
}

func (layer *instructionLayer) suffix(line, stage int, from bool) instructionMatch {
	if from {
		nextStage := layer.exact.lookup(line)
		if nextStage.matched == 0 {
			nextStage = layer.from.lookup(line)
		}
		if stage >= 0 {
			if inStage := layer.stages[stage+1].lookup(line); inStage.matched > nextStage.matched {
				return inStage
			}
		}
		return nextStage
	}
	if stage < 0 {
		return layer.from.lookup(line)
	}
	return layer.stages[stage+1].lookup(line)
}

type keyLayerCursor struct {
	normCandidates, rawCandidates []int
	normCursor, rawCursor         int
	rawLoaded                     bool
	normScore, rawScore           instructionScore
}

func (s *instructionKeySearch) newKeyLayerCursor(key *instructionKey) keyLayerCursor {
	var normCandidates []int
	if !key.from {
		normCandidates = s.candidates(key.normFirst)
	}
	c := keyLayerCursor{normCandidates: normCandidates}
	if !key.from && key.normFirst == key.rawFirst {
		c.rawCandidates = normCandidates
		c.rawLoaded = true
	}
	return c
}

// solve uses suffix dynamic programming. Each key visits candidate lines and
// stages once; transitions use binary searches into the next key's table.
// Cost is O(K*(L+S)*log(L+S)), space O(L+S) per retained layer. No stage
// suffix is enumerated again for another ordinary match in the same stage.
func (s *instructionKeySearch) solve() instructionMatch {
	next := instructionLayer{}
	for k := len(s.keys) - 1; k >= 0; k-- {
		key := &s.keys[k]
		state := s.newKeyLayerCursor(key)
		current, flat := s.newLayer(k, max(len(state.normCandidates), len(s.starts)))
		for stage := -1; stage < len(s.starts); stage++ {
			end := s.stageEnd(stage)
			offset := len(flat)
			flat = s.collectStageOptions(flat, k, stage, end, &current, &next, &state)
			options := flat[offset:]
			if len(options) == 0 {
				continue
			}
			options.bestSuffix(true)
			current.stages[stage+1] = options
			if k == 0 && s.rootComplete(key, stage, options) {
				return options[0].result
			}
		}
		if !key.from {
			current.from = slices.Clone(flat)
		}
		current.from.bestSuffix(false)
		current.exact.bestSuffix(false)
		next = current
	}
	return next.suffix(0, -1, s.keys[0].from)
}

func (s *instructionKeySearch) stageEnd(stage int) int {
	if stage+1 < len(s.starts) {
		return s.starts[stage+1]
	}
	return len(s.lines)
}

func (s *instructionKeySearch) collectStageOptions(flat instructionOptions, k, stage, end int,
	current, next *instructionLayer, state *keyLayerCursor) instructionOptions {
	key := &s.keys[k]
	offset := len(flat)
	if key.from {
		if stage >= 0 {
			flat = s.stageFromOption(flat, k, stage, s.starts[stage], next, &state.normScore)
			if len(flat) > offset {
				current.from = append(current.from, flat[offset:]...)
				if hasStage(key.exact, stage) {
					current.exact = append(current.exact, flat[offset:]...)
				}
			}
		}
	} else {
		normStart := state.normCursor
		state.normCursor = advanceCursor(state.normCandidates, state.normCursor, end, k == 0)
		if key.instFirst && normStart < state.normCursor {
			flat = s.stageInstructionOptions(flat, k, stage, state.normCandidates[normStart:state.normCursor], end, next, &state.normScore)
		}
	}
	if !key.instFirst || (key.rawSecond == "" && !hasCompleteSuffix(flat[offset:], len(s.keys)-k)) {
		flat = s.collectStageLiterals(flat, offset, k, stage, end, next, state)
	}
	return flat
}

func (s *instructionKeySearch) collectStageLiterals(flat instructionOptions, offset, k, stage, end int,
	next *instructionLayer, state *keyLayerCursor) instructionOptions {
	if !state.rawLoaded {
		state.rawCandidates = s.candidates(s.keys[k].rawFirst)
		state.rawLoaded = true
	}
	stageStart := 0
	if stage >= 0 {
		stageStart = s.starts[stage]
	}
	if state.rawCursor < len(state.rawCandidates) && state.rawCandidates[state.rawCursor] < stageStart {
		state.rawCursor = advanceCursor(state.rawCandidates, state.rawCursor, stageStart, true)
	}
	rawStart := state.rawCursor
	state.rawCursor = advanceCursor(state.rawCandidates, state.rawCursor, end, k == 0)
	if rawStart >= state.rawCursor {
		return flat
	}
	instCount := len(flat) - offset
	flat = s.stageLiteralOptions(flat, k, stage, state.rawCandidates[rawStart:state.rawCursor], end, next, &state.rawScore)
	if instCount > 0 && len(flat)-offset > instCount {
		slices.SortFunc(flat[offset:], func(a, b instructionOption) int { return a.line - b.line })
	}
	return flat
}

func advanceCursor(candidates []int, cursor, end int, binary bool) int {
	if cursor >= len(candidates) || candidates[cursor] >= end {
		return cursor
	}
	if binary {
		return cursor + sort.SearchInts(candidates[cursor:], end)
	}
	for cursor < len(candidates) && candidates[cursor] < end {
		cursor++
	}
	return cursor
}

func hasCompleteSuffix(options instructionOptions, want int) bool {
	for i := range options {
		if options[i].result.matched >= want {
			return true
		}
	}
	return false
}

// Allocate one flat stage table; the root needs only one best result per stage.
func (s *instructionKeySearch) newLayer(k, candidates int) (instructionLayer, instructionOptions) {
	key := &s.keys[k]
	layer := instructionLayer{stages: make([]instructionOptions, len(s.starts)+1)}
	if key.from && len(key.exact) > 0 {
		layer.exact = make(instructionOptions, 0, len(key.exact))
	}
	if k == 0 {
		candidates = min(candidates, len(s.starts)+1)
	}
	return layer, make(instructionOptions, 0, candidates)
}

// Only the root has no later threshold queries. After scoring a stage, its
// complete instruction match beats every later stage; exact FROM stages retain preference.
func (s *instructionKeySearch) rootComplete(key *instructionKey, stage int, options instructionOptions) bool {
	return len(options) > 0 &&
		options[0].result.matched == len(s.keys) &&
		options[0].result.instructions == len(s.keys) &&
		(!key.from || len(key.exact) == 0 || hasStage(key.exact, stage))
}

func (s *instructionKeySearch) candidates(first string) []int {
	candidates, cached := s.view.LinesContaining(first)
	if !cached {
		for i, line := range s.lines {
			if strings.Contains(line, first) {
				candidates = append(candidates, i)
			}
		}
	}
	return candidates
}

func (s *instructionKeySearch) stageFromOption(options instructionOptions, k, stage, line int,
	next *instructionLayer, score *instructionScore) instructionOptions {
	key := &s.keys[k]
	distance, start, finish, matched := score.match("FROM", key.normSecond, s.lines, line)
	if !matched {
		return options
	}
	result := s.chainResult(k, stage, line, 1, start, finish, next)
	return append(options, instructionOption{line: line, distance: distance, result: result})
}

func (s *instructionKeySearch) stageInstructionOptions(options instructionOptions, k, stage int, candidates []int,
	end int, next *instructionLayer, score *instructionScore) instructionOptions {
	key := &s.keys[k]
	offset := len(options)
	for i := 0; i < len(candidates) && candidates[i] < end; i++ {
		line := candidates[i]
		text := s.lines[line]
		if !startsAtInstruction(text, key.normFirst) {
			continue
		}
		second, inst := key.rawSecond, 1
		if key.instSecond {
			if startsAtInstruction(text, key.normSecond) {
				second = key.normSecond
			} else {
				inst = 0
			}
		}
		distance, start, finish, matched := score.match(key.normFirst, second, s.lines, line)
		if !matched {
			continue
		}
		result := s.chainResult(k, stage, line, inst, start, finish, next)
		option := instructionOption{line: line, distance: distance, result: result}
		options = options.add(option, offset, k == 0)
		if k == 0 && distance == 0 && result.matched == len(s.keys) && result.instructions == len(s.keys) {
			break
		}
	}
	return options
}

func (s *instructionKeySearch) stageLiteralOptions(options instructionOptions, k, stage int, candidates []int,
	end int, next *instructionLayer, score *instructionScore) instructionOptions {
	key := &s.keys[k]
	offset := len(options)
	for i := 0; i < len(candidates) && candidates[i] < end; i++ {
		line := candidates[i]
		if key.instFirst && startsAtInstruction(s.lines[line], key.normFirst) {
			continue
		}
		distance, start, finish, matched := score.match(key.rawFirst, key.rawSecond, s.lines, line)
		if !matched {
			continue
		}
		result := s.chainResult(k, stage, line, 0, start, finish, next)
		option := instructionOption{line: line, distance: distance, result: result}
		options = options.add(option, offset, k == 0)
	}
	return options
}

func (s *instructionKeySearch) chainResult(k, stage, line, inst int,
	start, finish model.ResourceLine, next *instructionLayer) instructionMatch {
	result := instructionMatch{line: line, matched: 1, instructions: inst, start: start, end: finish}
	if k+1 < len(s.keys) {
		suffix := next.suffix(line, stage, s.keys[k+1].from)
		if suffix.matched > 0 {
			result = suffix
			result.matched++
			result.instructions += inst
		}
	}
	return result
}

// Non-root layers retain every threshold. Root queries start at line zero, so
// only the best result within each stage is needed; ties keep source order.
func (options instructionOptions) add(option instructionOption, offset int, root bool) instructionOptions {
	if !root || len(options) == offset {
		return append(options, option)
	}
	best := &options[offset]
	if betterOption(*best, option, true) {
		*best = option
	}
	return options
}

// Docker MatchLine scores only the current logical instruction. Repeated stage
// lines therefore share a score; only their row coordinates differ. Keep one
// previous score per key (O(1) space), avoiding maps on the ordinary path.
type instructionScore struct {
	text           string
	line, distance int
	start, end     model.ResourceLine
	valid, matched bool
}

func (score *instructionScore) match(first, second string, lines []string, line int) (
	distance int, start, end model.ResourceLine, matched bool) {
	if !score.valid || score.text != lines[line] {
		score.text, score.line, score.valid = lines[line], line, true
		score.distance, score.start, score.end, score.matched = detector.MatchLine(first, second, lines, line, model.KindDOCKER)
	}
	start, end = score.start, score.end
	start.Line += line - score.line
	end.Line += line - score.line
	return score.distance, start, end, score.matched
}

func hasStage(stages []int, stage int) bool {
	i := sort.SearchInts(stages, stage)
	return i < len(stages) && stages[i] == stage
}
