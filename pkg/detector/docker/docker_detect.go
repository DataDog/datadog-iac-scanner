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
type instructionKeySearch struct {
	view        *model.FileMetadata
	lines       []string
	starts      []int
	exactStages map[string][]int
	keys        []instructionKey
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

// bestSuffix keeps each threshold line while selecting its best reachable
// result in one backward pass. Distance ranks alternatives within a stage;
// stage choices retain source order when prefixes have the same length.
func (options instructionOptions) bestSuffix(rankDistance bool) {
	for i := len(options) - 2; i >= 0; i-- {
		a, b := &options[i], &options[i+1]
		longer := b.result.matched > a.result.matched
		closer := rankDistance && b.result.matched == a.result.matched && b.distance < a.distance
		if longer || closer {
			a.result, a.distance = b.result, b.distance
		}
	}
}

type instructionLayer struct {
	stages      []instructionOptions
	from, exact instructionOptions
}

func (layer instructionLayer) suffix(line, stage int, from bool) instructionMatch {
	if from {
		if exact := layer.exact.lookup(line); exact.matched > 0 {
			return exact
		}
	}
	if from || stage < 0 {
		return layer.from.lookup(line)
	}
	return layer.stages[stage+1].lookup(line)
}

// solve uses suffix dynamic programming. Each key visits candidate lines and
// stages once; transitions use binary searches into the next key's table.
// Cost is O(K*(L+S)*log(L+S)), space O(L+S) per retained layer. No stage
// suffix is enumerated again for another ordinary match in the same stage.
func (s *instructionKeySearch) solve() instructionMatch {
	next := instructionLayer{}
	for k := len(s.keys) - 1; k >= 0; k-- {
		key := s.keys[k]
		candidates := s.candidates(key.first)
		current, flat := s.newLayer(k, len(candidates))
		cursor := 0
		score := instructionScore{}
		for stage := -1; stage < len(s.starts) && cursor < len(candidates); stage++ {
			end := len(s.lines)
			if stage+1 < len(s.starts) {
				end = s.starts[stage+1]
			}
			start := cursor
			if k == 0 {
				// Root matching can finish before visiting the whole stage.
				cursor = sort.SearchInts(candidates, end)
			} else {
				for cursor < len(candidates) && candidates[cursor] < end {
					cursor++
				}
			}
			if start == cursor || (key.from && stage < 0) {
				continue
			}
			limit := end
			if key.from {
				limit = min(end, s.starts[stage]+1)
			}
			offset := len(flat)
			flat = s.stageOptions(flat, k, stage, candidates[start:cursor], limit, next, &score)
			options := flat[offset:]
			options.bestSuffix(true)
			current.stages[stage+1] = options
			if hasStage(key.exact, stage) {
				current.exact = append(current.exact, options...)
			}
			if k == 0 && s.rootComplete(key, stage, options) {
				return options[0].result
			}
		}
		current.from = slices.Clone(flat)
		current.from.bestSuffix(false)
		current.exact.bestSuffix(false)
		next = current
	}
	return next.suffix(0, -1, s.keys[0].from)
}

// Allocate one flat stage table; the root needs only one best result per stage.
func (s *instructionKeySearch) newLayer(k, candidates int) (instructionLayer, instructionOptions) {
	key := s.keys[k]
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
// complete match beats every later stage; exact FROM stages retain preference.
func (s *instructionKeySearch) rootComplete(key instructionKey, stage int, options instructionOptions) bool {
	return len(options) > 0 && options[0].result.matched == len(s.keys) &&
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

func (s *instructionKeySearch) stageOptions(options instructionOptions, k, stage int, candidates []int,
	end int, next instructionLayer, score *instructionScore) instructionOptions {
	key := s.keys[k]
	offset := len(options)
	for i := 0; i < len(candidates) && candidates[i] < end; i++ {
		line := candidates[i]
		if key.accept != nil && !key.accept(line, s.lines[line]) {
			continue
		}
		distance, start, finish, matched := score.match(key.first, key.second, s.lines, line)
		if !matched {
			continue
		}
		result := instructionMatch{line: line, matched: 1, start: start, end: finish}
		if k+1 < len(s.keys) {
			suffix := next.suffix(line, stage, s.keys[k+1].from)
			if suffix.matched > 0 {
				result = suffix
				result.matched++
			}
		}
		option := instructionOption{line: line, distance: distance, result: result}
		options = options.add(option, offset, k == 0)
		// The root layer has only the initial threshold query. Once its full
		// key matches at zero distance, later lines in this stage cannot win.
		if k == 0 && distance == 0 && result.matched == len(s.keys) {
			break
		}
	}
	return options
}

// Non-root layers retain every threshold. Root queries start at line zero, so
// only the best result within each stage is needed; ties keep source order.
func (options instructionOptions) add(option instructionOption, offset int, root bool) instructionOptions {
	if !root || len(options) == offset {
		return append(options, option)
	}
	best := &options[offset]
	if option.result.matched > best.result.matched ||
		(option.result.matched == best.result.matched && option.distance < best.distance) {
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
