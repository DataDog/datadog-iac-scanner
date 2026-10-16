package helm

import (
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/helmaction"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// resolver finds the template line that wrote a rendered line of a document.
type resolver struct {
	lines, rendered []string
	invocations     model.HelmInvocations
	start           int // source line the document starts at
	from, to        int // the document's lines, as indexes
	inInclude       []bool
	inAction        []bool
	spanned         []bool
	depths          []int
	path            []keyMatch
	tree            *keyTree
	stamp           string // the document's ID stamp, when it is in the template
	memo            map[int]resolved
	globals         map[int]resolved
	aligned         map[int]int
	once            []bool
}

// resolved is the answer for the key of the path at an index.
type resolved struct {
	line    int
	printer bool // an action that may print the text, not a line that holds it
	ok      bool
}

func newResolver(lines, rendered []string, invocations model.HelmInvocations, start int, path []keyMatch, tree *keyTree,
	stamp string,
) *resolver {
	from, to := documentLines(lines, start)
	r := &resolver{
		lines: lines, rendered: rendered, invocations: invocations, start: start,
		from: from, to: to, path: path, tree: tree, stamp: stamp, memo: map[int]resolved{}, globals: map[int]resolved{},
	}
	if from >= 0 {
		r.inInclude, r.inAction, r.spanned = actionLines(lines, invocations)
		r.depths = lineDepths(lines)
	}
	return r
}

// pathOrNil returns path when its last key is the one at line.
func pathOrNil(path []keyMatch, line int) []keyMatch {
	if len(path) > 0 && path[len(path)-1].line == line {
		return path
	}
	return nil
}

// locate returns the index of the template line that wrote rendered line
// target, the last key of the path when there is one.
func (r *resolver) locate(target int) (int, bool) {
	if len(r.path) > 0 && r.path[len(r.path)-1].line == target {
		got := r.at(len(r.path) - 1)
		return got.line, got.ok
	}
	got := r.global(target)
	return got.line, got.ok
}

// global resolves rendered line target from the whole document.
func (r *resolver) global(target int) resolved {
	if got, done := r.globals[target]; done {
		return got
	}
	if r.aligned == nil {
		r.aligned = alignment(r.lines, r.rendered, r.invocations, r.start)
	}
	var got resolved
	if line, ok := r.aligned[target]; ok {
		got = resolved{line: line, ok: true}
	} else if line, ok := r.ordinal(target); ok {
		got = resolved{line: line, ok: true}
	} else {
		line, printer, ok := r.writerIn(target, 0, len(r.rendered), r.from, r.to, false)
		got = resolved{line: line, printer: printer, ok: ok}
	}
	r.globals[target] = got
	return got
}

// at resolves the key of the path at idx: from the whole document, or else
// from within the key that holds it, as a text repeated in several of its
// siblings is only once under each.
func (r *resolver) at(idx int) resolved {
	if got, done := r.memo[idx]; done {
		return got
	}
	got := r.global(r.path[idx].line)
	if !got.ok {
		got = r.scoped(idx)
	}
	r.memo[idx] = got
	return got
}

// scoped resolves the key of the path at idx within the nearest key above it
// whose template line is known. That key's output lies, in the document, from
// its line to the next node's, and in the template from its line to the line
// that wrote the next node, and no line writes anything out of order.
func (r *resolver) scoped(idx int) resolved {
	if r.tree == nil || r.from < 0 {
		return resolved{}
	}
	target := r.path[idx].line
	for j := idx - 1; j >= 0; j-- {
		match := r.path[j]
		if isIDLine(r.rendered[match.line]) {
			continue
		}
		k, ok := r.tree.at(match.line, match.key)
		if !ok {
			continue
		}
		scope := r.tree.scopeOf(k, match.selector)
		if scope == nil || match.selector && scope.Line-1 != match.line {
			continue
		}
		above := r.at(j)
		if !above.ok || above.printer {
			continue
		}
		end := r.tree.nextStart(scope, len(r.rendered))
		if target <= match.line || target >= end {
			return resolved{}
		}
		from, to := above.line+1, r.templateEnd(end, above.line)
		line, printer, ok := r.writerIn(target, match.line+1, end, from, to, true)
		return resolved{line: line, printer: printer, ok: ok}
	}
	return resolved{}
}

// templateEnd returns the index of the template line that wrote the first
// line at or after rendered line end, when it lies after above and in the
// document; the end of the document otherwise.
func (r *resolver) templateEnd(end, above int) int {
	for ; end < len(r.rendered); end++ {
		if strings.TrimSpace(r.rendered[end]) != "" {
			break
		}
	}
	if end >= len(r.rendered) || isIDLine(r.rendered[end]) {
		return r.to
	}
	if invocation, emitted := r.invocations.Containing(end + 1); emitted {
		if at := r.indexOfSource(invocation.Position.Line); at > above && at < r.to {
			return at
		}
		return r.to
	}
	if next := r.global(end); next.ok && next.line > above && next.line < r.to {
		return next.line
	}
	return r.to
}

// indexOfSource returns the index of the line at source line sourceLine, which
// counts the lines without their ID stamps, or -1.
func (r *resolver) indexOfSource(sourceLine int) int {
	source := 0
	for i, line := range r.lines {
		if isIDLine(line) {
			continue
		}
		source++
		if source == sourceLine {
			return i
		}
	}
	return -1
}

// writerIn returns the template line, among lines from..to-1, that wrote
// rendered line target, when the rendered lines rf..rt-1 hold that text only
// there. printer is set when the line is an action that may have printed it.
func (r *resolver) writerIn(target, rf, rt, from, to int, scoped bool) (line int, printer, ok bool) {
	if r.from < 0 || target < 0 || target >= len(r.rendered) {
		return 0, false, false
	}
	text := strings.TrimRight(r.rendered[target], " \t\r")
	if strings.TrimSpace(text) == "" || isIDLine(text) {
		return 0, false, false
	}
	if !renderedOnce(r.rendered, r.invocations, target, rf, rt, text) {
		return 0, false, false
	}
	writers := scanWriters(r.lines, max(from, r.from), min(to, r.to), text, r.inInclude, r.inAction, r.spanned, r.depths)
	// A plain line outside every block prints once, so it wrote a text that is
	// printed once in the document. Within a scope the text is once, but a line
	// of another scope may have printed it, unless it is the one candidate.
	if writers.literal0 >= 0 && writers.literals0 == 1 && (!scoped || writers.count == 1) {
		return writers.literal0, false, true
	}
	// A single candidate outside every block always prints, but several candidates
	// with a value cannot be told apart by their text.
	if writers.count == 1 && r.depths[writers.found] == 0 {
		return writers.found, false, true
	}
	line, ok = soleWriter(writers.found, writers.count, writers.printers)
	return line, ok && writers.count == 0, ok
}

// ordinal returns the index of the template line that wrote rendered line
// target among lines of plain text that print exactly once, and in order: those
// outside every block, and those that share their block with the document's ID
// stamp, which the document printed once. When the text is printed as many
// times, outside the marked includes, as such lines of the document hold it, no
// other line printed it, so its n-th print is the n-th line.
func (r *resolver) ordinal(target int) (int, bool) {
	if target < 0 || target >= len(r.rendered) || r.from < 0 {
		return 0, false
	}
	text := strings.TrimRight(r.rendered[target], " \t\r")
	if strings.TrimSpace(text) == "" || isIDLine(text) {
		return 0, false
	}
	if _, emitted := r.invocations.Containing(target + 1); emitted {
		return 0, false
	}
	nth, prints := r.printsOf(text, target)
	plain := r.plainWriters(text)
	if len(plain) < prints {
		return 0, false
	}
	once := r.onceLines()
	var written []int
	for _, i := range plain {
		if !once[i] {
			continue
		}
		if r.trimmedAround(i) {
			return 0, false
		}
		written = append(written, i)
	}
	if len(written) == 0 || len(written) != prints {
		return 0, false
	}
	return written[nth], true
}

// trimmedAround reports whether an action next to line may trim the line break
// that ends it or starts it, which joins line to its neighbour's output.
func (r *resolver) trimmedAround(i int) bool {
	if above := r.printedNeighbour(i, -1); above >= 0 && strings.HasSuffix(strings.TrimSpace(r.lines[above]), "-}}") {
		return true
	}
	below := r.printedNeighbour(i, 1)
	return below >= 0 && strings.HasPrefix(strings.TrimSpace(r.lines[below]), "{{-")
}

// printedNeighbour returns the index of the nearest line from i in direction
// step that is not blank or an ID stamp, or -1. A trim reaches across the blank
// lines between it and the line it trims.
func (r *resolver) printedNeighbour(i, step int) int {
	for j := i + step; j >= 0 && j < len(r.lines); j += step {
		if strings.TrimSpace(r.lines[j]) != "" && !isIDLine(r.lines[j]) {
			return j
		}
	}
	return -1
}

// onceLines reports, for each line, whether it prints exactly once when the
// template is rendered: it is outside every block, or in the block of the
// document's stamp, which is printed once.
func (r *resolver) onceLines() []bool {
	if r.once != nil {
		return r.once
	}
	branches := lineBranches(r.lines)
	stamp := -1
	for i, line := range r.lines {
		if r.stamp != "" && isIDLine(line) && strings.TrimSpace(line) == strings.TrimSpace(r.stamp) {
			stamp = i
			break
		}
	}
	if stamp >= 0 {
		printed := 0
		for _, line := range r.rendered {
			if strings.TrimSpace(line) == strings.TrimSpace(r.stamp) {
				printed++
			}
		}
		if printed != 1 {
			stamp = -1
		}
	}
	r.once = make([]bool, len(r.lines))
	for i := range r.lines {
		r.once[i] = branches[i] == 0 || stamp >= 0 && branches[i] == branches[stamp]
	}
	return r.once
}

// lineBranches returns, for each line, the identifier of the branch of the
// innermost block it is in, 0 outside every block. Lines of one branch print
// together, or not at all.
func lineBranches(lines []string) []int {
	branches, stack, next := make([]int, len(lines)), []int{0}, 0
	for i, line := range lines {
		branches[i] = stack[len(stack)-1]
		for _, action := range helmaction.Scan(line) {
			if action.Comment {
				continue
			}
			word := actionWord(line[action.Start:action.End])
			switch {
			case blockOpeners[word]:
				next++
				stack = append(stack, next)
			case word == keywordElse && len(stack) > 1:
				next++
				stack[len(stack)-1] = next
			case word == keywordEnd && len(stack) > 1:
				stack = stack[:len(stack)-1]
			}
		}
	}
	return branches
}

// printsOf returns how many lines of the document hold text outside the marked
// includes, and how many of them are before target.
func (r *resolver) printsOf(text string, target int) (before, prints int) {
	for i, line := range r.rendered {
		if _, emitted := r.invocations.Containing(i + 1); emitted || strings.TrimRight(line, " \t\r") != text {
			continue
		}
		if i < target {
			before++
		}
		prints++
	}
	return before, prints
}

// plainWriters returns the lines of the document that are plain text equal to
// text, outside the marked includes.
func (r *resolver) plainWriters(text string) []int {
	var plain []int
	for i := r.from; i < r.to; i++ {
		line := r.lines[i]
		if strings.TrimRight(line, " \t\r") == text && !r.inInclude[i] && !r.inAction[i] && !r.spanned[i] && !isIDLine(line) &&
			len(helmaction.Scan(line)) == 0 {
			plain = append(plain, i)
		}
	}
	return plain
}
