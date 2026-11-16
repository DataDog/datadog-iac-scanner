package helm

import (
	"fmt"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template/parse"
	"unicode"

	"github.com/DataDog/datadog-iac-scanner/pkg/helmaction"
	"helm.sh/helm/v3/pkg/chart"
)

// A chart is rendered with what the repository says about its installation,
// which seldom holds every value the templates read: some are only supplied
// when it is deployed. Helm prints an absent value as nothing, fails on a field
// of an absent map, and fails on required and fail. The templates are rewritten
// before the render so that it goes through and says what it does not know:
// an absent value printed as text becomes a placeholder naming it,
// "<.Values.env>", and a nondeterministic function prints a label naming it,
// "<randAlphaNum>", the same on every render.
//
// Every rewrite keeps the conditions of the template as Helm evaluates them: an
// absent value is still absent, and still false, wherever it is tested. Edits
// are made on the template text at the positions the Go template parser
// reports and never change its line count, so the rendered output maps back to
// the template as written.

// rewriteLevel is how far the templates are rewritten.
type rewriteLevel int

const (
	// rewriteDeterministic only replaces nondeterministic functions.
	rewriteDeterministic rewriteLevel = iota
	// rewriteTolerant also lets the render go through what only a deploy-time
	// value would make work: fields of absent maps, required and fail, and
	// named templates of charts outside the scan.
	rewriteTolerant
	// rewritePlaceholders also prints a placeholder for an absent value.
	rewritePlaceholders
)

// randomShape is the kind of value a nondeterministic function returns, which
// the value standing for it keeps where a label would not do.
type randomShape int

const (
	shapeString randomShape = iota
	shapeNumber
	shapeTime
	shapeCertificate
)

// randomFuncs are the template functions whose result changes from one render
// to the next. lookup is not one: rendering offline, it always returns an empty
// map, which is what a template must expect of it.
var randomFuncs = map[string]randomShape{
	"randAlphaNum": shapeString, "randAlpha": shapeString, "randAscii": shapeString,
	"randNumeric": shapeString, "randBytes": shapeString, "uuidv4": shapeString,
	"shuffle": shapeString, "bcrypt": shapeString, "htpasswd": shapeString,
	"encryptAES": shapeString, "genPrivateKey": shapeString, "ago": shapeString,
	"randInt": shapeNumber,
	"now":     shapeTime,
	"genCA":   shapeCertificate, "genCAWithKey": shapeCertificate,
	"genSelfSignedCert": shapeCertificate, "genSelfSignedCertWithKey": shapeCertificate,
	"genSignedCert": shapeCertificate, "genSignedCertWithKey": shapeCertificate,
}

// typedFuncs need a value of a given type, which a label is not: a time, a
// number or a certificate. A nondeterministic value they receive makes their
// result nondeterministic too.
var typedFuncs = setOf(
	"date", "dateInZone", "date_in_zone", "htmlDate", "htmlDateInZone", "unixEpoch",
	"dateModify", "date_modify", "mustDateModify", "must_date_modify", "toDate", "mustToDate",
	"duration", "durationRound",
	"add", "add1", "sub", "mul", "div", "mod", "max", "min", "biggest", "floor", "ceil", "round",
	"int", "int64", "float64", "atoi", "addf", "add1f", "subf", "mulf", "divf", "maxf", "minf",
	"until", "untilStep", "seq",
	"eq", "ne", "lt", "le", "gt", "ge",
)

// textFuncs transform the text of their last argument, the piped one: an
// absent value they receive is still a value that would be printed.
var textFuncs = setOf(
	"quote", "squote", "upper", "lower", "title", "untitle", "trim", "trimAll", "trimPrefix",
	"trimSuffix", "trunc", "abbrev", "abbrevboth", "replace", "nospace", "kebabcase", "snakecase",
	"camelcase", "swapcase", "toString", "substr", "repeat", "wrap", "wrapWith", "initials",
)

// chartValuesMethods are the methods of .Values, which are not values.
var chartValuesMethods = setOf("AsMap", "Encode", "PathValue", "Table", "YAML")

func setOf(names ...string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return set
}

// flow is what a value is used for.
type flow int

const (
	// flowOther is a test, a structure, or a use the rewriting knows nothing of.
	flowOther flow = iota
	// flowText is text a template file prints, possibly transformed.
	flowText
	// flowTextTested is text a named template prints, which a caller may test
	// as its include's result.
	flowTextTested
	// flowBound is text bound to a variable once transformed, which may be
	// tested.
	flowBound
	// flowDecl is a value bound to a variable as it is.
	flowDecl
	// flowTyped is a function needing a typed value (see typedFuncs).
	flowTyped
	// flowRequired is the value required tests.
	flowRequired
)

func (f flow) printed() bool { return f == flowText || f == flowTextTested || f == flowBound }

// emptyingFuncs give an empty result for an absent argument, where a
// placeholder would be text: through them, a placeholder could turn a test of
// the result.
var emptyingFuncs = setOf("quote", "squote", "cat", "default", "ternary")

// throughText is the flow of a value fn transforms as text, whose result has
// flow out. Where the result may be tested, the value is not given a
// placeholder through a function emptying an absent one: Helm's result is
// then empty, and must stay so.
func throughText(fn string, out flow) flow {
	switch out {
	case flowText:
		return flowText
	case flowTextTested, flowBound, flowDecl:
		if emptyingFuncs[fn] {
			return flowOther
		}
		if out == flowTextTested {
			return flowTextTested
		}
		return flowBound
	default:
		return flowOther
	}
}

// Template functions and fields the rewriting treats apart.
const (
	funcDefault  = "default"
	funcRequired = "required"
	funcLookup   = "lookup"
	funcIndex    = "index"
	funcFail     = "fail"
	fieldValues  = "Values"
	elementPath  = "[]"
	rightTrimEnd = "-}}"
)

// textArgs are, for functions printing more than their last argument, the
// arguments whose text their result holds.
var textArgs = map[string]func(index int, last bool) bool{
	"quote":     func(int, bool) bool { return true },
	"squote":    func(int, bool) bool { return true },
	"print":     func(int, bool) bool { return true },
	"println":   func(int, bool) bool { return true },
	"cat":       func(int, bool) bool { return true },
	"printf":    func(index int, _ bool) bool { return index > 0 },
	funcDefault: func(_ int, last bool) bool { return !last },
	"ternary":   func(index int, _ bool) bool { return index < 2 },
	helmTpl:     func(index int, _ bool) bool { return index == 0 },
}

// argFlow is the flow of argument index (0-based, the piped value last) of a
// call of fn with n arguments, whose result has flow out.
func argFlow(fn string, index, n int, out flow) flow {
	last := index == n-1
	text := textArgs[fn]
	switch {
	case typedFuncs[fn]:
		return flowTyped
	case fn == funcRequired && last:
		return flowRequired
	case textFuncs[fn] && last, text != nil && text(index, last):
		return throughText(fn, out)
	}
	return flowOther
}

// valueKind is what a value of the template is known to be.
type valueKind int

const (
	valueUnknown valueKind = iota
	// valueValues is part of .Values, at path.
	valueValues
	// valueLookup is what lookup returned: an empty map.
	valueLookup
	// valueRandom is what a nondeterministic function returned.
	valueRandom
)

type tplValue struct {
	kind valueKind
	// path is the place under .Values of a valueValues, "[]" for an element of
	// a list or map ranged over.
	path []string
	// maybeNil is set for a valueValues that may be absent.
	maybeNil bool
	// label names a valueRandom's function, shape the kind of value standing
	// for it.
	label string
	shape randomShape
}

type tplScope struct {
	dot    tplValue
	vars   map[string]tplValue
	parent *tplScope
}

func (s *tplScope) child(dot tplValue) *tplScope {
	return &tplScope{dot: dot, vars: map[string]tplValue{}, parent: s}
}

func (s *tplScope) lookup(name string) tplValue {
	for sc := s; sc != nil; sc = sc.parent {
		if v, ok := sc.vars[name]; ok {
			return v
		}
	}
	return tplValue{}
}

// assign updates the variable where it was declared, as Go templates do.
func (s *tplScope) assign(name string, v tplValue) {
	for sc := s; sc != nil; sc = sc.parent {
		if _, ok := sc.vars[name]; ok {
			sc.vars[name] = v
			return
		}
	}
	s.vars[name] = v
}

type tplEdit struct {
	start, end int
	text       string
}

// templateRewriter rewrites one template file.
type templateRewriter struct {
	src   string
	level rewriteLevel
	// defined are the named templates of the chart; an include of any other is
	// one of a chart outside the scan.
	defined map[string]bool
	actions []helmaction.Action
	edits   []tplEdit
	// needed is the least level making the same edits.
	needed rewriteLevel
	// inDefine is set while walking a named template.
	inDefine bool
	// missing are the named templates called that the chart does not define.
	missing map[string]bool
}

// need records that an edit is only made from level on.
func (r *templateRewriter) need(level rewriteLevel) {
	if level > r.needed {
		r.needed = level
	}
}

// labels reports whether absent values print placeholders. A placeholder in
// the output of a named template cannot turn a test of that output: Helm
// already makes an include of an absent value return "<no value>".
func (r *templateRewriter) labels() bool {
	return r.level >= rewritePlaceholders
}

// rewriteSummary is what rewriting templates did: the least level rewriting
// them the same, and the named templates they call that no chart defines.
type rewriteSummary struct {
	needed  rewriteLevel
	missing []string
}

func (s *rewriteSummary) add(o rewriteSummary) {
	s.needed = max(s.needed, o.needed)
	for _, m := range o.missing {
		if !slices.Contains(s.missing, m) {
			s.missing = append(s.missing, m)
		}
	}
	sort.Strings(s.missing)
}

// rewriteParsed returns src, the template file name parsed into trees,
// rewritten to level. defined names the templates an include can call, nil
// when unknown.
func rewriteParsed(name, src string, trees map[string]*parse.Tree, level rewriteLevel, defined map[string]bool) (string, rewriteSummary) {
	r := &templateRewriter{src: src, level: level, defined: defined, actions: helmaction.Code(src)}
	names := make([]string, 0, len(trees))
	for n := range trees {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if tree := trees[n]; tree != nil && tree.Root != nil {
			r.inDefine = n != name
			r.walkList(tree.Root, &tplScope{vars: map[string]tplValue{}})
		}
	}
	summary := rewriteSummary{needed: r.needed}
	for m := range r.missing {
		summary.missing = append(summary.missing, m)
	}
	sort.Strings(summary.missing)
	return r.apply(), summary
}

// parseTemplate parses src the way Helm does, without knowing its functions.
func parseTemplate(name, src string) (map[string]*parse.Tree, error) {
	t := parse.New(name)
	t.Mode = parse.SkipFuncCheck | parse.ParseComments
	trees := map[string]*parse.Tree{}
	if _, err := t.Parse(src, "", "", trees); err != nil {
		return nil, err
	}
	return trees, nil
}

// chartFiles calls fn with each template of ch and its dependencies, named as
// Helm names it.
func chartFiles(ch *chart.Chart, fn func(name string, f *chart.File)) {
	for _, f := range ch.Templates {
		fn(path.Join(ch.ChartFullPath(), f.Name), f)
	}
	for _, dep := range ch.Dependencies() {
		chartFiles(dep, fn)
	}
}

// rewriteChart rewrites the templates of ch and its dependencies to level.
// Rendering with fewer rewrites than level only renders something else below
// the level the summary says rewrites them the same.
func rewriteChart(ch *chart.Chart, level rewriteLevel) rewriteSummary {
	type parsedFile struct {
		name  string
		file  *chart.File
		trees map[string]*parse.Tree
	}
	var files []parsedFile
	// The names an include can call: the templates the chart and its
	// dependencies define, and their template files.
	defined := map[string]bool{}
	chartFiles(ch, func(name string, f *chart.File) {
		defined[name] = true
		trees, err := parseTemplate(name, string(f.Data))
		if err != nil {
			// Helm reports it.
			return
		}
		for n := range trees {
			defined[n] = true
		}
		files = append(files, parsedFile{name: name, file: f, trees: trees})
	})
	if level < rewriteTolerant {
		defined = nil
	}
	var summary rewriteSummary
	for _, p := range files {
		data, s := rewriteParsed(p.name, string(p.file.Data), p.trees, level, defined)
		p.file.Data = []byte(data)
		summary.add(s)
	}
	return summary
}

// apply returns the source with every edit made.
func (r *templateRewriter) apply() string {
	return r.textOf(0, len(r.src))
}

// textOf returns src[start:end] with the edits inside it made.
func (r *templateRewriter) textOf(start, end int) string {
	var b strings.Builder
	at := start
	for _, e := range r.edits {
		if e.start < start || e.end > end {
			continue
		}
		b.WriteString(r.src[at:e.start])
		b.WriteString(e.text)
		at = e.end
	}
	b.WriteString(r.src[at:end])
	return b.String()
}

// edit replaces the expression src[start:end] with text, which supersedes the
// edits inside it. text gets the line breaks the replaced text had, so that
// every later line keeps its number: inside an action, a line break is a space.
func (r *templateRewriter) edit(level rewriteLevel, start, end int, text string) {
	if start < 0 || end > len(r.src) || start >= end {
		return
	}
	text, ok := fitLines(r.src[start:end], text)
	if !ok {
		return
	}
	r.need(level)
	if missing := strings.Count(r.src[start:end], "\n") - strings.Count(text, "\n"); missing > 0 {
		text += strings.Repeat("\n", missing)
	}
	r.put(start, end, text)
}

// fitLines returns text with no more line breaks than the original it
// replaces: an expression copied into it more than once has its line breaks
// turned to spaces, which is the same in an action. It reports false when a
// raw string holds one.
func fitLines(original, text string) (string, bool) {
	if strings.Count(text, "\n") <= strings.Count(original, "\n") {
		return text, true
	}
	b := []byte(text)
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '"', '\'':
			i = quotedEnd(text, i)
		case '`':
			end := quotedEnd(text, i)
			if strings.ContainsAny(text[i:min(end, len(text))], "\n") {
				return text, false
			}
			i = end
		case '\n', '\r':
			b[i] = ' '
		}
	}
	return string(b), true
}

// editAction replaces the whole action a with text, which ends with an action
// whose closing delimiter the line breaks of a are put before.
func (r *templateRewriter) editAction(level rewriteLevel, a helmaction.Action, text string) {
	text, ok := fitLines(r.src[a.Start:a.End], text)
	if !ok {
		return
	}
	r.need(level)
	if missing := strings.Count(r.src[a.Start:a.End], "\n") - strings.Count(text, "\n"); missing > 0 {
		closing := len(text) - len("}}")
		if strings.HasSuffix(text, " -}}") {
			closing = len(text) - len(" -}}")
		}
		text = text[:closing] + strings.Repeat("\n", missing) + text[closing:]
	}
	r.put(a.Start, a.End, text)
}

func (r *templateRewriter) put(start, end int, text string) {
	for _, e := range r.edits {
		if start >= e.start && end <= e.end {
			// Already inside a replaced span.
			return
		}
	}
	kept := r.edits[:0]
	for _, e := range r.edits {
		if e.start >= start && e.end <= end {
			continue
		}
		kept = append(kept, e)
	}
	kept = append(kept, tplEdit{start: start, end: end, text: text})
	r.edits = kept
	sort.Slice(r.edits, func(i, j int) bool { return r.edits[i].start < r.edits[j].start })
}

// leftTrimmed and rightTrimmed report the trim markers of an action, which
// only are markers when a space separates them from the code.
func leftTrimmed(src string, a helmaction.Action) bool {
	return strings.HasPrefix(src[a.Start:], "{{-") && a.Start+3 < len(src) && isTemplateSpace(src[a.Start+3])
}

func rightTrimmed(src string, a helmaction.Action) bool {
	return a.End-4 >= a.Start && src[a.End-3:a.End] == rightTrimEnd && isTemplateSpace(src[a.End-4])
}

// delimiters returns the opening and closing delimiters of a, with its trim
// markers.
func delimiters(src string, a helmaction.Action) (left, right string) {
	left, right = "{{", "}}"
	if leftTrimmed(src, a) {
		left = "{{-"
	}
	if rightTrimmed(src, a) {
		right = rightTrimEnd
	}
	return left, right
}

func (r *templateRewriter) walkList(list *parse.ListNode, sc *tplScope) {
	if list == nil {
		return
	}
	for _, node := range list.Nodes {
		switch n := node.(type) {
		case *parse.ActionNode:
			r.walkAction(n, sc)
		case *parse.IfNode:
			v := r.walkPipe(n.Pipe, sc, sinkIf)
			r.walkList(n.List, r.blockScope(sc, sc.dot, n.Pipe, v))
			r.walkList(n.ElseList, r.blockScope(sc, sc.dot, n.Pipe, v))
		case *parse.WithNode:
			v := r.walkPipe(n.Pipe, sc, sinkWith)
			dot := v
			if dot.kind == valueValues {
				// The body only runs when the value is there.
				dot.maybeNil = false
			}
			r.walkList(n.List, r.blockScope(sc, dot, n.Pipe, v))
			r.walkList(n.ElseList, r.blockScope(sc, sc.dot, n.Pipe, v))
		case *parse.RangeNode:
			r.walkRange(n, sc)
		case *parse.TemplateNode:
			r.walkTemplateAction(n, sc)
		}
	}
}

// blockScope is the scope of a body of an if or with, where the variables its
// pipeline declares hold v.
func (r *templateRewriter) blockScope(sc *tplScope, dot tplValue, p *parse.PipeNode, v tplValue) *tplScope {
	body := sc.child(dot)
	for _, d := range p.Decl {
		body.vars[d.Ident[0]] = v
	}
	return body
}

func (r *templateRewriter) walkRange(n *parse.RangeNode, sc *tplScope) {
	v := r.walkPipe(n.Pipe, sc, sinkRange)
	elem := tplValue{}
	if v.kind == valueValues {
		elem = tplValue{kind: valueValues, path: appendPath(v.path, elementPath), maybeNil: true}
	}
	body := sc.child(elem)
	if decl := n.Pipe.Decl; len(decl) > 0 {
		// The last variable is the element, a first one of two its key.
		body.vars[decl[len(decl)-1].Ident[0]] = elem
		if len(decl) == 2 {
			body.vars[decl[0].Ident[0]] = tplValue{}
		}
	}
	r.walkList(n.List, body)
	r.walkList(n.ElseList, sc.child(sc.dot))
}

// pipeSink is what the result of a pipeline is for.
type pipeSink int

const (
	sinkPrint pipeSink = iota
	sinkDecl
	sinkIf
	sinkWith
	sinkRange
	sinkTemplate
)

// flow is the flow of a pipeline's value for the sink, printed by a named
// template when inDefine.
func (s pipeSink) flow(inDefine bool) flow {
	switch s {
	case sinkPrint:
		if inDefine {
			return flowTextTested
		}
		return flowText
	case sinkDecl:
		return flowDecl
	default:
		return flowOther
	}
}

func (r *templateRewriter) walkAction(n *parse.ActionNode, sc *tplScope) {
	sink := sinkPrint
	if len(n.Pipe.Decl) > 0 {
		sink = sinkDecl
	}
	if sink == sinkPrint && r.labels() {
		if r.placeholderAction(n, sc) {
			return
		}
	}
	r.walkPipe(n.Pipe, sc, sink)
}

// placeholderAction rewrites an action printing a value of .Values, possibly
// tested by required and transformed as text, to print its placeholder in
// place of the whole output when the value is absent, so that no
// transformation alters the placeholder. It reports whether it applies.
func (r *templateRewriter) placeholderAction(n *parse.ActionNode, sc *tplScope) bool {
	operand, required, ok := r.placeholderOperand(n.Pipe.Cmds)
	if !ok {
		return false
	}
	ch, ok := r.chainOf(operand, sc)
	if !ok || ch.random || ch.values && len(ch.fields) == 0 {
		return false
	}
	action, ok := r.actionAt(int(n.Pos))
	if !ok {
		return false
	}
	safe := r.chainExpr(&ch, "nil")
	start, end := nodeStart(r.src, operand), nodeEnd(r.src, operand)
	if safe != "" {
		r.edit(rewritePlaceholders, start, end, safe)
	} else {
		safe = r.src[start:end]
	}
	test := absentTest(safe, required)
	inner := strings.TrimSpace(r.textOf(r.actionCodeBounds(action)))
	left, right := delimiters(r.src, action)
	r.editAction(rewritePlaceholders, action, fmt.Sprintf("%s if %s }}%s{{ else }}{{ %s }}{{ end %s",
		left, test, placeholderText(ch.label), inner, right))
	return true
}

// placeholderOperand returns the value an action's pipeline prints, which
// placeholderAction can stand a placeholder for: the head of the pipeline, or
// what required tests there, transformed only as text by the commands after
// it. A transformation emptying an absent value in a named template leaves
// it out, as its output may be tested.
func (r *templateRewriter) placeholderOperand(cmds []*parse.CommandNode) (operand parse.Node, required, ok bool) {
	if len(cmds) == 0 {
		return nil, false, false
	}
	head := cmds[0]
	switch {
	case len(head.Args) == 1:
		operand = head.Args[0]
	case len(head.Args) == 3 && identName(head.Args[0]) == funcRequired:
		if _, isString := head.Args[1].(*parse.StringNode); !isString {
			return nil, false, false
		}
		operand, required = head.Args[2], true
	default:
		return nil, false, false
	}
	for _, cmd := range cmds[1:] {
		fn := identName(cmd.Args[0])
		if !textFuncs[fn] || !literalArgs(cmd.Args[1:]) || r.inDefine && emptyingFuncs[fn] {
			return nil, false, false
		}
	}
	return operand, required, true
}

// absentTest is a template condition on expr, true when the value is absent,
// or for required also an empty string.
func absentTest(expr string, required bool) string {
	if required {
		return fmt.Sprintf(`or (kindIs "invalid" %s) (and (kindIs "string" %s) (empty %s))`, expr, expr, expr)
	}
	return fmt.Sprintf(`kindIs "invalid" %s`, expr)
}

// placeholderText is the text standing for an unknown value labeled label.
func placeholderText(label string) string {
	return "<" + label + ">"
}

func literalArgs(args []parse.Node) bool {
	for _, a := range args {
		switch a.(type) {
		case *parse.StringNode, *parse.NumberNode, *parse.BoolNode:
		default:
			return false
		}
	}
	return true
}

func identName(n parse.Node) string {
	if id, ok := n.(*parse.IdentifierNode); ok {
		return id.Ident
	}
	return ""
}

// pipeResult is what walking a pipeline found out about its value.
type pipeResult struct {
	value tplValue
	// random is set when the value is nondeterministic, label and shape then
	// say how to stand for it.
	random bool
	label  string
	shape  randomShape
}

// walkPipe rewrites a pipeline whose value is for sink and returns what is
// known of the value. A nondeterministic pipeline nested in a command is left
// to the caller, which knows what its value is for.
func (r *templateRewriter) walkPipe(p *parse.PipeNode, sc *tplScope, sink pipeSink) tplValue {
	res := r.pipe(p, sc, sink.flow(r.inDefine))
	if res.random {
		r.replaceRandomPipe(p, sc, sink, &res)
		return tplValue{kind: valueRandom, label: res.label, shape: res.shape}
	}
	if sink == sinkDecl {
		r.bind(p, sc, res.value)
	}
	return res.value
}

func (r *templateRewriter) bind(p *parse.PipeNode, sc *tplScope, v tplValue) {
	for _, d := range p.Decl {
		if p.IsAssign {
			sc.assign(d.Ident[0], v)
		} else {
			sc.vars[d.Ident[0]] = v
		}
	}
}

// replaceRandomPipe replaces the commands of a nondeterministic pipeline: by a
// label where it is printed, by a value of its shape where it is kept.
func (r *templateRewriter) replaceRandomPipe(p *parse.PipeNode, sc *tplScope, sink pipeSink, res *pipeResult) {
	start, end := cmdsBounds(r.src, p)
	if start < 0 {
		return
	}
	var text string
	switch sink {
	case sinkPrint:
		text = strconv.Quote(placeholderText(res.label))
	case sinkRange:
		text = "list"
	default:
		text = shapeExpr(res.shape, res.label)
	}
	r.edit(rewriteDeterministic, start, end, text)
	// A declaration holds the stand-in wherever its variable is read; an
	// assignment, as in a branch, may not run, and leaves what the variable
	// is known to hold.
	if sink == sinkDecl && !p.IsAssign {
		r.bind(p, sc, tplValue{kind: valueRandom, label: res.label, shape: res.shape})
	}
}

// shapeExpr is a fixed value of shape standing for a nondeterministic one.
func shapeExpr(shape randomShape, label string) string {
	text := placeholderText(label)
	switch shape {
	case shapeNumber:
		return "0"
	case shapeTime:
		return `(toDate "2006-01-02" "2000-01-01")`
	case shapeCertificate:
		return fmt.Sprintf(`(dict "Cert" %q "Key" %q)`, text, text)
	default:
		return strconv.Quote(text)
	}
}

// pipe walks the commands of p, whose value has flow out, from the last to the
// first, each one's value being the piped argument of the next.
func (r *templateRewriter) pipe(p *parse.PipeNode, sc *tplScope, out flow) pipeResult {
	cmds := p.Cmds
	flows := make([]flow, len(cmds))
	next := out
	for i := len(cmds) - 1; i >= 0; i-- {
		flows[i] = next
		if fn := identName(cmds[i].Args[0]); fn != "" {
			next = argFlow(fn, len(cmds[i].Args)-1, len(cmds[i].Args), next)
		} else {
			next = flowOther
		}
	}
	res := pipeResult{}
	for i, cmd := range cmds {
		cr := r.command(cmd, sc, flows[i], i > 0)
		if cr.random && !res.random {
			res = pipeResult{random: true, label: cr.label, shape: cr.shape}
		}
		if i == 0 && !res.random && onlyDefaults(cmds[1:]) {
			// A value with defaults, as .Values.global | default dict, is still
			// the value for what reads it.
			res.value = cr.value
		}
	}
	return res
}

func onlyDefaults(cmds []*parse.CommandNode) bool {
	for _, c := range cmds {
		if identName(c.Args[0]) != funcDefault {
			return false
		}
	}
	return true
}

// command walks one command whose value has flow out; piped says it takes the
// value of the command before it as last argument.
func (r *templateRewriter) command(cmd *parse.CommandNode, sc *tplScope, out flow, piped bool) pipeResult {
	head := cmd.Args[0]
	fn := identName(head)
	if fn == "" {
		if len(cmd.Args) > 1 {
			// A method called with arguments.
			for _, a := range cmd.Args[1:] {
				r.arg(a, sc, flowOther)
			}
			return pipeResult{}
		}
		return r.operand(head, sc, out, true)
	}
	if shape, ok := randomFuncs[fn]; ok {
		return pipeResult{random: true, label: fn, shape: shape}
	}
	if r.level >= rewriteTolerant {
		if res, done := r.tolerantCommand(cmd, sc, fn, out, piped); done {
			return res
		}
	}
	res := pipeResult{}
	if fn == funcLookup {
		res.value = tplValue{kind: valueLookup}
	}
	n := len(cmd.Args) - 1
	if piped {
		n++
	}
	for i, a := range cmd.Args[1:] {
		ar := r.arg(a, sc, argFlow(fn, i, n, out))
		if ar.random && !res.random {
			res = ar
		}
	}
	return res
}

// tolerantCommand rewrites a call of fn that would fail without a value only
// a deployment supplies, and reports whether it did: fail, an include of a
// template of a chart outside the scan, and an index of an absent map.
func (r *templateRewriter) tolerantCommand(cmd *parse.CommandNode, sc *tplScope, fn string, out flow, piped bool) (pipeResult, bool) {
	switch fn {
	case funcFail:
		r.edit(rewriteTolerant, nodeStart(r.src, cmd), nodeEnd(r.src, cmd), `""`)
		return pipeResult{}, true
	case helmInclude:
		if name, ok := r.missingTemplate(cmd.Args); ok {
			text, level := `""`, rewriteTolerant
			if out.printed() && r.labels() {
				text, level = strconv.Quote(placeholderText(helmInclude+" "+name)), rewritePlaceholders
			}
			r.edit(level, nodeStart(r.src, cmd), nodeEnd(r.src, cmd), text)
			return pipeResult{}, true
		}
	case funcIndex:
		if !piped {
			if ch, ok := r.indexChain(cmd, sc); ok {
				return r.rewriteChain(&ch, cmd, out), true
			}
		}
	}
	return pipeResult{}, false
}

// missingTemplate returns the name an include of args calls when no template
// of the chart defines it.
func (r *templateRewriter) missingTemplate(args []parse.Node) (string, bool) {
	if r.defined == nil || len(args) < 2 {
		return "", false
	}
	s, ok := args[1].(*parse.StringNode)
	if !ok || r.defined[s.Text] {
		return "", false
	}
	r.recordMissing(s.Text)
	return s.Text, true
}

func (r *templateRewriter) recordMissing(name string) {
	if r.missing == nil {
		r.missing = map[string]bool{}
	}
	r.missing[name] = true
}

func (r *templateRewriter) walkTemplateAction(n *parse.TemplateNode, sc *tplScope) {
	if r.level >= rewriteTolerant && r.defined != nil && !r.defined[n.Name] {
		r.recordMissing(n.Name)
		if action, ok := r.actionAt(int(n.Pos)); ok {
			left, right := delimiters(r.src, action)
			r.editAction(rewriteTolerant, action, left+` "" `+right)
		}
		return
	}
	if n.Pipe != nil {
		r.walkPipe(n.Pipe, sc, sinkTemplate)
	}
}

// arg walks an argument with flow f. A nondeterministic argument is replaced
// here, unless a typed function receives it: the call is then
// nondeterministic itself, which the result says.
func (r *templateRewriter) arg(a parse.Node, sc *tplScope, f flow) pipeResult {
	switch n := a.(type) {
	case *parse.IdentifierNode:
		shape, ok := randomFuncs[n.Ident]
		if !ok {
			return pipeResult{}
		}
		if f == flowTyped {
			return pipeResult{random: true, label: n.Ident, shape: shape}
		}
		r.edit(rewriteDeterministic, nodeStart(r.src, n), nodeEnd(r.src, n), randomStandIn(f, shape, n.Ident))
		return pipeResult{}
	case *parse.PipeNode:
		res := r.pipe(n, sc, f)
		if !res.random {
			return pipeResult{}
		}
		if f == flowTyped {
			return res
		}
		start, end := parenBounds(r.src, n)
		if start >= 0 {
			r.edit(rewriteDeterministic, start, end, randomStandIn(f, res.shape, res.label))
		}
		return pipeResult{}
	default:
		return r.operand(a, sc, f, false)
	}
}

// randomStandIn replaces a nondeterministic value with flow f: its label when
// it is text, a fixed value of its shape otherwise.
func randomStandIn(f flow, shape randomShape, label string) string {
	if f.printed() || f == flowRequired {
		return strconv.Quote(placeholderText(label))
	}
	return shapeExpr(shape, label)
}

// operand walks a field, variable or chain used with flow f, as the whole
// command when head.
func (r *templateRewriter) operand(a parse.Node, sc *tplScope, f flow, head bool) pipeResult {
	if p, ok := a.(*parse.PipeNode); ok {
		res := r.pipe(p, sc, f)
		if res.random && !head {
			if start, end := parenBounds(r.src, p); start >= 0 {
				r.edit(rewriteDeterministic, start, end, randomStandIn(f, res.shape, res.label))
			}
			return pipeResult{}
		}
		return res
	}
	ch, ok := r.chainOf(a, sc)
	if !ok {
		if c, isChain := a.(*parse.ChainNode); isChain {
			if p, isPipe := c.Node.(*parse.PipeNode); isPipe {
				r.pipe(p, sc, flowOther)
			}
		}
		return pipeResult{}
	}
	if ch.random {
		// The command is the value of a nondeterministic function, or a field
		// of it: as a whole command, or for a typed function, it is
		// nondeterministic; as text, it is its label.
		if head || f == flowTyped {
			return pipeResult{random: true, label: ch.label, shape: ch.shape}
		}
		if len(ch.fields) > 0 || f.printed() {
			r.edit(rewriteDeterministic, nodeStart(r.src, a), nodeEnd(r.src, a), strconv.Quote(placeholderText(ch.label)))
		}
		return pipeResult{}
	}
	return r.rewriteChain(&ch, a, f)
}

// tplChain is a value read through fields: root, then fields.
type tplChain struct {
	// root is the template text of what the fields are read from.
	root string
	// values is set when root is .Values, whose first field is safe to read.
	values bool
	// maybeNil is set when root itself may be absent.
	maybeNil bool
	fields   []string
	// label names the value in its placeholder.
	label string
	// value is what the chain reads, for a variable bound to it.
	value tplValue
	// random is set for a field of a nondeterministic value, shape its shape.
	random bool
	shape  randomShape
}

// chainOf returns the chain read by a field, variable or chain node, when it
// reads .Values, the result of lookup, or a nondeterministic value.
func (r *templateRewriter) chainOf(a parse.Node, sc *tplScope) (tplChain, bool) {
	switch n := a.(type) {
	case *parse.FieldNode:
		return r.fieldChain(".", sc.dot, n.Ident)
	case *parse.VariableNode:
		if n.Ident[0] == "$" {
			if len(n.Ident) > 1 && n.Ident[1] == fieldValues {
				return valuesChain("$.Values", n.Ident[2:])
			}
			return tplChain{}, false
		}
		v := sc.lookup(n.Ident[0])
		if len(n.Ident) > 1 && n.Ident[1] == fieldValues && v.kind == valueUnknown {
			// A variable holding the context of the template, as $root := .
			return valuesChain(n.Ident[0]+".Values", n.Ident[2:])
		}
		return r.fieldChain(n.Ident[0], v, n.Ident[1:])
	case *parse.ChainNode:
		inner, ok := n.Node.(*parse.PipeNode)
		if !ok || len(inner.Cmds) != 1 || identName(inner.Cmds[0].Args[0]) != funcLookup {
			return tplChain{}, false
		}
		start, end := parenBounds(r.src, inner)
		if start < 0 {
			return tplChain{}, false
		}
		return tplChain{
			root: r.src[start:end], fields: n.Field, maybeNil: true, label: funcLookup,
			value: tplValue{kind: valueLookup},
		}, true
	}
	return tplChain{}, false
}

// fieldChain is the chain of fields read from root, whose value is v.
func (r *templateRewriter) fieldChain(root string, v tplValue, fields []string) (tplChain, bool) {
	switch v.kind {
	case valueValues:
		if len(v.path) == 0 {
			// .Values itself, held by a variable or dot.
			return valuesChain(root, fields)
		}
		return tplChain{
			root: root, fields: fields, maybeNil: v.maybeNil,
			label: valuesLabel(append(append([]string{}, v.path...), fields...)),
			value: tplValue{kind: valueValues, path: appendPath(v.path, fields...), maybeNil: true},
		}, true
	case valueLookup:
		return tplChain{root: root, fields: fields, maybeNil: true, label: funcLookup, value: tplValue{kind: valueLookup}}, true
	case valueRandom:
		return tplChain{root: root, fields: fields, random: true, label: v.label, shape: v.shape}, true
	}
	if root == "." && len(fields) > 0 && fields[0] == fieldValues {
		return valuesChain(".Values", fields[1:])
	}
	return tplChain{}, false
}

// valuesChain is the chain of fields read from a .Values written root.
func valuesChain(root string, fields []string) (tplChain, bool) {
	if len(fields) > 0 && chartValuesMethods[fields[0]] {
		return tplChain{}, false
	}
	return tplChain{
		root: root, values: true, fields: fields, label: valuesLabel(fields),
		value: tplValue{kind: valueValues, path: fields, maybeNil: true},
	}, true
}

func valuesLabel(fields []string) string {
	label := ".Values"
	for _, p := range fields {
		if p == elementPath {
			label += elementPath
			continue
		}
		label += "." + p
	}
	return label
}

func appendPath(base []string, more ...string) []string {
	out := make([]string, 0, len(base)+len(more))
	out = append(out, base...)
	return append(out, more...)
}

// indexChain returns the chain an index call with string keys reads from a
// chain of .Values or of lookup.
func (r *templateRewriter) indexChain(cmd *parse.CommandNode, sc *tplScope) (tplChain, bool) {
	if len(cmd.Args) < 3 {
		return tplChain{}, false
	}
	keys := make([]string, 0, len(cmd.Args)-2)
	for _, k := range cmd.Args[2:] {
		s, ok := k.(*parse.StringNode)
		if !ok {
			return tplChain{}, false
		}
		keys = append(keys, s.Text)
	}
	base, ok := r.chainOf(cmd.Args[1], sc)
	if !ok || base.random {
		return tplChain{}, false
	}
	full := base
	if base.values {
		full.fields = appendPath(base.fields, keys...)
	} else {
		// The keys are read from the base chain, itself read safely.
		root := r.chainExpr(&base, "nil")
		if root == "" {
			root = r.src[nodeStart(r.src, cmd.Args[1]):nodeEnd(r.src, cmd.Args[1])]
		}
		full.root, full.fields, full.maybeNil = root, keys, true
	}
	if base.label != funcLookup {
		full.label = base.label + "." + strings.Join(keys, ".")
	}
	if base.value.kind == valueValues {
		full.value = tplValue{kind: valueValues, path: appendPath(base.value.path, keys...), maybeNil: true}
	}
	return full, true
}

// rewriteChain rewrites node, which reads ch, for flow f: reading it without
// failing on an absent map, and printing its placeholder when it is absent
// text. A chain bound as it is to a variable binds the variable to it.
func (r *templateRewriter) rewriteChain(ch *tplChain, node parse.Node, f flow) pipeResult {
	res := pipeResult{value: ch.value}
	if r.level < rewriteTolerant || (ch.values && len(ch.fields) == 0) {
		return res
	}
	start, end := nodeStart(r.src, node), nodeEnd(r.src, node)
	original := r.src[start:end]
	if _, isCmd := node.(*parse.CommandNode); isCmd {
		original = "(" + original + ")"
	}
	switch {
	case f == flowRequired:
		safe := r.chainExpr(ch, "nil")
		if safe == "" {
			safe = original
		}
		r.edit(rewriteTolerant, start, end, fmt.Sprintf("(ternary %q %s (%s))",
			placeholderText(ch.label), safe, absentTest(safe, true)))
	case f.printed() && r.labels():
		label := strconv.Quote(placeholderText(ch.label))
		if expr := r.chainExpr(ch, label); expr != "" {
			r.edit(rewritePlaceholders, start, end, expr)
		} else {
			r.edit(rewritePlaceholders, start, end, fmt.Sprintf("(ternary %s %s (%s))", label, original, absentTest(original, false)))
		}
	default:
		if expr := r.chainExpr(ch, "nil"); expr != "" {
			r.edit(rewriteTolerant, start, end, expr)
		}
	}
	return res
}

// chainExpr reads the chain with dig, which returns def instead of failing on
// an absent map, or is empty when reading the chain as written cannot fail.
func (r *templateRewriter) chainExpr(ch *tplChain, def string) string {
	root, fields := ch.root, ch.fields
	if ch.values {
		// .Values is always a map, so its first field reads safely.
		if len(fields) < 2 {
			return ""
		}
		switch {
		case isTemplateIdent(fields[0]) && root == ".":
			root = "." + fields[0]
		case isTemplateIdent(fields[0]):
			root = root + "." + fields[0]
		default:
			root = fmt.Sprintf("(index %s %q)", root, fields[0])
		}
		fields = fields[1:]
	} else if !ch.maybeNil && len(fields) < 2 && def == "nil" {
		return ""
	}
	if len(fields) == 0 {
		return ""
	}
	keys := make([]string, len(fields))
	for i, f := range fields {
		keys[i] = strconv.Quote(f)
	}
	return fmt.Sprintf("(dig %s %s (%s | default dict))", strings.Join(keys, " "), def, root)
}

// actionAt returns the action holding pos.
func (r *templateRewriter) actionAt(pos int) (helmaction.Action, bool) {
	i := sort.Search(len(r.actions), func(i int) bool { return r.actions[i].Start > pos })
	if i == 0 || pos >= r.actions[i-1].End {
		return helmaction.Action{}, false
	}
	return r.actions[i-1], true
}

// actionCodeBounds returns the code of an action, without its delimiters and
// trim markers.
func (r *templateRewriter) actionCodeBounds(a helmaction.Action) (start, end int) {
	start, end = a.Start+len("{{"), a.End-len("}}")
	if leftTrimmed(r.src, a) {
		start++
	}
	if rightTrimmed(r.src, a) {
		end--
	}
	return start, end
}

// nodeStart is where a node starts in src. The parser places a field or
// variable read through several names at its second name.
func nodeStart(src string, n parse.Node) int {
	switch x := n.(type) {
	case *parse.FieldNode:
		if len(x.Ident) > 1 {
			return int(x.Pos) - len(x.Ident[0]) - 1
		}
	case *parse.VariableNode:
		if len(x.Ident) > 1 {
			return int(x.Pos) - len(x.Ident[0])
		}
	case *parse.ChainNode:
		if p, ok := x.Node.(*parse.PipeNode); ok {
			start, _ := parenBounds(src, p)
			return start
		}
		return nodeStart(src, x.Node)
	case *parse.PipeNode:
		start, _ := parenBounds(src, x)
		return start
	case *parse.CommandNode:
		if len(x.Args) > 0 {
			return nodeStart(src, x.Args[0])
		}
	}
	return int(n.Position())
}

// nodeEnd is where a node ends in src.
func nodeEnd(src string, n parse.Node) int {
	switch x := n.(type) {
	case *parse.StringNode:
		return int(x.Pos) + len(x.Quoted)
	case *parse.NumberNode:
		return int(x.Pos) + len(x.Text)
	case *parse.ChainNode:
		return int(x.Pos) + len("."+strings.Join(x.Field, "."))
	case *parse.PipeNode:
		_, end := parenBounds(src, x)
		return end
	case *parse.CommandNode:
		if len(x.Args) > 0 {
			return nodeEnd(src, x.Args[len(x.Args)-1])
		}
		return int(x.Pos)
	case *parse.FieldNode, *parse.VariableNode, *parse.IdentifierNode, *parse.DotNode,
		*parse.NilNode, *parse.BoolNode:
		return nodeStart(src, n) + len(n.String())
	}
	return int(n.Position())
}

// cmdsBounds returns the span of the commands of an action or block pipeline,
// after its declarations.
func cmdsBounds(src string, p *parse.PipeNode) (start, end int) {
	if len(p.Cmds) == 0 {
		return -1, -1
	}
	return nodeStart(src, p.Cmds[0]), nodeEnd(src, p.Cmds[len(p.Cmds)-1])
}

// parenBounds returns the span of a parenthesized pipeline, parentheses
// included, or -1 when p is not parenthesized.
func parenBounds(src string, p *parse.PipeNode) (start, end int) {
	open := int(p.Pos) - 1
	for open >= 0 && isTemplateSpace(src[open]) {
		open--
	}
	if open < 0 || src[open] != '(' {
		return -1, -1
	}
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '"', '\'', '`':
			i = quotedEnd(src, i)
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return open, i + 1
			}
		}
	}
	return -1, -1
}

// quotedEnd returns the index of the quote closing the string, character or
// raw string opening at i, or the end of src.
func quotedEnd(src string, i int) int {
	quote := src[i]
	for i++; i < len(src) && src[i] != quote; i++ {
		if src[i] == '\\' && quote != '`' {
			i++
		}
	}
	return i
}

// isTemplateIdent reports whether s can be written as a field name.
func isTemplateIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c != '_' && !unicode.IsLetter(c) && (i == 0 || !unicode.IsDigit(c)) {
			return false
		}
	}
	return true
}

func isTemplateSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
