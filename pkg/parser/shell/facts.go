package shell

import (
	"path"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	sitter "github.com/tree-sitter/go-tree-sitter"
)

const (
	cdCommand        = "cd"
	sourceCommand    = "source"
	shellSetCommand  = "set"
	evalCommand      = "eval"
	sudoCommand      = "sudo"
	envCommand       = "env"
	execCommand      = "exec"
	ashShell         = "ash"
	dashShell        = "dash"
	kshShell         = "ksh"
	suCommand        = "su"
	optionEnd        = "--"
	shellOptionValue = "-o"
	chrootCommand    = "chroot"
	maxFactNesting   = 256
	forStatement     = "for_statement"
	failureOperator  = "||"
	successGuard     = "success"
	xargsCommand     = "xargs"
)

const maxShellDepth = 16
const maxFactNodes = 50000
const maxScriptBytes = 1 << 20
const maxOrderingPairChecks = 65536
const maxOrderingRelations = 16384

// Value distinguishes a statically known word from an expansion. Raw preserves
// the source spelling; Text is useful only when Known is true.
type Value struct {
	Raw        string   `json:"raw,omitempty"`
	Default    *string  `json:"default,omitempty"`
	Pattern    string   `json:"pattern,omitempty"`
	References []string `json:"references,omitempty"`
	Text       string   `json:"value"`
	Known      bool     `json:"known"`
}

type Scope struct {
	ID     int    `json:"id"`
	Parent int    `json:"parent"`
	Kind   string `json:"kind"`
}

// Guard records a success/failure dependency on another syntactic call.
type Guard struct {
	Kind string `json:"kind"`
	Call int    `json:"call"`
}

// Span is a byte range of the analyzed script. Calls of nested scripts share
// the span of the argument holding the script; exec-form calls have none.
type Span struct {
	Start, End int
}

// Invocation is syntactic, not proof that a branch executes.
// Function bodies are deferred; scopes preserve isolation and conditionality.
type Invocation struct {
	Guards []Guard `json:"guards,omitempty"`
	// SuccessPredecessors lists source call indexes whose successful completion
	// is required before this call can run. It is deliberately narrower than
	// source order: ordinary sequencing and failure branches do not imply that
	// an earlier command succeeded.
	SuccessPredecessors []int `json:"success_predecessors,omitempty"`
	// OrderedPredecessors lists earlier calls whose ordering before this call
	// is guaranteed by the syntax. It excludes conditional branches except for
	// explicit success dependencies.
	OrderedPredecessors []int         `json:"ordered_predecessors,omitempty"`
	Name                string        `json:"name"`
	Executable          Value         `json:"executable"`
	Arguments           []Value       `json:"arguments"`
	CDPath              *Value        `json:"cd_path,omitempty"`
	DynamicArguments    bool          `json:"dynamic_arguments,omitempty"`
	Wrappers            []string      `json:"wrappers,omitempty"`
	Scope               int           `json:"scope"`
	Order               int           `json:"order"`
	Function            bool          `json:"function"`
	Deferred            bool          `json:"deferred"`
	Conditional         bool          `json:"conditional"`
	Source              *model.Source `json:"source,omitempty"`
	Span                Span          `json:"-"`
	ArgumentSpans       []Span        `json:"-"`
}

type Pipeline struct {
	Scope    int           `json:"scope"`
	Shell    string        `json:"shell"`
	Pipefail bool          `json:"pipefail"`
	Known    bool          `json:"known"`
	Deferred bool          `json:"deferred"`
	Source   *model.Source `json:"source,omitempty"`
	Span     Span          `json:"-"`
}

type shellOptions struct {
	shell    string
	pipefail bool
	known    bool
}

type Facts struct {
	// EnvironmentMayChange records syntactic assignments or shell state
	// operations. They may be conditional or deferred; this does not claim
	// that the environment actually changes during execution.
	EnvironmentMayChange bool             `json:"environment_may_change,omitempty"`
	Pipelines            []Pipeline       `json:"pipelines,omitempty"`
	Calls                []Invocation     `json:"calls"`
	PackageCommands      []PackageCommand `json:"package_commands"`
	Scopes               []Scope          `json:"scopes"`
	Complete             bool             `json:"complete"`
	Diagnostics          []string         `json:"diagnostics,omitempty"`
}

type factBuilder struct {
	result    *Facts
	nodes     int
	bytes     int
	options   map[int]shellOptions
	functions map[int]map[string]bool
	// nested is the span of the argument holding the nested script being walked.
	nested *Span
}

// Analyze parses once and projects scanner-owned command facts. Native trees
// are closed before returning; parser-specific node kinds are not the API.
func Analyze(script, shellName string) *Facts {
	builder := newFactBuilder()
	builder.options[0] = shellOptions{shell: normalizeShell(shellName), known: true}
	builder.script(script, shellName, 0, false, false, 0)
	return builder.finish()
}

// AnalyzeShell retains explicit shell option state as well as the grammar.
func AnalyzeShell(script string, argv []string) *Facts {
	if len(argv) == 0 {
		return Analyze(script, "sh")
	}
	builder := newFactBuilder()
	initial := shellOptions{shell: normalizeShell(argv[0]), known: true}
	values := make([]Value, len(argv))
	for i, arg := range argv {
		values[i] = Value{Text: arg, Known: true}
	}
	builder.options[0] = optionState(initial, values)
	builder.script(script, argv[0], 0, false, false, 0)
	return builder.finish()
}

// AnalyzeArgv preserves exec-form arguments literally, then recognizes known
// wrappers and explicit shell -c scripts. No shell expansion is applied to argv.
func AnalyzeArgv(argv []string) *Facts {
	builder := newFactBuilder()
	values := make([]Value, len(argv))
	for i, arg := range argv {
		values[i] = Value{Text: arg, Known: true}
	}
	builder.call(values, nil, Span{}, 0, false, false, 0, false)
	return builder.finish()
}

func newFactBuilder() *factBuilder {
	return &factBuilder{
		result:    &Facts{Calls: []Invocation{}, Scopes: []Scope{{ID: 0, Parent: -1, Kind: "script"}}, Complete: true},
		functions: make(map[int]map[string]bool),
		options:   map[int]shellOptions{0: {known: true}},
	}
}

func (b *factBuilder) finish() *Facts {
	budget := orderingBudget{}
	if !populateSuccessPredecessors(b.result, &budget) || !populateOrderedPredecessors(b.result, &budget) {
		clearOrderingFacts(b.result)
		b.diagnostic("command ordering analysis limit reached")
	}
	b.result.PackageCommands = packageCommands(b.result.Calls)
	for i := range b.result.Calls {
		call := &b.result.Calls[i]
		if call.Name == cdCommand {
			call.CDPath = cdOperand(call.Arguments, call.DynamicArguments)
		}
		if !call.Executable.Known || call.Function || environmentChangingCommand(call.Name) {
			b.result.EnvironmentMayChange = true
		}
	}
	return b.result
}

func (b *factBuilder) recordEnvironmentSyntax(kind string) {
	switch kind {
	case "variable_assignment", "declaration_command", "unset_command":
		b.result.EnvironmentMayChange = true
	}
}

func environmentChangingCommand(name string) bool {
	switch name {
	case ".", sourceCommand, evalCommand, cdCommand, "export", "unset", shellSetCommand:
		return true
	default:
		return false
	}
}

type orderingBudget struct {
	pairChecks int
	relations  int
}

func (b *orderingBudget) checkPair() bool {
	if b.pairChecks >= maxOrderingPairChecks {
		return false
	}
	b.pairChecks++
	return true
}

func (b *orderingBudget) addRelation() bool {
	if b.relations >= maxOrderingRelations {
		return false
	}
	b.relations++
	return true
}

// populateSuccessPredecessors projects && guards into a transitive relation.
// Calls in a shell pipeline are excluded because its stages execute
// concurrently and pipeline status depends on shell options. Strict scope
// matching keeps the relation within one subshell, nested script, or function.
func populateSuccessPredecessors(facts *Facts, budget *orderingBudget) bool {
	if facts == nil {
		return true
	}
	for i := range facts.Calls {
		if !populateCallSuccessPredecessors(facts, i, budget) {
			return false
		}
	}
	return true
}

func populateCallSuccessPredecessors(facts *Facts, callIndex int, budget *orderingBudget) bool {
	call := &facts.Calls[callIndex]
	if scopeHasKind(facts.Scopes, call.Scope, "pipeline") {
		return true
	}
	seen := make(map[int]bool)
	stack := successGuardCalls(call.Guards)
	for len(stack) > 0 {
		last := len(stack) - 1
		index := stack[last]
		stack = stack[:last]
		if !budget.checkPair() {
			return false
		}
		if !validSuccessPredecessor(facts, callIndex, index, seen) {
			continue
		}
		seen[index] = true
		if !budget.addRelation() {
			return false
		}
		call.SuccessPredecessors = append(call.SuccessPredecessors, index)
		stack = append(stack, successGuardCalls(facts.Calls[index].Guards)...)
	}
	// Stable source order makes the serialized facts deterministic.
	sort.Ints(call.SuccessPredecessors)
	return true
}

func successGuardCalls(guards []Guard) []int {
	var calls []int
	for _, guard := range guards {
		if guard.Kind == successGuard {
			calls = append(calls, guard.Call)
		}
	}
	return calls
}

func validSuccessPredecessor(facts *Facts, callIndex, predecessor int, seen map[int]bool) bool {
	if predecessor < 0 || predecessor >= len(facts.Calls) || seen[predecessor] || predecessor == callIndex {
		return false
	}
	call, previous := facts.Calls[callIndex], facts.Calls[predecessor]
	return previous.Scope == call.Scope && !scopeHasKind(facts.Scopes, previous.Scope, "pipeline")
}

func scopeHasKind(scopes []Scope, scope int, kind string) bool {
	for scope >= 0 && scope < len(scopes) {
		if scopes[scope].Kind == kind {
			return true
		}
		scope = scopes[scope].Parent
	}
	return false
}

// populateOrderedPredecessors records guaranteed source ordering for calls in
// one non-conditional execution scope. Within a conditional scope, only an
// explicit && success dependency proves that one call precedes another: other
// calls may be in mutually exclusive branches of the same if statement.
func populateOrderedPredecessors(facts *Facts, budget *orderingBudget) bool {
	if facts == nil {
		return true
	}
	for i := range facts.Calls {
		if !populateCallOrderedPredecessors(facts, i, budget) {
			return false
		}
	}
	return true
}

func populateCallOrderedPredecessors(facts *Facts, callIndex int, budget *orderingBudget) bool {
	call := &facts.Calls[callIndex]
	if scopeHasKind(facts.Scopes, call.Scope, "pipeline") {
		return true
	}
	conditionalScope := scopeHasKind(facts.Scopes, call.Scope, "conditional")
	successSet := successPredecessorSet(call.SuccessPredecessors)
	for predecessor := range facts.Calls {
		if !budget.checkPair() {
			return false
		}
		if !isOrderedPredecessor(facts, callIndex, predecessor, conditionalScope, successSet) {
			continue
		}
		if !budget.addRelation() {
			return false
		}
		call.OrderedPredecessors = append(call.OrderedPredecessors, predecessor)
	}
	return true
}

func successPredecessorSet(predecessors []int) map[int]bool {
	set := make(map[int]bool, len(predecessors))
	for _, predecessor := range predecessors {
		set[predecessor] = true
	}
	return set
}

func isOrderedPredecessor(facts *Facts, callIndex, predecessor int, conditionalScope bool, successSet map[int]bool) bool {
	if predecessor == callIndex {
		return false
	}
	call, previous := facts.Calls[callIndex], facts.Calls[predecessor]
	if previous.Scope != call.Scope || previous.Order >= call.Order || scopeHasKind(facts.Scopes, previous.Scope, "pipeline") {
		return false
	}
	return (!conditionalScope && !call.Conditional) || successSet[predecessor]
}

func clearOrderingFacts(facts *Facts) {
	for i := range facts.Calls {
		facts.Calls[i].SuccessPredecessors = nil
		facts.Calls[i].OrderedPredecessors = nil
	}
}

func (b *factBuilder) span(node *sitter.Node) Span {
	if b.nested != nil {
		return *b.nested
	}
	return Span{Start: int(node.StartByte()), End: int(node.EndByte())}
}

func (b *factBuilder) diagnostic(message string) {
	b.result.Complete = false
	for _, existing := range b.result.Diagnostics {
		if existing == message {
			return
		}
	}
	b.result.Diagnostics = append(b.result.Diagnostics, message)
}

func (b *factBuilder) scope(parent int, kind string) int {
	id := len(b.result.Scopes)
	b.result.Scopes = append(b.result.Scopes, Scope{ID: id, Parent: parent, Kind: kind})
	b.options[id] = b.options[parent]
	return id
}

func (b *factBuilder) script(script, shellName string, scope int, deferred, conditional bool, depth int) {
	if depth >= maxShellDepth || b.bytes+len(script) > maxScriptBytes {
		b.diagnostic("shell analysis limit reached")
		return
	}
	switch normalizeShell(shellName) {
	case sh, bashShell, ashShell, dashShell, kshShell, zsh:
	default:
		b.diagnostic("unsupported shell: " + shellName)
		return
	}
	b.bytes += len(script)
	tree, source, err := parseTree(script)
	if err != nil {
		b.diagnostic(err.Error())
		return
	}
	defer tree.Close()
	if tree.RootNode().HasError() {
		b.diagnostic("invalid shell syntax")
		return
	}
	b.walk(tree.RootNode(), source, scope, deferred, conditional, depth, 0)
}

func (b *factBuilder) walk(node *sitter.Node, source []byte, scope int, deferred, conditional bool, depth, nesting int) int {
	if b.nodes >= maxFactNodes || nesting > maxFactNesting {
		b.diagnostic("shell analysis limit reached")
		return -1
	}
	b.nodes++
	kind := node.Kind()
	b.recordEnvironmentSyntax(kind)
	if kind == "list" {
		return b.walkList(node, source, scope, deferred, conditional, depth, nesting)
	}
	if kind == "if_statement" || kind == "while_statement" || kind == forStatement || kind == "case_statement" {
		return b.walkConditional(node, source, scope, deferred, conditional, depth, nesting)
	}
	switch kind {
	case "subshell", commandSubstitutionNode, "process_substitution":
		scope = b.scope(scope, kind)
	case "function_definition":
		b.defineFunction(node, source, scope, conditional)
		scope = b.scope(scope, "function")
		deferred = true
	case "pipeline":
		scope = b.scope(scope, "pipeline")
		options := b.options[scope]
		b.result.Pipelines = append(b.result.Pipelines, Pipeline{
			Scope: scope, Shell: options.shell, Pipefail: options.pipefail,
			Known: options.known, Deferred: deferred, Span: b.span(node),
		})
	}
	last := -1
	for i := uint(0); i < node.NamedChildCount(); i++ {
		result := b.walk(node.NamedChild(i), source, scope, deferred, conditional, depth, nesting+1)
		if result >= 0 {
			last = result
		}
	}
	if kind == command {
		last = len(b.result.Calls)
		values, spans := commandValues(node, source)
		b.call(values, spans, b.span(node), scope, deferred, conditional, depth, true)
		if last >= len(b.result.Calls) {
			return -1
		}
	}
	return last
}

func (b *factBuilder) walkList(node *sitter.Node, source []byte, scope int, deferred, conditional bool, depth, nesting int) int {
	operator := ""
	for i := uint(0); i < node.ChildCount(); i++ {
		kind := node.Child(i).Kind()
		if kind == "&&" || kind == failureOperator {
			operator = kind
			break
		}
	}
	if node.NamedChildCount() != 2 || operator == "" {
		last := -1
		for i := uint(0); i < node.NamedChildCount(); i++ {
			last = b.walk(node.NamedChild(i), source, scope, deferred, conditional, depth, nesting+1)
		}
		return last
	}
	left := b.walk(node.NamedChild(0), source, scope, deferred, conditional, depth, nesting+1)
	firstRight := len(b.result.Calls)
	right := b.walk(node.NamedChild(1), source, scope, deferred, true, depth, nesting+1)
	guardKind := successGuard
	if operator == failureOperator {
		guardKind = "failure"
	}
	for i := firstRight; i < len(b.result.Calls); i++ {
		b.result.Calls[i].Guards = append(b.result.Calls[i].Guards, Guard{Kind: guardKind, Call: left})
	}
	if operator == failureOperator {
		return -1
	}
	return right
}

func (b *factBuilder) walkConditional(node *sitter.Node, source []byte, scope int, deferred, conditional bool, depth, nesting int) int {
	parent := scope
	scope = b.scope(scope, "conditional")
	initial := b.options[parent]
	for i := uint(0); i < node.NamedChildCount(); i++ {
		childConditional := true
		field := node.FieldNameForNamedChild(uint32(i))
		if field == "condition" || (node.Kind() == forStatement && field != "body") {
			childConditional = conditional
		}
		b.walk(node.NamedChild(i), source, scope, deferred, childConditional, depth, nesting+1)
	}
	if initial != b.options[scope] {
		initial.known = false
		b.options[parent] = initial
	}
	return -1
}

func (b *factBuilder) call(values []Value, spans []Span, span Span, scope int, deferred, conditional bool, depth int, shellForm bool) {
	if len(values) == 0 {
		return
	}
	if b.nested != nil {
		spans = nil
	}
	function := shellForm && values[0].Known && b.isFunction(scope, values[0].Text)
	words, chain, ok := values, []string{}, true
	if !function {
		words, chain, ok = unwrap(values, shellForm)
	}
	if !ok {
		b.result.Calls = append(b.result.Calls, Invocation{
			Name: path.Base(values[0].Text), Executable: values[0], Arguments: values[1:], Scope: scope,
			Deferred: deferred, Conditional: conditional, Order: len(b.result.Calls), DynamicArguments: true,
			Span: span, ArgumentSpans: argumentSpans(spans, len(values)-1),
		})
		b.diagnostic("unresolved command wrapper")
		return
	}
	call := Invocation{
		Executable: words[0], Arguments: words[1:], Wrappers: chain, Scope: scope,
		Order: len(b.result.Calls), Deferred: deferred, Conditional: conditional, Function: function,
		Span: span, ArgumentSpans: argumentSpans(spans, len(words)-1),
	}
	for _, wrapper := range chain {
		if wrapper == xargsCommand {
			call.DynamicArguments = true
			b.diagnostic("xargs supplies unknown stdin arguments")
		}
	}
	if words[0].Known {
		call.Name = path.Base(words[0].Text)
	} else {
		b.diagnostic("dynamic executable")
	}
	b.result.Calls = append(b.result.Calls, call)
	if call.Name == shellSetCommand && !deferred {
		options := optionState(b.options[scope], words)
		if conditional {
			options.known = false
		}
		b.options[scope] = options
	}
	if function {
		b.diagnostic("shell function invocation is not expanded")
		return
	}
	switch call.Name {
	case "alias", "unalias", evalCommand, sourceCommand, ".":
		b.diagnostic("dynamic shell state is not evaluated")
		return
	}
	b.nestedScript(words, call.Name, scope, deferred, conditional, depth)
}

func (b *factBuilder) nestedScript(words []Value, name string, scope int, deferred, conditional bool, depth int) {
	if !isScriptShell(name) && name != suCommand {
		return
	}
	scriptIndex := shellScriptIndex(words, name)
	if scriptIndex < 0 {
		return
	}
	script := words[scriptIndex]
	if !script.Known {
		b.diagnostic("dynamic nested shell script")
		return
	}
	childScope := b.scope(scope, "shell_script")
	shellName := name
	if shellName == suCommand {
		shellName = sh
	}
	initial := shellOptions{shell: shellName, known: true}
	b.options[childScope] = optionState(initial, words[:scriptIndex])
	if b.nested == nil {
		call := b.result.Calls[len(b.result.Calls)-1]
		nested := call.Span
		if index := scriptIndex - 1; index < len(call.ArgumentSpans) {
			nested = call.ArgumentSpans[index]
		}
		b.nested = &nested
		defer func() { b.nested = nil }()
	}
	b.script(script.Text, shellName, childScope, deferred, conditional, depth+1)
}

// argumentSpans keeps the spans of the last count words, the arguments left
// once wrappers are removed.
func argumentSpans(spans []Span, count int) []Span {
	if spans == nil || count > len(spans) {
		return nil
	}
	return spans[len(spans)-count:]
}

func isScriptShell(name string) bool {
	switch name {
	case sh, bashShell, ashShell, dashShell, kshShell, zsh:
		return true
	}
	return false
}

func shellScriptIndex(words []Value, name string) int {
	if name == suCommand {
		return suScriptIndex(words)
	}
	for i := 1; i < len(words); i++ {
		if !words[i].Known {
			return -1
		}
		option := words[i].Text
		if option == optionEnd {
			return -1
		}
		if shellValueOptions[option] {
			i++
			continue
		}
		if commandOption(option) {
			if i+1 < len(words) {
				return i + 1
			}
			return -1
		}
		if !strings.HasPrefix(option, "-") && !strings.HasPrefix(option, "+") {
			return -1
		}
	}
	return -1
}

var shellValueOptions = map[string]bool{shellOptionValue: true, "+o": true, "-O": true, "+O": true, "--rcfile": true, "--init-file": true}

func suScriptIndex(words []Value) int {
	for i := 1; i+1 < len(words); i++ {
		if words[i].Known && (words[i].Text == "-c" || words[i].Text == "--command") {
			return i + 1
		}
	}
	return -1
}

// Literal performs only quote removal for a single grammar-delimited word.
// Expansion, globbing, ANSI-C quoting and command substitution remain unknown.
func Literal(raw string) Value {
	result := Value{Raw: raw}
	state := literalState{}
	for _, r := range raw {
		if !state.consume(r) {
			return result
		}
	}
	if state.quote != 0 || state.escaped {
		return result
	}
	if state.pattern {
		result.Pattern = state.text.String()
		return result
	}
	result.Text = state.text.String()
	if result.Raw == result.Text {
		result.Raw = ""
	}
	result.Known = true
	return result
}

type literalState struct {
	text     strings.Builder
	quote    rune
	escaped  bool
	pattern  bool
	previous rune
}

func (s *literalState) consume(r rune) bool {
	if s.escaped {
		s.escape(r)
		return true
	}
	if s.quote == '\'' {
		s.quoted(r)
		return true
	}
	if r == '\\' {
		s.escaped = true
		return true
	}
	if r == '$' || r == '`' {
		return false
	}
	if s.quote != 0 {
		s.quoted(r)
		return true
	}
	if r == '\'' || r == '"' {
		s.quote = r
		return true
	}
	if s.expands(r) {
		return false
	}
	if strings.ContainsRune("*?[]{}", r) {
		s.pattern = true
	}
	s.text.WriteRune(r)
	s.previous = r
	return true
}

// expands reports an unquoted rune that makes the word dynamic. A tilde
// expands at the start of a word and after = or :, as in bash.
func (s *literalState) expands(r rune) bool {
	if r == '~' {
		return s.text.Len() == 0 || s.previous == '=' || s.previous == ':'
	}
	return r == '(' || r == ')'
}

func (s *literalState) quoted(r rune) {
	if r == s.quote {
		s.quote = 0
	} else {
		s.text.WriteRune(r)
	}
}

func (s *literalState) escape(r rune) {
	if s.quote == '"' && !strings.ContainsRune("$`\"\\\n", r) {
		s.text.WriteRune('\\')
	}
	if r != '\n' {
		s.text.WriteRune(r)
	}
	s.escaped = false
}

type wrapperSpec struct {
	operands  int
	values    map[string]bool
	flags     string
	longFlags map[string]bool
}

func wrapper(operands int, valueOptions, flags, longFlags string) wrapperSpec {
	spec := wrapperSpec{operands: operands, values: map[string]bool{}, flags: flags, longFlags: map[string]bool{}}
	for _, option := range strings.Fields(valueOptions) {
		spec.values[option] = true
	}
	for _, option := range strings.Fields(longFlags) {
		spec.longFlags[option] = true
	}
	return spec
}

var wrappers = map[string]wrapperSpec{
	sudoCommand: wrapper(0, "u user g group h host p prompt C close-from D chdir R chroot", "nEHSkb", "non-interactive preserve-env"),
	envCommand:  wrapper(0, "u unset C chdir argv0", "i0v", "ignore-environment null"),
	execCommand: wrapper(0, "a", "cl", ""), command: wrapper(0, "", "p", ""),
	"time":  wrapper(0, "f format o output", "pav", "portability append verbose"),
	"nohup": {}, "setsid": wrapper(0, "", "cfw", "ctty fork wait"),
	"nice":    wrapper(0, "n adjustment", "", ""),
	"timeout": wrapper(1, "s signal k kill-after", "v", "foreground preserve-status verbose"),
	"gosu":    {operands: 1}, "su-exec": {operands: 1},
	chrootCommand: wrapper(1, "userspec groups", "", "skip-chdir"),
	xargsCommand: wrapper(0,
		"a arg-file d delimiter E I L max-lines n max-args P max-procs s max-chars",
		"0rptx", "null no-run-if-empty verbose"),
}

func unwrap(values []Value, shellForm bool) ([]Value, []string, bool) {
	chain := []string{}
	for len(values) > 0 && values[0].Known {
		name := path.Base(values[0].Text)
		spec, found := wrappers[name]
		if !found || (!shellForm && (name == execCommand || name == command)) {
			break
		}
		start, ok := wrapperStart(values, name, spec)
		if !ok {
			return nil, nil, false
		}
		if start == 0 {
			break
		}
		chain = append(chain, name)
		values = values[start:]
	}
	return values, chain, len(values) > 0
}

func wrapperStart(values []Value, name string, spec wrapperSpec) (int, bool) {
	i := 1
	for i < len(values) {
		if !values[i].Known {
			return 0, false
		}
		arg := values[i].Text
		if name == command && strings.ContainsAny(strings.TrimPrefix(arg, "-"), "vV") && strings.HasPrefix(arg, "-") {
			return 0, true
		}
		if arg == optionEnd {
			i++
			break
		}
		if (name == envCommand || name == sudoCommand) && !strings.HasPrefix(arg, "-") && strings.Contains(arg, "=") {
			i++
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			break
		}
		consumed, ok := wrapperOption(arg, spec)
		if !ok {
			return 0, false
		}
		i += consumed
	}
	i += spec.operands
	return i, i < len(values)
}

func wrapperOption(arg string, spec wrapperSpec) (int, bool) {
	if strings.HasPrefix(arg, optionEnd) {
		option, _, attached := strings.Cut(strings.TrimPrefix(arg, optionEnd), "=")
		if spec.values[option] {
			if attached {
				return 1, true
			}
			return 2, true
		}
		return 1, spec.longFlags[option] && !attached
	}
	short := strings.TrimPrefix(arg, "-")
	for i, r := range short {
		if spec.values[string(r)] {
			if i+1 < len(short) {
				return 1, true
			}
			return 2, true
		}
		if !strings.ContainsRune(spec.flags, r) {
			return 0, false
		}
	}
	return 1, short != ""
}

func (b *factBuilder) isFunction(scope int, name string) bool {
	for scope >= 0 {
		if b.functions[scope][name] {
			return true
		}
		if b.result.Scopes[scope].Kind == "shell_script" {
			return false
		}
		scope = b.result.Scopes[scope].Parent
	}
	return false
}

func (b *factBuilder) defineFunction(node *sitter.Node, source []byte, scope int, conditional bool) {
	if conditional {
		b.diagnostic("conditional function definition")
	}
	name := node.ChildByFieldName("name")
	if name == nil {
		return
	}
	if b.functions[scope] == nil {
		b.functions[scope] = map[string]bool{}
	}
	b.functions[scope][name.Utf8Text(source)] = true
}

func commandValues(node *sitter.Node, source []byte) ([]Value, []Span) {
	values, spans := []Value{}, []Span{}
	add := func(word *sitter.Node) {
		values = append(values, Literal(word.Utf8Text(source)))
		spans = append(spans, Span{Start: int(word.StartByte()), End: int(word.EndByte())})
	}
	if name := node.ChildByFieldName("name"); name != nil {
		add(name)
	}
	// Use grammar fields, not an allow-list of expression kinds: numeric,
	// arithmetic, process-substitution and anonymous argument nodes must retain
	// their positions even when their values are unknown.
	for i := uint(0); i < node.ChildCount(); i++ {
		if node.FieldNameForChild(uint32(i)) == "argument" {
			add(node.Child(i))
		}
	}
	return values, spans
}

func optionState(state shellOptions, words []Value) shellOptions {
	for i, word := range words {
		if !word.Known {
			state.known = false
			continue
		}
		if (strings.HasPrefix(word.Text, "-") || strings.HasPrefix(word.Text, "+")) && strings.HasSuffix(word.Text, "o") && i+1 < len(words) {
			if words[i+1].Known && words[i+1].Text == "pipefail" {
				state.pipefail = strings.HasPrefix(word.Text, "-")
				state.known = true
			}
		}
	}
	return state
}

func commandOption(option string) bool {
	if !strings.HasPrefix(option, "-") || strings.HasPrefix(option, optionEnd) || !strings.Contains(option, "c") {
		return false
	}
	for _, letter := range option[1:] {
		if !strings.ContainsRune("abcefhiklmnprstuvxBCEHPT", letter) {
			return false
		}
	}
	return true
}
