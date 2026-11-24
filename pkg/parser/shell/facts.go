/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package shell

import (
	"path"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
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
	commandFlag      = "-c"
	shellOptionValue = "-o"
	chrootCommand    = "chroot"
	maxFactNesting   = 256
	successGuard     = "success"
	xargsCommand     = "xargs"
)

const (
	maxShellDepth         = 16
	maxFactNodes          = 50000
	maxScriptBytes        = 1 << 20
	maxOrderingPairChecks = 65536
	maxOrderingRelations  = 16384
)

// Value distinguishes a statically known word from an expansion. Raw preserves
// the source spelling; Text is useful only when Known is true.
type Value struct {
	Raw     string `json:"raw,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Text    string `json:"value"`
	Known   bool   `json:"known"`
}

// Scope represents a lexical or execution scope within a parsed shell script.
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
	OrderedPredecessors []int    `json:"ordered_predecessors,omitempty"`
	Name                string   `json:"name"`
	Executable          Value    `json:"executable"`
	Arguments           []Value  `json:"arguments"`
	CDPath              *Value   `json:"cd_path,omitempty"`
	DynamicArguments    bool     `json:"dynamic_arguments,omitempty"`
	Wrappers            []string `json:"wrappers,omitempty"`
	Scope               int      `json:"scope"`
	Order               int      `json:"order"`
	Function            bool     `json:"function"`
	Deferred            bool     `json:"deferred"`
	Conditional         bool     `json:"conditional"`
	Span                Span     `json:"-"`
	ArgumentSpans       []Span   `json:"-"`
}

// Pipeline records a shell pipeline and the pipefail option state in its scope.
type Pipeline struct {
	Scope    int    `json:"scope"`
	Shell    string `json:"shell"`
	Pipefail bool   `json:"pipefail"`
	Known    bool   `json:"known"`
	Deferred bool   `json:"deferred"`
	Span     Span   `json:"-"`
}

type shellOptions struct {
	shell    string
	pipefail bool
	known    bool
}

// Facts holds structured command, pipeline, scope, and package-manager facts
// extracted from a shell script or exec-form argv.
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

// Analyze parses once and projects scanner-owned command facts.
func Analyze(script, shellName string) *Facts {
	builder := newFactBuilder()
	builder.options[0] = shellOptions{shell: normalizeShell(shellName), known: true}
	builder.script(script, shellName, 0, false, false, 0)
	return builder.finish()
}

// AnalyzeShell retains explicit shell option state as well as the grammar.
func AnalyzeShell(script string, argv []string) *Facts {
	if len(argv) == 0 {
		return Analyze(script, sh)
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
	if scopeHasKind(facts.Scopes, call.Scope, pipeline) {
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
	return previous.Scope == call.Scope && !scopeHasKind(facts.Scopes, previous.Scope, pipeline)
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
	if scopeHasKind(facts.Scopes, call.Scope, pipeline) {
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
	if previous.Scope != call.Scope || previous.Order >= call.Order || scopeHasKind(facts.Scopes, previous.Scope, pipeline) {
		return false
	}
	return (!conditionalScope && !call.Conditional && !previous.Conditional) || successSet[predecessor]
}

func clearOrderingFacts(facts *Facts) {
	for i := range facts.Calls {
		facts.Calls[i].SuccessPredecessors = nil
		facts.Calls[i].OrderedPredecessors = nil
	}
}

func (b *factBuilder) nodeSpan(node syntax.Node) Span {
	if b.nested != nil {
		return *b.nested
	}
	return rawSpan(node)
}

func rawSpan(node syntax.Node) Span {
	return Span{Start: int(node.Pos().Offset()), End: int(node.End().Offset())}
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

func shellLangVariant(shellName string) (syntax.LangVariant, bool) {
	switch normalizeShell(shellName) {
	case sh, ashShell, dashShell:
		return syntax.LangPOSIX, true
	case bashShell, zsh:
		return syntax.LangBash, true
	case kshShell:
		return syntax.LangMirBSDKorn, true
	default:
		return 0, false
	}
}

func (b *factBuilder) script(script, shellName string, scope int, deferred, conditional bool, depth int) {
	if depth >= maxShellDepth || b.bytes+len(script) > maxScriptBytes {
		b.diagnostic("shell analysis limit reached")
		return
	}
	variant, ok := shellLangVariant(shellName)
	if !ok {
		b.diagnostic("unsupported shell: " + shellName)
		return
	}
	b.bytes += len(script)
	file, err := syntax.NewParser(syntax.Variant(variant)).Parse(strings.NewReader(script), "")
	if err != nil {
		b.diagnostic("invalid shell syntax")
		return
	}
	b.walkStmts(file.Stmts, script, scope, deferred, conditional, depth, 0)
}

func (b *factBuilder) walkStmts(stmts []*syntax.Stmt, source string, scope int, deferred, conditional bool, depth, nesting int) int {
	last := -1
	for _, stmt := range stmts {
		last = b.walkStmt(stmt, source, scope, deferred, conditional, depth, nesting)
	}
	return last
}

func (b *factBuilder) walkStmt(stmt *syntax.Stmt, source string, scope int, deferred, conditional bool, depth, nesting int) int {
	if stmt == nil {
		return -1
	}
	if b.nodes >= maxFactNodes || nesting > maxFactNesting {
		b.diagnostic("shell analysis limit reached")
		return -1
	}
	b.nodes++
	stmtScope := scope
	if stmt.Background || stmt.Coprocess {
		stmtScope = b.scope(scope, "background")
	}
	for _, redir := range stmt.Redirs {
		b.walkSubstitutions(redir, source, stmtScope, deferred, conditional, depth, nesting+1)
	}
	last := b.walkCmd(stmt.Cmd, source, stmtScope, deferred, conditional, depth, nesting+1)
	if stmt.Background || stmt.Coprocess || stmt.Negated {
		return -1
	}
	return last
}

func (b *factBuilder) walkCmd(cmd syntax.Command, source string, scope int, deferred, conditional bool, depth, nesting int) int {
	if cmd == nil {
		return -1
	}
	switch node := cmd.(type) {
	case *syntax.BinaryCmd:
		return b.walkBinaryCmd(node, source, scope, deferred, conditional, depth, nesting)
	case *syntax.IfClause:
		return b.walkIf(node, source, scope, deferred, conditional, depth, nesting)
	case *syntax.WhileClause:
		return b.walkWhile(node, source, scope, deferred, conditional, depth, nesting)
	case *syntax.ForClause:
		return b.walkFor(node, source, scope, deferred, conditional, depth, nesting)
	case *syntax.CaseClause:
		return b.walkCase(node, source, scope, deferred, conditional, depth, nesting)
	case *syntax.Subshell:
		subScope := b.scope(scope, "subshell")
		b.walkStmts(node.Stmts, source, subScope, deferred, conditional, depth, nesting+1)
		return -1
	case *syntax.Block:
		return b.walkStmts(node.Stmts, source, scope, deferred, conditional, depth, nesting+1)
	case *syntax.FuncDecl:
		b.defineFunction(node, scope, conditional)
		fnScope := b.scope(scope, "function")
		b.walkStmt(node.Body, source, fnScope, true, conditional, depth, nesting+1)
		return -1
	case *syntax.CallExpr:
		return b.walkCallExpr(node, source, scope, deferred, conditional, depth, nesting)
	case *syntax.DeclClause:
		b.result.EnvironmentMayChange = true
		for _, assign := range node.Args {
			b.walkSubstitutions(assign, source, scope, deferred, conditional, depth, nesting+1)
		}
		return -1
	case *syntax.TimeClause:
		return b.walkStmt(node.Stmt, source, scope, deferred, conditional, depth, nesting+1)
	case *syntax.CoprocClause:
		coprocScope := b.scope(scope, "coprocess")
		b.walkStmt(node.Stmt, source, coprocScope, deferred, conditional, depth, nesting+1)
		return -1
	default:
		b.walkSubstitutions(node, source, scope, deferred, conditional, depth, nesting+1)
		return -1
	}
}

func (b *factBuilder) walkBinaryCmd(node *syntax.BinaryCmd, source string, scope int, deferred, conditional bool, depth, nesting int) int {
	if node.Op == syntax.Pipe || node.Op == syntax.PipeAll {
		pipeScope := b.scope(scope, pipeline)
		options := b.options[pipeScope]
		b.result.Pipelines = append(b.result.Pipelines, Pipeline{
			Scope: pipeScope, Shell: options.shell, Pipefail: options.pipefail,
			Known: options.known, Deferred: deferred, Span: b.nodeSpan(node),
		})
		for _, stage := range collectPipelineStages(node) {
			stageScope := b.scope(pipeScope, "pipeline_stage")
			b.walkStmt(stage, source, stageScope, deferred, conditional, depth, nesting+1)
		}
		return -1
	}
	left := b.walkStmt(node.X, source, scope, deferred, conditional, depth, nesting+1)
	firstRight := len(b.result.Calls)
	right := b.walkStmt(node.Y, source, scope, deferred, true, depth, nesting+1)
	guardKind := successGuard
	if node.Op == syntax.OrStmt {
		guardKind = "failure"
	}
	for i := firstRight; i < len(b.result.Calls); i++ {
		b.result.Calls[i].Guards = append(b.result.Calls[i].Guards, Guard{Kind: guardKind, Call: left})
	}
	if node.Op == syntax.OrStmt {
		return -1
	}
	return right
}

func collectPipelineStages(node *syntax.BinaryCmd) []*syntax.Stmt {
	var stages []*syntax.Stmt
	if left, ok := node.X.Cmd.(*syntax.BinaryCmd); ok && (left.Op == syntax.Pipe || left.Op == syntax.PipeAll) {
		stages = append(stages, collectPipelineStages(left)...)
	} else {
		stages = append(stages, node.X)
	}
	stages = append(stages, node.Y)
	return stages
}

func (b *factBuilder) walkConditionalScope(scope int, fn func(condScope int)) int {
	parent := scope
	condScope := b.scope(scope, "conditional")
	initial := b.options[parent]
	fn(condScope)
	if initial != b.options[condScope] {
		initial.known = false
		b.options[parent] = initial
	}
	return -1
}

func (b *factBuilder) walkIf(node *syntax.IfClause, source string, scope int, deferred, conditional bool, depth, nesting int) int {
	return b.walkConditionalScope(scope, func(condScope int) {
		initial := b.options[condScope]
		changed := false
		for cur, first := node, true; cur != nil; cur, first = cur.Else, false {
			condConditional := true
			if first {
				condConditional = conditional
			}
			b.options[condScope] = initial
			b.walkStmts(cur.Cond, source, condScope, deferred, condConditional, depth, nesting+1)
			b.walkStmts(cur.Then, source, condScope, deferred, true, depth, nesting+1)
			if b.options[condScope] != initial {
				changed = true
			}
		}
		if changed {
			tainted := initial
			tainted.known = false
			b.options[condScope] = tainted
		}
	})
}

func (b *factBuilder) walkWhile(node *syntax.WhileClause, source string, scope int, deferred, conditional bool, depth, nesting int) int {
	return b.walkConditionalScope(scope, func(condScope int) {
		b.walkStmts(node.Cond, source, condScope, deferred, conditional, depth, nesting+1)
		b.walkStmts(node.Do, source, condScope, deferred, true, depth, nesting+1)
	})
}

func (b *factBuilder) walkFor(node *syntax.ForClause, source string, scope int, deferred, conditional bool, depth, nesting int) int {
	return b.walkConditionalScope(scope, func(condScope int) {
		if node.Loop != nil {
			b.walkSubstitutions(node.Loop, source, condScope, deferred, conditional, depth, nesting+1)
		}
		b.walkStmts(node.Do, source, condScope, deferred, true, depth, nesting+1)
	})
}

func (b *factBuilder) walkCase(node *syntax.CaseClause, source string, scope int, deferred, conditional bool, depth, nesting int) int {
	return b.walkConditionalScope(scope, func(condScope int) {
		if node.Word != nil {
			b.walkSubstitutions(node.Word, source, condScope, deferred, conditional, depth, nesting+1)
		}
		for _, item := range node.Items {
			for _, pattern := range item.Patterns {
				b.walkSubstitutions(pattern, source, condScope, deferred, true, depth, nesting+1)
			}
			b.walkStmts(item.Stmts, source, condScope, deferred, true, depth, nesting+1)
		}
	})
}

func (b *factBuilder) walkCallExpr(node *syntax.CallExpr, source string, scope int, deferred, conditional bool, depth, nesting int) int {
	if len(node.Assigns) > 0 {
		b.result.EnvironmentMayChange = true
		for _, assign := range node.Assigns {
			b.walkSubstitutions(assign, source, scope, deferred, conditional, depth, nesting+1)
		}
	}
	for _, arg := range node.Args {
		b.walkSubstitutions(arg, source, scope, deferred, conditional, depth, nesting+1)
	}
	if len(node.Args) == 0 {
		return -1
	}
	last := len(b.result.Calls)
	values := make([]Value, 0, len(node.Args))
	spans := make([]Span, 0, len(node.Args))
	for _, arg := range node.Args {
		span := rawSpan(arg)
		raw := ""
		if span.Start >= 0 && span.End <= len(source) && span.Start <= span.End {
			raw = source[span.Start:span.End]
		}
		values = append(values, wordValue(arg, raw))
		spans = append(spans, span)
	}
	b.call(values, spans, b.nodeSpan(node), scope, deferred, conditional, depth, true)
	if last >= len(b.result.Calls) {
		return -1
	}
	return last
}

// walkSubstitutions walks command and process substitutions nested inside words,
// assignments, redirects, and expressions.
func (b *factBuilder) walkSubstitutions(root syntax.Node, source string, scope int, deferred, conditional bool, depth, nesting int) {
	if root == nil {
		return
	}
	syntax.Walk(root, func(node syntax.Node) bool {
		switch sub := node.(type) {
		case *syntax.CmdSubst:
			subScope := b.scope(scope, commandSubstitutionNode)
			b.walkStmts(sub.Stmts, source, subScope, deferred, conditional, depth, nesting+1)
			return false
		case *syntax.ProcSubst:
			subScope := b.scope(scope, "process_substitution")
			b.walkStmts(sub.Stmts, source, subScope, deferred, conditional, depth, nesting+1)
			return false
		}
		return true
	})
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
	hasCommand := false
	for i := 1; i < len(words); i++ {
		if !words[i].Known {
			if hasCommand {
				return i
			}
			return -1
		}
		option := words[i].Text
		if option == optionEnd || option == "-" {
			if hasCommand && i+1 < len(words) {
				return i + 1
			}
			return -1
		}
		if shellValueOptions[option] {
			i++
			continue
		}
		if commandOption(option) {
			hasCommand = true
			continue
		}
		if !strings.HasPrefix(option, "-") && !strings.HasPrefix(option, "+") {
			if hasCommand {
				return i
			}
			return -1
		}
	}
	return -1
}

var shellValueOptions = map[string]bool{shellOptionValue: true, "+o": true, "-O": true, "+O": true, "--rcfile": true, "--init-file": true}

func suScriptIndex(words []Value) int {
	for i := 1; i < len(words); i++ {
		if !words[i].Known {
			return -1
		}
		if words[i].Text == optionEnd {
			return -1
		}
		if (words[i].Text == commandFlag || words[i].Text == "--command") && i+1 < len(words) {
			return i + 1
		}
	}
	return -1
}

// Literal performs only quote removal for a single grammar-delimited word.
// Expansion, globbing, ANSI-C quoting and command substitution remain unknown.
func Literal(raw string) Value {
	var parsed *syntax.Word
	count := 0
	err := syntax.NewParser().Words(strings.NewReader(raw), func(w *syntax.Word) bool {
		count++
		if count == 1 {
			parsed = w
		}
		return count == 1
	})
	if err != nil || count != 1 || parsed == nil {
		return Value{Raw: raw}
	}
	if int(parsed.Pos().Offset()) != 0 || int(parsed.End().Offset()) != len(raw) {
		return Value{Raw: raw}
	}
	return wordValue(parsed, raw)
}

func wordValue(word *syntax.Word, raw string) Value {
	result := Value{Raw: raw}
	var text strings.Builder
	pattern := false
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.SglQuoted:
			if p.Dollar {
				return result
			}
			text.WriteString(p.Value)
		case *syntax.DblQuoted:
			if p.Dollar || !appendDoubleQuoted(&text, p.Parts) {
				return result
			}
		case *syntax.Lit:
			if !appendUnquotedLit(&text, p.Value, &pattern) {
				return result
			}
		default:
			return result
		}
	}
	if pattern {
		result.Pattern = text.String()
		return result
	}
	result.Text = text.String()
	if result.Raw == result.Text {
		result.Raw = ""
	}
	result.Known = true
	return result
}

func appendDoubleQuoted(text *strings.Builder, parts []syntax.WordPart) bool {
	for _, part := range parts {
		lit, ok := part.(*syntax.Lit)
		if !ok {
			return false
		}
		escaped := false
		for _, r := range lit.Value {
			if escaped {
				if !strings.ContainsRune("$`\"\\\n", r) {
					text.WriteByte('\\')
				}
				if r != '\n' {
					text.WriteRune(r)
				}
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			text.WriteRune(r)
		}
		if escaped {
			return false
		}
	}
	return true
}

func appendUnquotedLit(text *strings.Builder, value string, pattern *bool) bool {
	escaped := false
	var previous rune
	for _, r := range value {
		if escaped {
			if r != '\n' {
				text.WriteRune(r)
				previous = r
			}
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '~' && (text.Len() == 0 || previous == '=' || previous == ':') {
			return false
		}
		if r == '(' || r == ')' {
			return false
		}
		if strings.ContainsRune("*?[]{}", r) {
			*pattern = true
		}
		text.WriteRune(r)
		previous = r
	}
	return !escaped
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

func (b *factBuilder) defineFunction(node *syntax.FuncDecl, scope int, conditional bool) {
	if conditional {
		b.diagnostic("conditional function definition")
	}
	if node.Name == nil {
		return
	}
	if b.functions[scope] == nil {
		b.functions[scope] = map[string]bool{}
	}
	b.functions[scope][node.Name.Value] = true
}

func optionState(state shellOptions, words []Value) shellOptions {
	for i := 1; i < len(words); i++ {
		word := words[i]
		if !word.Known {
			state.known = false
			return state
		}
		if word.Text == optionEnd || word.Text == "-" {
			break
		}
		if !strings.HasPrefix(word.Text, "-") && !strings.HasPrefix(word.Text, "+") {
			break
		}
		if strings.HasSuffix(word.Text, "o") && i+1 < len(words) {
			i++
			if !words[i].Known {
				state.known = false
				continue
			}
			if words[i].Text == "pipefail" {
				state.pipefail = strings.HasPrefix(word.Text, "-")
				state.known = true
			}
			continue
		}
		if shellValueOptions[word.Text] && i+1 < len(words) {
			i++
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
