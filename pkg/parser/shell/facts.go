/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package shell

import (
	"path"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const (
	cdCommand       = "cd"
	sourceCommand   = "source"
	shellSetCommand = "set"
	evalCommand     = "eval"

	maxShellDepth    = 16
	maxFactNodes     = 50000
	maxFactNesting   = 256
	maxSyntaxNesting = 512
	maxScriptBytes   = 1 << 20
)

type factBuilder struct {
	result    *Facts
	nodes     int
	bytes     int
	options   map[int]shellOptions
	functions map[int]map[string]bool
	// nested is the span of the argument holding the nested script being walked.
	nested *Span
}

// Analyze parses a shell script using a shell specification string (e.g. "sh",
// "bash -o pipefail", "/usr/bin/bash") and projects scanner-owned command facts.
func Analyze(script, shellSpec string) *Facts {
	fields := strings.Fields(shellSpec)
	if len(fields) == 0 {
		builder := newFactBuilder()
		builder.diagnostic("unsupported shell: " + shellSpec)
		return builder.finish()
	}
	return AnalyzeShell(script, fields)
}

// AnalyzeShell parses a shell script while retaining explicit shell option
// state from argv (e.g. []string{"/bin/bash", "-eo", "pipefail", "-c"}).
func AnalyzeShell(script string, argv []string) *Facts {
	if len(argv) == 0 {
		return AnalyzeShell(script, []string{sh})
	}
	builder := newFactBuilder()
	initial := shellOptions{shell: normalizeShell(argv[0]), known: true}
	values := make([]Value, len(argv))
	for i, arg := range argv {
		values[i] = Value{Text: arg, Known: true}
	}
	builder.options[0] = parseShellArgv(initial, values).options
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
		result:    &Facts{Calls: []Invocation{}, Scopes: []Scope{{ID: 0, Parent: -1, Kind: ScopeScript}}, Complete: true},
		functions: make(map[int]map[string]bool),
		options:   map[int]shellOptions{0: {known: true}},
	}
}

func (b *factBuilder) finish() *Facts {
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

func (b *factBuilder) scope(parent int, kind ScopeKind) int {
	id := len(b.result.Scopes)
	b.result.Scopes = append(b.result.Scopes, Scope{ID: id, Parent: parent, Kind: kind})
	b.options[id] = b.options[parent]
	return id
}

func (b *factBuilder) script(script, shellName string, scope int, deferred, conditional bool, depth int) {
	if depth >= maxShellDepth || b.bytes+len(script) > maxScriptBytes || exceedsNestingLimit(script, maxSyntaxNesting) {
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
		stmtScope = b.scope(scope, ScopeBackground)
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
		subScope := b.scope(scope, ScopeSubshell)
		b.walkStmts(node.Stmts, source, subScope, deferred, conditional, depth, nesting+1)
		return -1
	case *syntax.Block:
		return b.walkStmts(node.Stmts, source, scope, deferred, conditional, depth, nesting+1)
	case *syntax.FuncDecl:
		b.defineFunction(node, scope, conditional)
		fnScope := b.scope(scope, ScopeFunction)
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
		coprocScope := b.scope(scope, ScopeCoprocess)
		b.walkStmt(node.Stmt, source, coprocScope, deferred, conditional, depth, nesting+1)
		return -1
	default:
		b.walkSubstitutions(node, source, scope, deferred, conditional, depth, nesting+1)
		return -1
	}
}

func (b *factBuilder) walkBinaryCmd(node *syntax.BinaryCmd, source string, scope int, deferred, conditional bool, depth, nesting int) int {
	if node.Op == syntax.Pipe || node.Op == syntax.PipeAll {
		pipeScope := b.scope(scope, ScopePipeline)
		options := b.options[pipeScope]
		b.result.Pipelines = append(b.result.Pipelines, Pipeline{
			Scope: pipeScope, Shell: options.shell, Pipefail: options.pipefail,
			Known: options.known, Deferred: deferred, Span: b.nodeSpan(node),
		})
		for _, stage := range collectPipelineStages(node) {
			stageScope := b.scope(pipeScope, ScopePipelineStage)
			b.walkStmt(stage, source, stageScope, deferred, conditional, depth, nesting+1)
		}
		return -1
	}
	left := b.walkStmt(node.X, source, scope, deferred, conditional, depth, nesting+1)
	firstRight := len(b.result.Calls)
	right := b.walkStmt(node.Y, source, scope, deferred, true, depth, nesting+1)
	guardKind := GuardSuccess
	if node.Op == syntax.OrStmt {
		guardKind = GuardFailure
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
	for {
		stages = append(stages, node.Y)
		left, ok := node.X.Cmd.(*syntax.BinaryCmd)
		if !ok || (left.Op != syntax.Pipe && left.Op != syntax.PipeAll) {
			stages = append(stages, node.X)
			break
		}
		node = left
	}
	slices.Reverse(stages)
	return stages
}

func (b *factBuilder) walkConditionalScope(scope int, fn func(condScope int)) int {
	parent := scope
	condScope := b.scope(scope, ScopeConditional)
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
		conditionOptions := initial
		changed := false
		for cur, first := node, true; cur != nil; cur, first = cur.Else, false {
			condConditional := true
			if first {
				condConditional = conditional
			}
			b.options[condScope] = conditionOptions
			b.walkStmts(cur.Cond, source, condScope, deferred, condConditional, depth, nesting+1)
			conditionOptions = b.options[condScope]
			b.walkStmts(cur.Then, source, condScope, deferred, true, depth, nesting+1)
			if conditionOptions != initial || b.options[condScope] != initial {
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
	for i, arg := range node.Args {
		span := rawSpan(arg)
		raw := ""
		if span.Start >= 0 && span.End <= len(source) && span.Start <= span.End {
			raw = source[span.Start:span.End]
		}
		if i == 0 && raw == "[" {
			// `[` is a POSIX builtin command name, not a glob pattern.
			values = append(values, Value{Text: "[", Known: true})
		} else {
			values = append(values, wordValue(arg, raw))
		}
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
			subScope := b.scope(scope, ScopeCommandSubstitution)
			b.walkStmts(sub.Stmts, source, subScope, deferred, conditional, depth, nesting+1)
			return false
		case *syntax.ProcSubst:
			subScope := b.scope(scope, ScopeProcessSubstitution)
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
		options := parseShellArgv(b.options[scope], words).options
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
	shellName := name
	if shellName == suCommand {
		shellName = sh
	}
	initial := shellOptions{shell: shellName, known: true}

	var scriptIndex int
	var unknownOption bool
	var childOpts shellOptions
	if name == suCommand {
		scriptIndex, unknownOption = suScriptIndex(words)
		childOpts = initial
	} else {
		parsed := parseShellArgv(initial, words)
		scriptIndex = parsed.scriptIndex
		unknownOption = parsed.unknownOption
		childOpts = parsed.options
	}
	if scriptIndex < 0 {
		if unknownOption {
			b.diagnostic("dynamic nested shell script")
		}
		return
	}
	script := words[scriptIndex]
	if !script.Known {
		b.diagnostic("dynamic nested shell script")
		return
	}
	childScope := b.scope(scope, ScopeShellScript)
	b.options[childScope] = childOpts
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

func (b *factBuilder) isFunction(scope int, name string) bool {
	for scope >= 0 {
		if b.functions[scope][name] {
			return true
		}
		if b.result.Scopes[scope].Kind == ScopeShellScript {
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
