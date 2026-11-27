/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package cicd

import (
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	bash "github.com/tree-sitter/tree-sitter-bash/bindings/go"
)

var (
	redirectOperators = []string{">>", ">", "<", "&>", "&>>", "<>", shellDupOut, "<&", ">|"}
)

const (
	// Redirect syntax
	shellDupOut = ">&"
	shellNull   = "/dev/null"

	// Shells
	bash_shell = "bash"
	sh         = "sh"
	zsh        = "zsh"
	pwsh       = "pwsh"
	powershell = "powershell"

	// Node kinds
	command              = "command"
	string_kind          = "string"
	expansion            = "expansion"
	redirected_statement = "redirected_statement"
	pipeline             = "pipeline"
	shellList            = "list"
	shellComment         = "comment"
	command_name         = "command_name"
	simple_expansion     = "simple_expansion"
	command_substitution = "command_substitution"
	word                 = "word"
	raw_string           = "raw_string"
	concatenation        = "concatenation"
	file_redirect        = "file_redirect"
	herestringRedirect   = "herestring_redirect"
	heredocRedirect      = "heredoc_redirect"
	processSubstitution  = "process_substitution"
	variable_name        = "variable_name"

	// Types
	string_with_expansion = "string_with_expansion"
	literal               = "literal"
)

var lang = sitter.NewLanguage(bash.Language())

// parseRunBlock parses a shell script and returns structured command information
func parseRunBlock(runScript, shell string) *ParsedRun {
	return parseShellSource(runScript, shell, []byte(runScript))
}

// source is the same length as runScript; provider preprocessing may replace
// template syntax, but extracted values always come from the original script.
func parseShellSource(runScript, shell string, source []byte) *ParsedRun {
	result := &ParsedRun{
		Shell:    shell,
		Commands: []ParsedCommand{},
	}

	// Normalize shell name
	normalized := normalizeShell(shell)

	// Select appropriate parser based on shell type
	switch normalized {
	case bash_shell, sh, zsh:
		break
	case pwsh, powershell:
		// PowerShell not yet supported - Go bindings not available
		result.ParseOK = false
		result.Error = fmt.Errorf("PowerShell parsing not yet supported")
		return result
	default:
		result.ParseOK = false
		result.Error = fmt.Errorf("unsupported shell: %s", shell)
		return result
	}

	// Create parser
	parser := sitter.NewParser()
	defer parser.Close()
	err := parser.SetLanguage(lang)

	if err != nil {
		result.ParseOK = false
		result.Error = fmt.Errorf("failed to set Parser language")
		return result
	}

	// Parse the script
	tree := parser.Parse(source, nil)
	if tree == nil {
		result.ParseOK = false
		result.Error = fmt.Errorf("failed to parse script")
		return result
	}
	defer tree.Close()

	// Walk the AST and extract commands
	result.Commands = extractCommands(tree.RootNode(), runScript)
	// The legacy flag gates all command facts in existing security rules.
	// Recovery must not hide valid commands preceding an error: Bash may
	// already have executed those commands before it reads the broken tail.
	result.ParseOK = true
	if tree.RootNode().HasError() {
		result.Error = fmt.Errorf("invalid shell syntax")
	}

	return result
}

// extractCommands walks the tree and finds all commands
func extractCommands(node *sitter.Node, source string) []ParsedCommand {
	commands := []ParsedCommand{}
	collectShellCommands(node, newShellSource(source), &commands, nil, shellScope{})
	return commands
}

// Redirect bindings are immutable between scopes. Every descriptor is retained;
// the rule projection does not infer what content an executable produces.
type shellRedirects map[string]*ParsedRedirect

// Pending redirects belong to one command, even when grammar wrappers store
// them elsewhere. Enclosing compound redirects are a separate inherited base.
// A persistent chain avoids copying pending prefixes while descending wrappers.
type shellRedirectChain struct {
	owner  *sitter.Node
	parent *shellRedirectChain
}

type shellScope struct {
	inherited shellRedirects
	pending   *shellRedirectChain
}

// Visit each node once. Resolve same-command redirects only at their owner;
// AST traversal order never determines redirect precedence.
func collectShellCommands(node *sitter.Node, source *shellSource, commands *[]ParsedCommand,
	group *ParsedCommand, scope shellScope) {
	switch node.Kind() {
	case command:
		appendShellCommand(node, source, commands, group, scope.resolve(node, source))
		group, scope = nil, shellScope{}
	case redirected_statement:
		collectRedirectedShell(node, source, commands, group, scope)
		return
	case pipeline:
		if group == nil {
			group = &ParsedCommand{Type: pipeline, Pipeline: []ParsedCommand{}}
			collectShellChildren(node, source, commands, group, scope)
			*commands = append(*commands, *group)
			return
		}
	case shellList:
		// Command-local redirects are routed to the rightmost operand below.
	case command_substitution, file_redirect, herestringRedirect, heredocRedirect, processSubstitution:
		group, scope = nil, shellScope{}
	default:
		if scope.pending != nil {
			// Compound I/O takes effect before commands inside the construct,
			// irrespective of its later byte position in the source.
			scope.inherited = scope.resolve(node, source)
			scope.pending = nil
		}
	}
	collectShellChildren(node, source, commands, group, scope)
}

func appendShellCommand(node *sitter.Node, source *shellSource, commands *[]ParsedCommand,
	group *ParsedCommand, redirects shellRedirects) {
	cmd := *parseCommand(node, source)
	bindings := orderedShellBindings(redirects)
	if len(bindings) > 0 {
		cmd.Type, cmd.Redirect = redirected_statement, bindings[0]
	}
	*commands = append(*commands, cmd)
	if group != nil {
		group.Pipeline = append(group.Pipeline, cmd)
	}
	for i, redirect := range bindings {
		if i > 0 {
			*commands = append(*commands, ParsedCommand{Type: redirected_statement, Args: cmd.Args, Redirect: redirect})
		}
		if group != nil && len(cmd.Args) > 0 && !strings.HasPrefix(redirect.Operator, "<") {
			// A pipeline sink has unknown content, regardless of apparent argv.
			// Keep the executable and argv intact; this is a separate sink fact.
			*commands = append(*commands, ParsedCommand{Type: redirected_statement, Args: []ParsedArg{}, Redirect: redirect})
		}
	}
}

// Prefer stdout for the executable fact, then stdin/stderr and other FDs.
// Additional distinct bindings remain available as separate redirect facts.
func orderedShellBindings(redirects shellRedirects) []*ParsedRedirect {
	if len(redirects) == 0 {
		return nil
	}
	keys := []string{"1", "0", "2"}
	for key := range redirects {
		switch key {
		case "1", "0", "2":
		default:
			keys = append(keys, key)
		}
	}
	sort.Strings(keys[3:])
	var bindings []*ParsedRedirect
	seen := make(map[*ParsedRedirect]bool, len(keys))
	for _, key := range keys {
		value := redirects[key]
		if value != nil && !seen[value] {
			bindings = append(bindings, value)
			seen[value] = true
		}
	}
	return bindings
}

func collectShellChildren(node *sitter.Node, source *shellSource, commands *[]ParsedCommand,
	group *ParsedCommand, scope shellScope) {
	last := lastShellStage(node)
	for i := uint(0); i < node.NamedChildCount(); i++ {
		childScope := scope
		switch node.Kind() {
		case pipeline:
			childScope.inherited = pipelineShellBindings(scope.inherited, i == 0, int(i) == last)
			if int(i) != last {
				childScope.pending = nil
			}
		case shellList:
			if int(i) != last {
				childScope.pending = nil
			}
		}
		collectShellCommands(node.NamedChild(i), source, commands, group, childScope)
	}
}

func pipelineShellBindings(inherited shellRedirects, first, last bool) shellRedirects {
	if (first || inherited["0"] == nil) && (last || inherited["1"] == nil) {
		return inherited
	}
	out := make(shellRedirects, len(inherited))
	for descriptor, value := range inherited {
		if descriptor == "0" && !first || descriptor == "1" && !last {
			continue
		}
		out[descriptor] = value
	}
	return out
}

func collectRedirectedShell(node *sitter.Node, source *shellSource, commands *[]ParsedCommand,
	group *ParsedCommand, scope shellScope) {
	scope.pending = &shellRedirectChain{owner: node, parent: scope.pending}
	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if isShellRedirect(child) || child.Kind() == shellComment {
			// Retain executable substitutions in targets, outside the owning pipe.
			collectShellCommands(child, source, commands, nil, shellScope{})
		} else {
			collectShellCommands(child, source, commands, group, scope)
		}
	}
}

func isShellRedirect(node *sitter.Node) bool {
	switch node.Kind() {
	case file_redirect, herestringRedirect, heredocRedirect:
		return true
	}
	return false
}

func shellRedirectNodes(node *sitter.Node, events []*sitter.Node) []*sitter.Node {
	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if isShellRedirect(child) {
			events = append(events, child)
		}
	}
	return events
}

func (scope shellScope) resolve(node *sitter.Node, source *shellSource) shellRedirects {
	events := shellRedirectNodes(node, nil)
	for chain := scope.pending; chain != nil; chain = chain.parent {
		events = shellRedirectNodes(chain.owner, events)
	}
	if len(events) > 1 {
		sort.SliceStable(events, func(i, j int) bool { return events[i].StartByte() < events[j].StartByte() })
	}
	if len(events) == 0 {
		return scope.inherited
	}
	local := make(shellRedirects, len(scope.inherited)+len(events))
	for descriptor, value := range scope.inherited {
		local[descriptor] = value
	}
	for _, event := range events {
		applyShellRedirect(event, source, local)
	}
	return local
}

func applyShellRedirect(node *sitter.Node, source *shellSource, local shellRedirects) {
	var value *ParsedRedirect
	switch node.Kind() {
	case file_redirect:
		value = parseRedirect(node, source)
	case herestringRedirect:
		value = &ParsedRedirect{Operator: "<<<"}
		if node.NamedChildCount() > 0 {
			value.Target = parseArg(node.NamedChild(node.NamedChildCount()-1), source)
		}
	default:
		value = &ParsedRedirect{Operator: "<<"}
		if node.NamedChildCount() > 0 {
			value.Target = parseArg(node.NamedChild(0), source)
		}
	}
	descriptor := "1"
	if strings.HasPrefix(value.Operator, "<") {
		descriptor = "0"
	}
	descriptor = declaredShellDescriptor(node, source, descriptor)
	if strings.HasPrefix(value.Operator, "&") {
		local["1"], local["2"] = value, value
		return
	}
	if local[descriptor] != nil && selfShellDuplication(descriptor, value) {
		return
	}
	if descriptor == "1" && local["1"] != nil && identityShellOutput(value) {
		return
	}
	local[descriptor] = value
}

// The grammar can split a padded descriptor into a descriptor and an ERROR
// token. Read the complete numeric prefix before the operator in that case.
func declaredShellDescriptor(node *sitter.Node, source *shellSource, fallback string) string {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		kind := child.Kind()
		if strings.HasPrefix(kind, "<") || strings.HasPrefix(kind, ">") || strings.HasPrefix(kind, "&>") {
			prefix := source.raw[node.StartByte():child.StartByte()]
			if normalized, ok := shellDescriptorNumber(prefix); ok {
				return normalized
			}
			// A numeric fragment in a nonnumeric word is not an explicit FD.
			if declared := node.ChildByFieldName("descriptor"); declared != nil {
				if _, numeric := shellDescriptorNumber(shellText(declared, source)); numeric {
					return fallback
				}
			}
			break
		}
	}
	if declared := node.ChildByFieldName("descriptor"); declared != nil {
		raw := shellText(declared, source)
		if normalized, ok := shellDescriptorNumber(raw); ok {
			return normalized
		}
		return raw
	}
	return fallback
}

// Numeric FDs are decimal identities, not source spellings. String-based
// canonicalization avoids imposing a parser-side integer/range limit.
func shellDescriptorNumber(value string) (string, bool) {
	if value == "" {
		return value, false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return value, false
		}
	}
	normalized := strings.TrimLeft(value, "0")
	if normalized == "" {
		normalized = "0"
	}
	return normalized, true
}

func selfShellDuplication(descriptor string, redirect *ParsedRedirect) bool {
	if redirect.Operator != shellDupOut && redirect.Operator != "<&" {
		return false
	}
	value := redirect.Target.Value
	if redirect.Target.Type == literal {
		value = literalShellPath(redirect.Target)
	}
	target, ok := shellDescriptorNumber(value)
	return ok && descriptor == target
}

func identityShellOutput(redirect *ParsedRedirect) bool {
	filePath := literalShellPath(redirect.Target)
	return filePath == "/dev/stdout" || filePath == "/dev/fd/1"
}

func literalShellPath(arg ParsedArg) string {
	if arg.Type != literal {
		return ""
	}
	value := arg.Value
	if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] {
		value = value[1 : len(value)-1]
	}
	return value
}

// Trailing comments are syntax extras, not the pipeline's output stage.
func lastShellStage(node *sitter.Node) int {
	last := int(node.NamedChildCount()) - 1
	for last >= 0 && node.NamedChild(uint(last)).Kind() == shellComment {
		last--
	}
	return last
}

// Source text and its legacy quote/$-stripped form are each retained once.
// Nested arguments overlap; their strings must be views, not repeated copies.
type shellSource struct {
	raw, stripped string
	removed       []int
}

func newShellSource(raw string) *shellSource {
	source := &shellSource{raw: raw}
	var plain strings.Builder
	plain.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '$', '"', '\'', '`':
			source.removed = append(source.removed, i)
		default:
			plain.WriteByte(raw[i])
		}
	}
	source.stripped = plain.String()
	return source
}

func (source *shellSource) strippedText(node *sitter.Node) string {
	start, end := int(node.StartByte()), int(node.EndByte())
	left := sort.SearchInts(source.removed, start)
	right := sort.SearchInts(source.removed, end)
	return source.stripped[start-left : end-right]
}

// Node text is a view into the one original source string. Nested substitutions
// overlap, so converting each byte range to string would retain quadratic copies.
func shellText(node *sitter.Node, source *shellSource) string {
	return source.raw[node.StartByte():node.EndByte()]
}

// parseCommand extracts a command with its arguments
func parseCommand(node *sitter.Node, source *shellSource) *ParsedCommand {
	cmd := &ParsedCommand{
		Type: command,
		Args: []ParsedArg{},
	}

	childCount := node.NamedChildCount()
	for i := uint(0); i < childCount; i++ {
		child := node.NamedChild(i)
		if child == nil {
			continue
		}

		switch child.Kind() {
		case command_name:
			cmd.Command = shellText(child, source)
		case word, string_kind, raw_string, expansion, simple_expansion,
			command_substitution, concatenation, processSubstitution:
			arg := parseArg(child, source)
			cmd.Args = append(cmd.Args, arg)
		}
	}

	return cmd
}

// parseRedirect extracts file redirection information
func parseRedirect(node *sitter.Node, source *shellSource) *ParsedRedirect {
	redirect := &ParsedRedirect{}

	// Use all children (not just named) to capture operator tokens like ">>" and ">"
	childCount := node.ChildCount()
	for i := uint(0); i < childCount; i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}

		childKind := child.Kind()

		// Operators are typically single-character or double-character tokens
		if slices.Contains(redirectOperators, childKind) {
			redirect.Operator = shellText(child, source)
		} else if child.IsNamed() {
			// Named nodes are the target (file path/variable)
			redirect.Target = parseArg(child, source)
		}
	}

	return redirect
}

// parseArg classifies and extracts argument information
func parseArg(node *sitter.Node, source *shellSource) ParsedArg {
	arg := ParsedArg{
		Type:  node.Kind(),
		Value: shellText(node, source),
	}

	// For expansions, extract the variable name
	switch node.Kind() {
	case expansion, simple_expansion:
		// Look for variable_name child
		childCount := node.NamedChildCount()
		for i := uint(0); i < childCount; i++ {
			child := node.NamedChild(i)
			if child != nil && child.Kind() == variable_name {
				arg.Var = shellText(child, source)
				break
			}
		}

	case string_kind:
		// Check if string contains expansions
		if hasExpansion(node) {
			arg.Type = string_with_expansion
			// Preserve the legacy stripped value as a shared source view too.
			arg.Var = source.strippedText(node)
		} else {
			arg.Type = literal
		}

	case word, raw_string:
		arg.Type = literal
	}

	return arg
}

// hasExpansion checks if a node contains variable expansions
func hasExpansion(node *sitter.Node) bool {
	childCount := node.NamedChildCount()
	for i := uint(0); i < childCount; i++ {
		child := node.NamedChild(i)
		if child == nil {
			continue
		}

		childKind := child.Kind()
		if childKind == expansion || childKind == simple_expansion ||
			childKind == command_substitution {
			return true
		}

		// Recurse
		if hasExpansion(child) {
			return true
		}
	}
	return false
}

// normalizeShell extracts the base executable name from a shell command string.
func normalizeShell(shell string) string {
	fields := strings.Fields(shell)
	if len(fields) == 0 {
		return ""
	}
	return path.Base(fields[0])
}
