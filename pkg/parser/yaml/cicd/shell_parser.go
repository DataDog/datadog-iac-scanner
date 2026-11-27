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
	redirectOperators = []string{">>", ">", "<", "&>", "&>>", "<>"}
)

const (
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
	collectShellCommands(node, newShellSource(source), &commands, nil, shellRedirects{})
	return commands
}

// A pipeline retains flat executable members and their top-level positions.
// Sink projections can carry known input content without changing the actual
// executable command's argv. Compound stages keep their output unknown.
type shellStage struct {
	command           ParsedCommand
	position          int
	stdout, inputFile bool
}

type shellPipeline struct {
	stages []shellStage
	simple bool
}

type shellRedirects struct {
	stdout, stderr *ParsedRedirect
	inputFile      bool
}

// Visit each node once. Redirection scope is separate from pipeline membership.
func collectShellCommands(node *sitter.Node, source shellSource, commands *[]ParsedCommand,
	group *shellPipeline, redirects shellRedirects) {
	kind := node.Kind()
	switch kind {
	case command:
		cmd := *parseCommand(node, source)
		if redirects.stdout != nil {
			cmd.Type, cmd.Redirect = redirected_statement, redirects.stdout
		} else if redirects.stderr != nil {
			cmd.Type, cmd.Redirect = redirected_statement, redirects.stderr
		}
		position := len(*commands)
		*commands = append(*commands, cmd)
		if group != nil {
			group.stages = append(group.stages, shellStage{
				command: cmd, position: position, stdout: redirects.stdout != nil, inputFile: redirects.inputFile,
			})
		}
		if redirects.stdout != nil && redirects.stderr != nil && redirects.stdout != redirects.stderr {
			// An additional sink fact shares argv; it is not another executable.
			*commands = append(*commands, ParsedCommand{Type: redirected_statement, Args: cmd.Args, Redirect: redirects.stderr})
		}
		group, redirects = nil, shellRedirects{}
	case redirected_statement:
		collectRedirectedShell(node, source, commands, group, redirects)
		return
	case pipeline:
		if group == nil {
			group = &shellPipeline{simple: true}
			collectShellChildren(node, source, commands, group, redirects)
			projectShellPipeline(commands, group)
			members := make([]ParsedCommand, 0, len(group.stages))
			for _, stage := range group.stages {
				members = append(members, stage.command)
			}
			*commands = append(*commands, ParsedCommand{Type: pipeline, Pipeline: members})
			return
		}
	case command_substitution, file_redirect:
		group, redirects = nil, shellRedirects{}
	default:
		if group != nil && kind != shellComment {
			group.simple = false
		}
	}
	collectShellChildren(node, source, commands, group, redirects)
}

func collectShellChildren(node *sitter.Node, source shellSource, commands *[]ParsedCommand,
	group *shellPipeline, redirects shellRedirects) {
	last := lastShellStage(node)
	for i := uint(0); i < node.NamedChildCount(); i++ {
		childRedirects := redirects
		if node.Kind() == pipeline && int(i) != last {
			childRedirects.stdout = nil
			childRedirects.inputFile = false
		}
		collectShellCommands(node.NamedChild(i), source, commands, group, childRedirects)
	}
}

func collectRedirectedShell(node *sitter.Node, source shellSource, commands *[]ParsedCommand,
	group *shellPipeline, inherited shellRedirects) {
	local := inherited
	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if child.Kind() != file_redirect {
			continue
		}
		value := parseRedirect(child, source)
		descriptor := child.ChildByFieldName("descriptor")
		switch {
		case strings.HasPrefix(value.Operator, "&"):
			local.stdout, local.stderr = value, value
		case strings.HasPrefix(value.Operator, "<"):
			// Input redirection is not an output sink. In a pipeline it also
			// invalidates any known input content.
			local.inputFile = true
		case descriptor == nil || shellText(descriptor, source) == "1":
			local.stdout = value
		case shellText(descriptor, source) == "2":
			local.stderr = value
		}
	}
	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if child.Kind() == shellList {
			// In `a && b >f`, tree-sitter attaches >f to the list. Only b
			// receives this local redirect; a still receives enclosing redirects.
			collectShellList(child, source, commands, group, inherited, local)
		} else {
			collectShellCommands(child, source, commands, group, local)
		}
	}
}

func collectShellList(node *sitter.Node, source shellSource, commands *[]ParsedCommand,
	group *shellPipeline, inherited, local shellRedirects) {
	if group != nil {
		group.simple = false
	}
	last := lastShellStage(node)
	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		selected := inherited
		if int(i) == last {
			if child.Kind() == shellList {
				collectShellList(child, source, commands, group, inherited, local)
				continue
			}
			selected = local
		}
		collectShellCommands(child, source, commands, group, selected)
	}
}

// Propagate only known producer output through argument-free cat/sort stages.
// Other commands, file operands, compound stages and redirected input stay
// unknown. This is deliberately not a shell dataflow interpreter.
func projectShellPipeline(commands *[]ParsedCommand, group *shellPipeline) {
	if !group.simple {
		return
	}
	var content []ParsedArg
	for _, stage := range group.stages {
		cmd := stage.command
		if stage.inputFile {
			content = nil
		}
		switch {
		case cmd.Command == "echo" || cmd.Command == "printf":
			content = cmd.Args
			if len(content) == 0 {
				content = []ParsedArg{{Type: literal, Value: ""}}
			}
		case (cmd.Command == "cat" || cmd.Command == "sort") && len(cmd.Args) == 0:
			if stage.stdout && content != nil {
				actual := &(*commands)[stage.position]
				actual.Type, actual.Redirect = command, nil
				*commands = append(*commands, ParsedCommand{Type: redirected_statement, Args: content, Redirect: cmd.Redirect})
			}
		default:
			content = nil
		}
		if stage.stdout {
			content = []ParsedArg{{Type: literal, Value: ""}}
		}
	}
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

func newShellSource(raw string) shellSource {
	source := shellSource{raw: raw}
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

func (source shellSource) strippedText(node *sitter.Node) string {
	start, end := int(node.StartByte()), int(node.EndByte())
	left := sort.SearchInts(source.removed, start)
	right := sort.SearchInts(source.removed, end)
	return source.stripped[start-left : end-right]
}

// Node text is a view into the one original source string. Nested substitutions
// overlap, so converting each byte range to string would retain quadratic copies.
func shellText(node *sitter.Node, source shellSource) string {
	return source.raw[node.StartByte():node.EndByte()]
}

// parseCommand extracts a command with its arguments
func parseCommand(node *sitter.Node, source shellSource) *ParsedCommand {
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
			command_substitution, concatenation:
			arg := parseArg(child, source)
			cmd.Args = append(cmd.Args, arg)
		}
	}

	return cmd
}

// parseRedirect extracts file redirection information
func parseRedirect(node *sitter.Node, source shellSource) *ParsedRedirect {
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
func parseArg(node *sitter.Node, source shellSource) ParsedArg {
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
