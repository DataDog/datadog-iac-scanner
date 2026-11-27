/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package cicd

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	bash "github.com/tree-sitter/tree-sitter-bash/bindings/go"
)

var (
	re                = regexp.MustCompile(`(\$|"|'|` + "`" + `)`)
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
	result.Commands = extractCommands(tree.RootNode(), []byte(runScript))
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
func extractCommands(node *sitter.Node, source []byte) []ParsedCommand {
	commands := []ParsedCommand{}
	collectShellCommands(node, source, &commands, nil, nil)
	return commands
}

// Visit each syntax node once. A connected pipeline owns one flat member list;
// member facts never contain another pipeline. Thus both traversal and retained
// command entries grow linearly, including alternating pipes and redirections.
func collectShellCommands(node *sitter.Node, source []byte, commands *[]ParsedCommand,
	group *ParsedCommand, redirect *shellRedirection) {
	kind := node.Kind()
	newGroup := false
	switch kind {
	case command:
		cmd := *parseCommand(node, source)
		if redirect != nil {
			cmd.Type, cmd.Redirect = redirected_statement, redirect.value
		}
		*commands = append(*commands, cmd)
		if group != nil {
			group.Pipeline = append(group.Pipeline, cmd)
		}
		// Executable substitutions in arguments are separate commands, not
		// members of the containing command's pipeline or output redirection.
		group, redirect = nil, nil
	case redirected_statement:
		redirect = collectShellRedirection(node, source, commands, redirect)
	case pipeline:
		if group == nil {
			group = &ParsedCommand{Type: pipeline, Pipeline: []ParsedCommand{}}
			newGroup = true
		}
	case command_substitution, file_redirect:
		group, redirect = nil, nil
	}
	last := lastShellStage(node)
	for i := uint(0); i < node.NamedChildCount(); i++ {
		childRedirect := redirect
		if kind == pipeline && int(i) != last {
			// Only the last pipeline stage inherits the pipeline's output.
			childRedirect = nil
		}
		collectShellCommands(node.NamedChild(i), source, commands, group, childRedirect)
	}
	if newGroup {
		*commands = append(*commands, *group)
	}
}

// Stream context is internal; the legacy rule projection still has one
// redirect per command. Keep an opaque inherited-redirection fact when another
// stream is redirected locally, as the original grouped representation did.
type shellRedirection struct {
	value  *ParsedRedirect
	stream string
}

func collectShellRedirection(node *sitter.Node, source []byte, commands *[]ParsedCommand,
	inherited *shellRedirection) *shellRedirection {
	selected := inherited
	overridden := false
	for i := uint(0); i < node.NamedChildCount(); i++ {
		child := node.NamedChild(i)
		if child.Kind() != file_redirect {
			continue
		}
		value := parseRedirect(child, source)
		stream := "1"
		if strings.HasPrefix(value.Operator, "<") {
			stream = "0"
		}
		if descriptor := child.ChildByFieldName("descriptor"); descriptor != nil {
			stream = descriptor.Utf8Text(source)
		}
		if strings.HasPrefix(value.Operator, "&") {
			stream = "&"
		}
		if inherited != nil && (stream == inherited.stream || stream == "&") {
			overridden = true
		}
		selected = &shellRedirection{value: value, stream: stream}
	}
	if inherited != nil && selected != inherited && !overridden {
		*commands = append(*commands, ParsedCommand{Type: redirected_statement, Args: []ParsedArg{}, Redirect: inherited.value})
	}
	return selected
}

// Trailing comments are syntax extras, not the pipeline's output stage.
func lastShellStage(node *sitter.Node) int {
	last := int(node.NamedChildCount()) - 1
	for last >= 0 && node.NamedChild(uint(last)).Kind() == "comment" {
		last--
	}
	return last
}

// parseCommand extracts a command with its arguments
func parseCommand(node *sitter.Node, source []byte) *ParsedCommand {
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
			cmd.Command = child.Utf8Text(source)
		case word, string_kind, raw_string, expansion, simple_expansion,
			command_substitution, concatenation:
			arg := parseArg(child, source)
			cmd.Args = append(cmd.Args, arg)
		}
	}

	return cmd
}

// parseRedirect extracts file redirection information
func parseRedirect(node *sitter.Node, source []byte) *ParsedRedirect {
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
			redirect.Operator = child.Utf8Text(source)
		} else if child.IsNamed() {
			// Named nodes are the target (file path/variable)
			redirect.Target = parseArg(child, source)
		}
	}

	return redirect
}

// parseArg classifies and extracts argument information
func parseArg(node *sitter.Node, source []byte) ParsedArg {
	arg := ParsedArg{
		Type:  node.Kind(),
		Value: node.Utf8Text(source),
	}

	// For expansions, extract the variable name
	switch node.Kind() {
	case expansion, simple_expansion:
		// Look for variable_name child
		childCount := node.NamedChildCount()
		for i := uint(0); i < childCount; i++ {
			child := node.NamedChild(i)
			if child != nil && child.Kind() == variable_name {
				arg.Var = child.Utf8Text(source)
				break
			}
		}

	case string_kind:
		// Check if string contains expansions
		if hasExpansion(node) {
			arg.Type = string_with_expansion
			arg.Var = re.ReplaceAllString(node.Utf8Text(source), "")
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
