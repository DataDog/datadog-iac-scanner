/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package cicd

import (
	"fmt"
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
	scriptBytes := []byte(runScript)
	tree := parser.Parse(scriptBytes, nil)
	if tree == nil {
		result.ParseOK = false
		result.Error = fmt.Errorf("failed to parse script")
		return result
	}
	defer tree.Close()

	// Walk the AST and extract commands
	result.Commands = extractCommands(tree.RootNode(), scriptBytes)
	result.ParseOK = true

	return result
}

// extractCommands walks the tree and finds all commands
func extractCommands(node *sitter.Node, source []byte) []ParsedCommand {
	commands := []ParsedCommand{}

	cursor := node.Walk()
	defer cursor.Close()

	walkNode(cursor, source, &commands)

	return commands
}

// walkNode recursively walks the AST node by node
func walkNode(cursor *sitter.TreeCursor, source []byte, commands *[]ParsedCommand) {
	node := cursor.Node()

	// Track if we've fully processed this node
	fullyProcessed := false

	switch node.Kind() {
	case command:
		// Only process standalone commands, not those inside redirected_statement or pipeline
		// We'll let those be processed by their parent
		cmd := parseCommand(node, source)
		if cmd != nil {
			*commands = append(*commands, *cmd)
		}

	case redirected_statement:
		// Parse the full redirected statement including its command
		cmd := parseRedirectedStatement(node, source)
		if cmd != nil {
			*commands = append(*commands, *cmd)
		}
		// Don't recurse - we've already manually parsed the children
		fullyProcessed = true

	case pipeline:
		// Parse the full pipeline including all its commands
		cmd := parsePipeline(node, source)
		if cmd != nil {
			*commands = append(*commands, *cmd)
		}
		// Don't recurse - we've already manually parsed the children
		fullyProcessed = true
	}

	// Only recurse to children if we haven't already fully processed this node
	if !fullyProcessed && cursor.GotoFirstChild() {
		for {
			walkNode(cursor, source, commands)
			if !cursor.GotoNextSibling() {
				break
			}
		}
		cursor.GotoParent()
	}
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

// parseRedirectedStatement extracts a command with redirection
func parseRedirectedStatement(node *sitter.Node, source []byte) *ParsedCommand {
	cmd := &ParsedCommand{
		Type: redirected_statement,
	}

	childCount := node.NamedChildCount()
	for i := uint(0); i < childCount; i++ {
		child := node.NamedChild(i)
		if child == nil {
			continue
		}

		switch child.Kind() {
		case command:
			innerCmd := parseCommand(child, source)
			if innerCmd != nil {
				cmd.Command = innerCmd.Command
				cmd.Args = innerCmd.Args
			}

		case file_redirect:
			cmd.Redirect = parseRedirect(child, source)
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

// parsePipeline extracts pipeline commands
func parsePipeline(node *sitter.Node, source []byte) *ParsedCommand {
	cmd := &ParsedCommand{
		Type:     pipeline,
		Pipeline: []ParsedCommand{},
	}

	childCount := node.NamedChildCount()
	for i := uint(0); i < childCount; i++ {
		child := node.NamedChild(i)
		if child == nil {
			continue
		}

		if child.Kind() == command {
			innerCmd := parseCommand(child, source)
			if innerCmd != nil {
				cmd.Pipeline = append(cmd.Pipeline, *innerCmd)
			}
		}
	}

	return cmd
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

// normalizeShell normalizes shell names to standard forms
func normalizeShell(shell string) string {
	normalized := strings.TrimPrefix(shell, "/bin/")
	normalized = strings.TrimPrefix(normalized, "/usr/bin/")
	normalized = strings.Fields(normalized)[0]
	return normalized
}
