package shell

import (
	"fmt"
	"path"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	bash "github.com/tree-sitter/tree-sitter-bash/bindings/go"
)

const (
	// Shells
	bashShell  = "bash"
	sh         = "sh"
	zsh        = "zsh"
	pwsh       = "pwsh"
	powershell = "powershell"

	// Node kinds
	command                 = "command"
	stringNode              = "string"
	expansion               = "expansion"
	redirectedStatementNode = "redirected_statement"
	pipeline                = "pipeline"
	commandNameNode         = "command_name"
	simpleExpansionNode     = "simple_expansion"
	commandSubstitutionNode = "command_substitution"
	word                    = "word"
	rawStringNode           = "raw_string"
	concatenation           = "concatenation"
	fileRedirectNode        = "file_redirect"
	variableNameNode        = "variable_name"

	// Types
	stringWithExpansion = "string_with_expansion"
	literal             = "literal"
)

var lang = sitter.NewLanguage(bash.Language())

// parseTree is the common native frontend. Facts is the policy contract;
// Parse remains a deprecated CI/CD compatibility projection of the same grammar.
func parseTree(script string) (*sitter.Tree, []byte, error) {
	parser := sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(lang); err != nil {
		return nil, nil, err
	}
	source := []byte(script)
	tree := parser.Parse(source, nil)
	if tree == nil {
		return nil, nil, fmt.Errorf("shell parse failed")
	}
	return tree, source, nil
}

func normalizeShell(shell string) string {
	fields := strings.Fields(shell)
	if len(fields) == 0 {
		return ""
	}
	return path.Base(fields[0])
}
