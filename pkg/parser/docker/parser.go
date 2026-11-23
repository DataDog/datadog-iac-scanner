package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/pkg/errors"
)

// Parser is a Dockerfile parser
type Parser struct {
}

// Resource Separates the list of commands by file
type Resource struct {
	CommandList map[string][]Command `json:"command"`
	Arguments   []Command            `json:"args"`
}

// Command is the struct for each dockerfile command
type Command struct {
	Cmd       string
	SubCmd    string
	Flags     []string
	Value     []string
	Original  string
	StartLine int `json:"_dd_line"`
	KicsLine  int `json:"_kics_line"` // legacy field kept for backward compat; drop once all rules use _dd_line
	EndLine   int
	JSON      bool
}

// Parse - parses dockerfile to Json
func (p *Parser) Parse(ctx context.Context, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	reader := bytes.NewReader(fileContent)

	parsed, err := parser.Parse(reader)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to parse Dockerfile")
	}

	fromValue := ""
	from := make(map[string][]Command)
	arguments := make([]Command, 0)
	ignoreStruct := newIgnore()

	variables := make(dockerfileVariables)
	declarationLexer := shell.NewLex(parsed.EscapeToken)
	commandLexer := shell.NewLex(parsed.EscapeToken)
	// Keep command syntax and references to variables only available at runtime.
	commandLexer.RawQuotes = true
	commandLexer.RawEscapes = true
	commandLexer.SkipUnsetEnv = true

	for _, child := range parsed.AST.Children {
		child.Value = strings.ToLower(strings.TrimSpace(child.Value))
		if child.Value == "from" {
			fromValue = strings.TrimPrefix(strings.TrimSpace(child.Original), "FROM ")
		}

		if ignoreStruct.getIgnoreComments(child) {
			ignoreStruct.setIgnore(fromValue)
		}

		ignoreStruct.ignoreBlock(child, fromValue)

		cmd := Command{
			Cmd:       child.Value,
			Original:  strings.TrimSpace(child.Original),
			Flags:     child.Flags,
			StartLine: child.StartLine,
			KicsLine:  child.StartLine,
			EndLine:   child.EndLine,
		}

		if child.Next != nil && len(child.Next.Children) > 0 {
			cmd.SubCmd = strings.ToLower(child.Next.Children[0].Value)
			child = child.Next.Children[0]
		}

		cmd.JSON = child.Attributes["json"]
		for n := child.Next; n != nil; n = n.Next {
			cmd.Value = append(cmd.Value, n.Value)
		}

		switch child.Value {
		case "arg":
			saveArgs(cmd.Value, variables, declarationLexer)
		case "env":
			saveEnvs(cmd.Value, variables, declarationLexer)
		default:
			for i, value := range cmd.Value {
				if strings.ContainsRune(value, '$') {
					cmd.Value[i] = expandCommandWord(value, variables, commandLexer, byte(parsed.EscapeToken))
				}
			}
		}

		if fromValue == "" {
			arguments = append(arguments, cmd)
		} else {
			from[fromValue] = append(from[fromValue], cmd)
		}
	}

	doc := &model.Document{}
	var resource Resource
	resource.CommandList = from
	resource.Arguments = arguments

	j, err := json.Marshal(resource)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to Marshal Dockerfile")
	}

	if err := json.Unmarshal(j, &doc); err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "failed to Unmarshal Dockerfile")
	}

	documents = append(documents, *doc)

	ignoreLines = ignoreStruct.getIgnoreLines()

	return fileContent, documents, ignoreLines, resolvedFiles, nil
}

// GetKind returns the kind of the parser
func (p *Parser) GetKind() model.FileKind {
	return model.KindDOCKER
}

// SupportedExtensions returns Dockerfile extensions
func (p *Parser) SupportedExtensions() []string {
	return []string{"Dockerfile", ".dockerfile", ".ubi8", ".debian", "possibleDockerfile"}
}

// SupportedTypes returns types supported by this parser, which are dockerfile
func (p *Parser) SupportedTypes() map[string]bool {
	return map[string]bool{"dockerfile": true}
}

// GetCommentToken return the comment token of Docker - #
func (p *Parser) GetCommentToken() string {
	return "#"
}

// StringifyContent converts original content into string formatted version
func (p *Parser) StringifyContent(content []byte) (string, error) {
	return string(content), nil
}

type dockerfileVariables map[string]string

func (v dockerfileVariables) Get(name string) (string, bool) {
	value, found := v[name]
	return value, found
}

func (v dockerfileVariables) Keys() []string {
	return slices.Sorted(maps.Keys(v))
}

func saveArgs(values []string, variables dockerfileVariables, lexer *shell.Lex) {
	for _, assignment := range values {
		name, value, hasDefault := strings.Cut(assignment, "=")
		if hasDefault {
			variables[name] = expandWord(value, variables, lexer)
		}
	}
}

func saveEnvs(values []string, variables dockerfileVariables, lexer *shell.Lex) {
	// BuildKit represents ENV as triples of name, value and separator.
	// Resolve all values against the previous bindings and keep the source values for rules.
	assignments := make(dockerfileVariables, len(values)/3)
	for i := 0; i+2 < len(values); i += 3 {
		assignments[values[i]] = expandWord(values[i+1], variables, lexer)
	}
	maps.Copy(variables, assignments)
}
