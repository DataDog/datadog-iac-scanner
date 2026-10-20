package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/moby/buildkit/frontend/dockerfile/command"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
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

	lex := newWordExpander(parsed.EscapeToken, true)
	declarationLex := newWordExpander(parsed.EscapeToken, false)
	globalArgs := make(map[string]string)
	scope := variableScope{args: globalArgs, envs: make(map[string]string)}
	stages := make(map[string]variableScope)

	for _, child := range parsed.AST.Children {
		child.Value = strings.ToLower(strings.TrimSpace(child.Value))
		if child.Value == command.From {
			fromValue = fromArguments(child.Original)
			scope = scopeForStage(child, globalArgs, stages, lex)
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

		scope.expandCommand(&cmd, globalArgs, lex, declarationLex)

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

// fromArguments strips the case-insensitive FROM keyword from a stage name.
func fromArguments(original string) string {
	original = strings.TrimSpace(original)
	if len(original) < len("from") || !strings.EqualFold(original[:len("from")], "from") {
		return ""
	}
	return strings.TrimSpace(original[len("from"):])
}

// GetKind returns the kind of the parser
func (p *Parser) GetKind() model.FileKind {
	return model.KindDOCKER
}

// SupportedExtensions returns Dockerfile extensions
func (p *Parser) SupportedExtensions() []string {
	return []string{"Dockerfile", ".dockerfile", ".ubi8", ".debian", utils.PossibleDockerfile}
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

type variableScope struct {
	args map[string]string
	envs map[string]string
}

func scopeForStage(node *parser.Node, globals map[string]string, stages map[string]variableScope, lex *wordExpander) variableScope {
	scope := variableScope{args: make(map[string]string), envs: make(map[string]string)}
	if node.Next == nil {
		return scope
	}
	base := expandValues(lex, []string{node.Next.Value}, globals)[0]
	if parent, found := stages[strings.ToLower(base)]; found {
		scope.args = maps.Clone(parent.args)
		scope.envs = maps.Clone(parent.envs)
	}
	if as := node.Next.Next; as != nil && strings.EqualFold(as.Value, "as") && as.Next != nil {
		stages[strings.ToLower(as.Next.Value)] = scope
	}
	return scope
}

func (s variableScope) declareArgs(lex *wordExpander, values []string, globals map[string]string) []string {
	for i, value := range values {
		name, defaultValue, hasDefault := strings.Cut(value, "=")
		if hasDefault {
			resolved := expandValues(lex, []string{defaultValue}, s.envs, s.args)[0]
			s.args[name] = resolved
			values[i] = name + "=" + resolved
		} else if global, ok := globals[name]; ok {
			// Global ARGs become stage variables only through an ARG declaration.
			s.args[name] = global
		}
	}
	return values
}

// All values in one ENV instruction are expanded before updating the scope.
func (s variableScope) declareEnvs(lex *wordExpander, values []string) []string {
	for i := 1; i < len(values); i += 3 {
		values[i] = expandValues(lex, []string{values[i]}, s.envs, s.args)[0]
	}
	saveEnvs(s.envs, values)
	return values
}

// variableEnvironment searches scopes in priority order (ENV before ARG).
type variableEnvironment []map[string]string

func (env variableEnvironment) Get(name string) (string, bool) {
	for _, scope := range env {
		if value, ok := scope[name]; ok {
			return value, true
		}
	}
	return "", false
}

func (env variableEnvironment) Keys() []string {
	keys := make(map[string]struct{})
	for _, scope := range env {
		for key := range scope {
			keys[key] = struct{}{}
		}
	}
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	return result
}

func saveEnvs(envs map[string]string, envValues []string) map[string]string {
	// Multiple env variables may be defined in the same instruction
	// Each env variable slice looks like ["name", "value", "="]
	if len(envValues)%3 == 0 {
		for i := 0; i < len(envValues); i += 3 {
			envs[envValues[i]] = envValues[i+1]
		}
	}
	return envs
}

func (s variableScope) expandCommand(cmd *Command, globalArgs map[string]string, lex, declarationLex *wordExpander) {
	switch cmd.Cmd {
	case command.From:
		cmd.Value = expandValues(lex, cmd.Value, globalArgs)
	case command.Arg:
		cmd.Value = s.declareArgs(declarationLex, cmd.Value, globalArgs)
	case command.Env:
		cmd.Value = s.declareEnvs(declarationLex, cmd.Value)
	case command.Onbuild:
		// Triggers execute in a future child build, not in this stage.
	default:
		cmd.Value = expandValues(lex, cmd.Value, s.envs, s.args)
	}
}
