package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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

	args := make(map[string]string, 0)
	envs := make(map[string]string, 0)

	for _, child := range parsed.AST.Children {
		child.Value = strings.ToLower(strings.TrimSpace(child.Value))
		if child.Value == "from" {
			fromValue = fromArguments(child.Original)
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

		if child.Value != "arg" {
			cmd.Value = resolveArgsAndEnvs(cmd.Value, args)
		} else {
			// A bare ARG has no value; an ARG may also declare several names.
			for _, argValue := range cmd.Value {
				args = saveArgs(args, resolveArgsAndEnvs([]string{argValue}, args)[0])
			}
		}

		if child.Value != "env" {
			cmd.Value = resolveArgsAndEnvs(cmd.Value, envs)
		} else {
			// Resolve against the prior scope without changing declaration text.
			envValues := append([]string(nil), cmd.Value...)
			envs = saveEnvs(envs, resolveArgsAndEnvs(envValues, envs))
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

var variableReference = regexp.MustCompile(`\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)`)

// resolveArgsAndEnvs replaces whole variable names in one pass, leaving unknown
// references intact. Map order cannot affect the result or recursively expand it.
func resolveArgsAndEnvs(values []string, args map[string]string) []string {
	if len(args) == 0 {
		return values
	}
	for i := range values {
		values[i] = variableReference.ReplaceAllStringFunc(values[i], func(reference string) string {
			name := reference[1:]
			if name[0] == '{' {
				name = name[1 : len(name)-1]
			}
			if value, ok := args[name]; ok {
				return value
			}
			return reference
		})
	}

	return values
}

func saveArgs(args map[string]string, argValue string) map[string]string {
	value := strings.Split(argValue, "=")
	if len(value) == 2 {
		args[value[0]] = value[1]
	}
	if len(value) > 2 {
		// to handle cases like ARG VAR=erereR=E
		args[value[0]] = strings.Join(value[1:], "=")
	}

	return args
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
