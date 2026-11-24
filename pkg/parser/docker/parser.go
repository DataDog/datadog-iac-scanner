package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	iacparser "github.com/DataDog/datadog-iac-scanner/pkg/parser"
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

	lineInfoOnly := iacparser.IsLineInfoOnly(ctx)
	var lex, declarationLex *wordExpander
	if !lineInfoOnly {
		lex = newWordExpander(parsed.EscapeToken, true)
		declarationLex = newWordExpander(parsed.EscapeToken, false)
	}
	stages := newStageScopes()

	for _, child := range parsed.AST.Children {
		name := strings.ToLower(strings.TrimSpace(child.Value))
		if name == command.From {
			fromValue = fromArguments(child.Original)
			if !lineInfoOnly {
				stages.enter(child, declarationLex)
			}
		}

		if ignoreStruct.getIgnoreComments(child) {
			ignoreStruct.setIgnore(fromValue)
		}

		ignoreStruct.ignoreBlock(child, fromValue)

		cmd := commandFromNode(child)

		// Source locations keep raw commands before rule-facing enrichment.
		if !lineInfoOnly {
			stages.expandCommand(&cmd, lex, declarationLex)
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

// IsDockerfile reports whether content parses as a Dockerfile whose first
// non-ARG instruction is a FROM with an image or stage argument.
func IsDockerfile(content []byte) bool {
	parsed, err := parser.Parse(bytes.NewReader(content))
	if err != nil || parsed == nil || parsed.AST == nil {
		return false
	}
	for _, node := range parsed.AST.Children {
		if strings.EqualFold(node.Value, command.Arg) {
			continue
		}
		return strings.EqualFold(node.Value, command.From) && node.Next != nil
	}
	return false
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

// commandFromNode keeps BuildKit's nested instruction and source boundaries.
func commandFromNode(child *parser.Node) Command {
	cmd := Command{
		Cmd:       strings.ToLower(strings.TrimSpace(child.Value)),
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

	return cmd
}

// fromArguments returns the raw arguments of a FROM instruction, including
// flags and an optional alias. Non-instructions and keyword prefixes return "".
func fromArguments(original string) string {
	original = strings.TrimSpace(original)
	end := strings.IndexAny(original, " \t\r\n\v\f")
	if end < 0 || !strings.EqualFold(original[:end], command.From) {
		return ""
	}
	return strings.TrimSpace(original[end:])
}
