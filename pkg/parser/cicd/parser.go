/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package cicd

import (
	"bytes"
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/file"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

// Parser defines a parser type
type Parser struct {
	shellParser      *ShellScriptParser
	expressionParser *ExpressionParser
}

// ParsedCommand represents a parsed shell command
type ParsedCommand struct {
	Type     string          `json:"type"`    // "command", "pipeline", "redirected_statement"
	Command  string          `json:"command"` // Command name (e.g., "echo", "cargo")
	Args     []ParsedArg     `json:"args"`    // Command arguments
	Redirect *ParsedRedirect `json:"redirect,omitempty"`
	Pipeline []ParsedCommand `json:"pipeline,omitempty"`
}

// ParsedArg represents a command argument
type ParsedArg struct {
	Type  string `json:"type"`          // "literal", "expansion", "command_substitution"
	Value string `json:"value"`         // The text content
	Var   string `json:"var,omitempty"` // Variable name if type is expansion
}

// ParsedRedirect represents a file redirection
type ParsedRedirect struct {
	Operator string    `json:"operator"` // ">>", ">", etc.
	Target   ParsedArg `json:"target"`   // Redirect target
}

// ParsedRun represents a fully parsed run block
type ParsedRun struct {
	Shell    string          `json:"shell"`           // "bash", "pwsh", etc.
	Commands []ParsedCommand `json:"commands"`        // All commands found
	ParseOK  bool            `json:"parse_ok"`        // Whether parsing succeeded
	Error    string          `json:"error,omitempty"` // Parse error if any
}

// Resolve - replace or modifies in-memory content before parsing
func (p *Parser) Resolve(ctx context.Context, fileContent []byte, filename string,
	resolveReferences bool, maxResolverDepth int) (resolved []byte, resolvedFiles map[string]model.ResolvedFile, err error) {
	// Resolve files passed as arguments with file resolver (e.g. file://)
	res := file.NewResolver(yaml.Unmarshal, yaml.Marshal, p.SupportedExtensions())
	resolvedFilesCache := make(map[string]file.ResolvedFile)
	resolved = res.Resolve(ctx, fileContent, filename, 0, maxResolverDepth, resolvedFilesCache, resolveReferences)

	if len(res.ResolvedFiles) == 0 {
		return fileContent, res.ResolvedFiles, nil
	}

	return resolved, res.ResolvedFiles, nil
}

// Parse parses yaml/yml file and returns it as a Document
func (p *Parser) Parse(ctx context.Context, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	resolved, resolvedFiles, err = p.Resolve(ctx, fileContent, filePath, resolveReferences, maxResolverDepth)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	ignore := &model.Ignore{}

	// Parse all documents as nodes
	dec := yaml.NewDecoder(bytes.NewReader(resolved))
	for {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			break
		}

		// Process each document node
		if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
			// Get the actual content (not the document wrapper)
			contentNode := node.Content[0]
			doc := model.Document{}
			if err := doc.UnmarshalYAML(ctx, contentNode, ignore); err != nil {
				return []byte{}, nil, []int{}, map[string]model.ResolvedFile{}, errors.Wrap(err, "failed to unmarshal yaml")
			}

			if len(doc) > 0 {
				documents = append(documents, doc)
			}
		}
	}

	if len(documents) == 0 {
		return []byte{}, nil, []int{}, map[string]model.ResolvedFile{}, errors.New("no documents found in yaml file")
	}

	// Convert keys to string format
	documents = convertKeysToString(documents)

	// Enhance documents with parsed run blocks
	p.enhanceWithParsedRuns(ctx, documents)

	linesToIgnore := ignore.GetLines()

	// UnmarshalYAML already adds line tracking, so we can use documents directly
	return resolved, convertKeysToString(addExtraInfo(ctx, documents, filePath)), linesToIgnore, resolvedFiles, nil
}

// convertKeysToString goes through every document to convert map[interface{}]interface{}
// to map[string]interface{}
func convertKeysToString(docs []model.Document) []model.Document {
	documents := make([]model.Document, 0, len(docs))
	for _, doc := range docs {
		for key, value := range doc {
			doc[key] = convert(value)
		}
		documents = append(documents, doc)
	}
	return documents
}

// convert goes recursively through the keys in the given value and converts nested maps type of map[interface{}]interface{}
// to map[string]interface{}
func convert(value interface{}) interface{} {
	switch t := value.(type) {
	case map[interface{}]interface{}:
		mapStr := map[string]interface{}{}
		for key, val := range t {
			if t, ok := key.(string); ok {
				mapStr[t] = convert(val)
			}
		}
		return mapStr
	case []interface{}:
		for key, val := range t {
			t[key] = convert(val)
		}
	case model.Document:
		for key, val := range t {
			t[key] = convert(val)
		}
	}
	return value
}

// SupportedExtensions returns extensions supported by this parser, which are yaml and yml extension
func (p *Parser) SupportedExtensions() []string {
	return []string{".yaml", ".yml"}
}

// SupportedTypes returns types supported by this parser, which are ansible, cloudFormation, k8s
func (p *Parser) SupportedTypes() map[string]bool {
	return map[string]bool{
		"cicd": true,
	}
}

// GetKind returns YAML constant kind
func (p *Parser) GetKind() model.FileKind {
	return model.KindYAML
}

func processCertContent(ctx context.Context, elements map[string]interface{}, content, filePath string) {
	var certInfo map[string]interface{}
	if content != "" {
		certInfo = utils.AddCertificateInfo(ctx, filePath, content)
		if certInfo != nil {
			elements["certificate"] = certInfo
		}
	}
}

func processElements(ctx context.Context, elements map[string]interface{}, filePath string) {
	if elements["certificate"] != nil {
		processCertContent(ctx, elements, utils.CheckCertificate(elements["certificate"].(string)), filePath)
	}
}

func addExtraInfo(ctx context.Context, documents []model.Document, filePath string) []model.Document {
	for _, documentPlaybooks := range documents { // iterate over documents
		if playbooks, ok := documentPlaybooks["playbooks"]; ok {
			processPlaybooks(ctx, playbooks, filePath)
		}
	}

	return documents
}

func processPlaybooks(ctx context.Context, playbooks interface{}, filePath string) {
	contextLogger := logger.FromContext(ctx)
	sliceResources, ok := playbooks.([]interface{})
	if !ok { // prevent panic if playbooks is not a slice
		contextLogger.Warn().Msgf("Failed to parse playbooks: %s", filePath)
		return
	}
	for _, resources := range sliceResources { // iterate over playbooks
		processPlaybooksElements(ctx, resources, filePath)
	}
}

func processPlaybooksElements(ctx context.Context, resources interface{}, filePath string) {
	contextLogger := logger.FromContext(ctx)
	mapResources, ok := resources.(map[string]interface{})
	if !ok {
		contextLogger.Warn().Msgf("Failed to parse playbooks elements: %s", filePath)
		return
	}
	for _, value := range mapResources {
		mapValue, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		processElements(ctx, mapValue, filePath)
	}
}

// GetCommentToken return the comment token of YAML - #
func (p *Parser) GetCommentToken() string {
	return "#"
}

// StringifyContent converts original content into string formatted version
func (p *Parser) StringifyContent(content []byte) (string, error) {
	return string(content), nil
}

// getShellParser returns the shell parser, initializing it if needed
func (p *Parser) getShellParser() *ShellScriptParser {
	if p.shellParser == nil {
		p.shellParser = NewShellScriptParser()
	}
	return p.shellParser
}

// enhanceWithParsedRuns walks through documents and parses run blocks with tree-sitter
func (p *Parser) enhanceWithParsedRuns(ctx context.Context, documents []model.Document) {
	shellParser := p.getShellParser()

	for _, doc := range documents {
		// Look for jobs in the workflow
		jobs, ok := doc["jobs"]
		if !ok {
			continue
		}

		jobsMap, ok := jobs.(map[string]interface{})
		if !ok {
			continue
		}

		for _, j := range jobsMap {
			job, ok := j.(map[string]interface{})
			if !ok {
				continue
			}

			// Look for steps in the job
			steps, ok := job["steps"]
			if !ok {
				continue
			}

			stepsSlice, ok := steps.([]interface{})
			if !ok {
				continue
			}

			for _, s := range stepsSlice {
				step, ok := s.(map[string]interface{})
				if !ok {
					continue
				}

				// Check if step has a run block
				runScript, ok := step["run"].(string)
				if !ok {
					continue
				}

				// Determine shell (default to bash)
				shell := "bash"
				if shellVal, ok := step["shell"].(string); ok {
					shell = shellVal
				}

				// Parse the run block
				parsed := shellParser.ParseRunBlock(ctx, runScript, shell)

				// Add parsed structure to step
				step["_parsed_run"] = parsed
			}
		}
	}
}
