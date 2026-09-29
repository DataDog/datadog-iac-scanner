/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package yaml

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/utils"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/file"
	"gopkg.in/yaml.v3"
)

// Resolve - replace or modifies in-memory content before parsing
func resolve(ctx context.Context, fileContent []byte, filename string,
	resolveReferences bool, maxResolverDepth int) (resolved []byte, resolvedFiles map[string]model.ResolvedFile) {
	// Resolve files passed as arguments with file resolver (e.g. file://)
	res := file.NewResolver(yaml.Unmarshal, yaml.Marshal, SupportedExtensions())
	resolvedFilesCache := make(map[string]file.ResolvedFile)
	resolved = res.Resolve(ctx, fileContent, filename, 0, maxResolverDepth, resolvedFilesCache, resolveReferences)

	if len(res.ResolvedFiles) == 0 {
		return fileContent, res.ResolvedFiles
	}

	return resolved, res.ResolvedFiles
}

// Parse parses a YAML stream. Empty documents are a successful no-op. If some
// documents are usable but others fail, it returns those documents alongside a
// model.PartialYAMLParseError; callers must retain the failure diagnostic.
func Parse(ctx context.Context, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	return ParseWithNodeTransform(ctx, fileContent, filePath, resolveReferences, maxResolverDepth, nil)
}

// ParseWithNodeTransform parses like Parse, but applies fn to each
// document's root mapping node before it is converted to a model.Document.
// The transform sees the same nodes that line tracking is built from, so
// in-place value rewrites keep their original line numbers. A nil fn is
// equivalent to Parse.
func ParseWithNodeTransform(ctx context.Context, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int, fn func(node *yaml.Node)) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	resolved, resolvedFiles = resolve(ctx, fileContent, filePath, resolveReferences, maxResolverDepth)
	documents, ignoreLines, err = parseNodes(ctx, resolved, filePath, fn)
	return resolved, documents, ignoreLines, resolvedFiles, err
}

// ParseWithNodeTransformNoResolve is ParseWithNodeTransform without the
// generic file-reference resolution pass. Platforms with their own
// sibling-file semantics (Docker Compose extends/env_file) resolve those
// references themselves; the generic resolver would otherwise inline any
// .yaml-valued scalar as a reference target.
func ParseWithNodeTransformNoResolve(ctx context.Context, fileContent []byte, filePath string,
	fn func(node *yaml.Node)) (
	documents []model.Document,
	ignoreLines []int,
	err error) {
	return parseNodes(ctx, fileContent, filePath, fn)
}

// parseNodes decodes the (already resolved) YAML bytes into documents,
// applying fn to each document's root node before conversion.
func parseNodes(ctx context.Context, resolved []byte, filePath string, fn func(node *yaml.Node)) (
	documents []model.Document,
	ignoreLines []int,
	err error) {
	ignore := &model.Ignore{}

	dec := yaml.NewDecoder(bytes.NewReader(resolved))
	var failures []error
	for documentIndex := 1; ; documentIndex++ {
		var node yaml.Node
		if decodeErr := dec.Decode(&node); decodeErr != nil {
			if !errors.Is(decodeErr, io.EOF) {
				failures = append(failures, fmt.Errorf("YAML document %d: %w", documentIndex, safeNodeDecodeError(decodeErr)))
			}
			// A syntax error prevents reliable recovery of the rest of the stream.
			break
		}

		if node.Kind != yaml.DocumentNode || len(node.Content) == 0 {
			continue
		}
		contentNode := node.Content[0]
		if isEmptyYAMLDocument(contentNode) {
			continue
		}
		if contentNode.Kind == yaml.ScalarNode {
			// Scalar roots cannot represent IaC documents. Reject them before
			// conversion, which may log their raw value while decoding a tag.
			failures = append(failures, fmt.Errorf("YAML document %d: unsupported scalar document", documentIndex))
			continue
		}
		if fn != nil {
			fn(contentNode)
		}
		doc := model.Document{}
		if conversionErr := doc.UnmarshalYAML(ctx, contentNode, ignore); conversionErr != nil {
			failures = append(failures, fmt.Errorf("YAML document %d: %w", documentIndex, conversionErr))
			continue
		}

		if len(doc) > 0 {
			doc["_path"] = filePath
			documents = append(documents, doc)
		}
	}

	err = errors.Join(failures...)
	if err != nil && len(documents) > 0 {
		err = &model.PartialYAMLParseError{Err: err}
	}
	// Successfully reaching EOF with only empty documents is a benign no-op.
	// Conversion failures are not empty documents and remain errors.
	return documents, ignore.GetLines(), err
}

// Decoding into yaml.Node bypasses Go-value conversion errors. yaml.v3's
// parser/scanner diagnostics carry syntax and location, except unknown aliases
// quote a source-supplied anchor name. Do not retain that name in the error chain.
func safeNodeDecodeError(err error) error {
	message := err.Error()
	if strings.HasPrefix(message, "yaml: unknown anchor '") && strings.HasSuffix(message, "' referenced") {
		return errors.New("yaml: unknown anchor referenced")
	}
	return err
}

func isEmptyYAMLDocument(node *yaml.Node) bool {
	if node == nil {
		return true
	}
	if node.Kind != yaml.ScalarNode {
		return false
	}
	if node.Tag == "!!str" && node.Value == "" {
		return true
	}
	if node.Tag != "!!null" {
		return false
	}
	// An explicit null tag can still carry an invalid value; only genuine
	// nulls (including the decoder's representation of an empty document) skip conversion.
	var value interface{}
	return node.Decode(&value) == nil && value == nil
}

// convertKeysToString goes through every document to convert map[interface{}]interface{}
// to map[string]interface{}
func ConvertKeysToString(docs []model.Document) []model.Document {
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
func SupportedExtensions() []string {
	return []string{".yaml", ".yml"}
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

func AddExtraInfo(ctx context.Context, documents []model.Document, filePath string) []model.Document {
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
