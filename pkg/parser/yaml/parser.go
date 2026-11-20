/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package yaml

import (
	"bytes"
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/utils"
	fixtureutils "github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/file"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

// resolve replaces the file references of the documents with the content
// they reference (see file.Resolver.ResolveYAML). It returns no documents
// when nothing was resolved.
func resolve(ctx context.Context, fsys vfs.FS, fileContent []byte, filename string,
	resolveReferences bool, maxResolverDepth int) (resolved []*yaml.Node, resolvedFiles map[string]model.ResolvedFile) {
	// Resolve files passed as arguments with file resolver (e.g. file://)
	res := file.NewResolver(fsys, yaml.Unmarshal, yaml.Marshal, SupportedExtensions())
	resolved = res.ResolveYAML(ctx, fileContent, filename, maxResolverDepth, resolveReferences)

	if len(res.ResolvedFiles) == 0 {
		return nil, res.ResolvedFiles
	}

	return resolved, res.ResolvedFiles
}

// Parse parses yaml/yml file and returns it as a Document
func Parse(ctx context.Context, fsys vfs.FS, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	return ParseWithNodeTransform(ctx, fsys, fileContent, filePath, resolveReferences, maxResolverDepth, nil)
}

// ParseWithNodeTransform parses like Parse, but applies fn to each
// document's root mapping node before it is converted to a model.Document.
// The transform sees the same nodes that line tracking is built from, so
// in-place value rewrites keep their original line numbers. A nil fn is
// equivalent to Parse.
//
// The returned content is fileContent: resolved references are inlined in the
// documents only, where the content of a file referenced several times is
// shared between its references instead of being copied.
func ParseWithNodeTransform(ctx context.Context, fsys vfs.FS, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int, fn func(node *yaml.Node)) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	resolvedDocs, resolvedFiles := resolve(ctx, fsys, fileContent, filePath, resolveReferences, maxResolverDepth)
	if resolvedDocs == nil {
		documents, ignoreLines, err = parseNodes(ctx, fileContent, filePath, fn)
		return fileContent, documents, ignoreLines, resolvedFiles, err
	}
	documents, err = convertResolvedNodes(ctx, resolvedDocs, filePath, fn)
	if err != nil {
		return fileContent, nil, []int{}, resolvedFiles, err
	}
	// Ignore comments are read from the file itself: resolved nodes carry the
	// comments of the referenced files too, with no position in this one.
	ignoreLines = model.GetIgnoreLines(&model.FileMetadata{FilePath: filePath, OriginalData: string(fileContent)})
	return fileContent, documents, ignoreLines, resolvedFiles, nil
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
	ctx = model.WithYAMLFilePath(ctx, filePath)
	ignore := &model.Ignore{}

	dec := yaml.NewDecoder(bytes.NewReader(resolved))
	for {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			break
		}
		documents = appendDocument(ctx, documents, &node, filePath, fn, ignore)
	}

	if len(documents) == 0 {
		return nil, []int{}, errors.New("no documents found in yaml file")
	}

	linesToIgnore := ignore.GetLines()

	return documents, linesToIgnore, nil
}

// convertResolvedNodes converts documents whose file references were resolved,
// keeping the nodes they share shared (see model.Document.UnmarshalSharedYAML).
func convertResolvedNodes(ctx context.Context, nodes []*yaml.Node, filePath string, fn func(node *yaml.Node)) (
	documents []model.Document,
	err error) {
	ctx = model.WithYAMLFilePath(ctx, filePath)
	for _, node := range nodes {
		documents = appendDocument(ctx, documents, node, filePath, fn, nil)
	}
	if len(documents) == 0 {
		return nil, errors.New("no documents found in yaml file")
	}
	return documents, nil
}

// appendDocument converts one decoded document and appends it to documents,
// skipping empty and unparseable ones. A nil ignore marks a resolved document,
// whose nodes can be shared (see model.Document.UnmarshalSharedYAML).
func appendDocument(ctx context.Context, documents []model.Document, node *yaml.Node, filePath string,
	fn func(node *yaml.Node), ignore *model.Ignore) []model.Document {
	if IsEmptyDocument(node) {
		return documents
	}
	contentNode := node.Content[0]
	if fn != nil {
		fn(contentNode)
	}
	doc := model.Document{}
	var err error
	if ignore == nil {
		err = doc.UnmarshalSharedYAML(ctx, contentNode)
	} else {
		err = doc.UnmarshalYAML(ctx, contentNode, ignore)
	}
	if err != nil {
		fixtureutils.WarnUnlessFixture(ctx, filePath).Err(err).Msgf("skipping unparseable yaml document in %s", filePath)
		return documents
	}
	if len(doc) > 0 {
		doc["_path"] = filePath
		documents = append(documents, doc)
	}
	return documents
}

// IsEmptyDocument reports whether a decoded YAML document holds nothing, an
// empty or comment-only document the parser skips without a document index.
func IsEmptyDocument(doc *yaml.Node) bool {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0] == nil {
		return true
	}
	n := doc.Content[0]
	return n.Kind == yaml.ScalarNode && (n.Value == "" || n.Tag == "!!null")
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

// certificateEnricher owns the filesystem and source context for one document
// traversal; recursive helpers need only the values they process.
type certificateEnricher struct {
	ctx      context.Context
	fsys     vfs.FS
	filePath string
}

func (e *certificateEnricher) processElements(elements map[string]interface{}) {
	// A map shared by several resolved references is seen once per reference,
	// and certificate is a map once processed.
	certificate, ok := elements["certificate"].(string)
	if !ok {
		return
	}
	content := utils.CheckCertificate(certificate)
	if content == "" {
		return
	}
	if info := utils.AddCertificateInfo(e.ctx, e.fsys, e.filePath, content); info != nil {
		elements["certificate"] = info
	}
}

// AddExtraInfo enriches certificates through a non-nil parser-owned filesystem.
// Callers resolve their filesystem defaults before enrichment.
func AddExtraInfo(ctx context.Context, fsys vfs.FS, documents []model.Document, filePath string) []model.Document {
	enricher := certificateEnricher{ctx: ctx, fsys: fsys, filePath: filePath}
	for _, documentPlaybooks := range documents { // iterate over documents
		if playbooks, ok := documentPlaybooks["playbooks"]; ok {
			enricher.processPlaybooks(playbooks)
		}
	}

	return documents
}

func (e *certificateEnricher) processPlaybooks(playbooks interface{}) {
	contextLogger := logger.FromContext(e.ctx)
	sliceResources, ok := playbooks.([]interface{})
	if !ok { // prevent panic if playbooks is not a slice
		contextLogger.Warn().Msgf("Failed to parse playbooks: %s", e.filePath)
		return
	}
	for _, resources := range sliceResources { // iterate over playbooks
		e.processPlaybooksElements(resources)
	}
}

func (e *certificateEnricher) processPlaybooksElements(resources interface{}) {
	contextLogger := logger.FromContext(e.ctx)
	mapResources, ok := resources.(map[string]interface{})
	if !ok {
		contextLogger.Warn().Msgf("Failed to parse playbooks elements: %s", e.filePath)
		return
	}
	for _, value := range mapResources {
		mapValue, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		e.processElements(mapValue)
	}
}
