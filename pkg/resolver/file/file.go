package file

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/analyzer"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"gopkg.in/yaml.v3"
)

var serverlessFileReferenceRE = regexp.MustCompile(`^\${file\((.*\.(yaml|yml))\)}$`)

// ResolvedFile - used for caching the already resolved files
type ResolvedFile struct {
	fileContent []byte
	readErr     error
	// Views depend on the caller's existing remaining depth, not the path by
	// which it reached this file. Raw bytes are shared across all those views.
	views map[int]any
}

// Resolver - replace or modifies in-memory content before parsing
type Resolver struct {
	fsys          vfs.FS
	unmarshler    func(fileContent []byte, v any) error
	marshler      func(v any) ([]byte, error)
	ResolvedFiles map[string]model.ResolvedFile
	Extension     []string
}

// NewResolver returns a new Resolver
func NewResolver(
	fsys vfs.FS,
	unmarshler func(fileContent []byte, v any) error,
	marshler func(v any) ([]byte, error),
	ext []string) *Resolver {
	if fsys == nil {
		fsys = vfs.DiskFS{}
	}
	return &Resolver{
		fsys:          fsys,
		unmarshler:    unmarshler,
		marshler:      marshler,
		ResolvedFiles: make(map[string]model.ResolvedFile),
		Extension:     ext,
	}
}

func isOpenAPI(fileContent []byte) bool {
	// Cheap necessary condition: every regex below requires the literal
	// openapi/swagger anchor, so a memchr-speed literal scan rejects the
	// non-OpenAPI YAML files (nearly all of them) before any regex runs over
	// the full content — the regex scans were ~30% of prepare CPU on
	// manifest-heavy corpora.
	if !bytes.Contains(fileContent, []byte("openapi")) &&
		!bytes.Contains(fileContent, []byte("swagger")) {
		return false
	}
	regexToRun :=
		[]*regexp.Regexp{analyzer.OpenAPIRegex,
			analyzer.OpenAPIRegexInfo,
			analyzer.OpenAPIRegexPath}
	for _, regex := range regexToRun {
		if !regex.Match(fileContent) {
			return false
		}
	}
	return true
}

// mayReferenceYAMLFiles reports whether the resolution can change a YAML
// file: it needs a $ref/include_vars key or a scalar naming an external
// .yaml/.yml file (findFilePath requires the extension in the value; the
// serverless ${file(...)} form embeds it too), and each of those leaves a
// literal in the file bytes. Without any of them the resolution is a full
// parse and walk that returns an equivalent document, so it is skipped.
func mayReferenceYAMLFiles(fileContent []byte) bool {
	return bytes.Contains(fileContent, []byte("$ref")) ||
		bytes.Contains(fileContent, []byte("include_vars")) ||
		bytes.Contains(fileContent, []byte(".yaml")) ||
		bytes.Contains(fileContent, []byte(".yml"))
}

// ResolveYAML replaces the file references of every document of a YAML file
// with the content they reference, and returns the documents. It returns no
// documents when the file cannot hold a reference; ResolvedFiles is empty when
// nothing was resolved.
//
// A referenced file is read once per call. Its resolved nodes are shared for
// references with the same remaining depth, preserving the caller's configured
// frontier even when a deep reference is visited before a shallow one. When
// references form a DAG, the retained graph grows with file/depth views rather
// than the number of paths through the references.
// The nodes are not to be modified, since a change to a shared node shows at
// every reference to it.
//
// The nodes of a referenced file carry no position: line numbers are those
// of the file being resolved, and the referenced file has its own (see
// ResolvedFiles).
func (r *Resolver) ResolveYAML(ctx context.Context, fileContent []byte, path string,
	maxResolverDepth int, resolveReferences bool) (docs []*yaml.Node) {
	contextLogger := logger.FromContext(ctx)
	defer func() {
		if p := recover(); p != nil {
			contextLogger.Err(fmt.Errorf("panic: %v", p)).Msg("Recovered from panic during resolve of file " + path)
			// The file is left unresolved: it must not report resolved files.
			docs = nil
			clear(r.ResolvedFiles)
		}
		if ctx.Err() != nil {
			docs = nil
			clear(r.ResolvedFiles)
		}
	}()
	if ctx.Err() != nil {
		return nil
	}

	if (!resolveReferences && isOpenAPI(fileContent)) || !mayReferenceYAMLFiles(fileContent) {
		return nil
	}

	resolvedFilesCache := map[string]ResolvedFile{filepath.Clean(path): {fileContent: fileContent, views: map[int]any{}}}
	dec := yaml.NewDecoder(bytes.NewReader(fileContent))
	for ctx.Err() == nil {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			break
		}
		resolved := r.resolveYAMLDocument(ctx, fileContent, &doc, path, 0, maxResolverDepth, resolvedFilesCache, resolveReferences)
		if ctx.Err() != nil {
			return nil
		}
		docs = append(docs, &resolved)
	}
	return docs
}

// Resolve - replace or modifies in-memory content before parsing.
// For a YAML file, it returns the first document with the referenced content
// copied at each reference; ResolveYAML shares it instead.
func (r *Resolver) Resolve(ctx context.Context, fileContent []byte, path string,
	resolveCount, maxResolverDepth int, resolvedFilesCache map[string]ResolvedFile,
	resolveReferences bool) (resolved []byte) {
	contextLogger := logger.FromContext(ctx)
	// handle panic during resolve process
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("panic: %v", r)
			contextLogger.Err(err).Msg("Recovered from panic during resolve of file " + path)
		}
		if ctx.Err() != nil {
			resolved = fileContent
			clear(r.ResolvedFiles)
		}
	}()
	if ctx.Err() != nil {
		return fileContent
	}
	if resolvedFilesCache == nil {
		resolvedFilesCache = make(map[string]ResolvedFile)
	}
	if _, exists := resolvedFilesCache[filepath.Clean(path)]; !exists {
		resolvedFilesCache[filepath.Clean(path)] = ResolvedFile{fileContent: fileContent, views: map[int]any{}}
	}

	if !resolveReferences && isOpenAPI(fileContent) {
		return fileContent
	}

	if utils.Contains(filepath.Ext(path), []string{".yml", ".yaml"}) {
		if !mayReferenceYAMLFiles(fileContent) {
			return fileContent
		}
		return r.yamlResolve(ctx, fileContent, path, resolveCount, maxResolverDepth, resolvedFilesCache, resolveReferences)
	}
	var obj any
	err := r.unmarshler(fileContent, &obj)
	if err != nil {
		return fileContent
	}

	// resolve the paths
	obj, _ = r.walk(ctx, fileContent, obj, obj, path, resolveCount, maxResolverDepth, resolvedFilesCache, false, resolveReferences)

	if ctx.Err() != nil {
		return fileContent
	}
	b, err := json.MarshalIndent(obj, "", "")
	if err == nil {
		return b
	}

	return fileContent
}

func (r *Resolver) walk(
	ctx context.Context,
	originalFileContent []byte,
	fullObject interface{},
	value any,
	path string,
	resolveCount, maxResolverDepth int,
	resolvedFilesCache map[string]ResolvedFile,
	refBool, resolveReferences bool) (any, bool) {
	if ctx.Err() != nil {
		return value, false
	}
	// go over the value and replace paths with the real content
	switch typedValue := value.(type) {
	case string:
		if filepath.Base(path) != typedValue {
			return r.resolvePath(
				ctx,
				originalFileContent, fullObject, typedValue, path, resolveCount,
				maxResolverDepth, resolvedFilesCache, refBool, resolveReferences)
		}
		return value, false
	case []any:
		for i, v := range typedValue {
			if ctx.Err() != nil {
				return value, false
			}
			typedValue[i], _ = r.walk(
				ctx,
				originalFileContent, fullObject, v, path, resolveCount,
				maxResolverDepth, resolvedFilesCache, refBool, resolveReferences)
		}
		return typedValue, false
	case map[string]any:
		return r.handleMap(
			ctx,
			originalFileContent, fullObject, typedValue, path, resolveCount,
			maxResolverDepth, resolvedFilesCache, resolveReferences)
	default:
		return value, false
	}
}

func (r *Resolver) handleMap(
	ctx context.Context,
	originalFileContent []byte,
	fullObject interface{},
	value map[string]interface{},
	path string,
	resolveCount, maxResolverDepth int,
	resolvedFilesCache map[string]ResolvedFile,
	resolveReferences bool,
) (any, bool) {
	for k, v := range value {
		if ctx.Err() != nil {
			return value, false
		}
		isRef := strings.Contains(strings.ToLower(k), "$ref")
		val, res := r.walk(ctx, originalFileContent, fullObject, v, path, resolveCount, maxResolverDepth,
			resolvedFilesCache, isRef, resolveReferences)
		// check if it is a ref then add new details
		if valMap, ok := val.(map[string]interface{}); (ok || !res) && isRef {
			// Reference metadata belongs to this occurrence, not the cached view.
			// Only the outer mapping changes; nested resolved content stays shared.
			valMap = maps.Clone(valMap)
			if valMap == nil {
				valMap = make(map[string]interface{})
			}
			valMap["RefMetadata"] = make(map[string]interface{})
			valMap["RefMetadata"].(map[string]interface{})["$ref"] = v
			valMap["RefMetadata"].(map[string]interface{})["alone"] = len(value) == 1
			return valMap, false
		}
		if isRef && res {
			return val, false
		}
		value[k] = val
	}
	return value, false
}

func (r *Resolver) yamlResolve(ctx context.Context, fileContent []byte, path string,
	resolveCount, maxResolverDepth int, resolvedFilesCache map[string]ResolvedFile,
	resolveReferences bool) []byte {
	var obj yaml.Node
	err := r.unmarshler(fileContent, &obj)
	if err != nil {
		return fileContent
	}

	obj = r.resolveYAMLDocument(ctx, fileContent, &obj, path, resolveCount, maxResolverDepth, resolvedFilesCache, resolveReferences)

	if obj.Kind == yaml.DocumentNode && len(obj.Content) == 1 {
		obj = *obj.Content[0]
	}

	if ctx.Err() != nil {
		return fileContent
	}
	b, err := r.marshler(obj)
	if err != nil {
		return fileContent
	}

	return b
}

// resolveYAMLDocument replaces the file references found in doc, a decoded
// document of the file at path, with the content they reference.
func (r *Resolver) resolveYAMLDocument(ctx context.Context, fileContent []byte, doc *yaml.Node, path string,
	resolveCount, maxResolverDepth int, resolvedFilesCache map[string]ResolvedFile,
	resolveReferences bool) yaml.Node {
	fullObjectCopy := *doc
	resolved, _ := r.yamlWalk(
		ctx,
		fileContent, &fullObjectCopy, doc, path, resolveCount,
		maxResolverDepth, resolvedFilesCache, false, resolveReferences, false)
	return resolved
}

func (r *Resolver) yamlWalk(
	ctx context.Context,
	originalFileContent []byte,
	fullObject *yaml.Node,
	value *yaml.Node,
	path string,
	resolveCount, maxResolverDepth int,
	resolvedFilesCache map[string]ResolvedFile,
	refBool, resolveReferences, ansibleVars bool) (yaml.Node, bool) {
	if ctx.Err() != nil {
		return *value, false
	}
	// go over the value and replace paths with the real content
	switch value.Kind {
	case yaml.ScalarNode:
		if filepath.Base(path) != value.Value {
			return r.resolveYamlPath(ctx, originalFileContent, fullObject,
				value, path,
				resolveCount, maxResolverDepth, resolvedFilesCache,
				refBool, resolveReferences, ansibleVars)
		}
		return *value, false
	default:
		refBool := false
		ansibleVars := false
		for i := range value.Content {
			if ctx.Err() != nil {
				return *value, false
			}
			if i >= 1 {
				refBool = strings.Contains(value.Content[i-1].Value, "$ref")
				ansibleVars = strings.Contains(value.Content[i-1].Value, "include_vars")
			}
			resolved, ok := r.yamlWalk(ctx, originalFileContent, fullObject,
				value.Content[i], path,
				resolveCount, maxResolverDepth, resolvedFilesCache,
				refBool, resolveReferences, ansibleVars)

			if i >= 1 && refBool && (resolved.Kind == yaml.MappingNode || !ok) {
				// Create RefMetadata and add it to yaml Node
				if !ok {
					resolved = yaml.Node{
						Kind: yaml.MappingNode,
					}
				}
				originalValueNode := &yaml.Node{
					Kind:  yaml.ScalarNode,
					Value: "$ref",
				}
				refAloneKeyNode := &yaml.Node{
					Kind:  yaml.ScalarNode,
					Value: "alone",
				}
				refAloneValueNode := &yaml.Node{
					Kind:  yaml.ScalarNode,
					Value: strconv.FormatBool(len(value.Content) == 2),
				}
				refMetadataKeyNode := &yaml.Node{
					Kind:  yaml.ScalarNode,
					Value: "RefMetadata",
				}
				refMetadataValueNode := &yaml.Node{
					Kind: yaml.MappingNode,
				}
				refMetadataValueNode.Content = append(refMetadataValueNode.Content,
					originalValueNode, value.Content[i], refAloneKeyNode, refAloneValueNode)
				// resolved shares its Content with the referenced node and with
				// every other reference to it: append to a copy, or the
				// references would overwrite each other's metadata.
				resolved.Content = append(resolved.Content[:len(resolved.Content):len(resolved.Content)],
					refMetadataKeyNode, refMetadataValueNode)

				return resolved, false
			}
			value.Content[i] = &resolved
		}
		return *value, false
	}
}

// isPath returns true if the value is a valid path
func (r *Resolver) resolveYamlPath(
	ctx context.Context,
	originalFileContent []byte,
	fullObject *yaml.Node,
	v *yaml.Node,
	filePath string,
	resolveCount, maxResolverDepth int,
	resolvedFilesCache map[string]ResolvedFile,
	refBool, resolveReferences, ansibleVars bool) (yaml.Node, bool) {
	value := v.Value
	if ctx.Err() != nil || resolveCount >= maxResolverDepth || (strings.HasPrefix(value, "#") && !refBool) || (value == "#" && refBool) {
		return *v, false
	}
	var splitPath []string
	var obj *yaml.Node
	sameFileResolve := false
	if strings.HasPrefix(value, "#") { // same file resolve
		sameFileResolve = true
		path := filePath + value
		splitPath = strings.SplitN(path, "#", 2) // splitting by removing the section to look for in the file
		obj = fullObject
	} else { // external file resolve
		value = checkServerlessFileReference(value)

		exists, path, filename := r.findFilePath(filepath.Dir(filePath), value, ansibleVars, r.Extension)
		if !exists {
			return *v, false
		}

		splitPath = strings.SplitN(path, "#", 2)
		resolved, isError := r.resolveFile(ctx, filename, resolveCount, maxResolverDepth, resolvedFilesCache, true, resolveReferences)
		if isError {
			return *v, false
		}

		r.ResolvedFiles[getPathFromString(value)] = model.ResolvedFile{
			Content:      resolvedFilesCache[filename].fileContent,
			Path:         path,
			LinesContent: utils.SplitLines(string(resolvedFilesCache[filename].fileContent)),
		}

		node := resolved.(yaml.Node)
		obj = &node

		if strings.Contains(strings.ToLower(value), "!ref") { // Cloudformation !Ref check
			return *obj, false
		}
		if !strings.Contains(path, "#") {
			return *obj, true
		}
	}

	return r.returnResolveYamlPathValue(splitPath, sameFileResolve, filePath, originalFileContent, obj, v)
}

func (r *Resolver) returnResolveYamlPathValue(
	splitPath []string,
	sameFileResolve bool,
	filePath string,
	originalFileContent []byte,
	obj, v *yaml.Node) (yaml.Node, bool) {
	if len(splitPath) > 1 {
		if sameFileResolve {
			r.ResolvedFiles[filePath] = model.ResolvedFile{
				Content:      originalFileContent,
				Path:         filePath,
				LinesContent: utils.SplitLines(string(originalFileContent)),
			}
		}
		section, err := findSectionYaml(obj, splitPath[1])
		// Check if there was an error finding the section or if the reference is circular
		if err == nil && !checkIfCircularYaml(v.Value, &section) {
			return section, true
		}
	}
	return *v, false
}

// resolveFile separates canonical file identity and bytes from resolved views.
// The existing depth limit remains authoritative: a deeper first visit must
// not cache a truncated view for a later caller with more depth available.
func (r *Resolver) resolveFile(
	ctx context.Context, filePath string, resolveCount, maxResolverDepth int,
	cache map[string]ResolvedFile, yamlResolve, resolveReferences bool,
) (any, bool) {
	if ctx.Err() != nil {
		return nil, true
	}
	filePath = filepath.Clean(filePath)
	cached, exists := cache[filePath]
	remaining := maxResolverDepth - resolveCount
	if view, ok := cached.views[remaining]; ok {
		return view, false
	}
	if !exists {
		cached.fileContent, cached.readErr = r.fsys.ReadFile(filePath)
		cache[filePath] = cached
	}
	if cached.readErr != nil || ctx.Err() != nil {
		return nil, true
	}
	if cached.views == nil {
		cached.views = map[int]any{}
	}
	// Publish bytes before recursive resolution. Cycles request successively
	// smaller budgets; each successful (file,budget) view is resolved once.
	cache[filePath] = cached
	object, ok := r.resolveFileObject(ctx, cached.fileContent, filePath, resolveCount, maxResolverDepth, cache, yamlResolve, resolveReferences)
	if !ok || ctx.Err() != nil {
		return nil, true
	}
	cached.views[remaining] = object
	cache[filePath] = cached
	return object, false
}

func (r *Resolver) resolveFileObject(
	ctx context.Context, content []byte, filePath string, resolveCount, maxResolverDepth int,
	cache map[string]ResolvedFile, yamlResolve, resolveReferences bool,
) (any, bool) {
	if yamlResolve {
		var obj yaml.Node
		if err := r.unmarshler(content, &obj); err != nil || ctx.Err() != nil {
			return nil, false
		}
		clearYAMLPositions(&obj)
		if (resolveReferences || !isOpenAPI(content)) && mayReferenceYAMLFiles(content) {
			obj = r.resolveYAMLDocument(ctx, content, &obj, filePath, resolveCount+1, maxResolverDepth, cache, resolveReferences)
		}
		if obj.Kind == yaml.DocumentNode && len(obj.Content) == 1 {
			obj = *obj.Content[0]
		}
		return obj, obj.Kind != 0 && ctx.Err() == nil
	}
	resolved := r.Resolve(ctx, content, filePath, resolveCount+1, maxResolverDepth, cache, resolveReferences)
	if ctx.Err() != nil {
		return nil, false
	}
	var obj any
	err := r.unmarshler(resolved, &obj)
	return obj, err == nil
}

// clearYAMLPositions drops the line and column of every node of a document
// inlined in another file, where they would be read as positions in that file.
func clearYAMLPositions(node *yaml.Node) {
	node.Line, node.Column = 0, 0
	for _, child := range node.Content {
		clearYAMLPositions(child)
	}
}

func getPathFromString(path string) string {
	fragmentIndex := strings.Index(path, "#")
	if fragmentIndex == -1 {
		return path
	}
	return path[:fragmentIndex]
}

// isPath returns true if the value is a valid path
func (r *Resolver) resolvePath(
	ctx context.Context,
	originalFileContent []byte,
	fullObject interface{},
	value, filePath string,
	resolveCount, maxResolverDepth int,
	resolvedFilesCache map[string]ResolvedFile,
	refBool bool, resolveReferences bool) (any, bool) {
	if ctx.Err() != nil || resolveCount >= maxResolverDepth || (strings.HasPrefix(value, "#") && !refBool) || (value == "#" && refBool) {
		return value, false
	}
	var splitPath []string
	var obj any
	sameFileResolve := false
	if strings.HasPrefix(value, "#") { // same file resolve
		sameFileResolve = true
		path := filePath + value
		splitPath = strings.SplitN(path, "#", 2) // splitting by removing the section to look for in the file
		obj = fullObject
	} else { // external file resolve
		exists, path, onlyFilePath := r.findFilePath(filepath.Dir(filePath), value, false, r.Extension)
		if !exists {
			return value, false
		}
		splitPath = strings.SplitN(path, "#", 2)
		var isError bool
		obj, isError = r.resolveFile(ctx, onlyFilePath, resolveCount, maxResolverDepth, resolvedFilesCache, false, resolveReferences)
		if isError {
			return value, false
		}

		r.ResolvedFiles[getPathFromString(value)] = model.ResolvedFile{
			Content:      resolvedFilesCache[onlyFilePath].fileContent,
			Path:         path,
			LinesContent: utils.SplitLines(string(resolvedFilesCache[onlyFilePath].fileContent)),
		}

		// Cloudformation !Ref check
		if strings.Contains(strings.ToLower(value), "!ref") || len(splitPath) == 1 {
			return obj, false
		}
	}
	return r.resolvePathReturnValue(value, filePath, splitPath, sameFileResolve, originalFileContent, obj, maxResolverDepth)
}

func (r *Resolver) resolvePathReturnValue(
	value, filePath string,
	splitPath []string,
	sameFileResolve bool,
	originalFileContent []byte,
	obj any,
	maxResolverDepth int) (any, bool) {
	if len(splitPath) > 1 {
		if sameFileResolve {
			r.ResolvedFiles[filePath] = model.ResolvedFile{
				Content:      originalFileContent,
				Path:         filePath,
				LinesContent: utils.SplitLines(string(originalFileContent)),
			}
		}
		section, err := findSection(obj, splitPath[1])
		// Check if there was an error finding the section or if the reference is circular
		if err != nil || checkIfCircular(value, section, maxResolverDepth) {
			return value, false
		}
		return section, true
	}
	return value, false
}

func findSectionYaml(object *yaml.Node, sectionsString string) (yaml.Node, error) {
	if object.Kind == yaml.DocumentNode && len(object.Content) == 1 {
		object = object.Content[0]
	}
	if sectionsString == "" {
		return *object, nil
	}
	sectionsString = strings.ReplaceAll(sectionsString, "\\", "/")
	if !strings.HasPrefix(sectionsString, "/") {
		return *object, errors.New("unsupported reference fragment")
	}
	sections := strings.Split(sectionsString[1:], "/")
	for _, section := range sections {
		if object.Kind != yaml.MappingNode {
			return *object, errors.New("section not of map type")
		}
		found := false
		for index := 0; index+1 < len(object.Content); index += 2 {
			key := object.Content[index]
			if key.Kind == yaml.ScalarNode && key.Value == section {
				object = object.Content[index+1]
				found = true
				break
			}
		}
		if !found {
			return *object, errors.New("section not present in file")
		}
	}
	return *object, nil
}

func checkIfCircularYaml(circularValue string, yamlSection *yaml.Node) bool {
	return checkIfCircularYamlNode(circularValue, yamlSection, make(map[*yaml.Node]bool))
}

// checkIfCircularYamlNode visits each node once: resolved content shares its
// nodes between references, and visiting them per path would take time
// exponential in the nesting depth of the references.
func checkIfCircularYamlNode(circularValue string, yamlSection *yaml.Node, visited map[*yaml.Node]bool) bool {
	if len(yamlSection.Content) == 0 || visited[yamlSection] {
		return false
	}
	visited[yamlSection] = true
	for index := 0; index < len(yamlSection.Content)-1; index += 1 {
		// nolint:goconst
		// if there is a reference to the same value that was resolved it is a circular definition
		if yamlSection.Content[index].Value == "$ref" && yamlSection.Content[index+1].Value == circularValue {
			return true
		} else if checkIfCircularYamlNode(circularValue, yamlSection.Content[index], visited) {
			return true
		}
	}
	return checkIfCircularYamlNode(circularValue, yamlSection.Content[len(yamlSection.Content)-1], visited)
}

func findSection(object interface{}, sectionsString string) (interface{}, error) {
	if sectionsString == "" {
		return object, nil
	}
	sectionsString = strings.ReplaceAll(sectionsString, "\\", "/")
	if !strings.HasPrefix(sectionsString, "/") {
		return object, errors.New("unsupported reference fragment")
	}
	sections := strings.Split(sectionsString[1:], "/")
	for _, section := range sections {
		if sectionObjectTemp, ok := object.(map[string]interface{}); ok {
			if sectionObject, ok := sectionObjectTemp[section]; ok {
				object = sectionObject
			} else {
				return object, errors.New("section not present in file")
			}
		} else {
			return object, errors.New("section not of map type")
		}
	}
	return object, nil
}

func checkIfCircular(circularValue string, section interface{}, maxResolverDepth int) bool {
	if maxResolverDepth > 0 {
		sectionAsMap, okMap := section.(map[string]interface{})
		sectionAsList, okList := section.([]interface{})
		if !okList && !okMap {
			return false
		}
		if okMap {
			for key, val := range sectionAsMap {
				// if there is a reference to the same value that was resolved it is a circular definition
				if key == "$ref" && val == circularValue {
					return true
				} else if checkIfCircular(circularValue, val, maxResolverDepth-1) {
					return true
				}
			}
		} else {
			for _, listSection := range sectionAsList {
				if checkIfCircular(circularValue, listSection, maxResolverDepth-1) {
					return true
				}
			}
		}
	}
	return false
}

func contains(elem string, list []string) bool {
	for _, e := range list {
		if elem == e {
			return true
		}
	}
	return false
}

func checkServerlessFileReference(value string) string {
	matches := serverlessFileReferenceRE.FindStringSubmatch(value)
	if len(matches) > 1 {
		return matches[1]
	}
	return value
}

func (r *Resolver) findFilePath(folderPath, filename string, ansibleVars bool, extensions []string) (exists bool, path, filePath string) {
	name, fragment, hasFragment := strings.Cut(filename, "#")
	path = filepath.Join(folderPath, name)
	// Validate the file component, never the fragment. Most scalar values are
	// not references, so unsupported extensions are rejected before stat.
	if !contains(filepath.Ext(path), extensions) {
		return false, "", ""
	}
	if ansibleVars {
		var found bool
		found, path = r.findAnsibleVarsPath(folderPath, name)
		if !found {
			return false, "", ""
		}
	} else if _, err := r.fsys.Stat(path); err != nil {
		return false, "", ""
	}
	filePath = filepath.Clean(path)
	path = filePath
	if hasFragment {
		path += "#" + fragment
	}
	return true, path, filePath
}

func (r *Resolver) findAnsibleVarsPath(folderPath, filename string) (exists bool, ansibleVarsPath string) {
	possiblePaths := []string{
		filepath.Join(folderPath, "vars", filename),
		filepath.Join(folderPath, filename),
	}

	for _, path := range possiblePaths {
		if _, err := r.fsys.Stat(path); err == nil {
			return true, path
		}
	}

	return false, ""
}
