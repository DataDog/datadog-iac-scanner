/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package dockercompose

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
)

// YAML tag constants for synthesized nodes.
const (
	strTag  = "!!str"
	seqTag  = "!!seq"
	nullTag = "!!null"
	boolTag = "!!bool"
)

// maxExtendsDepth bounds service extends chains, guarding against cycles that
// slip past the visited set (e.g. through different files).
const maxExtendsDepth = 10

// transformer holds the per-file resolution state: interpolation variables,
// sibling-file access, and the override file's raw bytes (raw, because merging
// mutates nodes and each document needs a fresh copy).
type transformer struct {
	ctx    context.Context
	fsys   vfs.FS
	dir    string
	self   string
	env    map[string]string
	logger zerolog.Logger
	// overrideContent is the raw sibling override file content, nil when absent.
	overrideContent []byte
	// fileContent caches sibling compose file reads for extends resolution.
	fileContent map[string][]byte
}

// transform applies the Compose semantic pipeline to one document root:
// override merge (before extends, per Compose), extends inheritance,
// env_file materialization, then interpolation on all string values.
func (t *transformer) transform(doc *yaml.Node) {
	if doc == nil || doc.Kind != yaml.MappingNode {
		return
	}

	// Compose merges the override file before resolving extends.
	if t.overrideContent != nil {
		if overrideRoot := firstMappingDoc(t.overrideContent); overrideRoot != nil {
			mergeMappings(doc, overrideRoot, true, fileMergePolicy)
		}
	}

	services := mappingValue(doc, "services")
	if isServiceMapping(services) {
		for i := 0; i+1 < len(services.Content); i += 2 {
			if svc := services.Content[i+1]; isServiceMapping(svc) {
				t.resolveExtends(services, svc, t.self, 0, map[string]struct{}{})
			}
		}
	}

	if isServiceMapping(services) {
		for i := 0; i+1 < len(services.Content); i += 2 {
			if svc := services.Content[i+1]; isServiceMapping(svc) {
				t.mergeEnvFiles(svc)
			}
		}
	}

	interpolateNode(doc, t.lookupVar)
}

// isServiceMapping reports whether n is a usable service/config mapping node.
func isServiceMapping(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.MappingNode
}

// rewriteLines sets every node's line to line. Nodes merged in from another
// file carry that file's coordinates, which mean nothing in the file being
// scanned; only the merged-in subtree is walked.
func rewriteLines(n *yaml.Node, line int) {
	if n == nil {
		return
	}
	n.Line = line
	for _, child := range n.Content {
		rewriteLines(child, line)
	}
}

// lookupVar resolves a variable from the .env file only, never the host
// environment, keeping scans deterministic.
func (t *transformer) lookupVar(name string) (string, bool) {
	v, ok := t.env[name]
	return v, ok
}

// siblingPath resolves path relative to the compose file's directory.
func (t *transformer) siblingPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(t.dir, path)
}

// readSibling reads a sibling file, nil when unreadable.
func (t *transformer) readSibling(path string) []byte {
	full := t.siblingPath(path)
	if content, ok := t.fileContent[full]; ok {
		return content
	}
	content, err := t.fsys.ReadFile(full)
	if err != nil {
		t.logger.Debug().Msgf("dockercompose: could not read %s: %s", full, err)
		return nil
	}
	if t.fileContent == nil {
		t.fileContent = map[string][]byte{}
	}
	t.fileContent[full] = content
	return content
}

// removeExtends deletes the resolved extends declaration from a service node.
func removeExtends(m *yaml.Node) {
	removeMappingKey(m, "extends")
}

// extendsTarget extracts the (service, file) pair from an extends
// declaration node, supporting both the string and {service, file} forms.
func extendsTarget(extendsNode *yaml.Node) (service, file string) {
	switch extendsNode.Kind {
	case yaml.ScalarNode:
		return extendsNode.Value, ""
	case yaml.MappingNode:
		service, file = "", ""
		if s := mappingValue(extendsNode, "service"); s != nil {
			service = s.Value
		}
		if f := mappingValue(extendsNode, "file"); f != nil {
			file = f.Value
		}
		return service, file
	}
	return "", ""
}

// extendsTargetNode resolves the extends target and the services mapping it
// lives in (live mapping for same-file targets, the sibling's own mapping
// otherwise), so nested extends resolve in the right file.
func (t *transformer) extendsTargetNode(services *yaml.Node, targetService, targetFile string) (target, targetServices *yaml.Node) {
	if targetFile == "" {
		if idx := mappingKeyIndex(services, targetService); idx >= 0 {
			return services.Content[idx+1], services
		}
		return nil, nil
	}
	content := t.readSibling(targetFile)
	if content == nil {
		return nil, nil
	}
	targetRoot := firstMappingDoc(content)
	if targetRoot == nil {
		return nil, nil
	}
	return serviceNode(targetRoot, targetService), mappingValue(targetRoot, "services")
}

// resolveExtends merges a service's extends target into svc, svc winning.
// services is the mapping the target lookup starts from (live mapping of the
// file being transformed, or the sibling's for cross-file targets); file names
// that mapping's file for cycle detection via visited "file:service" keys.
func (t *transformer) resolveExtends(services, svc *yaml.Node, file string, depth int, visited map[string]struct{}) {
	extendsNode := mappingValue(svc, "extends")
	if extendsNode == nil {
		return
	}
	declLine := extendsNode.Line
	targetService, targetFile := extendsTarget(extendsNode)
	// extends paths and service names are interpolated before resolution;
	// an unresolvable path stays literal and the sibling read simply fails.
	targetFile = Interpolate(targetFile, t.lookupVar)
	targetService = Interpolate(targetService, t.lookupVar)
	removeExtends(svc)
	if targetService == "" {
		return
	}

	// Identify the file the target lives in: the file the current mapping
	// belongs to for same-file targets, otherwise the referenced sibling.
	contentKey := file
	if targetFile != "" {
		contentKey = t.siblingPath(targetFile)
	}
	chainKey := fmt.Sprintf("%s:%s", contentKey, targetService)
	if _, cyc := visited[chainKey]; cyc || depth >= maxExtendsDepth {
		t.logger.Debug().Msgf("dockercompose: extends cycle or depth limit at %s", chainKey)
		return
	}
	visited[chainKey] = struct{}{}
	defer delete(visited, chainKey)

	target, targetServices := t.extendsTargetNode(services, targetService, targetFile)
	if target == nil {
		return
	}

	// Deep-copy the target before mutating: it may be shared via the content
	// cache, and sibling services may extend the same target.
	targetCopy := copyNode(target)
	if targetCopy == nil || targetCopy.Kind != yaml.MappingNode {
		return
	}

	// The target may itself extend another service; resolve against the
	// mapping it lives in.
	t.resolveExtends(targetServices, targetCopy, contentKey, depth+1, visited)

	// Values inherited from a sibling file are attributed to the extends
	// declaration's line, which is in this file.
	if targetFile != "" {
		rewriteLines(targetCopy, declLine)
	}

	// Merge svc over the target (svc wins) and take over the merged content.
	mergeMappings(targetCopy, svc, false, extendsMergePolicy)
	svc.Content = targetCopy.Content
}

// serviceNode finds services.<name> in a document root.
func serviceNode(root *yaml.Node, name string) *yaml.Node {
	services := mappingValue(root, "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil
	}
	if idx := mappingKeyIndex(services, name); idx >= 0 {
		return services.Content[idx+1]
	}
	return nil
}

// envFileRef is one entry of a service's env_file declaration.
type envFileRef struct {
	path     string
	required bool
}

// mergeEnvFiles materializes env_file variables into the service's
// environment; explicit environment entries win, per Compose precedence.
func (t *transformer) mergeEnvFiles(svc *yaml.Node) {
	envFileNode := mappingValue(svc, "env_file")
	if envFileNode == nil {
		return
	}
	refs := parseEnvFileRefs(envFileNode)
	if len(refs) == 0 {
		return
	}

	// env_file line doubles as the attribution line for synthesized entries.
	attrLine := envFileNode.Line

	vars := make(map[string]string)
	for _, ref := range refs {
		// Compose interpolates env_file paths as well.
		content := t.readSibling(Interpolate(ref.path, t.lookupVar))
		if content == nil {
			if ref.required {
				t.logger.Debug().Msgf("dockercompose: required env_file %s not readable", ref.path)
			}
			continue
		}
		for k, v := range ParseEnvFile(content) {
			vars[k] = v
		}
	}
	if len(vars) == 0 {
		return
	}

	envNode := mappingValue(svc, "environment")
	switch {
	case envNode == nil:
		// Materialize the whole env_file as a list environment node.
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: seqTag, Line: attrLine}
		appendEnvEntries(seq, vars, attrLine)
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: strTag, Value: "environment", Line: attrLine}
		svc.Content = append(svc.Content, keyNode, seq)
	case envNode.Kind == yaml.SequenceNode:
		present := t.fillBareEnvEntries(envNode, vars)
		appendEnvEntries(envNode, remainingVars(vars, present), attrLine)
	case envNode.Kind == yaml.MappingNode:
		present := t.fillBareEnvEntries(envNode, vars)
		for _, k := range sortedKeys(remainingVars(vars, present)) {
			keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: strTag, Value: k, Line: attrLine}
			valNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: strTag, Value: vars[k], Line: attrLine}
			envNode.Content = append(envNode.Content, keyNode, valNode)
		}
	}
}

// fillBareEnvEntries resolves bare KEY list entries and null mapping values
// from the env-file vars (falling back to .env variables), returning the set
// of keys already declared.
func (t *transformer) fillBareEnvEntries(envNode *yaml.Node, vars map[string]string) map[string]struct{} {
	lookup := func(key string) (string, bool) {
		if v, ok := vars[key]; ok {
			return v, true
		}
		if t.env != nil {
			if v, ok := t.env[key]; ok {
				return v, true
			}
		}
		return "", false
	}
	present := map[string]struct{}{}
	if envNode.Kind == yaml.SequenceNode {
		for _, entry := range envNode.Content {
			if entry.Kind != yaml.ScalarNode {
				continue
			}
			key := entry.Value
			if eq := strings.IndexByte(key, '='); eq >= 0 {
				present[key[:eq]] = struct{}{}
				continue
			}
			present[key] = struct{}{}
			if v, ok := lookup(key); ok {
				entry.Value = key + "=" + v
			}
		}
		return present
	}
	for i := 0; i+1 < len(envNode.Content); i += 2 {
		key := envNode.Content[i].Value
		present[key] = struct{}{}
		valNode := envNode.Content[i+1]
		if valNode.Kind == yaml.ScalarNode && valNode.Tag == nullTag {
			if v, ok := lookup(key); ok {
				valNode.Tag = strTag
				valNode.Value = v
			}
		}
	}
	return present
}

// appendEnvEntries appends KEY=VALUE entries in sorted key order so merged
// documents are reproducible.
func appendEnvEntries(seq *yaml.Node, vars map[string]string, line int) {
	for _, k := range sortedKeys(vars) {
		seq.Content = append(seq.Content, &yaml.Node{
			Kind: yaml.ScalarNode, Tag: strTag, Value: k + "=" + vars[k], Line: line,
		})
	}
}

// sortedKeys returns the map's keys in sorted order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func remainingVars(vars map[string]string, present map[string]struct{}) map[string]string {
	out := make(map[string]string, len(vars))
	for k, v := range vars {
		if _, ok := present[k]; !ok {
			out[k] = v
		}
	}
	return out
}

// parseEnvFileRefs supports the three env_file forms: a string, a list of
// strings, and the {path, required} long syntax (alone or in a list).
func parseEnvFileRefs(node *yaml.Node) []envFileRef {
	var refs []envFileRef
	appendRef := func(n *yaml.Node) {
		switch n.Kind {
		case yaml.ScalarNode:
			if n.Value != "" {
				refs = append(refs, envFileRef{path: n.Value, required: true})
			}
		case yaml.MappingNode:
			pathNode := mappingValue(n, "path")
			if pathNode == nil || pathNode.Value == "" {
				return
			}
			required := true
			if req := mappingValue(n, "required"); req != nil {
				// Only an actual YAML boolean counts: a quoted "false" is a
				// string and Compose would reject it, so it stays required.
				required = req.Tag != boolTag || !strings.EqualFold(req.Value, "false")
			}
			refs = append(refs, envFileRef{path: pathNode.Value, required: required})
		}
	}
	switch node.Kind {
	case yaml.ScalarNode:
		appendRef(node)
	case yaml.SequenceNode:
		for _, entry := range node.Content {
			appendRef(entry)
		}
	case yaml.MappingNode:
		appendRef(node)
	}
	return refs
}

// firstMappingDoc decodes the first non-empty YAML document's root mapping
// node, or nil.
func firstMappingDoc(content []byte) *yaml.Node {
	if len(content) == 0 {
		return nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(content))
	for {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			return nil
		}
		if node.Kind != yaml.DocumentNode || len(node.Content) == 0 {
			continue
		}
		root := node.Content[0]
		if root.Kind == yaml.MappingNode {
			return root
		}
		return nil
	}
}
