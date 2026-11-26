/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package gitlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/yamlnode"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"gopkg.in/yaml.v3"
)

const (
	parentDirSegment = ".."
	// MaxIncludeFileBytes bounds a single local include file read to 5 MiB
	// (matching the scanner's default MaxFileSizeFlag = 5 MiB) so an oversized
	// file referenced via include: local: is not read into memory in full.
	MaxIncludeFileBytes = 5 * 1024 * 1024
)

type localIncludeEntry struct {
	path      string
	inputs    map[string]*yaml.Node
	inputsKey string
}

type maxIncludeFileBytesKey struct{}

// WithMaxFileSize applies the caller's scan policy alongside the compiler cap.
// Negative sizes disable only the scan policy, retaining the compiler bound.
func WithMaxFileSize(ctx context.Context, megabytes int) context.Context {
	limit := int64(MaxIncludeFileBytes)
	if megabytes >= 0 && int64(megabytes) < limit/(1<<20) {
		limit = int64(megabytes) * (1 << 20)
	}
	return context.WithValue(ctx, maxIncludeFileBytesKey{}, limit)
}

func maxIncludeBytes(ctx context.Context) int64 {
	if limit, configured := ctx.Value(maxIncludeFileBytesKey{}).(int64); configured {
		return limit
	}
	return MaxIncludeFileBytes
}

// baseInclude holds a local include file's once-decoded, alias-expanded
// mapping documents and no-input subtree markers. Written source is retained
// for included findings. Parameterized variants derive
// copy-on-write from these base documents so untouched subtrees stay shared.
type baseInclude struct {
	docs []baseIncludeDoc
}

type baseIncludeDoc struct {
	specDefaults map[string]*yaml.Node
	root         *yaml.Node
	noInput      map[*yaml.Node]bool
}

// repoBaseDir resolves the repository root against which GitLab CI
// `include: local:` paths resolve. For disk scans, a detected Git root within
// the explicit scan root (such as a checked-out submodule) takes precedence.
// Relative paths without an explicit scan root resolve from ".".
func repoBaseDir(fsys vfs.FS, repoRoot, filePath string) string {
	if filepath.IsAbs(filePath) && (repoRoot == "" || vfs.IsDisk(fsys)) {
		if root, ok := vfs.RepositoryRoot(fsys, filepath.Dir(filePath)); ok {
			if repoRoot == "" {
				return root
			}
			if rel, err := filepath.Rel(repoRoot, root); err == nil && filepath.IsLocal(rel) {
				return root
			}
		}
	}
	if repoRoot != "" {
		return filepath.Clean(repoRoot)
	}
	if !filepath.IsAbs(filePath) {
		return "."
	}
	slash := filepath.ToSlash(filepath.Clean(filePath))
	if idx := strings.Index(strings.ToLower(slash), "/.gitlab/ci/"); idx >= 0 {
		if idx == 0 {
			return "/"
		}
		return filepath.FromSlash(slash[:idx])
	}
	return filepath.Dir(filePath)
}

// collectLocalIncludes preserves each nested file's merge boundary. Compiling
// children with their own file before combining siblings is essential because
// recursive mapping merge is not associative across mappings and null values.
// Completed, acyclic invocations are shared across diamond graphs and documents.
func (s *FileState) collectLocalIncludes(root *yaml.Node) []*yaml.Node {
	active := map[string]bool{filepath.ToSlash(filepath.Clean(s.self)): true}
	layers, _ := s.collectIncludeLayers(root, active)
	return layers
}

func (s *FileState) collectIncludeLayers(root *yaml.Node, active map[string]bool) ([]*yaml.Node, bool) {
	var layers []*yaml.Node
	cyclic := false
	for _, entry := range extractLocalIncludes(s.ctx, yamlnode.MappingValue(root, kwInclude), s.includeEnabled) {
		if s.ctx.Err() != nil {
			break
		}
		if strings.ContainsAny(entry.path, "*?[{\\") {
			for _, match := range s.expandLocalPattern(entry.path) {
				literal := entry
				literal.path = match
				docs, cycle := s.compileLiteralInclude(literal, active)
				layers = append(layers, docs...)
				cyclic = cyclic || cycle
			}
		} else {
			docs, cycle := s.compileLiteralInclude(entry, active)
			layers = append(layers, docs...)
			cyclic = cyclic || cycle
		}
	}
	return layers, cyclic
}

func (s *FileState) compileLiteralInclude(entry localIncludeEntry, active map[string]bool) ([]*yaml.Node, bool) {
	if s.ctx.Err() != nil {
		return nil, false
	}
	target, ok := s.resolveConfinedLocalPath(entry.path)
	if !ok {
		return nil, false
	}
	canonical := filepath.ToSlash(filepath.Clean(target))
	if active[canonical] {
		return nil, true
	}
	if len(active) > maxGraphDepth {
		ExceedLimit(s.ctx, "include nesting depth")
		return nil, false
	}
	key := canonical + "\x00" + entry.inputsKey
	if cached, found := s.compiledIncludeCache[key]; found {
		return cached, false
	}
	docs, ok := s.loadIncludeVariantDocs(target, canonical, key, entry.inputs)
	if !ok {
		return nil, false
	}
	active[canonical] = true
	defer delete(active, canonical)
	compiled := make([]*yaml.Node, 0, len(docs))
	cyclic := false
	for _, doc := range docs {
		layers, cycle := s.collectIncludeLayers(doc, active)
		cyclic = cyclic || cycle
		result := doc
		if len(layers) > 0 {
			result = s.mergeIncludeLayers(append(layers, doc))
			s.nodeOrigins[result] = s.nodeOrigins[doc]
			markSubtreeNoRef(result, s.cachedNoRefNodes)
		}
		compiled = append(compiled, result)
	}
	// A cycle's partial expansion depends on the current active ancestors.
	if !cyclic && s.ctx.Err() == nil {
		s.compiledIncludeCache[key] = compiled
	}
	return compiled, cyclic
}

// loadIncludeVariantDocs returns the expanded documents for (canonPath, inputs),
// decoding the underlying YAML file at most once and deriving input variants
// copy-on-write so subtrees without `$[[` stay shared across variants.
func (s *FileState) loadIncludeVariantDocs(
	target, canonPath, cacheKey string,
	inputs map[string]*yaml.Node,
) ([]*yaml.Node, bool) {
	if docs, cached := s.variantIncludeCache[cacheKey]; cached {
		return docs, docs != nil
	}

	base, ok := s.loadBaseInclude(target, canonPath)
	if !ok {
		s.variantIncludeCache[cacheKey] = nil
		return nil, false
	}

	docs := make([]*yaml.Node, 0, len(base.docs))
	for _, bdoc := range base.docs {
		if s.ctx.Err() != nil {
			return nil, false
		}
		mergedInputs := mergeInputs(bdoc.specDefaults, inputs)
		docRoot := bdoc.root
		if len(mergedInputs) > 0 {
			docRoot = s.interpolateInputs(docRoot, mergedInputs, bdoc.noInput)
			if docRoot != bdoc.root {
				markSubtreeNoRef(docRoot, s.cachedNoRefNodes)
			}
		}
		docs = append(docs, docRoot)
	}
	s.variantIncludeCache[cacheKey] = docs
	return docs, true
}

func (s *FileState) loadBaseInclude(target, canonPath string) (*baseInclude, bool) {
	if s.ctx.Err() != nil {
		return nil, false
	}
	if cached, ok := s.baseIncludeCache[canonPath]; ok {
		return cached, cached != nil
	}

	data, ok := readIncludeBounded(s.ctx, s.fsys, target)
	if !ok {
		s.baseIncludeCache[canonPath] = nil
		return nil, false
	}

	if !Reserve(s.ctx, 1, len(data)) {
		return nil, false
	}
	var incSpecDefaults map[string]*yaml.Node
	base := &baseInclude{}
	written := string(data)
	roots, err := decodeMappingDocuments(data)
	if err != nil {
		failParse(s.ctx, fmt.Errorf("%w %s: %w", ErrInvalidInclude, target, err))
		return nil, false
	}
	for index, incRoot := range roots {
		if s.ctx.Err() != nil {
			return nil, false
		}
		s.RegisterSource(incRoot, target, written, index)
		if !reserveGraph(s.ctx, incRoot) {
			return nil, false
		}
		yamlnode.BreakAliasCycles(incRoot)
		s.expandAnchors(incRoot)
		if IsSpecHeaderNode(incRoot) {
			incSpecDefaults = extractSpecInputDefaults(incRoot)
			continue
		}
		noInput := make(map[*yaml.Node]bool)
		markNoInputNodes(incRoot, noInput)
		markSubtreeNoRef(incRoot, s.cachedNoRefNodes)
		base.docs = append(base.docs, baseIncludeDoc{
			specDefaults: incSpecDefaults,
			root:         incRoot,
			noInput:      noInput,
		})
		incSpecDefaults = nil
	}
	s.baseIncludeCache[canonPath] = base
	return base, true
}

// readIncludeBounded reads target up to MaxIncludeFileBytes while preserving
// MemFS missing-file recording for IDE escalation.
func readIncludeBounded(ctx context.Context, fsys vfs.FS, target string) ([]byte, bool) {
	limit := maxIncludeBytes(ctx)
	if vfs.IsDisk(fsys) {
		return readDiskInclude(ctx, fsys, target, limit)
	}

	if info, err := fsys.Stat(target); err == nil {
		if info.Size() > limit {
			ExceedLimit(ctx, "local include bytes")
			return nil, false
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		failParse(ctx, fmt.Errorf("%w %s: %w", ErrInvalidInclude, target, err))
		return nil, false
	}
	data, err := fsys.ReadFile(target)
	if err != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Debug().Msgf("gitlab-ci: could not read local include %s: %v", target, err)
		if !errors.Is(err, fs.ErrNotExist) {
			failParse(ctx, fmt.Errorf("%w %s: %w", ErrInvalidInclude, target, err))
		} else if snapshot, ok := fsys.(vfs.DirectorySnapshot); ok && snapshot.DirectoryComplete(filepath.Dir(target)) {
			failParse(ctx, fmt.Errorf("%w %s: %w", ErrInvalidInclude, target, err))
		}
		return nil, false
	}
	if int64(len(data)) > limit {
		ExceedLimit(ctx, "local include bytes")
		return nil, false
	}
	return data, true
}

func readDiskInclude(ctx context.Context, fsys vfs.FS, target string, limit int64) ([]byte, bool) {
	includePath := filepath.Clean(target)
	info, err := fsys.Stat(includePath)
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("local include is not a regular file")
	}
	var f *os.File
	if err == nil {
		f, err = os.Open(includePath) //nolint:gosec
	}
	if err != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Debug().Msgf("gitlab-ci: could not read local include %s: %v", target, err)
		failParse(ctx, fmt.Errorf("%w %s: %w", ErrInvalidInclude, target, err))
		return nil, false
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		failParse(ctx, fmt.Errorf("%w %s: %w", ErrInvalidInclude, target, err))
		return nil, false
	}
	if int64(len(data)) > limit {
		ExceedLimit(ctx, "local include bytes")
		return nil, false
	}
	return data, true
}

func inputsSignature(inputs map[string]*yaml.Node, digests map[*yaml.Node][sha256.Size]byte) string {
	if len(inputs) == 0 {
		return ""
	}
	keys := make([]string, 0, len(inputs))
	for key := range inputs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, key := range keys {
		_, _ = fmt.Fprintf(h, "%d:%s", len(key), key)
		digest := inputNodeDigest(inputs[key], digests)
		_, _ = h.Write(digest[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Input identities retain fixed-size digests, never copies of shared values.
// Merkle-style child digests let distinct variants reuse large shared inputs.
func inputNodeDigest(node *yaml.Node, memo map[*yaml.Node][sha256.Size]byte) [sha256.Size]byte {
	if node == nil {
		return sha256.Sum256(nil)
	}
	if digest, seen := memo[node]; seen {
		return digest
	}
	memo[node] = sha256.Sum256(nil) // Defensive cycle edge.
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d:%d:%s:%d:", node.Kind, len(node.Tag), node.Tag, len(node.Value))
	_, _ = io.WriteString(h, node.Value)
	if node.Alias != nil {
		digest := inputNodeDigest(node.Alias, memo)
		_, _ = h.Write(digest[:])
	}
	for _, child := range node.Content {
		digest := inputNodeDigest(child, memo)
		_, _ = h.Write(digest[:])
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	memo[node] = digest
	return digest
}

// extractLocalIncludes extracts concrete local include entries from an
// `include:` node in precedence order, walking in reverse so only the last
// occurrence of each identical (path, inputs) entry is emitted and each shared
// sequence DAG node is visited at most once without intermediate slice copies.
func extractLocalIncludes(ctx context.Context, node *yaml.Node, enabled func(*yaml.Node) bool) []localIncludeEntry {
	type entryID struct {
		path      string
		inputsKey string
	}
	emitted := make(map[entryID]struct{})
	seenContainers := make(map[*yaml.Node]struct{})
	digests := make(map[*yaml.Node][sha256.Size]byte)
	var reversed []localIncludeEntry

	emit := func(e localIncludeEntry) {
		id := entryID{path: e.path, inputsKey: e.inputsKey}
		if _, exists := emitted[id]; exists {
			return
		}
		emitted[id] = struct{}{}
		reversed = append(reversed, e)
	}

	var walkReverse func(n *yaml.Node)
	walkReverse = func(n *yaml.Node) {
		if n == nil || ctx.Err() != nil {
			return
		}
		if _, seen := seenContainers[n]; seen {
			return
		}
		switch n.Kind {
		case yaml.ScalarNode:
			if isConcreteLocalInclude(n.Value) {
				emit(localIncludeEntry{path: n.Value})
			}
		case yaml.SequenceNode:
			seenContainers[n] = struct{}{}
			for i := len(n.Content) - 1; i >= 0; i-- {
				if ctx.Err() != nil {
					return
				}
				walkReverse(n.Content[i])
			}
		case yaml.MappingNode:
			seenContainers[n] = struct{}{}
			extractLocalIncludesFromMappingReverse(n, emit, digests, enabled)
		}
	}
	walkReverse(node)
	slices.Reverse(reversed)
	return reversed
}

func extractLocalIncludesFromMappingReverse(
	n *yaml.Node, emit func(localIncludeEntry), digests map[*yaml.Node][sha256.Size]byte, enabled func(*yaml.Node) bool,
) {
	localVal := yamlnode.MappingValue(n, "local")
	if localVal == nil {
		return
	}
	if !enabled(n) {
		return
	}
	inputs := extractIncludeInputs(yamlnode.MappingValue(n, "inputs"))
	sig := inputsSignature(inputs, digests)
	switch localVal.Kind {
	case yaml.ScalarNode:
		if isConcreteLocalInclude(localVal.Value) {
			emit(localIncludeEntry{path: localVal.Value, inputs: inputs, inputsKey: sig})
		}
	case yaml.SequenceNode:
		for i := len(localVal.Content) - 1; i >= 0; i-- {
			item := localVal.Content[i]
			if item.Kind == yaml.ScalarNode && isConcreteLocalInclude(item.Value) {
				emit(localIncludeEntry{path: item.Value, inputs: inputs, inputsKey: sig})
			}
		}
	}
}

func isConcreteLocalInclude(raw string) bool {
	s := strings.TrimSpace(raw)
	if s == "" {
		return false
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	if strings.Contains(s, "$") {
		return false
	}
	return strings.ContainsAny(s, "*?[") || strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}

// resolveConfinedLocalPath resolves a GitLab CI local include path relative to
// s.baseDir and ensures it cannot escape s.baseDir via ".." or symlinks.
func (s *FileState) resolveConfinedLocalPath(raw string) (string, bool) {
	trimmed := strings.TrimLeft(strings.TrimSpace(raw), "/")
	if trimmed == "" {
		return "", false
	}
	cleaned := filepath.ToSlash(filepath.Clean(trimmed))
	if cleaned == "." || cleaned == parentDirSegment ||
		strings.HasPrefix(cleaned, parentDirSegment+"/") || strings.HasPrefix(cleaned, "/") {
		return "", false
	}
	joined := filepath.Join(s.baseDir, filepath.FromSlash(cleaned))

	if vfs.IsDisk(s.fsys) {
		absBase, err := filepath.Abs(s.baseDir)
		if err != nil {
			return "", false
		}
		realBase, err := filepath.EvalSymlinks(absBase)
		if err != nil {
			realBase = absBase
		}
		absTarget, err := filepath.Abs(joined)
		if err != nil {
			return "", false
		}
		if realTarget, err := filepath.EvalSymlinks(absTarget); err == nil {
			rel, relErr := filepath.Rel(realBase, realTarget)
			if relErr != nil || rel == parentDirSegment || strings.HasPrefix(rel, parentDirSegment+string(filepath.Separator)) {
				return "", false
			}
		}
	}
	return joined, true
}

// decodeMappingDocuments decodes all non-empty top-level mapping documents from
// raw YAML bytes.
func decodeMappingDocuments(content []byte) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(content))
	var roots []*yaml.Node
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				return roots, nil
			}
			return nil, err
		}
		if yamlnode.IsImplicitEmptyDocument(&doc) {
			continue
		}
		root := doc.Content[0]
		if root.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("expected a top-level YAML mapping at line %d", root.Line)
		}
		roots = append(roots, root)
	}
}

type missingRequestsKey struct{}

// WithDeferredMissingRequests lets the runner retain request effects alongside
// the invocation, rather than mixing them into the entire IDE snapshot eagerly.
func WithDeferredMissingRequests(ctx context.Context, collect func(func())) context.Context {
	return context.WithValue(ctx, missingRequestsKey{}, collect)
}

// ScopeMissingRequests isolates only pushed snapshots; disk reads have no
// escalation effects. Direct parser callers keep immediate request recording.
func ScopeMissingRequests(ctx context.Context, fsys vfs.FS) (scopedFS vfs.FS, finish func()) {
	collect, deferred := ctx.Value(missingRequestsKey{}).(func(func()))
	snapshot, memory := fsys.(*vfs.MemFS)
	if !deferred || !memory {
		return fsys, func() {}
	}
	scoped := snapshot.Fork()
	return scoped, func() {
		paths := scoped.MissingFiles()
		if len(paths) > 0 {
			collect(func() {
				for _, path := range paths {
					snapshot.RecordMissing(path)
				}
			})
		}
	}
}

type localGlob struct {
	state       *FileState
	matches     map[string]bool
	yamlOnly    bool
	directories bool
	probe       bool
	uncertain   bool
}

// expandLocalPattern supports local wildcards without walking unrelated trees.
// Literal prefixes and actual matches use the same repository confinement check.
func (s *FileState) expandLocalPattern(pattern string) []string {
	if _, ok := s.resolveConfinedLocalPath(pattern); !ok {
		return nil
	}
	pattern = strings.TrimLeft(strings.TrimSpace(pattern), "/")
	// Glob syntax is platform-independent; Windows separators must not rewrite
	// backslash escapes before the matcher sees them.
	pattern = path.Clean(pattern)
	glob := localGlob{state: s, yamlOnly: true, matches: make(map[string]bool)}
	prefix, possible := glob.match(pattern)
	if !possible {
		return nil
	}
	matches := make([]string, 0, len(glob.matches))
	for match := range glob.matches {
		matches = append(matches, match)
	}
	sort.Strings(matches)
	if missing, ok := s.fsys.(vfs.MissingRecorder); ok {
		directory := filepath.Join(s.baseDir, filepath.FromSlash(prefix))
		if snapshot, ok := s.fsys.(vfs.DirectorySnapshot); !ok || !snapshot.DirectoryComplete(directory) {
			missing.RecordMissing(directory)
		}
	}
	return matches
}

func (g *localGlob) match(pattern string) (string, bool) {
	program := compileGitLabGlob(g.state.ctx, pattern)
	if program.start < 0 || !validGlobPrefix(program.prefix) {
		return "", false
	}
	machine := program.machine()
	if machine == nil {
		return program.prefix, false
	}
	states := machine.start()
	if program.prefix != "" {
		states = machine.advance(states, program.prefix+"/")
		if g.directories && machine.accepts(states) {
			g.addMatch(program.prefix)
		}
	}
	g.walkPattern(program.prefix, append([]int(nil), states...), machine, 0)
	return program.prefix, true
}

func validGlobPrefix(prefix string) bool {
	if prefix == "" {
		return true
	}
	for _, segment := range strings.Split(prefix, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func (g *localGlob) walkPattern(dir string, states []int, machine *globMachine, depth int) {
	if g.state.ctx.Err() != nil || (g.probe && len(g.matches) > 0) {
		return
	}
	if depth > maxGraphDepth {
		ExceedLimit(g.state.ctx, "include directory depth")
		return
	}
	for _, entry := range g.readDir(dir) {
		if g.probe && len(g.matches) > 0 {
			return
		}
		if !Reserve(g.state.ctx, 1, 0) {
			return
		}
		g.walkEntry(dir, entry, states, machine, depth)
	}
}

func (g *localGlob) walkEntry(dir string, entry fs.DirEntry, states []int, machine *globMachine, depth int) {
	if entry.Name() == gitMetadataDir || (!g.probe && entry.Type()&fs.ModeSymlink != 0) {
		return
	}
	next := machine.advance(states, entry.Name())
	child := path.Join(dir, entry.Name())
	if !entry.IsDir() {
		if !g.directories && machine.accepts(next) {
			g.addMatch(child)
		}
		return
	}
	next = machine.advance(next, "/")
	if len(next) == 0 {
		return
	}
	if g.directories && machine.accepts(next) {
		g.addMatch(child)
	}
	if Reserve(g.state.ctx, 0, len(next)*pointerAllocationBytes) {
		g.walkPattern(child, append([]int(nil), next...), machine, depth+1)
	}
}

func (g *localGlob) addMatch(name string) {
	lower := strings.ToLower(name)
	if g.yamlOnly && !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") {
		return
	}
	target, ok := g.state.resolveConfinedLocalPath(name)
	if g.probe {
		target, ok = g.state.existenceTarget(name)
	}
	if !ok {
		return
	}
	info, err := g.stat(target)
	if err != nil && g.directories {
		if directories, ok := g.state.fsys.(interface {
			DirInfo(string) (fs.FileInfo, bool)
		}); ok {
			if directory, exists := directories.DirInfo(target); exists {
				info, err = directory, nil
			}
		}
	}
	if err != nil {
		g.recordIOError(target, err)
		return
	}
	if info.IsDir() == g.directories {
		g.matches[name] = true
	}
}

func (g *localGlob) readDir(dir string) []fs.DirEntry {
	target, ok := g.state.resolveConfinedLocalPath(dir)
	if dir == "." || dir == "" {
		target = g.state.baseDir
		ok = true
	}
	if !ok {
		return nil
	}
	info, err := g.stat(target)
	if g.probe {
		if err == nil && info.Mode()&fs.ModeSymlink != 0 {
			return nil
		}
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		g.recordIOError(target, err)
		return nil
	}
	// MemFS synthesizes directories in ReadDir, while Stat probes files only.
	if err == nil && !info.IsDir() {
		return nil
	}
	entries, err := g.state.fsys.ReadDir(target)
	if err != nil {
		g.recordIOError(target, err)
		return nil
	}
	return entries
}

func (g *localGlob) stat(target string) (fs.FileInfo, error) {
	if g.probe {
		return g.state.existenceStat(target)
	}
	return g.state.fsys.Stat(target)
}

func (g *localGlob) recordIOError(target string, err error) {
	if !errors.Is(err, fs.ErrNotExist) {
		if g.probe {
			g.uncertain = true
			return
		}
		failParse(g.state.ctx, fmt.Errorf("%w: wildcard include %s: %w", ErrInvalidInclude, target, err))
	}
}
