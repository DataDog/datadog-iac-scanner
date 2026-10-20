/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2025 Datadog, Inc.
 */
package kustomize

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
	kyamlyaml "sigs.k8s.io/kustomize/kyaml/yaml"
)

var (
	kustomizationFileNames = map[string]bool{
		"kustomization.yaml": true,
		"kustomization.yml":  true,
		"Kustomization":      true,
	}
)

// fileRole classifies a file the adapter served during a render.
type fileRole string

const (
	roleKustomization fileRole = "kustomization"
	roleOther         fileRole = "other"
)

// ErrReason classifies why a render could not run or was refused. The reason
// travels with the error so callers can log a category instead of error text,
// which can echo input values.
type ErrReason string

const (
	ReasonValidation  ErrReason = "validation"
	ReasonMissingFile ErrReason = "missing_file"
	ReasonSizeLimit   ErrReason = "size_limit"
	ReasonRenderError ErrReason = "render_error"
)

// RenderError is a refusal or failure with a stable reason category. Its text
// is safe to drop: callers should log Reason, never Error.
type RenderError struct {
	Reason ErrReason
	Err    error
}

func (e *RenderError) Error() string { return e.Err.Error() }
func (e *RenderError) Unwrap() error { return e.Err }

func failf(reason ErrReason, format string, args ...interface{}) *RenderError {
	return &RenderError{Reason: reason, Err: fmt.Errorf(format, args...)}
}

const (
	// DefaultMaxFileBytes caps single files before they are read.
	DefaultMaxFileBytes int64 = 5 * 1024 * 1024
	// MaxTotalBytes caps the cumulative bytes cached per scan.
	MaxTotalBytes int64 = 256 * 1024 * 1024
)

// kustomizationPathFields and kustomizationNoPathFields classify the fields
// of types.Kustomization for the field-coverage test, which fails when an
// upstream field addition is not sorted into one of the lists.
var kustomizationPathFields = []string{ //nolint:unused // classification list for TestKustomizationFieldClassification
	"Resources", "Components", "Crds", "Bases", "Configurations",
	"PatchesStrategicMerge", "Replacements",
}

var kustomizationNoPathFields = []string{ //nolint:unused // classification list for TestKustomizationFieldClassification
	"TypeMeta", "MetaData", "Namespace", "NamePrefix", "NameSuffix",
	"CommonLabels", "Labels", "CommonAnnotations", "Images", "ImageTags",
	"Replicas", "Vars", "SortOptions", "Patches", "PatchesJson6902",
	"GeneratorOptions", "BuildMetadata", "OpenAPI",
	"ConfigMapGenerator", "SecretGenerator",
}

// Fields that may hold executables or fetch content beyond plain local files.
var kustomizationForbiddenFields = []string{ //nolint:unused // classification list for TestKustomizationFieldClassification
	"Generators", "Transformers", "Validators", "HelmCharts",
	"HelmChartInflationGenerator", "HelmGlobals",
}

// plainLocalPath reports whether s is a plain relative local path. It is
// deliberately stricter than Kustomize's own grammar: anything unusual falls
// back to raw scanning instead of risking egress or a git clone.
func plainLocalPath(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	if filepath.IsAbs(s) || strings.HasPrefix(s, "/") || len(s) >= 2 && s[1] == ':' {
		return false
	}
	for _, banned := range []string{"://", "@", ":", "?", "\\"} {
		if strings.Contains(s, banned) {
			return false
		}
	}
	if strings.HasPrefix(strings.ToLower(s), "git::") {
		return false
	}
	if strings.EqualFold(strings.SplitN(s, "/", 2)[0], "github.com") {
		return false
	}
	return true
}

// pathRef pairs a kustomization field with a path value it bears, for
// uniform validation and for the field-coverage test.
type pathRef struct {
	field string
	path  string
}

// kustomizationPaths lists every path-bearing value in the kustomization.
// Deprecated fields are still validated because old kustomizations use them.
func kustomizationPaths(k *types.Kustomization) []pathRef {
	var refs []pathRef
	add := func(field, p string) {
		if p != "" {
			refs = append(refs, pathRef{field: field, path: p})
		}
	}
	for _, p := range k.Resources {
		add("resources", p)
	}
	for _, p := range k.Components {
		add("components", p)
	}
	for _, p := range k.Crds {
		add("crds", p)
	}
	for _, p := range k.Configurations {
		add("configurations", p)
	}
	for _, p := range k.PatchesStrategicMerge { //nolint:staticcheck // deprecated but still in use upstream
		add("patchesStrategicMerge", string(p))
	}
	for i := range k.Patches {
		add("patches", k.Patches[i].Path)
	}
	for i := range k.PatchesJson6902 { //nolint:staticcheck // deprecated but still in use upstream
		add("patchesJson6902", k.PatchesJson6902[i].Path) //nolint:staticcheck // deprecated but still in use upstream
	}
	for i := range k.Replacements {
		add("replacements", k.Replacements[i].Path)
	}
	add("openapi", k.OpenAPI["path"])
	return refs
}

// checkForbidden refuses fields that could execute code or fetch content
// beyond plain local files.
func checkForbidden(k *types.Kustomization) error {
	if len(k.Generators) > 0 {
		return failf(ReasonValidation, "generators is not allowed")
	}
	if len(k.Transformers) > 0 {
		return failf(ReasonValidation, "transformers is not allowed")
	}
	if len(k.Validators) > 0 {
		return failf(ReasonValidation, "validators is not allowed")
	}
	if len(k.HelmCharts) > 0 {
		return failf(ReasonValidation, "helmCharts is not allowed")
	}
	if len(k.HelmChartInflationGenerator) > 0 {
		return failf(ReasonValidation, "helmChartInflationGenerator is not allowed")
	}
	if k.HelmGlobals != nil {
		return failf(ReasonValidation, "helmGlobals is not allowed")
	}
	return nil
}

// validateKustomization decodes data as a kustomization and refuses anything
// that could make the renderer touch the network, run git, or load a plugin.
//
// Decoding must go through types.Kustomization.Unmarshal, the path Kustomize
// itself takes: it matches field names case-insensitively, so "Resources:"
// binds for Kustomize while a case-sensitive YAML decoder would wave it
// through unvalidated. The generic YAML decode runs first only to reject
// duplicate keys, which the JSON path resolves last-wins.
func validateKustomization(data []byte) (*types.Kustomization, error) {
	fields := map[string]interface{}{}
	if err := kyamlyaml.Unmarshal(data, &fields); err != nil {
		return nil, failf(ReasonValidation, "cannot decode kustomization")
	}
	k := &types.Kustomization{}
	if err := k.Unmarshal(data); err != nil {
		return nil, failf(ReasonValidation, "cannot decode kustomization")
	}
	k.FixKustomization()
	if err := checkForbidden(k); err != nil {
		return nil, err
	}
	for _, ref := range kustomizationPaths(k) {
		if !plainLocalPath(ref.path) {
			return nil, failf(ReasonValidation, "unsupported path in %s", ref.field)
		}
	}
	for i := range k.ConfigMapGenerator {
		g := &k.ConfigMapGenerator[i]
		if err := validateKvPairSources("configMapGenerator", g.FileSources, g.EnvSources, g.EnvSource); err != nil {
			return nil, err
		}
	}
	for i := range k.SecretGenerator {
		g := &k.SecretGenerator[i]
		if err := validateKvPairSources("secretGenerator", g.FileSources, g.EnvSources, g.EnvSource); err != nil {
			return nil, err
		}
	}
	return k, nil
}

func validateKvPairSources(field string, fileSources, envSources []string, envSource string) error {
	for _, f := range fileSources {
		if !plainLocalPath(stripKeyPrefix(f)) {
			return failf(ReasonValidation, "unsupported path in %s files", field)
		}
	}
	for _, e := range envSources {
		if !plainLocalPath(e) {
			return failf(ReasonValidation, "unsupported path in %s envs", field)
		}
	}
	if envSource != "" && !plainLocalPath(envSource) {
		return failf(ReasonValidation, "unsupported path in %s env", field)
	}
	return nil
}

// stripKeyPrefix removes the optional "key=" prefix of a generator file source.
func stripKeyPrefix(s string) string {
	if i := strings.IndexByte(s, '='); i >= 0 {
		return s[i+1:]
	}
	return s
}

// byteCache holds original file bytes shared by all renders of one scan. It
// also supplies OriginalData for source line mapping.
type byteCache struct {
	mu    sync.Mutex
	files map[string][]byte
}

func (c *byteCache) get(path string, load func() ([]byte, error)) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if b, ok := c.files[path]; ok {
		return b, nil
	}
	b, err := load()
	if err != nil {
		return nil, err
	}
	c.files[path] = b
	return b, nil
}

// readSet records every file one render served, by role.
type readSet struct {
	mu    sync.Mutex
	files map[string]fileRole
}

func (r *readSet) record(path string, role fileRole) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.files[path] = role
}

func (r *readSet) sorted() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.files))
	for p := range r.files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// constrainedFS adapts vfs.FS to filesys.FileSystem for one render. It is the
// security boundary: confined to the workspace, read-only, size-limited, and
// it validates kustomization files at read time because Kustomize's loader can
// reach the network and git without going through this interface.
type constrainedFS struct {
	fsys            vfs.FS
	confinementRoot string // resolved real path of the workspace root
	renderRoot      string // absolute path of the kustomization being rendered
	maxFileBytes    int64
	budget          *atomic.Int64
	cache           *byteCache
	read            *readSet
	topKustomFile   string // resolved real path of the render root's kustomization file
	mem             *memIndex
	slashPaths      bool // report resolved paths with "/" instead of the OS separator
}

var _ filesys.FileSystem = (*constrainedFS)(nil)

func newConstrainedFS(
	fsys vfs.FS, confinementRoot, renderRoot string,
	maxFileBytes int64, budget *atomic.Int64, cache *byteCache,
) (*constrainedFS, error) {
	realRoot, err := realPath(fsys, confinementRoot)
	if err != nil {
		return nil, failf(ReasonMissingFile, "confinement root does not exist")
	}
	resolved, err := realPath(fsys, absUnderRoot(confinementRoot, renderRoot))
	if err != nil {
		return nil, failf(ReasonMissingFile, "render root does not exist")
	}
	if !underDir(resolved, realRoot) {
		return nil, failf(ReasonValidation, "render root outside confinement")
	}
	c := &constrainedFS{
		fsys:            fsys,
		confinementRoot: realRoot,
		renderRoot:      resolved,
		maxFileBytes:    maxFileBytes,
		budget:          budget,
		cache:           cache,
		read:            &readSet{files: make(map[string]fileRole)},
		// Pushed files are addressed with "/" on every OS, so their resolved
		// paths must be too; disk files keep the OS separator, matching the
		// Helm resolver.
		slashPaths: !vfs.IsDisk(fsys),
	}
	if m, ok := fsys.(*vfs.MemFS); ok {
		c.mem = newMemIndex(m)
	}
	if _, _, err := c.statExists(resolved); err != nil {
		return nil, failf(ReasonMissingFile, "render root does not exist")
	}
	return c, nil
}

// memIndex lets the adapter probe the in-memory filesystem for directories
// without delegating misses to it: MemFS.Stat cannot see directories and
// MemFS.ReadDir records a miss, which would fake an escalation request.
type memIndex struct {
	files map[string]bool
	dirs  map[string]bool
}

func newMemIndex(mem *vfs.MemFS) *memIndex {
	idx := &memIndex{files: make(map[string]bool), dirs: make(map[string]bool)}
	for _, p := range mem.Paths() {
		idx.files[p] = true
		for d := filepath.Dir(p); d != "." && d != string(filepath.Separator); d = filepath.Dir(d) {
			if idx.dirs[d] {
				break
			}
			idx.dirs[d] = true
		}
	}
	return idx
}

// realPath resolves symlinks on the real filesystem; the in-memory filesystem
// cannot hold symlinks, so cleaning is enough there.
func realPath(fsys vfs.FS, path string) (string, error) {
	abs, err := fsys.Abs(path)
	if err != nil {
		return "", err
	}
	if !vfs.IsDisk(fsys) {
		return filepath.Clean(abs), nil
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

func underDir(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

// isRooted reports whether p addresses a location on its own rather than one
// relative to some directory. filepath.IsAbs is the wrong test: on Windows a
// leading "/" is rooted but not absolute, and treating it as relative would
// join it onto the confinement root a second time.
func isRooted(p string) bool {
	return filepath.IsAbs(p) || strings.HasPrefix(p, "/") || strings.HasPrefix(p, string(filepath.Separator))
}

// absUnderRoot interprets p as the confinement root does: a rooted path
// stands on its own, anything else is relative to root.
func absUnderRoot(root, p string) string {
	if isRooted(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(root, p)
}

// confine checks path is inside the workspace and returns its real path.
func (c *constrainedFS) confine(op, path string) (string, error) {
	abs, err := c.fsys.Abs(path)
	if err != nil {
		return "", failf(ReasonValidation, "unresolvable path")
	}
	resolved, err := realPath(c.fsys, abs)
	if err != nil {
		return "", failf(ReasonMissingFile, "%s: does not exist", op)
	}
	if !underDir(resolved, c.confinementRoot) {
		return "", failf(ReasonValidation, "%s: outside confinement", op)
	}
	return resolved, nil
}

// statExists stats the path itself, never delegating a miss to the underlying
// filesystem's read calls: on a MemFS a delegated read miss would be recorded
// as an escalation request, and Kustomize probes three names per directory.
func (c *constrainedFS) statExists(path string) (fs.FileInfo, string, error) {
	resolved, err := c.confine("stat", path)
	if err != nil {
		return nil, "", err
	}
	info, err := c.fsys.Stat(resolved)
	if err == nil {
		return info, resolved, nil
	}
	if c.mem != nil {
		if c.mem.files[resolved] {
			return memFileInfo{name: filepath.Base(resolved)}, resolved, nil
		}
		if c.mem.dirs[resolved] {
			return memFileInfo{name: filepath.Base(resolved), dir: true}, resolved, nil
		}
	}
	return nil, resolved, failf(ReasonMissingFile, "stat: does not exist")
}

// loadKustomization returns the validated kustomization parsed from the
// original bytes of a kustomization file (the cache and ReadFile serve of the
// top-level file carry injected build metadata, never stored).
func (c *constrainedFS) loadKustomization(path string) (*types.Kustomization, error) {
	info, found, err := c.statExists(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() || info.Size() > c.maxFileBytes {
		return nil, failf(ReasonSizeLimit, "kustomization file outside limits")
	}
	data, err := c.cache.get(found, func() ([]byte, error) { return c.fsys.ReadFile(found) })
	if err != nil {
		return nil, failf(ReasonMissingFile, "cannot load kustomization")
	}
	return validateKustomization(data)
}

func (c *constrainedFS) ReadFile(path string) ([]byte, error) {
	info, found, err := c.statExists(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, failf(ReasonMissingFile, "read: is a directory")
	}
	if info.Size() > c.maxFileBytes {
		return nil, failf(ReasonSizeLimit, "file exceeds size limit")
	}
	if c.budget != nil && c.budget.Add(-info.Size()) < 0 {
		c.budget.Add(info.Size())
		return nil, failf(ReasonSizeLimit, "cumulative size budget exceeded")
	}
	base := filepath.Base(path) // the requested name: a symlinked kustomization.yaml still validates and gets annotated
	data, err := c.cache.get(found, func() ([]byte, error) { return c.fsys.ReadFile(found) })
	if err != nil {
		return nil, failf(ReasonMissingFile, "read: cannot load file")
	}
	if kustomizationFileNames[base] {
		if _, err := validateKustomization(data); err != nil {
			return nil, err
		}
		c.read.record(found, roleKustomization)
		if found == c.topKustomFile {
			if withOrigin, err := injectOriginAnnotations(data); err == nil {
				return withOrigin, nil
			}
		}
		return data, nil
	}
	c.read.record(found, roleOther)
	return data, nil
}

// memFile serves a ReadFile result through filesys.File. Writes fail: the
// adapter is read-only.
type memFile struct {
	*strings.Reader
	info os.FileInfo
}

var errReadOnly = errors.New("writes are not allowed")

func (f *memFile) Write([]byte) (int, error)  { return 0, errReadOnly }
func (f *memFile) Close() error               { return nil }
func (f *memFile) Stat() (os.FileInfo, error) { return f.info, nil }

type memFileInfo struct {
	name string
	size int64
	dir  bool
}

func (fi memFileInfo) Name() string { return fi.name }
func (fi memFileInfo) Size() int64  { return fi.size }

// memDirMode is the mode reported for directories synthesized from pushed keys.
const memDirMode = fs.ModeDir | 0o755

func (fi memFileInfo) Mode() fs.FileMode {
	if fi.dir {
		return memDirMode
	}
	return 0
}
func (fi memFileInfo) ModTime() time.Time { return time.Time{} }
func (fi memFileInfo) IsDir() bool        { return fi.dir }
func (fi memFileInfo) Sys() interface{}   { return nil }

func (c *constrainedFS) Open(path string) (filesys.File, error) {
	data, err := c.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &memFile{
		Reader: strings.NewReader(string(data)),
		info:   memFileInfo{name: filepath.Base(path), size: int64(len(data))},
	}, nil
}

func (c *constrainedFS) Exists(path string) bool {
	_, _, err := c.statExists(path)
	return err == nil
}

func (c *constrainedFS) IsDir(path string) bool {
	info, _, err := c.statExists(path)
	return err == nil && info.IsDir()
}

func (c *constrainedFS) CleanedAbs(path string) (filesys.ConfirmedDir, string, error) {
	info, found, err := c.statExists(path)
	if err != nil {
		return "", "", err
	}
	if info.IsDir() {
		return filesys.ConfirmedDir(found), "", nil
	}
	return filesys.ConfirmedDir(filepath.Dir(found)), filepath.Base(found), nil
}

func (c *constrainedFS) ReadDir(path string) ([]string, error) {
	dir, err := c.confine("readdir", path)
	if err != nil {
		return nil, err
	}
	entries, err := c.fsys.ReadDir(dir)
	if err != nil {
		return nil, failf(ReasonMissingFile, "readdir: does not exist")
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out, nil
}

func (c *constrainedFS) Glob(pattern string) ([]string, error) {
	matches, err := c.fsys.Glob(pattern)
	if err != nil {
		return nil, nil
	}
	var out []string
	for _, m := range matches {
		found, err := c.confine("glob", m)
		if err != nil {
			continue
		}
		out = append(out, found)
	}
	return out, nil
}

func (c *constrainedFS) Walk(path string, walkFn filepath.WalkFunc) error {
	return errors.New("walk is not supported")
}

func (c *constrainedFS) Create(path string) (filesys.File, error) {
	return nil, failf(ReasonValidation, "writes are not allowed")
}

func (c *constrainedFS) Mkdir(path string) error {
	return failf(ReasonValidation, "writes are not allowed")
}

func (c *constrainedFS) MkdirAll(path string) error {
	return failf(ReasonValidation, "writes are not allowed")
}

func (c *constrainedFS) RemoveAll(path string) error {
	return failf(ReasonValidation, "writes are not allowed")
}

func (c *constrainedFS) WriteFile(path string, _ []byte) error {
	return failf(ReasonValidation, "writes are not allowed")
}

// injectOriginAnnotations returns a copy of a kustomization file with
// originAnnotations added to buildMetadata, so every rendered resource carries
// a config.kubernetes.io/origin annotation. The copy is only ever served to
// the renderer, never cached or used as OriginalData.
func injectOriginAnnotations(data []byte) ([]byte, error) {
	var node kyamlyaml.Node
	if err := kyamlyaml.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	mapping := documentMappingNode(&node)
	if mapping == nil {
		return nil, errors.New("kustomization is not a mapping")
	}
	const field = "buildMetadata"
	var seq *kyamlyaml.Node
	for i := 0; i < len(mapping.Content)-1; i += 2 {
		// Kustomize binds keys case-insensitively, so "BuildMetadata" is the
		// same key; matching exactly would append a duplicate that wins under
		// last-wins and drops the options the user set. The sequence values
		// below stay exact: Kustomize compares those with ==.
		if strings.EqualFold(mapping.Content[i].Value, field) {
			seq = mapping.Content[i+1]
			break
		}
	}
	if seq == nil {
		key := &kyamlyaml.Node{Kind: kyamlyaml.ScalarNode, Tag: "!!str", Value: field}
		seq = &kyamlyaml.Node{Kind: kyamlyaml.SequenceNode, Tag: "!!seq"}
		mapping.Content = append(mapping.Content, key, seq)
	}
	for _, item := range seq.Content {
		if item.Value == "originAnnotations" {
			return kyamlyaml.Marshal(&node)
		}
	}
	seq.Content = append(seq.Content, &kyamlyaml.Node{Kind: kyamlyaml.ScalarNode, Tag: "!!str", Value: "originAnnotations"})
	return kyamlyaml.Marshal(&node)
}

func documentMappingNode(node *kyamlyaml.Node) *kyamlyaml.Node {
	for n := node; n != nil; n = firstContent(n) {
		if n.Kind == kyamlyaml.MappingNode {
			return n
		}
	}
	return nil
}

func firstContent(n *kyamlyaml.Node) *kyamlyaml.Node {
	if len(n.Content) == 0 {
		return nil
	}
	return n.Content[0]
}
