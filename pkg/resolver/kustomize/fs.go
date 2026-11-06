package kustomize

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

// maxServedBytes caps the bytes all renders of one scan may read from the
// repository.
const maxServedBytes = 256 << 20

var errReadOnly = errors.New("read-only filesystem")

// failure categories reported for a root that did not render. They come from
// adapter and plan state, never from Kustomize error text.
const (
	ReasonValidation  = "validation"
	ReasonMissingFile = "missing_file"
	ReasonSizeLimit   = "size_limit"
	ReasonBudget      = "budget"
	ReasonTimeout     = "timeout"
	ReasonPlanSkip    = "plan_skip"
	ReasonRenderError = "render_error"
)

// sourceCache keeps the original bytes of every file served, shared by all the
// renders of a scan.
type sourceCache struct {
	mu      sync.Mutex
	files   map[string][]byte
	kusts   map[string]*types.Kustomization
	served  int64
	maxFile int64
	// resolved caches symlink evaluation: paths do not grow symlinks during
	// a read-only scan, and EvalSymlinks' syscalls dominate small renders.
	resolved map[string]string
}

// adapter exposes a vfs.FS to Kustomize as a read-only filesystem confined to
// root. One adapter serves one render; reads are recorded in its read set.
type adapter struct {
	fsys     vfs.FS
	root     string
	cache    *sourceCache
	rootKust string
	rootCopy []byte
	reads    map[string]struct{}
	reason   string
}

func (a *adapter) refuse(reason string) {
	if a.reason == "" {
		a.reason = reason
	}
}

// resolve returns the absolute, symlink-free form of p when it lies inside the
// confinement root. Results are cached on the scan's shared cache.
func (a *adapter) resolve(p string) (string, bool) {
	abs, err := a.fsys.Abs(p)
	if err != nil {
		return "", false
	}
	abs = filepath.Clean(abs)
	if vfs.IsDisk(a.fsys) {
		orig := abs
		a.cache.mu.Lock()
		resolved, ok := a.cache.resolved[orig]
		a.cache.mu.Unlock()
		if !ok {
			if resolved, err := filepath.EvalSymlinks(orig); err == nil {
				abs = resolved
			} else if resolved, err := filepath.EvalSymlinks(filepath.Dir(orig)); err == nil {
				abs = filepath.Join(resolved, filepath.Base(orig))
			}
			a.cache.mu.Lock()
			a.cache.resolved[orig] = abs
			a.cache.mu.Unlock()
		} else {
			abs = resolved
		}
	}
	return abs, abs == a.root || strings.HasPrefix(abs, a.root+string(filepath.Separator))
}

func (a *adapter) stat(p string) (string, fs.FileInfo, bool) {
	abs, ok := a.resolve(p)
	if !ok {
		return "", nil, false
	}
	info, err := a.fsys.Stat(abs)
	if err != nil {
		// MemFS knows only files; its directories are synthesized from them.
		if d, ok := a.fsys.(interface {
			DirInfo(string) (fs.FileInfo, bool)
		}); ok {
			if info, ok := d.DirInfo(abs); ok {
				return abs, info, true
			}
		}
		return "", nil, false
	}
	return abs, info, true
}

func (a *adapter) ReadFile(p string) ([]byte, error) {
	abs, ok := a.resolve(p)
	if !ok {
		a.refuse(ReasonValidation)
		return nil, fs.ErrNotExist
	}
	// The role follows the requested name, not the symlink target: a
	// kustomization.yaml symlink to an ordinary file is still validated as a
	// kustomization, so a remote resource cannot reach Kustomize's loaders.
	kust := IsKustomizationFile(filepath.Base(p))
	if abs == a.rootKust && a.rootCopy != nil {
		a.reads[abs] = struct{}{}
		return a.rootCopy, nil
	}
	content, err := a.load(abs, kust)
	if err != nil {
		return nil, err
	}
	a.reads[abs] = struct{}{}
	return content, nil
}

// load returns the original bytes of abs, validated as a kustomization when
// the requested role is one, from the cache or the filesystem.
func (a *adapter) load(abs string, kustomization bool) ([]byte, error) {
	c := a.cache
	c.mu.Lock()
	defer c.mu.Unlock()
	if content, ok := c.files[abs]; ok {
		if kustomization && c.kusts[abs] == nil {
			// First requested under another name, or invalid: decode now.
			k, err := decodeKustomization(content)
			if err != nil {
				a.refuse(ReasonValidation)
				return nil, err
			}
			c.kusts[abs] = k
		}
		return content, nil
	}
	info, err := a.fsys.Stat(abs)
	if err != nil || !info.Mode().IsRegular() {
		// A miss is never recorded: Kustomize probes names that do not exist.
		// Only regular files are served: a device or FIFO could block forever.
		return nil, fs.ErrNotExist
	}
	if info.Size() > c.maxFile {
		a.refuse(ReasonSizeLimit)
		return nil, errRefused
	}
	if c.served+info.Size() > maxServedBytes {
		a.refuse(ReasonBudget)
		return nil, errRefused
	}
	content, err := a.fsys.ReadFile(abs)
	if err != nil {
		return nil, fs.ErrNotExist
	}
	c.served += int64(len(content))
	c.files[abs] = content
	if kustomization {
		k, err := decodeKustomization(content)
		if err != nil {
			a.refuse(ReasonValidation)
			return nil, err
		}
		c.kusts[abs] = k
	}
	return content, nil
}

func (a *adapter) Open(p string) (filesys.File, error) {
	content, err := a.ReadFile(p)
	if err != nil {
		return nil, err
	}
	abs, _ := a.resolve(p)
	info, err := a.fsys.Stat(abs)
	if err != nil {
		return nil, err
	}
	return &file{Reader: bytes.NewReader(content), info: info}, nil
}

func (a *adapter) IsDir(p string) bool {
	_, info, ok := a.stat(p)
	return ok && info.IsDir()
}

func (a *adapter) Exists(p string) bool {
	_, _, ok := a.stat(p)
	return ok
}

func (a *adapter) ReadDir(p string) ([]string, error) {
	abs, info, ok := a.stat(p)
	if !ok || !info.IsDir() {
		return nil, fs.ErrNotExist
	}
	entries, err := a.fsys.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

func (a *adapter) CleanedAbs(p string) (filesys.ConfirmedDir, string, error) {
	abs, info, ok := a.stat(p)
	if !ok {
		return "", "", fs.ErrNotExist
	}
	if info.IsDir() {
		return filesys.ConfirmedDir(abs), "", nil
	}
	return filesys.ConfirmedDir(filepath.Dir(abs)), filepath.Base(abs), nil
}

func (a *adapter) Glob(pattern string) ([]string, error) {
	abs, ok := a.resolve(filepath.Dir(pattern))
	if !ok {
		return nil, nil
	}
	matches, err := a.fsys.Glob(filepath.Join(abs, filepath.Base(pattern)))
	if err != nil {
		return nil, err
	}
	out := matches[:0]
	for _, m := range matches {
		if _, ok := a.resolve(m); ok {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (a *adapter) Walk(p string, walkFn filepath.WalkFunc) error {
	abs, info, ok := a.stat(p)
	if !ok {
		return walkFn(p, nil, fs.ErrNotExist)
	}
	if err := walkFn(abs, info, nil); err != nil || !info.IsDir() {
		if errors.Is(err, filepath.SkipDir) {
			return nil
		}
		return err
	}
	names, err := a.ReadDir(abs)
	if err != nil {
		return err
	}
	for _, n := range names {
		if err := a.Walk(filepath.Join(abs, n), walkFn); err != nil && !errors.Is(err, filepath.SkipDir) {
			return err
		}
	}
	return nil
}

func (a *adapter) Create(string) (filesys.File, error) { return nil, errReadOnly }
func (a *adapter) Mkdir(string) error                  { return errReadOnly }
func (a *adapter) MkdirAll(string) error               { return errReadOnly }
func (a *adapter) RemoveAll(string) error              { return errReadOnly }
func (a *adapter) WriteFile(string, []byte) error      { return errReadOnly }

var _ filesys.FileSystem = (*adapter)(nil)

type file struct {
	*bytes.Reader
	info fs.FileInfo
}

func (f *file) Write([]byte) (int, error)  { return 0, errReadOnly }
func (f *file) Close() error               { return nil }
func (f *file) Stat() (os.FileInfo, error) { return f.info, nil }

// withOriginAnnotations returns content with originAnnotations added to
// buildMetadata, or nil when content is not a mapping.
func withOriginAnnotations(content []byte) []byte {
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil
	}
	m := doc.Content[0]
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != "buildMetadata" {
			continue
		}
		seq := m.Content[i+1]
		if seq.Kind != yaml.SequenceNode {
			return nil
		}
		for _, v := range seq.Content {
			if v.Value == types.OriginAnnotations {
				return content
			}
		}
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: types.OriginAnnotations})
		out, err := yaml.Marshal(&doc)
		if err != nil {
			return nil
		}
		return out
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "buildMetadata"},
		&yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: types.OriginAnnotations},
		}})
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil
	}
	return out
}
