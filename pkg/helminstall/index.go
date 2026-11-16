/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package helminstall

import (
	"bytes"
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/internal/pathutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// Inputs are what discovery reads.
type Inputs struct {
	// Root is the root of the repository, which descriptors naming repository
	// paths (Argo CD, Flux) are relative to.
	Root string
	// Files are the descriptor files of the scan (see IsDescriptorName and
	// SniffDescriptor), and its Terraform files.
	Files []string
	// ChartRoots are the directories of the scan holding a Chart.yaml.
	ChartRoots []string
	// RepositoryURL is the URL of the scanned repository, when known. A
	// descriptor naming another repository says nothing of this one's charts.
	RepositoryURL string
}

// Index holds the installations found for the charts of a scan. It is safe
// for concurrent use.
type Index struct {
	fsys vfs.FS
	// root is the repository, in which every file discovery reads lies.
	root string
	// resolved caches the canonical form of the paths of the disk.
	resolved sync.Map
	// charts are the chart roots of the scan, by clean path.
	charts map[string]*chartInfo
	// declared are the installations descriptors declare, by chart.
	declared map[string][]Installation

	mu       sync.Mutex
	computed map[string][]Installation
	// parents are, for each chart, the charts of the scan depending on it.
	parentsOnce sync.Once
	parents     map[string][]dependent
	// configs are the ConfigMaps and Secrets of the scan, for Flux values.
	configs map[configKey]configData
}

// dependent is a chart depending on another of the scan, through dep.
type dependent struct {
	dir string
	dep *chartDependency
}

// Discover reads the descriptors of in and returns the installations found.
func Discover(ctx context.Context, fsys vfs.FS, in *Inputs) *Index {
	if fsys == nil {
		fsys = vfs.Default()
	}
	if in == nil {
		in = &Inputs{}
	}
	idx := &Index{
		fsys:     fsys,
		charts:   map[string]*chartInfo{},
		declared: map[string][]Installation{},
		computed: map[string][]Installation{},
	}
	idx.root = idx.canonical(in.Root)
	if in.Root == "" {
		idx.root = CommonDir(idx.canonicalAll(append(append([]string{}, in.ChartRoots...), in.Files...)))
	}
	for _, root := range in.ChartRoots {
		dir := idx.canonical(root)
		if _, ok := idx.charts[dir]; ok {
			continue
		}
		if info, ok := readChartInfo(fsys, dir); ok {
			idx.charts[dir] = info
		}
	}
	d := &discovery{ctx: ctx, idx: idx, repoURL: in.RepositoryURL}
	d.run(idx.canonicalAll(in.Files))
	if n := len(idx.declared); n > 0 {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Info().Msgf("Found the installations of %d Helm charts in the deployment descriptors of the scan", n)
	}
	return idx
}

// For returns the installations of the chart at dir, never none: a chart no
// descriptor names, nor any parent chart, is installed by convention.
func (x *Index) For(dir string) []Installation {
	if x == nil {
		return nil
	}
	return x.forChart(x.canonical(dir), map[string]bool{})
}

func (x *Index) forChart(dir string, visiting map[string]bool) []Installation {
	x.mu.Lock()
	if cached, ok := x.computed[dir]; ok {
		x.mu.Unlock()
		return cached
	}
	x.mu.Unlock()
	if visiting[dir] {
		return nil
	}
	visiting[dir] = true
	defer delete(visiting, dir)

	installs := append([]Installation{}, x.declared[dir]...)
	installs = append(installs, x.fromParents(dir, visiting)...)
	if len(installs) == 0 {
		installs = x.conventions(dir)
		for i := range installs {
			installs[i].Layers = x.confinedLayers(installs[i].Layers)
		}
	}
	installs = selectInstallations(installs)
	x.mu.Lock()
	x.computed[dir] = installs
	x.mu.Unlock()
	return installs
}

// Declared returns the installations descriptors declare for the chart at dir.
func (x *Index) Declared(dir string) []Installation {
	if x == nil {
		return nil
	}
	return x.declared[x.canonical(dir)]
}

// add records an installation of the chart at dir, when dir is a chart of the
// scan: descriptors also name charts the scan does not render.
func (x *Index) add(dir string, inst *Installation) {
	dir = x.canonical(dir)
	if _, ok := x.charts[dir]; !ok {
		return
	}
	recorded := *inst
	recorded.Layers = x.confinedLayers(inst.Layers)
	if recorded.Release == "" {
		recorded.Release = x.charts[dir].name
	}
	x.declared[dir] = append(x.declared[dir], recorded)
}

// chartDir returns the chart of the scan at dir, as a descriptor names it.
func (x *Index) chartDir(dir string) (string, bool) {
	dir = x.canonical(dir)
	_, ok := x.charts[dir]
	return dir, ok
}

// canonical is the form the index keeps paths in: absolute with symbolic
// links resolved on disk, as pushed in memory. A path and the same through a
// link to one of its directories are one path.
func (x *Index) canonical(p string) string {
	clean := filepath.Clean(filepath.FromSlash(p))
	if abs, err := x.fsys.Abs(clean); err == nil {
		clean = filepath.Clean(filepath.FromSlash(abs))
	}
	if !vfs.IsDisk(x.fsys) {
		return clean
	}
	if cached, ok := x.resolved.Load(clean); ok {
		return cached.(string)
	}
	resolved := resolveExisting(clean)
	x.resolved.Store(clean, resolved)
	return resolved
}

// resolveExisting resolves the symbolic links of the deepest directory of p
// that exists, keeping the rest of p as it is.
func resolveExisting(p string) string {
	rest := ""
	for cur := p; ; {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(resolved, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

func (x *Index) canonicalAll(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = x.canonical(p)
	}
	return out
}

// CommonDir is the deepest directory holding every path.
func CommonDir(paths []string) string {
	if len(paths) == 0 {
		return "."
	}
	common := strings.Split(filepath.Dir(paths[0]), string(filepath.Separator))
	for _, p := range paths[1:] {
		parts := strings.Split(filepath.Dir(p), string(filepath.Separator))
		n := 0
		for n < len(common) && n < len(parts) && common[n] == parts[n] {
			n++
		}
		common = common[:n]
	}
	dir := strings.Join(common, string(filepath.Separator))
	if dir == "" {
		if paths[0] != "" && paths[0][0] == filepath.Separator {
			return string(filepath.Separator)
		}
		return "."
	}
	return dir
}

// confined reports whether a path a descriptor names lies in the repository.
// A descriptor is the repository's, and must not have the scan read a file
// outside it, through ".." or a symbolic link.
func (x *Index) confined(p string) bool {
	rel, err := filepath.Rel(x.root, x.canonical(p))
	return err == nil && !pathutil.PathEscapesDir(rel)
}

// confinedLayers drops the values files outside the repository.
func (x *Index) confinedLayers(layers []Layer) []Layer {
	kept := make([]Layer, 0, len(layers))
	for _, l := range layers {
		if l.File == "" || x.confined(l.File) {
			kept = append(kept, l)
		}
	}
	return kept
}

// discovery is one run of the descriptor readers.
type discovery struct {
	ctx     context.Context
	idx     *Index
	repoURL string
	pending pendingManifests
	// tfDirs are the Terraform modules read.
	tfDirs    map[string]bool
	bazelEval *bazelEval
	// chartFiles are the files of the charts values functions select from.
	chartFiles map[string][]string
}

func (d *discovery) fsys() vfs.FS { return d.idx.fsys }

func (d *discovery) debugf(format string, args ...interface{}) {
	contextLogger := logger.FromContext(d.ctx)
	contextLogger.Debug().Msgf(format, args...)
}

// read returns the content of a file a descriptor names, nil when it cannot
// be read or lies outside the repository.
func (d *discovery) read(path string) []byte {
	if !d.idx.confined(path) {
		d.debugf("Not reading %s, which a deployment descriptor names outside the repository", path)
		return nil
	}
	data, err := d.fsys().ReadFile(path)
	if err != nil {
		d.debugf("Could not read deployment descriptor %s: %v", path, err)
		return nil
	}
	return data
}

// descriptorKind is the kind of descriptor a file is.
type descriptorKind int

const (
	kindNone descriptorKind = iota
	kindKustomization
	kindManifests
	kindHelmfile
	kindFleet
	kindTerraform
	kindBazel
	kindDeployConfig
)

// descriptorKindOf returns what kind of descriptor path may be.
func descriptorKindOf(path string) descriptorKind {
	base := filepath.Base(path)
	switch {
	case isBazelFile(base):
		return kindBazel
	case isHelmfile(path):
		return kindHelmfile
	case isKustomization(base):
		return kindKustomization
	case isFleetFile(base):
		return kindFleet
	case isDeployConfig(base):
		return kindDeployConfig
	case strings.EqualFold(filepath.Ext(base), ".tf"):
		return kindTerraform
	case isYAMLFile(base):
		return kindManifests
	}
	return kindNone
}

// run reads the descriptors. Those others refer to are read first: the
// ConfigMaps kustomizations generate, and the Bazel targets deploy.yaml apps
// name.
func (d *discovery) run(files []string) {
	byKind := map[descriptorKind][]string{}
	seen := map[string]bool{}
	for _, f := range files {
		path := filepath.FromSlash(f)
		if !seen[path] {
			seen[path] = true
			kind := descriptorKindOf(path)
			byKind[kind] = append(byKind[kind], path)
		}
	}
	readers := []struct {
		kind descriptorKind
		read func(string)
	}{
		{kindKustomization, d.kustomization},
		{kindManifests, d.manifests},
		{kindHelmfile, d.helmfile},
		{kindFleet, d.fleet},
		{kindTerraform, d.terraform},
	}
	for _, r := range readers {
		for _, p := range byKind[r.kind] {
			r.read(p)
		}
	}
	if len(byKind[kindBazel]) > 0 {
		d.bazel(byKind[kindBazel])
	}
	for _, p := range byKind[kindDeployConfig] {
		d.deployConfig(p)
	}
	d.resolveManifests()
}

// bazelEvaluator returns the evaluator of the Bazel files of the scan,
// creating it when none was run.
func (d *discovery) bazelEvaluator() *bazelEval {
	if d.bazelEval == nil {
		d.bazelEval = newBazelEval(d)
	}
	return d.bazelEval
}

// IsDescriptorName reports whether path names a file that may describe how a
// chart is installed, whatever its content.
func IsDescriptorName(path string) bool {
	base := filepath.Base(filepath.FromSlash(path))
	return isBazelFile(base) || isHelmfile(path) || isKustomization(base) || isFleetFile(base) ||
		isDeployConfig(base) || base == serviceDefinitionName
}

// descriptorKinds are the API groups of the Kubernetes resources installing
// charts: Argo CD applications, Flux releases and charts.
var descriptorKinds = [][]byte{
	[]byte("argoproj.io/"),
	[]byte("helm.toolkit.fluxcd.io/"),
	[]byte("source.toolkit.fluxcd.io/"),
}

// SniffDescriptor reports whether the content of a YAML file may hold a
// resource installing a chart, or a ConfigMap Flux reads values from.
func SniffDescriptor(content []byte) bool {
	for _, kind := range descriptorKinds {
		if bytes.Contains(content, kind) {
			return true
		}
	}
	return false
}

func isYAMLFile(base string) bool {
	ext := strings.ToLower(filepath.Ext(base))
	return ext == ".yaml" || ext == ".yml"
}

func isHelmfile(path string) bool {
	base := filepath.Base(path)
	switch base {
	case "helmfile.yaml", "helmfile.yml", "helmfile.yaml.gotmpl", "helmfile.yaml.tpl":
		return true
	}
	return filepath.Base(filepath.Dir(path)) == "helmfile.d" &&
		(isYAMLFile(base) || strings.HasSuffix(base, ".yaml.gotmpl"))
}

func isKustomization(base string) bool {
	return base == "kustomization.yaml" || base == "kustomization.yml" || base == "Kustomization"
}

func isFleetFile(base string) bool {
	return base == "fleet.yaml" || base == "fleet.yml"
}

// dirExists reports whether dir is a directory, without an in-memory FS
// recording a miss for it.
func dirExists(fsys vfs.FS, dir string) bool {
	if m, ok := fsys.(interface {
		DirInfo(string) (fs.FileInfo, bool)
	}); ok {
		_, found := m.DirInfo(dir)
		return found
	}
	info, err := fsys.Stat(dir)
	return err == nil && info.IsDir()
}

// fileExists reports whether path is a file, without recording a miss.
func fileExists(fsys vfs.FS, path string) bool {
	info, err := fsys.Stat(path)
	return err == nil && !info.IsDir()
}

// readDir lists dir, nothing when it does not exist.
func readDir(fsys vfs.FS, dir string) []fs.DirEntry {
	if !dirExists(fsys, dir) {
		return nil
	}
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return nil
	}
	return entries
}

// walkFiles lists the files under dir, recursively, relative to it with "/",
// leaving version control data out.
func walkFiles(fsys vfs.FS, dir string) []string {
	var out []string
	var walk func(abs, rel string)
	walk = func(abs, rel string) {
		for _, e := range readDir(fsys, abs) {
			childRel := e.Name()
			if rel != "" {
				childRel = rel + "/" + e.Name()
			}
			if e.IsDir() {
				if e.Name() != ".git" {
					walk(filepath.Join(abs, e.Name()), childRel)
				}
				continue
			}
			out = append(out, childRel)
		}
	}
	walk(dir, "")
	return out
}
