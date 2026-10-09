package helm

import (
	"context"
	"path/filepath"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
)

const (
	maxDependencyDepth = 10
	// maxAttachedCharts bounds the charts attached to one render. Helm renders
	// a copy of a dependency per parent, so a chart reached through several
	// paths is attached once per path, and a few charts depending on each
	// other grow the tree exponentially.
	maxAttachedCharts = 100
)

type indexedChart struct {
	dir     string
	version string
}

// chartIndex maps chart names to the chart roots of the scan that declare them.
// It reads the roots' Chart.yaml only once a dependency is actually missing.
type chartIndex struct {
	fsys vfs.FS
	// dirs are the cleaned chart roots. Overlapping scan paths walk a chart
	// more than once; a repeated root is the same chart, not a second candidate
	// that would make the lookup a tie.
	dirs   []string
	inScan map[string]bool
	once   sync.Once
	byName map[string][]indexedChart
}

func newChartIndex(fsys vfs.FS, roots []string) *chartIndex {
	idx := &chartIndex{fsys: fsys, inScan: make(map[string]bool, len(roots))}
	for _, root := range roots {
		dir := filepath.Clean(filepath.FromSlash(root))
		if !idx.inScan[dir] {
			idx.inScan[dir] = true
			idx.dirs = append(idx.dirs, dir)
		}
	}
	return idx
}

// contains reports whether dir is a chart root of the scan.
func (idx *chartIndex) contains(dir string) bool {
	return idx != nil && idx.inScan[filepath.Clean(dir)]
}

func (idx *chartIndex) load() {
	idx.byName = make(map[string][]indexedChart, len(idx.dirs))
	for _, dir := range idx.dirs {
		data, err := idx.fsys.ReadFile(filepath.Join(dir, "Chart.yaml"))
		if err != nil {
			continue
		}
		var md struct {
			Name    string `yaml:"name"`
			Version string `yaml:"version"`
		}
		if yaml.Unmarshal(data, &md) != nil || md.Name == "" {
			continue
		}
		idx.byName[md.Name] = append(idx.byName[md.Name], indexedChart{dir: dir, version: md.Version})
	}
}

// lookup returns the chart in the scan named like dep, preferring versions
// compatible with its constraint. Helm still renders a vendored chart whose
// version does not match, so with anyVersion an incompatible one is the
// fallback. Among several candidates the one sharing the deepest directory
// with the dependent chart wins; a tie is ambiguous and yields none.
func (idx *chartIndex) lookup(dep *chart.Dependency, self string, anyVersion bool) (string, bool) {
	if idx == nil {
		return "", false
	}
	idx.once.Do(idx.load)
	var compatible, others []indexedChart
	for _, c := range idx.byName[dep.Name] {
		if filepath.Clean(c.dir) == filepath.Clean(self) {
			continue
		}
		if versionMatches(dep.Version, c.version) {
			compatible = append(compatible, c)
		} else {
			others = append(others, c)
		}
	}
	if len(compatible) > 0 || !anyVersion {
		return nearest(compatible, self)
	}
	return nearest(others, self)
}

// versionMatches reports whether version satisfies constraint; no constraint
// accepts any version.
func versionMatches(constraint, version string) bool {
	return constraint == "" || chartutil.IsCompatibleRange(constraint, version)
}

func nearest(candidates []indexedChart, self string) (string, bool) {
	self = filepath.Clean(self)
	match, best, tied := "", -1, false
	for _, c := range candidates {
		dir := filepath.Clean(c.dir)
		switch shared := sharedDepth(dir, self); {
		case shared > best:
			match, best, tied = c.dir, shared, false
		case shared == best:
			tied = true
		}
	}
	if match == "" || tied {
		return "", false
	}
	return match, true
}

func sharedDepth(a, b string) int {
	as := strings.Split(filepath.ToSlash(a), "/")
	bs := strings.Split(filepath.ToSlash(b), "/")
	n := 0
	for n < len(as) && n < len(bs) && as[n] == bs[n] {
		n++
	}
	return n
}

// attachMissingDependencies loads declared dependencies that are not vendored
// under charts/, the way the build that packages the chart would provide them:
// a "file://" repository is read from its path (as `helm dependency build`
// copies it), anything else from the single chart in the scan with the same
// name and a compatible version (monorepos whose build system links charts).
// A dependency without a repository may also take an incompatible version, as
// a vendored copy would; one naming a remote repository is not replaced by a
// different chart of the same name. On disk a "file://" path is read only when
// it is a chart of the scan, as it may name any directory of the host; an
// in-memory FS asks the client for it only when it stays inside the workspace.
// Helm then matches them by name and version and applies aliases at install.
//
// The returned locator remembers where each file of a dependency comes from.
func attachMissingDependencies(ctx context.Context, fsys vfs.FS, idx *chartIndex, ch *chart.Chart, dir string) *fileLocator {
	a := newAttacher(ctx, fsys, idx, dir, true)
	a.attachFrom(ch, dir, 0)
	return a.locator
}

// locateDependencies records where the vendored dependencies of ch come from,
// attaching none.
func locateDependencies(ctx context.Context, fsys vfs.FS, ch *chart.Chart, dir string) *fileLocator {
	a := newAttacher(ctx, fsys, nil, dir, false)
	a.attachFrom(ch, dir, 0)
	return a.locator
}

// fileLocator records where the files of a chart's dependencies come from.
// Helm names them after the position they render at (parent/charts/dep/...),
// which is not a path of the repository when a dependency was attached from
// elsewhere, unpacked in a directory named otherwise, or packaged. Keys are the
// chart files themselves, which stay the same objects while Helm renames,
// instruments and aliases charts. A nil locator knows no file.
type fileLocator struct {
	// real maps the files of unpacked dependencies to their paths.
	real map[*chart.File]string
	// packaged maps the files of a dependency packaged as an archive to the
	// directory of the chart whose charts/ holds the archive.
	packaged map[*chart.File]string
	// attached counts the charts attached from outside charts/.
	attached int
}

func (l *fileLocator) record(ch *chart.Chart, dir string) {
	for _, f := range ch.Templates {
		l.real[f] = filepath.Join(dir, filepath.FromSlash(f.Name))
	}
	for _, f := range ch.Files {
		l.real[f] = filepath.Join(dir, filepath.FromSlash(f.Name))
	}
}

func (l *fileLocator) recordPackaged(ch *chart.Chart, parent string) {
	for _, files := range [][]*chart.File{ch.Raw, ch.Templates, ch.Files} {
		for _, f := range files {
			l.packaged[f] = parent
		}
	}
}

// realPath returns where f really lives, when it is a file of an unpacked
// dependency.
func (l *fileLocator) realPath(f *chart.File) (string, bool) {
	if l == nil {
		return "", false
	}
	p, ok := l.real[f]
	return p, ok
}

// packagedParent returns the directory of the chart holding the archive ch was
// loaded from, when ch is a packaged dependency.
func (l *fileLocator) packagedParent(ch *chart.Chart) (string, bool) {
	if l == nil {
		return "", false
	}
	for _, files := range [][]*chart.File{ch.Raw, ch.Templates, ch.Files} {
		for _, f := range files {
			if parent, ok := l.packaged[f]; ok {
				return parent, true
			}
		}
	}
	return "", false
}

// attachedAny reports whether a chart was attached from outside charts/.
func (l *fileLocator) attachedAny() bool {
	return l != nil && l.attached > 0
}

type attacher struct {
	ctx  context.Context
	fsys vfs.FS
	idx  *chartIndex
	root string
	// attach is false when only the vendored dependencies are recorded.
	attach bool
	// ancestors are the directories on the path from the root, so a cycle ends
	// at once instead of unfolding to the depth cap.
	ancestors map[string]bool
	locator   *fileLocator
	capped    bool
}

func newAttacher(ctx context.Context, fsys vfs.FS, idx *chartIndex, root string, attach bool) *attacher {
	return &attacher{
		ctx: ctx, fsys: fsys, idx: idx, root: root, attach: attach,
		ancestors: map[string]bool{filepath.Clean(root): true},
		locator:   &fileLocator{real: map[*chart.File]string{}, packaged: map[*chart.File]string{}},
	}
}

// inMemory reports an in-memory FS, which cannot reach the host and turns a
// missing dependency into a request for the client to push it.
func inMemory(fsys vfs.FS) bool {
	_, ok := fsys.(vfs.MissingRecorder)
	return ok
}

// insideWorkspace reports whether a pushed path lies below the workspace root.
// The root itself is left out: loading it as a chart would read every pushed
// file.
func insideWorkspace(p string) bool {
	clean := filepath.ToSlash(filepath.Clean(p))
	return !filepath.IsAbs(p) && !strings.HasPrefix(clean, "/") &&
		clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

// attachFrom records and completes the dependencies of ch, both those under
// its charts/ directory and those attached from elsewhere in the scan.
func (a *attacher) attachFrom(ch *chart.Chart, dir string, depth int) {
	if ch.Metadata == nil || depth >= maxDependencyDepth {
		return
	}
	unpacked := map[*chart.Chart]bool{}
	for _, vendored := range vendoredDependencies(a.fsys, ch, dir) {
		unpacked[vendored.chart] = true
		a.locator.record(vendored.chart, vendored.dir)
		a.descend(vendored.chart, vendored.dir, depth)
	}
	vendoredNames := map[string]bool{}
	for _, dep := range ch.Dependencies() {
		vendoredNames[dep.Name()] = true
		if !unpacked[dep] {
			a.locator.recordPackaged(dep, dir)
		}
	}
	if !a.attach {
		return
	}
	attachedDirs := map[string]bool{}
	for _, dep := range ch.Metadata.Dependencies {
		if dep == nil || vendoredNames[dep.Name] || satisfied(ch, dep) {
			continue
		}
		if !a.attachDeclared(ch, dep, dir, depth, attachedDirs) {
			return
		}
	}
}

// attachDeclared attaches the chart providing dep to ch, and reports false once
// no more charts may be attached.
func (a *attacher) attachDeclared(
	ch *chart.Chart, dep *chart.Dependency, dir string, depth int, attachedDirs map[string]bool,
) bool {
	// No incompatible fallback for a remote repository, nor once another
	// declaration of the chart, under an alias, attached a version this one
	// does not accept.
	anyVersion := dep.Repository == "" && !hasDependency(ch, dep.Name)
	depDir, ok := dependencyDir(dep, dir, a.idx, anyVersion)
	if !ok {
		return true
	}
	key := filepath.Clean(depDir)
	if a.ancestors[key] || attachedDirs[key] {
		return true
	}
	contextLogger := logger.FromContext(a.ctx)
	if !a.mayLoad(depDir) {
		contextLogger.Warn().Msgf("helm dependency %q of chart '%s' is not loaded from %s, which is not a chart of the scan",
			dep.Name, dir, depDir)
		return true
	}
	if a.locator.attached >= maxAttachedCharts {
		if !a.capped {
			a.capped = true
			contextLogger.Warn().Msgf("chart '%s' attaches more than %d dependency charts; the others are not rendered",
				a.root, maxAttachedCharts)
		}
		return false
	}
	sub, err := loadChart(a.ctx, a.fsys, depDir)
	if err != nil {
		contextLogger.Warn().Msgf("helm dependency %q of chart '%s' could not be loaded from %s: %v",
			dep.Name, dir, depDir, err)
		return true
	}
	attachedDirs[key] = true
	a.locator.attached++
	a.locator.record(sub, depDir)
	a.descend(sub, depDir, depth)
	ch.AddDependency(sub)
	return true
}

// mayLoad reports whether a dependency may be loaded from dir: a chart of the
// scan, or on an in-memory FS a directory of the workspace the client can push.
func (a *attacher) mayLoad(dir string) bool {
	return a.idx.contains(dir) || (inMemory(a.fsys) && insideWorkspace(dir))
}

func (a *attacher) descend(ch *chart.Chart, dir string, depth int) {
	key := filepath.Clean(dir)
	a.ancestors[key] = true
	a.attachFrom(ch, dir, depth+1)
	delete(a.ancestors, key)
}

type vendoredDependency struct {
	chart *chart.Chart
	dir   string
}

// vendoredDependencies pairs the dependencies Helm loaded from the charts/
// directory of dir with the directory each was unpacked in. That directory is
// named freely, so it is found by the chart name it declares when it is not the
// name itself. Packaged dependencies have no directory and are left out.
func vendoredDependencies(fsys vfs.FS, ch *chart.Chart, dir string) []vendoredDependency {
	deps := ch.Dependencies()
	if len(deps) == 0 {
		return nil
	}
	chartsDir := filepath.Join(dir, dependenciesDirName)
	var byDeclaredName map[string]string
	vendored := make([]vendoredDependency, 0, len(deps))
	for _, dep := range deps {
		depDir := filepath.Join(chartsDir, dep.Name())
		if _, err := fsys.Stat(filepath.Join(depDir, "Chart.yaml")); err != nil {
			if byDeclaredName == nil {
				byDeclaredName = chartDirsByName(fsys, chartsDir)
			}
			var ok bool
			if depDir, ok = byDeclaredName[dep.Name()]; !ok {
				continue
			}
		}
		vendored = append(vendored, vendoredDependency{chart: dep, dir: depDir})
	}
	return vendored
}

// chartDirsByName maps the chart names declared under chartsDir to their directories.
func chartDirsByName(fsys vfs.FS, chartsDir string) map[string]string {
	dirs := map[string]string{}
	entries, err := fsys.ReadDir(chartsDir)
	if err != nil {
		return dirs
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		chartFile := filepath.Join(chartsDir, entry.Name(), "Chart.yaml")
		// Stat first: a miss on an in-memory FS would become an escalation request.
		if _, err := fsys.Stat(chartFile); err != nil {
			continue
		}
		data, err := fsys.ReadFile(chartFile)
		if err != nil {
			continue
		}
		var meta struct {
			Name string `yaml:"name"`
		}
		if yaml.Unmarshal(data, &meta) == nil && meta.Name != "" {
			dirs[meta.Name] = filepath.Join(chartsDir, entry.Name())
		}
	}
	return dirs
}

func dependencyDir(dep *chart.Dependency, dir string, idx *chartIndex, anyVersion bool) (string, bool) {
	if rel, ok := strings.CutPrefix(dep.Repository, "file://"); ok {
		// A rooted path is not relative to the chart even where it is not
		// absolute, as /home/user on Windows.
		if filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") {
			return rel, true
		}
		return filepath.Join(dir, rel), true
	}
	return idx.lookup(dep, dir, anyVersion)
}

func hasDependency(ch *chart.Chart, name string) bool {
	for _, d := range ch.Dependencies() {
		if d.Name() == name {
			return true
		}
	}
	return false
}

// satisfied reports whether a dependency of ch already provides the
// declaration dep, the way Helm picks the chart an alias renders.
func satisfied(ch *chart.Chart, dep *chart.Dependency) bool {
	for _, d := range ch.Dependencies() {
		if d.Name() == dep.Name && d.Metadata != nil && versionMatches(dep.Version, d.Metadata.Version) {
			return true
		}
	}
	return false
}
