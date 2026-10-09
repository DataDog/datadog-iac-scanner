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

const maxDependencyDepth = 10

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
// version does not match, so incompatible ones are the fallback. Among several
// candidates the one sharing the deepest directory with the dependent chart
// wins; a tie is ambiguous and yields none.
func (idx *chartIndex) lookup(dep *chart.Dependency, self string) (string, bool) {
	if idx == nil {
		return "", false
	}
	idx.once.Do(idx.load)
	var compatible, others []indexedChart
	for _, c := range idx.byName[dep.Name] {
		if filepath.Clean(c.dir) == filepath.Clean(self) {
			continue
		}
		if dep.Version == "" || chartutil.IsCompatibleRange(dep.Version, c.version) {
			compatible = append(compatible, c)
		} else {
			others = append(others, c)
		}
	}
	if len(compatible) > 0 {
		return nearest(compatible, self)
	}
	return nearest(others, self)
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
// On disk a "file://" path is read only when it is a chart of the scan, as it
// may name any directory of the host.
// Helm then matches them by name and version and applies aliases at install.
//
// The returned locator remembers where each attached file really lives: Helm
// names it after the position it is attached at (parent/charts/dep/...), a
// path that does not exist in the repository.
func attachMissingDependencies(
	ctx context.Context, fsys vfs.FS, idx *chartIndex, ch *chart.Chart, dir string, depth int,
) fileLocator {
	locator := fileLocator{}
	attachFrom(ctx, fsys, idx, ch, dir, depth, map[string]bool{filepath.Clean(dir): true}, locator)
	return locator
}

// fileLocator maps the files of dependencies attached from another directory
// of the scan to their real paths. Keys are the chart files themselves, which
// stay the same objects while Helm renames, instruments and aliases charts.
type fileLocator map[*chart.File]string

// readsOnlyPushedFiles reports an in-memory FS, which cannot reach the host and
// turns a missing dependency into a request for the client to push it.
func readsOnlyPushedFiles(fsys vfs.FS) bool {
	_, ok := fsys.(vfs.MissingRecorder)
	return ok
}

// record registers the files of ch under the directory it was loaded from.
func (l fileLocator) record(ch *chart.Chart, dir string) {
	for _, f := range ch.Templates {
		l[f] = filepath.Join(dir, filepath.FromSlash(f.Name))
	}
	for _, f := range ch.Files {
		l[f] = filepath.Join(dir, filepath.FromSlash(f.Name))
	}
}

// attachFrom records and completes the dependencies of ch, both those unpacked
// under its charts/ directory and those attached from elsewhere in the scan. A
// dependency whose directory is already on the path from the root is skipped,
// so a cycle ends at once instead of unfolding to the depth cap.
func attachFrom(
	ctx context.Context, fsys vfs.FS, idx *chartIndex, ch *chart.Chart,
	dir string, depth int, ancestors map[string]bool, locator fileLocator,
) {
	if ch.Metadata == nil || depth >= maxDependencyDepth {
		return
	}
	for _, vendored := range vendoredDependencies(fsys, ch, dir) {
		locator.record(vendored.chart, vendored.dir)
		descend(ctx, fsys, idx, vendored.chart, vendored.dir, depth, ancestors, locator)
	}
	for _, dep := range ch.Metadata.Dependencies {
		if dep == nil || hasDependency(ch, dep.Name) {
			continue
		}
		depDir, ok := dependencyDir(dep, dir, idx)
		if !ok || ancestors[filepath.Clean(depDir)] {
			continue
		}
		if !idx.contains(depDir) && !readsOnlyPushedFiles(fsys) {
			contextLogger := logger.FromContext(ctx)
			contextLogger.Warn().Msgf("helm dependency %q of chart '%s' is not loaded from %s, which is not a chart of the scan",
				dep.Name, dir, depDir)
			continue
		}
		sub, err := loadChart(ctx, fsys, depDir)
		if err != nil {
			contextLogger := logger.FromContext(ctx)
			contextLogger.Warn().Msgf("helm dependency %q of chart '%s' could not be loaded from %s: %v",
				dep.Name, dir, depDir, err)
			continue
		}
		locator.record(sub, depDir)
		descend(ctx, fsys, idx, sub, depDir, depth, ancestors, locator)
		ch.AddDependency(sub)
	}
}

func descend(
	ctx context.Context, fsys vfs.FS, idx *chartIndex, ch *chart.Chart,
	dir string, depth int, ancestors map[string]bool, locator fileLocator,
) {
	key := filepath.Clean(dir)
	ancestors[key] = true
	attachFrom(ctx, fsys, idx, ch, dir, depth+1, ancestors, locator)
	delete(ancestors, key)
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

func dependencyDir(dep *chart.Dependency, dir string, idx *chartIndex) (string, bool) {
	if rel, ok := strings.CutPrefix(dep.Repository, "file://"); ok {
		if filepath.IsAbs(rel) {
			return rel, true
		}
		return filepath.Join(dir, rel), true
	}
	return idx.lookup(dep, dir)
}

func hasDependency(ch *chart.Chart, name string) bool {
	for _, d := range ch.Dependencies() {
		if d.Name() == name {
			return true
		}
	}
	return false
}
