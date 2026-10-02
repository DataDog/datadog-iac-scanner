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
	fsys   vfs.FS
	roots  []string
	once   sync.Once
	byName map[string][]indexedChart
}

func newChartIndex(fsys vfs.FS, roots []string) *chartIndex {
	return &chartIndex{fsys: fsys, roots: roots}
}

func (idx *chartIndex) load() {
	idx.byName = make(map[string][]indexedChart, len(idx.roots))
	for _, root := range idx.roots {
		dir := filepath.FromSlash(root)
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
// Helm then matches them by name and version and applies aliases at install.
//
// The returned locator remembers where each attached file really lives: Helm
// names it after the position it is attached at (parent/charts/dep/...), a
// path that does not exist in the repository.
func attachMissingDependencies(
	ctx context.Context, fsys vfs.FS, idx *chartIndex, ch *chart.Chart, dir string, depth int,
) fileLocator {
	locator := fileLocator{}
	locator.recordVendored(fsys, ch, dir)
	attachFrom(ctx, fsys, idx, ch, dir, depth, map[string]bool{filepath.Clean(dir): true}, locator)
	return locator
}

// fileLocator maps the files of dependencies attached from another directory
// of the scan to their real paths. Keys are the chart files themselves, which
// stay the same objects while Helm renames, instruments and aliases charts.
type fileLocator map[*chart.File]string

// record registers every file of ch, and of the dependencies vendored in its
// charts/ directory, under the directory ch was loaded from.
func (l fileLocator) record(fsys vfs.FS, ch *chart.Chart, dir string) {
	for _, f := range ch.Templates {
		l[f] = filepath.Join(dir, filepath.FromSlash(f.Name))
	}
	for _, f := range ch.Files {
		l[f] = filepath.Join(dir, filepath.FromSlash(f.Name))
	}
	l.recordVendored(fsys, ch, dir)
}

// recordVendored registers the dependencies of ch that sit unpacked in the
// charts/ directory of dir. Their directory is named freely, so it is found by
// the chart name it declares when it is not the name itself.
func (l fileLocator) recordVendored(fsys vfs.FS, ch *chart.Chart, dir string) {
	for _, dep := range ch.Dependencies() {
		if _, loaded := l[firstFile(dep)]; loaded {
			continue
		}
		if vendored, ok := vendoredChartDir(fsys, dir, dep.Name()); ok {
			l.record(fsys, dep, vendored)
		}
	}
}

func vendoredChartDir(fsys vfs.FS, dir, name string) (string, bool) {
	chartsDir := filepath.Join(dir, dependenciesDirName)
	if _, err := fsys.Stat(filepath.Join(chartsDir, name, "Chart.yaml")); err == nil {
		return filepath.Join(chartsDir, name), true
	}
	entries, err := fsys.ReadDir(chartsDir)
	if err != nil {
		return "", false
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
		if yaml.Unmarshal(data, &meta) == nil && meta.Name == name {
			return filepath.Join(chartsDir, entry.Name()), true
		}
	}
	return "", false
}

func firstFile(ch *chart.Chart) *chart.File {
	if len(ch.Templates) > 0 {
		return ch.Templates[0]
	}
	if len(ch.Files) > 0 {
		return ch.Files[0]
	}
	return nil
}

// attachFrom skips a dependency whose directory is already on the path from the
// root, so a cycle ends at once instead of unfolding to the depth cap.
func attachFrom(
	ctx context.Context, fsys vfs.FS, idx *chartIndex, ch *chart.Chart,
	dir string, depth int, ancestors map[string]bool, locator fileLocator,
) {
	if ch.Metadata == nil || depth >= maxDependencyDepth {
		return
	}
	for _, dep := range ch.Metadata.Dependencies {
		if dep == nil || hasDependency(ch, dep.Name) {
			continue
		}
		depDir, ok := dependencyDir(dep, dir, idx)
		if !ok {
			continue
		}
		key := filepath.Clean(depDir)
		if ancestors[key] {
			continue
		}
		sub, err := loadChart(fsys, depDir)
		if err != nil {
			contextLogger := logger.FromContext(ctx)
			contextLogger.Warn().Msgf("helm dependency %q of chart '%s' could not be loaded from %s: %v",
				dep.Name, dir, depDir, err)
			continue
		}
		ancestors[key] = true
		locator.record(fsys, sub, depDir)
		attachFrom(ctx, fsys, idx, sub, depDir, depth+1, ancestors, locator)
		delete(ancestors, key)
		ch.AddDependency(sub)
	}
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
