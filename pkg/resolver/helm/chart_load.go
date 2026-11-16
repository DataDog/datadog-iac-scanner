package helm

import (
	"bytes"
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/pkg/errors"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/ignore"
)

// loadedCharts keeps the files a chart's first load read while the chart is
// being rendered. A chart is installed once per installation, and each later
// load builds the chart from these files instead of reading the disk again.
// The files are dropped once the chart's installations are rendered (forget),
// so the scan never holds more than the charts being rendered.
type loadedCharts struct {
	mu    sync.Mutex
	byDir map[string][]*loader.BufferedFile
}

func (c *loadedCharts) get(dir string) ([]*loader.BufferedFile, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	files, ok := c.byDir[dir]
	return files, ok
}

// forget drops the files kept for dir.
func (c *loadedCharts) forget(dir string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byDir, dir)
}

// put keeps the files ch was loaded from. A chart's Raw is every file its
// load read, and rendering only ever replaces the bytes of a chart's files,
// never writes into them, so the kept bytes stay those the disk held.
func (c *loadedCharts) put(dir string, ch *chart.Chart) {
	if c == nil {
		return
	}
	files := make([]*loader.BufferedFile, 0, len(ch.Raw))
	for _, f := range ch.Raw {
		files = append(files, &loader.BufferedFile{Name: f.Name, Data: f.Data})
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byDir == nil {
		c.byDir = map[string][]*loader.BufferedFile{}
	}
	if _, ok := c.byDir[dir]; !ok {
		c.byDir[dir] = files
	}
}

// loadChart loads the chart at dir from the scan FS, from the files cache of
// the scan when it holds them (nil for none). The real disk keeps helm's own directory loader (symlink and .helmignore
// semantics unchanged from the CLI); any other FS (the server's in-memory one)
// is walked via the vfs and assembled with helm's in-memory loader.
func loadChart(ctx context.Context, fsys vfs.FS, dir string, cache *loadedCharts) (*chart.Chart, error) {
	var ch *chart.Chart
	var err error
	if files, ok := cache.get(dir); ok {
		ch, err = loader.LoadFiles(files)
	} else if vfs.IsDisk(fsys) {
		ch, err = loader.LoadDir(dir)
	} else {
		ch, err = loadChartFromFS(fsys, dir)
	}
	if err != nil {
		return ch, err
	}
	cache.put(dir, ch)
	if dropped := dropNonTemplateFiles(ch); len(dropped) > 0 {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Debug().Msgf("Not rendering non-template files of chart '%s': %s", dir, strings.Join(dropped, ", "))
	}
	return ch, nil
}

// Helm renders every file under templates/, so a build or documentation file
// kept there without a .helmignore breaks the whole chart although no
// deployment ships it. Only those are dropped: a template may use any
// extension, and a partial (a name starting with "_") never renders on its own.
var (
	nonTemplateFileNames = map[string]struct{}{
		"build": {}, "build.bazel": {}, "workspace": {}, "workspace.bazel": {}, "module.bazel": {},
		"owners": {}, "owners_aliases": {}, "codeowners": {}, "makefile": {},
		"license": {}, "readme": {},
	}
	nonTemplateFileExts = map[string]struct{}{
		".bzl": {}, ".bazel": {}, ".md": {},
	}
)

func isNonTemplateFile(name string) bool {
	base := strings.ToLower(filepath.Base(name))
	if strings.HasPrefix(base, "_") {
		return false
	}
	if _, ok := nonTemplateFileNames[base]; ok {
		return true
	}
	_, ok := nonTemplateFileExts[filepath.Ext(base)]
	return ok
}

// dropNonTemplateFiles removes the non-template files of ch and of its
// dependencies, and returns their chart paths.
func dropNonTemplateFiles(ch *chart.Chart) []string {
	var dropped []string
	kept := ch.Templates[:0]
	for _, f := range ch.Templates {
		if isNonTemplateFile(f.Name) {
			dropped = append(dropped, f.Name)
			continue
		}
		kept = append(kept, f)
	}
	ch.Templates = kept
	for _, dep := range ch.Dependencies() {
		for _, name := range dropNonTemplateFiles(dep) {
			dropped = append(dropped, dependenciesDirName+"/"+dep.Name()+"/"+name)
		}
	}
	return dropped
}

// ArchiveChartIdentity returns the name and version a packaged chart declares.
// The name is the directory it renders under when the parent does not alias it
// (nginx-1.2.3.tgz renders under charts/nginx/). An alias in the parent's
// dependencies replaces that directory.
func ArchiveChartIdentity(data []byte) (name, version string, err error) {
	ch, err := loader.LoadArchive(bytes.NewReader(data))
	if err != nil {
		return "", "", err
	}
	version = ""
	if ch.Metadata != nil {
		version = ch.Metadata.Version
	}
	return ch.Name(), version, nil
}

// utf8bom mirrors loader's BOM handling for files read through the vfs.
var utf8bom = []byte{0xEF, 0xBB, 0xBF}

// loadChartFromFS mirrors loader.LoadDir over the scan FS: .helmignore rules,
// regular files only, each capped at helm's MaxDecompressedFileSize, then
// loader.LoadFiles (the same in-memory entry point LoadDir feeds).
func loadChartFromFS(fsys vfs.FS, dir string) (*chart.Chart, error) {
	rules := ignore.Empty()
	// Stat first so a missing .helmignore is not recorded as a missing file by
	// an in-memory FS (it would become a pointless escalation request).
	if _, err := fsys.Stat(filepath.Join(dir, ignore.HelmIgnore)); err == nil {
		data, err := fsys.ReadFile(filepath.Join(dir, ignore.HelmIgnore))
		if err != nil {
			return nil, errors.Wrapf(err, "error reading %s", ignore.HelmIgnore)
		}
		parsed, err := ignore.Parse(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		rules = parsed
	}
	rules.AddDefaults()

	files := make([]*loader.BufferedFile, 0)
	if err := walkChartFiles(fsys, rules, dir, "", &files); err != nil {
		return nil, err
	}
	return loader.LoadFiles(files)
}

// walkChartFiles recursively collects dir's files into out, keyed by their
// chart-root-relative slash path. A ReadDir miss is not an error: an absent
// optional subdirectory must not fail the whole render.
func walkChartFiles(fsys vfs.FS, rules *ignore.Rules, dir, rel string, out *[]*loader.BufferedFile) error {
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return errors.Wrapf(err, "error reading %s", rel)
	}
	for _, entry := range entries {
		entryRel := entry.Name()
		if rel != "" {
			entryRel = rel + "/" + entry.Name()
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return errors.Wrapf(infoErr, "error stating %s", entryRel)
		}
		if info.IsDir() {
			// Directory-based ignore rules skip the entire subtree.
			if rules.Ignore(entryRel, info) {
				continue
			}
			if err := walkChartFiles(fsys, rules, filepath.Join(dir, entry.Name()), entryRel, out); err != nil {
				return err
			}
			continue
		}
		if rules.Ignore(entryRel, info) {
			continue
		}
		if !info.Mode().IsRegular() {
			return errors.Errorf("cannot load irregular file %s as it has file mode type bits set", entryRel)
		}
		if info.Size() > loader.MaxDecompressedFileSize {
			return errors.Errorf("chart file %q is larger than the maximum file size %d", entry.Name(), loader.MaxDecompressedFileSize)
		}
		data, err := fsys.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return errors.Wrapf(err, "error reading %s", entryRel)
		}
		*out = append(*out, &loader.BufferedFile{
			Name: entryRel,
			Data: bytes.TrimPrefix(data, utf8bom),
		})
	}
	return nil
}
