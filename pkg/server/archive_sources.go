/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package server

import (
	"context"
	"path"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/helm"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/chartutil"
)

// chartsDirName is the chart subdirectory Helm loads subcharts from.
const chartsDirName = "charts"

// archiveSources maps each finding path that was not pushed but was rendered
// from a pushed packaged subchart (<chart>/charts/*.tgz) to that archive.
func archiveSources(ctx context.Context, findings []model.Vulnerability, memfs *vfs.MemFS) map[string]string {
	paths := memfs.Paths()
	archivesByDir := make(map[string][]string)
	for _, p := range paths {
		if strings.HasSuffix(strings.ToLower(p), ".tgz") && path.Base(path.Dir(p)) == chartsDirName {
			archivesByDir[path.Dir(p)] = append(archivesByDir[path.Dir(p)], p)
		}
	}
	if len(archivesByDir) == 0 {
		return nil
	}
	pushed, dirs := pushedIndex(paths)
	byRendered := renderedArchives(ctx, memfs, archivesByDir)

	out := make(map[string]string)
	for i := range findings {
		p := filepath.ToSlash(findings[i].FileName)
		if _, ok := pushed[p]; ok {
			continue
		}
		if _, ok := out[p]; ok {
			continue
		}
		if archive := sourceArchive(p, dirs, byRendered); archive != "" {
			out[p] = archive
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// pushedIndex returns the set of pushed paths and the set of their ancestor directories.
func pushedIndex(paths []string) (pushed, dirs map[string]struct{}) {
	pushed = make(map[string]struct{}, len(paths))
	dirs = make(map[string]struct{})
	for _, p := range paths {
		pushed[p] = struct{}{}
		for dir := path.Dir(p); dir != "." && dir != "/"; dir = path.Dir(dir) {
			if _, seen := dirs[dir]; seen {
				break
			}
			dirs[dir] = struct{}{}
		}
	}
	return pushed, dirs
}

type chartDependency struct {
	Name    string `yaml:"name"`
	Alias   string `yaml:"alias"`
	Version string `yaml:"version"`
}

// renderedArchives maps "<chart>/charts/<rendered name>" to the pushed archive
// Helm loaded for it. The rendered name is the dependency alias when the parent
// sets one, and the archive's own chart name otherwise.
func renderedArchives(ctx context.Context, memfs *vfs.MemFS, archivesByDir map[string][]string) map[string]string {
	out := make(map[string]string)
	depsOf := make(map[string][]chartDependency)
	for chartsDir, archives := range archivesByDir {
		parent := path.Dir(chartsDir)
		deps, ok := depsOf[parent]
		if !ok {
			deps = chartDependencies(memfs, parent)
			depsOf[parent] = deps
		}
		for _, archive := range archives {
			data, err := memfs.ReadFile(archive)
			if err != nil {
				continue
			}
			name, version, loadErr := helm.ArchiveChartIdentity(data)
			if loadErr != nil {
				contextLogger := logger.FromContext(ctx)
				contextLogger.Debug().Msgf("could not read chart name from pushed archive %s: %v", archive, loadErr)
				continue
			}
			out[chartsDir+"/"+renderedChartName(name, version, deps)] = archive
		}
	}
	return out
}

func chartDependencies(memfs *vfs.MemFS, parent string) []chartDependency {
	chartYAML := "Chart.yaml"
	if parent != "." && parent != "" {
		chartYAML = parent + "/Chart.yaml"
	}
	data, err := memfs.ReadFile(chartYAML)
	if err != nil {
		return nil
	}
	var meta struct {
		Dependencies []chartDependency `yaml:"dependencies"`
	}
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return nil
	}
	return meta.Dependencies
}

// renderedChartName is the directory Helm emits under charts/. A dependency
// alias replaces the archive's chart name; with no matching dependency the
// archive's own name is that directory.
func renderedChartName(name, version string, deps []chartDependency) string {
	for _, dep := range deps {
		if dep.Name != name {
			continue
		}
		if dep.Version != "" && version != "" && !chartutil.IsCompatibleRange(dep.Version, version) {
			continue
		}
		if dep.Alias != "" {
			return dep.Alias
		}
		return dep.Name
	}
	return name
}

// sourceArchive finds the outermost charts/<name> segment of p that was not
// pushed as a directory, and returns the archive Helm rendered under that name.
func sourceArchive(p string, dirs map[string]struct{}, byRendered map[string]string) string {
	segs := strings.Split(p, "/")
	for i := 0; i+2 < len(segs); i++ {
		if segs[i] != chartsDirName {
			continue
		}
		if _, unpacked := dirs[strings.Join(segs[:i+2], "/")]; unpacked {
			continue
		}
		chartsDir := strings.Join(segs[:i+1], "/")
		if archive := byRendered[chartsDir+"/"+segs[i+1]]; archive != "" {
			return archive
		}
		return ""
	}
	return ""
}
