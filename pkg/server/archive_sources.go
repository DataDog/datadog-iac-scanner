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

	chartNames := make(map[string]string)
	chartName := func(archive string) string {
		if name, ok := chartNames[archive]; ok {
			return name
		}
		name := ""
		if data, err := memfs.ReadFile(archive); err == nil {
			if n, loadErr := helm.ArchiveChartName(data); loadErr == nil {
				name = n
			} else {
				contextLogger := logger.FromContext(ctx)
				contextLogger.Debug().Msgf("could not read chart name from pushed archive %s: %v", archive, loadErr)
			}
		}
		chartNames[archive] = name
		return name
	}

	out := make(map[string]string)
	for i := range findings {
		p := filepath.ToSlash(findings[i].FileName)
		if _, ok := pushed[p]; ok {
			continue
		}
		if _, ok := out[p]; ok {
			continue
		}
		if archive := sourceArchive(p, dirs, archivesByDir, chartName); archive != "" {
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

// sourceArchive finds the outermost charts/<name> segment of p that was not
// pushed as a directory, and returns the pushed archive in that charts/ whose
// chart is named <name>.
func sourceArchive(p string, dirs map[string]struct{}, archivesByDir map[string][]string,
	chartName func(string) string) string {
	segs := strings.Split(p, "/")
	for i := 0; i+2 < len(segs); i++ {
		if segs[i] != chartsDirName {
			continue
		}
		if _, unpacked := dirs[strings.Join(segs[:i+2], "/")]; unpacked {
			continue
		}
		chartsDir := strings.Join(segs[:i+1], "/")
		for _, archive := range archivesByDir[chartsDir] {
			if chartName(archive) == segs[i+1] {
				return archive
			}
		}
		return ""
	}
	return ""
}
