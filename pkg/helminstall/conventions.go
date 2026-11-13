/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package helminstall

import (
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// A chart no descriptor names is installed under its own name, the release
// name of "helm install <chart>", with the values files kept beside it:
//
//   - values-<env>.yaml at its root, and every file under values/, is one
//     environment it is deployed to, each an installation. A file named
//     common, base, default or shared under values/ applies to all of them.
//     A file of values/environments/ also takes the less specific ones whose
//     name, with "_" as a wildcard, matches its own, as Datadog CNAB tools do.
//   - ci/*.yaml (chart-testing), and lint, test or example values files,
//     stand in for the values supplied when deployed: they only fill what
//     nothing else sets.

var (
	// overlayName matches a values file at the root of a chart other than
	// values.yaml: values-prod.yaml, values.staging.yml, values_dev.yaml.
	overlayName = regexp.MustCompile(`^values[-_.](.+)\.ya?ml$`)
	// placeholderWords mark a values file as test or lint values.
	placeholderWords = regexp.MustCompile(
		`(?i)(^|[-_./])(lint|linter|linting|ci|example|examples|sample|samples|dummy|fake|mock|placeholder|placeholders)([-_./]|$)`)
	// baseNames are the values files applying to every environment.
	baseNames = map[string]bool{
		"common": true, "base": true, "default": true, "defaults": true, "shared": true, "global": true,
		"all": true, "values": true,
	}
)

// conventionFiles are the values files of a chart, relative to it, by what
// they are for.
type conventionFiles struct {
	// overlays are one environment each, bases apply to all of them, envs are
	// values/environments files, and fills are test and lint values.
	overlays, bases, envs, fills []string
}

// conventions returns the installations of the chart at dir inferred from the
// chart alone.
func (x *Index) conventions(dir string) []Installation {
	name := filepath.Base(dir)
	if info, ok := x.charts[dir]; ok {
		name = info.name
	} else if info, ok := readChartInfo(x.fsys, dir); ok {
		name = info.name
	}
	files := x.conventionFiles(dir)
	fillLayers := x.valuesLayers(dir, files.fills)
	for i := range fillLayers {
		fillLayers[i].Fill = true
	}
	install := func(source string, own ...string) Installation {
		layers := x.valuesLayers(dir, append(append([]string{}, files.bases...), own...))
		return Installation{
			Release: name,
			Layers:  append(layers, fillLayers...),
			Source:  source,
			Origin:  OriginConvention,
		}
	}
	var out []Installation
	for _, o := range files.overlays {
		out = append(out, install(o, o))
	}
	for _, e := range files.envs {
		out = append(out, install(e, environmentFilesFor(e, files.envs)...))
	}
	if len(out) == 0 {
		source := "the chart's values"
		if len(files.bases) > 0 || len(fillLayers) > 0 {
			source = "the chart's values files"
		}
		out = append(out, install(source))
	}
	return out
}

// conventionFiles sorts the values files of the chart at dir.
func (x *Index) conventionFiles(dir string) conventionFiles {
	var files conventionFiles
	for _, e := range readDir(x.fsys, dir) {
		if !e.IsDir() {
			files.addRoot(e.Name())
		}
	}
	for _, rel := range walkFiles(x.fsys, filepath.Join(dir, "values")) {
		if isYAMLFile(rel) {
			files.addValues(rel)
		}
	}
	for _, rel := range walkFiles(x.fsys, filepath.Join(dir, "ci")) {
		if isYAMLFile(rel) && !strings.Contains(rel, "/") {
			files.fills = append(files.fills, "ci/"+rel)
		}
	}
	sort.Strings(files.bases)
	sort.Strings(files.fills)
	sort.Strings(files.overlays)
	return files
}

// addRoot sorts a file at the root of the chart: values-<env>.yaml, or lint
// values as lint-values.yaml.
func (f *conventionFiles) addRoot(name string) {
	m := overlayName.FindStringSubmatch(name)
	switch {
	case len(m) > 1 && placeholderWords.MatchString(m[1]):
		f.fills = append(f.fills, name)
	case len(m) > 1:
		f.overlays = append(f.overlays, name)
	case isYAMLFile(name) && placeholderWords.MatchString(name) && name != chartFileName:
		f.fills = append(f.fills, name)
	}
}

// addValues sorts a file under values/, rel being relative to it.
func (f *conventionFiles) addValues(rel string) {
	file := "values/" + rel
	stem := strings.TrimSuffix(path.Base(rel), path.Ext(rel))
	switch {
	case placeholderWords.MatchString(rel):
		f.fills = append(f.fills, file)
	case baseNames[stem]:
		f.bases = append(f.bases, file)
	case strings.HasPrefix(rel, "environments/"):
		f.envs = append(f.envs, file)
	default:
		f.overlays = append(f.overlays, file)
	}
}

// valuesLayers returns the layers of the values files of the chart at dir.
func (x *Index) valuesLayers(dir string, files []string) []Layer {
	var layers []Layer
	for _, f := range files {
		if file := filepath.Join(dir, filepath.FromSlash(f)); x.confined(file) && x.isValuesFile(file) {
			layers = append(layers, Layer{File: file})
		}
	}
	return layers
}

// isValuesFile reports whether file holds values: a YAML mapping.
func (x *Index) isValuesFile(file string) bool {
	_, err := ReadValuesFile(x.fsys, file)
	return err == nil
}

// environmentFilesFor returns the environment files applying along with file,
// least specific first, file last.
func environmentFilesFor(file string, all []string) []string {
	name := environmentFileName(file)
	var matched []string
	for _, other := range all {
		if other == file {
			continue
		}
		if environmentPattern(environmentFileName(other)).MatchString(name) {
			matched = append(matched, other)
		}
	}
	sortBySpecificity(matched)
	return append(matched, file)
}

func environmentFileName(file string) string {
	return strings.TrimSuffix(path.Base(file), path.Ext(file))
}

// environmentPattern turns an environment file name into the pattern it
// matches installation names with: "_" stands for any characters, dots
// included.
func environmentPattern(name string) *regexp.Regexp {
	parts := strings.Split(name, "_")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return regexp.MustCompile("^" + strings.Join(parts, ".*") + "$")
}

// sortBySpecificity orders environment files from the least specific, the one
// with the most wildcards, to the most specific.
func sortBySpecificity(files []string) {
	sort.SliceStable(files, func(i, j int) bool {
		wi := strings.Count(environmentFileName(files[i]), "_")
		wj := strings.Count(environmentFileName(files[j]), "_")
		if wi != wj {
			return wi > wj
		}
		return files[i] < files[j]
	})
}
