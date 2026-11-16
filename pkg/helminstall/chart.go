/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package helminstall

import (
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"gopkg.in/yaml.v3"
)

// chartFileName is the file a chart's metadata is in.
const chartFileName = "Chart.yaml"

// chartInfo is what discovery needs of a chart's metadata.
type chartInfo struct {
	name         string
	dependencies []chartDependency
}

// chartDependency is a dependency a chart declares.
type chartDependency struct {
	Name       string   `yaml:"name"`
	Alias      string   `yaml:"alias"`
	Repository string   `yaml:"repository"`
	Condition  string   `yaml:"condition"`
	Tags       []string `yaml:"tags"`
}

// renderedAs is the name the dependency's values and templates have.
func (d *chartDependency) renderedAs() string {
	if d.Alias != "" {
		return d.Alias
	}
	return d.Name
}

func readChartInfo(fsys vfs.FS, dir string) (*chartInfo, bool) {
	data, err := fsys.ReadFile(filepath.Join(dir, chartFileName))
	if err != nil {
		return nil, false
	}
	var meta struct {
		Name         string            `yaml:"name"`
		Dependencies []chartDependency `yaml:"dependencies"`
	}
	if yaml.Unmarshal(data, &meta) != nil {
		return nil, false
	}
	info := &chartInfo{name: meta.Name, dependencies: meta.Dependencies}
	if info.name == "" {
		info.name = filepath.Base(dir)
	}
	reqPath := filepath.Join(dir, "requirements.yaml")
	if fileExists(fsys, reqPath) {
		if req, err := fsys.ReadFile(reqPath); err == nil {
			var legacy struct {
				Dependencies []chartDependency `yaml:"dependencies"`
			}
			if yaml.Unmarshal(req, &legacy) == nil {
				info.dependencies = append(info.dependencies, legacy.Dependencies...)
			}
		}
	}
	return info, true
}

// chartValues reads the values.yaml of the chart at dir.
func chartValues(fsys vfs.FS, dir string) map[string]interface{} {
	path := filepath.Join(dir, "values.yaml")
	if !fileExists(fsys, path) {
		return map[string]interface{}{}
	}
	values, err := ReadValuesFile(fsys, path)
	if err != nil {
		return map[string]interface{}{}
	}
	return values
}

// dependentsOf maps each chart of the scan to the charts depending on it: a
// dependency vendored under charts/, one a file:// repository names, or one
// Helm would not find, which the scan attaches from its other charts by name.
func (x *Index) dependentsOf() map[string][]dependent {
	x.parentsOnce.Do(func() {
		x.parents = map[string][]dependent{}
		byName := map[string][]string{}
		for dir, info := range x.charts {
			byName[info.name] = append(byName[info.name], dir)
		}
		for dir, info := range x.charts {
			declared := map[string]bool{}
			for i := range info.dependencies {
				dep := &info.dependencies[i]
				declared[dep.Name] = true
				if child, ok := x.dependencyDir(dir, dep, byName); ok {
					x.parents[child] = append(x.parents[child], dependent{dir: dir, dep: dep})
				}
			}
			// Helm also loads every chart under charts/ that no entry declares.
			for _, e := range readDir(x.fsys, filepath.Join(dir, "charts")) {
				child := filepath.Join(dir, "charts", e.Name())
				sub, ok := x.charts[child]
				if !e.IsDir() || !ok || declared[sub.name] {
					continue
				}
				x.parents[child] = append(x.parents[child], dependent{dir: dir, dep: &chartDependency{Name: sub.name}})
			}
		}
	})
	return x.parents
}

// dependencyDir returns the chart of the scan the dependency dep of the chart
// at dir resolves to.
func (x *Index) dependencyDir(dir string, dep *chartDependency, byName map[string][]string) (string, bool) {
	for _, e := range readDir(x.fsys, filepath.Join(dir, "charts")) {
		child := filepath.Join(dir, "charts", e.Name())
		if sub, ok := x.charts[child]; ok && e.IsDir() && sub.name == dep.Name {
			return child, true
		}
	}
	if rel, ok := strings.CutPrefix(dep.Repository, "file://"); ok {
		child := filepath.Clean(filepath.Join(dir, filepath.FromSlash(rel)))
		_, known := x.charts[child]
		return child, known
	}
	return nearestChart(byName[dep.Name], dir)
}

// nearestChart picks among candidates the chart sharing the deepest directory
// with dir, none on a tie.
func nearestChart(candidates []string, dir string) (string, bool) {
	match, best, tied := "", -1, false
	for _, c := range candidates {
		if c == dir {
			continue
		}
		switch shared := sharedDepth(c, dir); {
		case shared > best:
			match, best, tied = c, shared, false
		case shared == best:
			tied = true
		}
	}
	return match, match != "" && !tied
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

// fromParents returns the installations of the chart at dir through the
// umbrella charts depending on it: the release of the parent, and the values
// the parent gives it, its section of the parent's values and the global ones.
func (x *Index) fromParents(dir string, visiting map[string]bool) []Installation {
	var out []Installation
	// The dependency's own defaults, under the parent's values, which Helm
	// evaluates its condition on.
	ownDefaults := chartValues(x.fsys, dir)
	for _, p := range x.dependentsOf()[dir] {
		chartDefaults := chartValues(x.fsys, p.dir)
		for _, parent := range x.forChart(p.dir, visiting) {
			values, fills := parent.Resolve(x.fsys, func(error) {})
			defaults := chartDefaults
			if parent.ReplaceChartValues {
				defaults = map[string]interface{}{}
			}
			merged := MergeValues(defaults, values)
			for _, fill := range fills {
				merged = MergeValues(merged, Missing(merged, fill))
			}
			coalesced := MergeValues(map[string]interface{}{p.dep.renderedAs(): ownDefaults}, merged)
			if !dependencyEnabled(p.dep, coalesced) {
				continue
			}
			inst := Installation{
				Release:   parent.Release,
				Namespace: parent.Namespace,
				Layers:    []Layer{{Values: scopedValues(merged, p.dep.renderedAs())}},
				Source:    "dependency of the chart " + p.dir + ", " + parent.Source,
				Origin:    OriginParent,
			}
			out = append(out, inst)
		}
	}
	return out
}

// scopedValues returns what a dependency rendered as name sees of its parent's
// values: their section name, and the global values.
func scopedValues(parent map[string]interface{}, name string) map[string]interface{} {
	out := map[string]interface{}{}
	if section, ok := parent[name].(map[string]interface{}); ok {
		out = MergeValues(out, section)
	}
	if global, ok := parent["global"].(map[string]interface{}); ok {
		out["global"] = MergeValues(asMap(out["global"]), global)
	}
	return out
}

func asMap(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{}
}

// dependencyEnabled evaluates a dependency's condition, then its tags, on the
// values of its parent, as Helm does.
func dependencyEnabled(dep *chartDependency, values map[string]interface{}) bool {
	for _, cond := range strings.Split(dep.Condition, ",") {
		cond = strings.TrimSpace(cond)
		if cond == "" {
			continue
		}
		if b, ok := lookupPath(values, strings.Split(cond, ".")).(bool); ok {
			return b
		}
	}
	tags := asMap(values["tags"])
	set, enabled := false, false
	for _, t := range dep.Tags {
		if b, ok := tags[t].(bool); ok {
			set = true
			enabled = enabled || b
		}
	}
	return !set || enabled
}

func lookupPath(values map[string]interface{}, path []string) interface{} {
	var cur interface{} = values
	for _, p := range path {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}
