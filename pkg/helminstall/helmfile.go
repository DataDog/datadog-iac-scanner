/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package helminstall

import (
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"gopkg.in/yaml.v3"
)

// A helmfile declares releases: a name, a namespace, a chart and the values
// to install it with. It is a Go template rendered for one environment at a
// time, and its parts, separated by "---", are rendered in order: the
// environment values a part loads are those the next ones read.

// helmfilePartSeparator splits a helmfile into its parts.
var helmfilePartSeparator = regexp.MustCompile(`(?m)^---[ \t]*(#.*)?$`)

// maxHelmfileEnvironments bounds the environments a helmfile is rendered for.
const maxHelmfileEnvironments = 16

func (d *discovery) helmfile(path string) {
	data := d.read(path)
	if data == nil {
		return
	}
	for _, env := range d.helmfileEnvironments(path, data) {
		d.helmfileFor(path, data, env)
	}
}

// helmfileEnvironments returns the environments a helmfile declares, the
// default one when it declares none.
func (d *discovery) helmfileEnvironments(path string, data []byte) []string {
	seen := map[string]bool{}
	var envs []string
	add := func(m map[string]interface{}) {
		for _, name := range sortedKeys(mapOf(m, "environments")) {
			if !seen[name] && len(envs) < maxHelmfileEnvironments {
				seen[name] = true
				envs = append(envs, name)
			}
		}
	}
	for _, part := range helmfilePartSeparator.Split(string(data), -1) {
		// The environment names are read from the template as written:
		// rendering needs to know which environment it renders for.
		if doc := parseHelmfilePart(stripTemplateActions(part)); doc != nil {
			add(doc)
			for _, base := range strList(doc, "bases") {
				if b := d.read(filepath.Join(filepath.Dir(path), filepath.FromSlash(base))); b != nil {
					for _, bp := range helmfilePartSeparator.Split(string(b), -1) {
						if bd := parseHelmfilePart(stripTemplateActions(bp)); bd != nil {
							add(bd)
						}
					}
				}
			}
		}
	}
	if len(envs) == 0 {
		envs = []string{"default"}
	}
	return envs
}

// helmfileState is what rendering a helmfile for an environment accumulates.
type helmfileState struct {
	env       string
	values    map[string]interface{}
	templates map[string]interface{}
}

func (d *discovery) helmfileFor(path string, data []byte, env string) {
	dir := filepath.Dir(path)
	st := &helmfileState{env: env, values: map[string]interface{}{}, templates: map[string]interface{}{}}
	for _, part := range helmfilePartSeparator.Split(string(data), -1) {
		doc := parseHelmfilePart(d.renderHelmfile(dir, part, st, nil))
		if doc == nil {
			continue
		}
		for _, base := range strList(doc, "bases") {
			basePath := filepath.Join(dir, filepath.FromSlash(base))
			if b := d.read(basePath); b != nil {
				for _, bp := range helmfilePartSeparator.Split(string(b), -1) {
					if bd := parseHelmfilePart(d.renderHelmfile(filepath.Dir(basePath), bp, st, nil)); bd != nil {
						d.loadHelmfileEnvironment(filepath.Dir(basePath), bd, st)
					}
				}
			}
		}
		d.loadHelmfileEnvironment(dir, doc, st)
		for k, v := range mapOf(doc, "templates") {
			st.templates[k] = v
		}
		for _, r := range listOf(doc, "releases") {
			if rel, ok := r.(map[string]interface{}); ok {
				d.helmfileRelease(path, dir, rel, st)
			}
		}
	}
}

// loadHelmfileEnvironment merges the values of the environment being rendered
// that doc declares.
func (d *discovery) loadHelmfileEnvironment(dir string, doc map[string]interface{}, st *helmfileState) {
	envs := mapOf(doc, "environments")
	env := mapOf(envs, st.env)
	if env == nil {
		return
	}
	for _, v := range listOf(env, "values") {
		switch x := v.(type) {
		case string:
			if values := d.helmfileValuesFile(filepath.Join(dir, filepath.FromSlash(x)), st, nil); values != nil {
				st.values = MergeValues(st.values, values)
			}
		case map[string]interface{}:
			if values, ok := helmValues(x); ok {
				st.values = MergeValues(st.values, values)
			}
		}
	}
}

// helmfileValuesFile reads a values file a helmfile names, rendered first when
// it is a template.
func (d *discovery) helmfileValuesFile(path string, st *helmfileState, release map[string]interface{}) map[string]interface{} {
	if !fileExists(d.fsys(), path) {
		d.debugf("Values file %s of a helmfile does not exist", path)
		return nil
	}
	data := d.read(path)
	if data == nil {
		return nil
	}
	if strings.HasSuffix(path, ".gotmpl") {
		data = []byte(d.renderHelmfile(filepath.Dir(path), string(data), st, release))
	}
	values, err := ParseValues(data)
	if err != nil {
		d.debugf("Values file %s of a helmfile is not valid YAML: %v", path, err)
		return nil
	}
	return values
}

func (d *discovery) helmfileRelease(path, dir string, rel map[string]interface{}, st *helmfileState) {
	rel = withInheritedTemplates(rel, st)
	if !helmfileReleaseInstalled(rel, st) || str(rel, "chart") == "" {
		return
	}
	chartDir, ok := d.idx.chartDir(localPath(dir, str(rel, "chart")))
	if !ok {
		return
	}
	inst := Installation{
		Release:   str(rel, "name"),
		Namespace: str(rel, "namespace"),
		Source:    "helmfile " + path + " (environment " + st.env + ")",
		Origin:    OriginDescriptor,
		Layers:    d.helmfileValues(dir, rel, st),
	}
	if set := helmfileSets(rel); len(set.Set) > 0 {
		inst.Layers = append(inst.Layers, set)
	}
	d.idx.add(chartDir, &inst)
}

// withInheritedTemplates returns a release with the templates it inherits
// under its own fields.
func withInheritedTemplates(rel map[string]interface{}, st *helmfileState) map[string]interface{} {
	for _, inherit := range listOf(rel, "inherit") {
		if name := str(asMap(inherit), "template"); name != "" {
			if tmpl := asMap(st.templates[name]); len(tmpl) > 0 {
				rel = MergeValues(tmpl, rel)
			}
		}
	}
	return rel
}

// helmfileReleaseInstalled reports whether a release is installed in the
// environment st renders: installed, and with its condition true.
func helmfileReleaseInstalled(rel map[string]interface{}, st *helmfileState) bool {
	if !boolOr(rel, "installed", true) {
		return false
	}
	if cond := str(rel, "condition"); cond != "" {
		if b, ok := lookupPath(st.values, strings.Split(cond, ".")).(bool); ok && !b {
			return false
		}
	}
	return true
}

// helmfileValues returns the values of a release: files, rendered first when
// templates, and inline maps.
func (d *discovery) helmfileValues(dir string, rel map[string]interface{}, st *helmfileState) []Layer {
	var layers []Layer
	for _, v := range listOf(rel, "values") {
		switch x := v.(type) {
		case string:
			file := localPath(dir, x)
			if strings.HasSuffix(x, ".gotmpl") {
				if values := d.helmfileValuesFile(file, st, rel); values != nil {
					layers = append(layers, Layer{Values: values})
				}
			} else if fileExists(d.fsys(), file) {
				layers = append(layers, Layer{File: file})
			}
		case map[string]interface{}:
			if values, ok := helmValues(x); ok {
				layers = append(layers, Layer{Values: values})
			}
		}
	}
	return layers
}

// helmfileSets returns the set entries of a release.
func helmfileSets(rel map[string]interface{}) Layer {
	var set Layer
	for _, s := range listOf(rel, "set") {
		entry := asMap(s)
		name := str(entry, "name")
		if name == "" {
			continue
		}
		if values := listOf(entry, "values"); values != nil {
			var items []string
			for _, item := range values {
				if t, ok := scalarText(item); ok {
					items = append(items, t)
				}
			}
			set.Set = append(set.Set, setListExpr(name, items, helmfileEscaper.Replace))
			continue
		}
		if t, ok := scalarText(entry["value"]); ok {
			set.Set = append(set.Set, helmfileSetExpr(name, t))
		}
	}
	return set
}

func parseHelmfilePart(text string) map[string]interface{} {
	var doc interface{}
	if yaml.Unmarshal([]byte(text), &doc) != nil {
		return nil
	}
	m, _ := normalizeYAML(doc).(map[string]interface{})
	return m
}

// renderHelmfile renders a helmfile part, or a values template, for the
// environment st is rendering.
func (d *discovery) renderHelmfile(dir, text string, st *helmfileState, release map[string]interface{}) string {
	if !strings.Contains(text, "{{") {
		return text
	}
	funcs := d.helmfileFuncs(dir)
	tmpl, err := template.New("helmfile").Option("missingkey=zero").Funcs(funcs).Parse(text)
	if err != nil {
		d.debugf("Could not parse a helmfile template in %s: %v", dir, err)
		return text
	}
	data := map[string]interface{}{
		"Environment": map[string]interface{}{"Name": st.env, "Values": st.values, "KubeContext": ""},
		"Values":      st.values,
		"StateValues": st.values,
		"Namespace":   "",
	}
	if release != nil {
		data["Release"] = map[string]interface{}{
			"Name": str(release, "name"), "Namespace": str(release, "namespace"), "Chart": str(release, "chart"),
			"Labels": mapOf(release, "labels"),
		}
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, data); err != nil {
		d.debugf("Could not render a helmfile template in %s: %v", dir, err)
		return text
	}
	return strings.ReplaceAll(b.String(), "<no value>", "")
}

// helmfileFuncs are the functions a helmfile template calls, reading files of
// dir. Nothing reads the environment of the scan, runs a command or reaches
// the network: those stand for placeholders.
func (d *discovery) helmfileFuncs(dir string) template.FuncMap {
	funcs := sprig.TxtFuncMap()
	for _, name := range []string{"env", "expandenv", "getHostByName"} {
		delete(funcs, name)
	}
	funcs["env"] = func(string) string { return "" }
	funcs["requiredEnv"] = func(name string) string { return "<env " + name + ">" }
	funcs["exec"] = func(...interface{}) string { return "" }
	funcs["fetchSecretValue"] = func(ref string) string { return "<" + ref + ">" }
	funcs["expandSecretRefs"] = func(v interface{}) interface{} { return v }
	inRepo := func(name string) (string, bool) {
		p := localPath(dir, name)
		return p, d.idx.confined(p)
	}
	funcs["readFile"] = func(name string) string {
		p, ok := inRepo(name)
		if !ok || !fileExists(d.fsys(), p) {
			return ""
		}
		return string(d.read(p))
	}
	funcs["isFile"] = func(name string) bool {
		p, ok := inRepo(name)
		return ok && fileExists(d.fsys(), p)
	}
	funcs["isDir"] = func(name string) bool {
		p, ok := inRepo(name)
		return ok && dirExists(d.fsys(), p)
	}
	funcs["toYaml"] = func(v interface{}) string {
		b, err := yaml.Marshal(v)
		if err != nil {
			return ""
		}
		return strings.TrimSuffix(string(b), "\n")
	}
	funcs["fromYaml"] = func(s string) map[string]interface{} {
		values, err := ParseValues([]byte(s))
		if err != nil {
			return map[string]interface{}{}
		}
		return values
	}
	funcs["get"] = helmfileGet
	funcs["getOrNil"] = func(path string, values interface{}) interface{} {
		return lookupPath(asMap(values), strings.Split(path, "."))
	}
	funcs["required"] = func(msg string, v interface{}) interface{} {
		if v == nil || v == "" {
			return "<" + msg + ">"
		}
		return v
	}
	funcs["setValueAtPath"] = setValueAtPath
	return funcs
}

// helmfileGet is helmfile's get: the value at a dotted path, or a default.
func helmfileGet(path string, args ...interface{}) interface{} {
	var def interface{}
	var values map[string]interface{}
	switch len(args) {
	case 1:
		values = asMap(args[0])
	case 2:
		def, values = args[0], asMap(args[1])
	}
	if v := lookupPath(values, strings.Split(path, ".")); v != nil {
		return v
	}
	return def
}

// setValueAtPath is helmfile's setValueAtPath: values with value at a dotted
// path.
func setValueAtPath(path string, value interface{}, values map[string]interface{}) map[string]interface{} {
	keys := strings.Split(path, ".")
	cur := values
	for _, k := range keys[:len(keys)-1] {
		next, ok := cur[k].(map[string]interface{})
		if !ok {
			next = map[string]interface{}{}
			cur[k] = next
		}
		cur = next
	}
	cur[keys[len(keys)-1]] = value
	return values
}

// templateAction matches a template action, to read a template as YAML.
var templateAction = regexp.MustCompile(`\{\{.*?\}\}`)

func stripTemplateActions(text string) string {
	return templateAction.ReplaceAllString(text, "")
}
