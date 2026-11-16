/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package helminstall

import (
	"encoding/json"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"github.com/Masterminds/sprig/v3"
)

// An Argo CD Application installs the chart at the path of a source of this
// repository, under its helm releaseName or else its own name, with the value
// files, inline values and parameters of the source, in that order. An
// ApplicationSet is a template of Applications its generators fill.

// maxGeneratedApplications bounds the applications one ApplicationSet yields.
const maxGeneratedApplications = 64

func (d *discovery) argoApplication(descriptor string, app map[string]interface{}, origin string) {
	spec := mapOf(app, "spec")
	name := str(mapOf(app, "metadata"), "name")
	namespace := str(mapOf(spec, "destination"), "namespace")
	sources := argoSources(spec)
	// A source with a ref names this repository's root for the value files of
	// the others, as $ref/path.
	refs := map[string]bool{}
	for _, s := range sources {
		if ref := str(s, "ref"); ref != "" && d.sameRepository(str(s, "repoURL")) {
			refs[ref] = true
		}
	}
	source := firstNonEmpty(origin, "Argo CD application "+descriptor)
	for _, s := range sources {
		p, ok := s["path"].(string)
		if !ok || str(s, "chart") != "" || !d.sameRepository(str(s, "repoURL")) {
			continue
		}
		chartDir, ok := d.idx.chartDir(d.repoPath(p))
		if !ok {
			continue
		}
		env := argoBuildEnv(name, namespace, str(spec, "project"), s)
		helm := expandArgoHelm(mapOf(s, "helm"), env)
		inst := Installation{
			Release:   firstNonEmpty(str(helm, "releaseName"), name),
			Namespace: firstNonEmpty(str(helm, "namespace"), namespace),
			Source:    source, Origin: OriginDescriptor,
			Layers: d.argoLayers(chartDir, helm, refs),
		}
		d.idx.add(chartDir, &inst)
	}
}

// argoBuildEnv is the build environment Argo CD gives a source, what only
// Argo CD knows being placeholders.
func argoBuildEnv(app, namespace, project string, source map[string]interface{}) map[string]string {
	return map[string]string{
		"ARGOCD_APP_NAME":                   app,
		"ARGOCD_APP_NAMESPACE":              namespace,
		"ARGOCD_APP_PROJECT_NAME":           project,
		"ARGOCD_APP_SOURCE_PATH":            str(source, "path"),
		"ARGOCD_APP_SOURCE_REPO_URL":        str(source, "repoURL"),
		"ARGOCD_APP_SOURCE_TARGET_REVISION": str(source, "targetRevision"),
		"ARGOCD_APP_REVISION":               "<revision>",
		"ARGOCD_APP_REVISION_SHORT":         "<revision>",
		"KUBE_VERSION":                      "<kube-version>",
		"KUBE_API_VERSIONS":                 "<kube-api-versions>",
	}
}

// argoEnvVar matches a variable of the build environment, $NAME or ${NAME}.
var argoEnvVar = regexp.MustCompile(`\$\{?([A-Z_][A-Z0-9_]*)\}?`)

// expandArgoHelm substitutes the build environment in the helm section of a
// source where Argo CD does: its release name, value files, values and
// parameters. A variable it does not know is left as written.
func expandArgoHelm(helm map[string]interface{}, env map[string]string) map[string]interface{} {
	if helm == nil {
		return nil
	}
	expand := func(s string) string {
		return argoEnvVar.ReplaceAllStringFunc(s, func(m string) string {
			if v, ok := env[argoEnvVar.FindStringSubmatch(m)[1]]; ok {
				return v
			}
			return m
		})
	}
	out := make(map[string]interface{}, len(helm))
	for k, v := range helm {
		out[k] = v
	}
	for _, key := range []string{"releaseName", "values"} {
		if s, ok := helm[key].(string); ok {
			out[key] = expand(s)
		}
	}
	var files []interface{}
	for _, f := range strList(helm, "valueFiles") {
		files = append(files, expand(f))
	}
	if files != nil {
		out["valueFiles"] = files
	}
	var params []interface{}
	for _, p := range listOf(helm, "parameters") {
		pm := MergeValues(asMap(p), nil)
		if v, ok := pm["value"].(string); ok {
			pm["value"] = expand(v)
		}
		params = append(params, pm)
	}
	if params != nil {
		out["parameters"] = params
	}
	return out
}

// argoSources returns the sources of an application: its source, then its
// sources.
func argoSources(spec map[string]interface{}) []map[string]interface{} {
	var sources []map[string]interface{}
	if s := mapOf(spec, "source"); s != nil {
		sources = append(sources, s)
	}
	for _, s := range listOf(spec, "sources") {
		if m, ok := s.(map[string]interface{}); ok {
			sources = append(sources, m)
		}
	}
	return sources
}

// argoLayers returns the values the helm section of a source gives: its value
// files, its inline values, then its parameters.
func (d *discovery) argoLayers(chartDir string, helm map[string]interface{}, refs map[string]bool) []Layer {
	var layers []Layer
	for _, vf := range strList(helm, "valueFiles") {
		if file, ok := d.argoValueFile(chartDir, vf, refs); ok {
			layers = append(layers, Layer{File: file})
		}
	}
	if obj, ok := helmValues(helm["valuesObject"]); ok {
		layers = append(layers, Layer{Values: obj})
	} else if text := str(helm, "values"); text != "" {
		if values, err := ParseValues([]byte(text)); err == nil {
			layers = append(layers, Layer{Values: values})
		}
	}
	if set := d.argoParameters(chartDir, helm, refs); len(set.Set)+len(set.SetString) > 0 {
		layers = append(layers, set)
	}
	return layers
}

// argoParameters returns the parameters and file parameters of a helm section.
func (d *discovery) argoParameters(chartDir string, helm map[string]interface{}, refs map[string]bool) Layer {
	var set Layer
	for _, param := range listOf(helm, "parameters") {
		pm := asMap(param)
		if str(pm, "name") == "" {
			continue
		}
		expr := argoSetExpr(str(pm, "name"), str(pm, "value"))
		if boolOr(pm, "forceString", false) {
			set.SetString = append(set.SetString, expr)
		} else {
			set.Set = append(set.Set, expr)
		}
	}
	for _, param := range listOf(helm, "fileParameters") {
		pm := asMap(param)
		file, ok := d.argoValueFile(chartDir, str(pm, "path"), refs)
		if str(pm, "name") == "" || !ok {
			continue
		}
		if content := d.read(file); content != nil {
			set.SetString = append(set.SetString, literalSetExpr(str(pm, "name"), string(content)))
		}
	}
	return set
}

// argoValueFile resolves a value file of a source: relative to the chart, or
// to the root of the repository through a $ref.
func (d *discovery) argoValueFile(chartDir, vf string, refs map[string]bool) (string, bool) {
	// Argo CD refuses an absolute path outside its checkout of the repository.
	if vf == "" || strings.Contains(vf, "://") || filepath.IsAbs(vf) {
		return "", false
	}
	var file string
	if strings.HasPrefix(vf, "$") {
		ref, rest, _ := strings.Cut(vf[1:], "/")
		if !refs[ref] {
			return "", false
		}
		file = d.repoPath(rest)
	} else {
		file = localPath(chartDir, vf)
	}
	if !fileExists(d.fsys(), file) {
		d.debugf("Value file %s of an Argo CD application does not exist", file)
		return "", false
	}
	return file, true
}

func (d *discovery) argoApplicationSet(set manifestDoc) {
	spec := set.spec()
	tmpl := mapOf(spec, "template")
	if tmpl == nil {
		return
	}
	goTemplate := boolOr(spec, "goTemplate", false)
	var params []map[string]interface{}
	for _, g := range listOf(spec, "generators") {
		params = append(params, d.argoGenerate(asMap(g), goTemplate, nil)...)
	}
	if len(params) > maxGeneratedApplications {
		params = params[:maxGeneratedApplications]
	}
	for _, p := range params {
		app, ok := renderArgoTemplate(tmpl, p, goTemplate).(map[string]interface{})
		if !ok {
			continue
		}
		d.argoApplication(set.path, app, "Argo CD application set "+set.path)
	}
}

// argoGenerate returns the parameter sets of a generator. parent holds the
// parameters of an enclosing matrix generator, which the generator's own
// configuration may use.
func (d *discovery) argoGenerate(g map[string]interface{}, goTemplate bool, parent map[string]interface{}) []map[string]interface{} {
	if parent != nil {
		g, _ = renderArgoTemplate(g, parent, goTemplate).(map[string]interface{})
	}
	switch {
	case mapOf(g, "list") != nil:
		var out []map[string]interface{}
		for _, e := range listOf(mapOf(g, "list"), "elements") {
			if m, ok := e.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out
	case mapOf(g, "git") != nil:
		return d.argoGit(mapOf(g, "git"), goTemplate)
	case mapOf(g, "matrix") != nil:
		return d.argoMatrix(mapOf(g, "matrix"), goTemplate)
	case mapOf(g, "merge") != nil:
		return d.argoMerge(mapOf(g, "merge"), goTemplate)
	}
	// Clusters, pull requests, SCM providers and plugins are only known to
	// Argo CD: their parameters stay placeholders.
	return []map[string]interface{}{{}}
}

// argoMatrix combines every parameter set of a matrix's first generator with
// those its second one yields for it.
func (d *discovery) argoMatrix(m map[string]interface{}, goTemplate bool) []map[string]interface{} {
	children := listOf(m, "generators")
	if len(children) != 2 {
		return nil
	}
	var out []map[string]interface{}
	for _, a := range d.argoGenerate(asMap(children[0]), goTemplate, nil) {
		for _, b := range d.argoGenerate(asMap(children[1]), goTemplate, a) {
			out = append(out, MergeValues(a, b))
			if len(out) >= maxGeneratedApplications {
				return out
			}
		}
	}
	return out
}

// argoMerge merges into the parameter sets of a merge's first generator those
// of the others with the same merge keys.
func (d *discovery) argoMerge(m map[string]interface{}, goTemplate bool) []map[string]interface{} {
	keys := strList(m, "mergeKeys")
	children := listOf(m, "generators")
	if len(children) == 0 {
		return nil
	}
	base := d.argoGenerate(asMap(children[0]), goTemplate, nil)
	for _, child := range children[1:] {
		for _, extra := range d.argoGenerate(asMap(child), goTemplate, nil) {
			for i, b := range base {
				if sameMergeKeys(b, extra, keys) {
					base[i] = MergeValues(b, extra)
				}
			}
		}
	}
	return base
}

func sameMergeKeys(a, b map[string]interface{}, keys []string) bool {
	if len(keys) == 0 {
		return false
	}
	for _, k := range keys {
		av, _ := scalarText(lookupFlat(a, k))
		bv, _ := scalarText(lookupFlat(b, k))
		if av != bv {
			return false
		}
	}
	return true
}

func lookupFlat(m map[string]interface{}, key string) interface{} {
	if v, ok := m[key]; ok {
		return v
	}
	return lookupPath(m, strings.Split(key, "."))
}

// argoGit returns the parameters of a git generator: one set per directory or
// file of this repository its patterns match.
func (d *discovery) argoGit(g map[string]interface{}, goTemplate bool) []map[string]interface{} {
	if !d.sameRepository(str(g, "repoURL")) {
		return nil
	}
	extra := map[string]interface{}{}
	if values := mapOf(g, "values"); values != nil {
		extra["values"] = values
	}
	var out []map[string]interface{}
	if dirs := listOf(g, "directories"); dirs != nil {
		for _, dir := range d.matchRepoPaths(dirs, d.repoDirectories()) {
			out = append(out, MergeValues(argoPathParams(dir, goTemplate), extra))
		}
	}
	for _, file := range d.matchRepoPaths(listOf(g, "files"), d.repoFilesFor(listOf(g, "files"))) {
		content := d.read(d.repoPath(file))
		if content == nil {
			continue
		}
		var docs []map[string]interface{}
		var list []interface{}
		if json.Unmarshal(content, &list) == nil {
			for _, item := range list {
				if m, ok := normalizeYAML(item).(map[string]interface{}); ok {
					docs = append(docs, m)
				}
			}
		} else {
			docs = yamlDocuments(content)
		}
		for _, doc := range docs {
			params := doc
			if !goTemplate {
				params = flattenParams(doc, "")
			}
			out = append(out, MergeValues(MergeValues(params, argoPathParams(path.Dir(file), goTemplate)), extra))
		}
	}
	return out
}

// argoPathParams are the parameters a git generator gives for a directory.
func argoPathParams(dir string, goTemplate bool) map[string]interface{} {
	segments := strings.Split(dir, "/")
	base := path.Base(dir)
	normalized := argoSanitizeName(base)
	if goTemplate {
		p := map[string]interface{}{
			"path": dir, "basename": base, "basenameNormalized": normalized, "segments": toInterfaces(segments),
		}
		return map[string]interface{}{"path": p}
	}
	params := map[string]interface{}{
		"path": dir, "path.basename": base, "path.basenameNormalized": normalized,
	}
	for i, s := range segments {
		params["path["+strconv.Itoa(i)+"]"] = s
	}
	return params
}

// argoSanitizeName is a name as Argo CD sanitizes it for basenameNormalized:
// lowercased, with every character a DNS name cannot hold as "-".
func argoSanitizeName(name string) string {
	const maxDNSNameLength = 253
	name = regexp.MustCompile(`[^-a-z0-9.]`).ReplaceAllString(strings.ToLower(name), "-")
	if len(name) > maxDNSNameLength {
		name = name[:maxDNSNameLength]
	}
	return strings.Trim(name, "-.")
}

func toInterfaces(s []string) []interface{} {
	out := make([]interface{}, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// flattenParams flattens nested maps into dotted keys, as Argo CD does for the
// parameters of a file that templates read without Go templates.
func flattenParams(m map[string]interface{}, prefix string) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if sub, ok := v.(map[string]interface{}); ok {
			for fk, fv := range flattenParams(sub, key) {
				out[fk] = fv
			}
			continue
		}
		out[key] = v
	}
	return out
}

// repoDirectories lists the directories of the repository a directory
// generator can name and that may hold a chart: the charts of the scan and
// the directories above them.
func (d *discovery) repoDirectories() []string {
	seen := map[string]bool{}
	var out []string
	for dir := range d.idx.charts {
		rel, err := filepath.Rel(d.idx.root, dir)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		for rel = filepath.ToSlash(rel); rel != "." && rel != "" && !seen[rel]; rel = path.Dir(rel) {
			seen[rel] = true
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}

// repoFilesFor lists the files under the fixed directories the patterns of a
// files generator start with.
func (d *discovery) repoFilesFor(patterns []interface{}) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range patterns {
		pattern := str(asMap(p), "path")
		prefix := pattern
		if i := strings.IndexAny(pattern, "*?[{"); i >= 0 {
			prefix = path.Dir(pattern[:i] + "x")
		}
		// A pattern from the root of the repository would walk all of it.
		prefix = strings.Trim(prefix, "/")
		if prefix == "" || prefix == "." || !d.idx.confined(d.repoPath(prefix)) {
			continue
		}
		for _, rel := range walkFiles(d.fsys(), d.repoPath(prefix)) {
			full := prefix + "/" + rel
			if !seen[full] {
				seen[full] = true
				out = append(out, full)
			}
		}
	}
	sort.Strings(out)
	return out
}

// matchRepoPaths returns the candidates the include patterns of a git
// generator match and its exclude patterns do not.
func (d *discovery) matchRepoPaths(patterns []interface{}, candidates []string) []string {
	var out []string
	for _, c := range candidates {
		included := false
		for _, p := range patterns {
			pm := asMap(p)
			if !globMatch(str(pm, "path"), c) {
				continue
			}
			if boolOr(pm, "exclude", false) {
				included = false
				break
			}
			included = true
		}
		if included {
			out = append(out, c)
		}
	}
	return out
}

// globMatch matches a slash path against a pattern where "**" spans
// directories, none included: "**/x" also matches "x".
func globMatch(pattern, name string) bool {
	re := globRegexp(pattern)
	return re != nil && re.MatchString(name)
}

// globs caches the expressions of the glob patterns matched.
var globs sync.Map

// globRegexp returns the expression a glob pattern stands for, nil for none.
func globRegexp(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	if cached, ok := globs.Load(pattern); ok {
		return cached.(*regexp.Regexp)
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; {
		case strings.HasPrefix(pattern[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case strings.HasPrefix(pattern[i:], "/**") && i+3 == len(pattern):
			b.WriteString("(?:/.*)?")
			i += 2
		case strings.HasPrefix(pattern[i:], "**"):
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	globs.Store(pattern, re)
	return re
}

// fastTemplateTag matches a parameter of an Argo CD template without Go
// templates.
var fastTemplateTag = regexp.MustCompile(`\{\{\s*([^{}]*?)\s*\}\}`)

// renderArgoTemplate fills the strings of an ApplicationSet template with
// params. A parameter no generator gives stays a placeholder.
func renderArgoTemplate(v interface{}, params map[string]interface{}, goTemplate bool) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(x))
		for k, val := range x {
			out[k] = renderArgoTemplate(val, params, goTemplate)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, val := range x {
			out[i] = renderArgoTemplate(val, params, goTemplate)
		}
		return out
	case string:
		if !strings.Contains(x, "{{") {
			return x
		}
		if goTemplate {
			return renderGoParams(x, params)
		}
		return fastTemplateTag.ReplaceAllStringFunc(x, func(tag string) string {
			key := fastTemplateTag.FindStringSubmatch(tag)[1]
			if t, ok := scalarText(params[key]); ok && params[key] != nil {
				return t
			}
			return "<" + key + ">"
		})
	}
	return v
}

func renderGoParams(text string, params map[string]interface{}) string {
	funcs := sprig.TxtFuncMap()
	for _, name := range []string{"env", "expandenv", "getHostByName"} {
		delete(funcs, name)
	}
	t, err := template.New("appset").Option("missingkey=zero").Funcs(funcs).Parse(text)
	if err != nil {
		return text
	}
	var b strings.Builder
	if t.Execute(&b, params) != nil {
		return text
	}
	return strings.ReplaceAll(b.String(), "<no value>", "<?>")
}
