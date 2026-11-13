/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package helminstall

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dop251/goja"
)

// A Datadog deployment configuration, deploy.yaml, installs the chart of the
// bundle beside it under config.k8s.name, in config.k8s.namespace, on the
// clusters each target selects. Its apps install several bundles, each under
// its name, the bundle being the target named depName of the BUILD file beside
// it, or else the deployment's own. An installation of app <release> in
// namespace <ns> on cluster <cluster> of datacenter <dc> is named
// <release>.<ns>.<cluster>.<dc>, which picks the values/environments files of
// the chart; its valuesFilesJs and valuesMapJs extensions, JavaScript
// functions of the installation, select more values files and values, in that
// order of precedence.

const (
	deployConfigName      = "deploy.yaml"
	serviceDefinitionName = "service.datadog.yaml"
	// valuesJSTimeout is the time a values function gets, as when deployed.
	valuesJSTimeout = 100 * time.Millisecond
	// maxDeployClusters bounds the clusters one app is evaluated for.
	maxDeployClusters = 64
)

func isDeployConfig(base string) bool {
	return base == deployConfigName || base == "deploy.yml"
}

// deployCluster is a cluster a target deploys to, as much as deploy.yaml says
// of it.
type deployCluster struct {
	name, fqdn, datacenter, environment string
}

// clusterFQDNs matches the cluster names a selector lists.
var (
	clusterNameIn = regexp.MustCompile(`cluster\.name\s+in\s+\[([^\]]*)\]`)
	clusterNameEq = regexp.MustCompile(`cluster\.name\s*==\s*["']([^"']+)["']`)
	clusterEnvEq  = regexp.MustCompile(`cluster\.env(?:ironment)?\s*==\s*["']([^"']+)["']`)
	quoted        = regexp.MustCompile(`["']([^"']+)["']`)
)

// datacenterEnvironment is the environment of a datacenter named
// <region>.<environment>.<domain>.
func datacenterEnvironment(dc string) string {
	parts := strings.Split(dc, ".")
	if len(parts) < 3 {
		return ""
	}
	switch env := parts[1]; env {
	case "fed":
		return "gov"
	case "ddbuild":
		return "prod"
	default:
		return env
	}
}

func clusterOf(fqdn, env string) deployCluster {
	name, dc, _ := strings.Cut(fqdn, ".")
	if env == "" {
		env = datacenterEnvironment(dc)
	}
	return deployCluster{name: name, fqdn: fqdn, datacenter: dc, environment: env}
}

// deployClusters returns the clusters a target or app deploys to, from its
// selector or placement. The clusters a placement picks are only known when
// deploying: one stands for each datacenter it names.
func deployClusters(m map[string]interface{}) ([]deployCluster, bool) {
	if sel := str(m, "selector"); sel != "" {
		env := ""
		if e := clusterEnvEq.FindStringSubmatch(sel); e != nil {
			env = e[1]
		}
		var out []deployCluster
		for _, in := range clusterNameIn.FindAllStringSubmatch(sel, -1) {
			for _, q := range quoted.FindAllStringSubmatch(in[1], -1) {
				out = append(out, clusterOf(q[1], env))
			}
		}
		for _, eq := range clusterNameEq.FindAllStringSubmatch(sel, -1) {
			out = append(out, clusterOf(eq[1], env))
		}
		if len(out) == 0 {
			out = append(out, deployCluster{environment: env})
		}
		return out, true
	}
	placement := mapOf(m, "placement")
	if placement == nil {
		return nil, false
	}
	env := str(placement, "environment")
	var out []deployCluster
	for _, c := range listOf(placement, "datacenter_constraints") {
		for _, name := range strList(mapOf(asMap(c), "datacenter_selector"), "names") {
			if strings.Count(name, ".") >= 2 {
				out = append(out, deployCluster{datacenter: name, environment: firstNonEmpty(env, datacenterEnvironment(name))})
			}
		}
	}
	for _, name := range strList(placement, "static_cluster_names") {
		out = append(out, clusterOf(name, env))
	}
	if len(out) == 0 {
		out = append(out, deployCluster{environment: env})
	}
	return out, true
}

// deployApps returns the apps of a deploy.yaml block, those of its app groups
// included.
func deployApps(m map[string]interface{}) ([]map[string]interface{}, bool) {
	list, ok := m["apps"].([]interface{})
	if !ok {
		return nil, false
	}
	var out []map[string]interface{}
	for _, a := range list {
		app := asMap(a)
		if group := mapOf(app, "appGroup"); group != nil {
			nested, _ := deployApps(group)
			out = append(out, nested...)
			continue
		}
		if str(app, "name") != "" {
			out = append(out, app)
		}
	}
	return out, true
}

func (d *discovery) deployConfig(path string) {
	data := d.read(path)
	if data == nil {
		return
	}
	docs := yamlDocuments(data)
	if len(docs) == 0 || mapOf(docs[0], "config") == nil {
		return
	}
	config := mapOf(docs[0], "config")
	dir := filepath.Dir(path)
	k8s := mapOf(config, "k8s")
	ext := mapOf(config, "extensions")
	globalApps, _ := deployApps(config)
	targets := listOf(config, "targets")
	if len(targets) == 0 {
		targets = []interface{}{map[string]interface{}{}}
	}
	for _, t := range targets {
		target := asMap(t)
		apps, ok := deployApps(target)
		if !ok {
			apps = globalApps
		}
		if len(apps) == 0 {
			apps = []map[string]interface{}{{"name": str(k8s, "name")}}
		}
		targetK8s := MergeValues(k8s, mapOf(target, "k8s"))
		namespace := firstNonEmpty(str(mapOf(target, "extra"), "namespace"), str(targetK8s, "namespace"))
		clusters, ok := deployClusters(target)
		if !ok {
			clusters = []deployCluster{{}}
		}
		targetExt := MergeValues(ext, mapOf(target, "extensions"))
		for _, app := range apps {
			d.deployApp(path, dir, str(target, "name"), str(k8s, "name"), namespace, app, clusters, targetExt)
		}
	}
}

func (d *discovery) deployApp(path, dir, target, mainRelease, namespace string, app map[string]interface{},
	clusters []deployCluster, ext map[string]interface{}) {
	release := firstNonEmpty(str(app, "name"), mainRelease)
	if release == "" {
		return
	}
	chartDir, ok := d.deployAppChart(dir, str(app, "depName"), release)
	if !ok {
		d.debugf("No chart of the scan found for app %s of %s", release, path)
		return
	}
	appNamespace := firstNonEmpty(str(mapOf(app, "extra"), "namespace"), str(mapOf(app, "k8s"), "namespace"), namespace)
	if own, ok := deployClusters(app); ok {
		clusters = own
	}
	if len(clusters) > maxDeployClusters {
		clusters = clusters[:maxDeployClusters]
	}
	ext = MergeValues(ext, mapOf(app, "extensions"))
	chartFiles := d.chartFileList(chartDir)
	for _, c := range clusters {
		req := deployRequest(release, appNamespace, target, c, chartFiles)
		inst := Installation{
			Release: release, Namespace: appNamespace, Origin: OriginDescriptor,
			Source: fmt.Sprintf("Datadog deployment %s, target %q, cluster %s", path, target, firstNonEmpty(c.fqdn, c.datacenter, "?")),
		}
		for _, f := range environmentFiles(d.fsys(), chartDir, installationName(release, appNamespace, c)) {
			inst.Layers = append(inst.Layers, Layer{File: f})
		}
		if js := str(ext, "valuesFilesJs"); js != "" {
			for _, f := range d.valuesFilesJS(js, req, chartFiles, path) {
				if file := filepath.Join(chartDir, filepath.FromSlash(f)); fileExists(d.fsys(), file) {
					inst.Layers = append(inst.Layers, Layer{File: file})
				}
			}
		}
		if js := str(ext, "valuesMapJs"); js != "" {
			if values := d.valuesMapJS(js, req, path); len(values) > 0 {
				inst.Layers = append(inst.Layers, Layer{Values: values})
			}
		}
		d.idx.add(chartDir, &inst)
	}
}

// installationName is the CNAB installation name of an app on a cluster, with
// placeholders for what the deployment only knows when it runs.
func installationName(release, namespace string, c deployCluster) string {
	return strings.Join([]string{
		release, firstNonEmpty(namespace, "<namespace>"), firstNonEmpty(c.name, "<cluster>"),
		firstNonEmpty(c.datacenter, "<datacenter>"),
	}, ".")
}

// deployAppChart returns the chart an app installs: the bundle depName names
// beside the deploy.yaml, or the deployment's own bundle.
func (d *discovery) deployAppChart(dir, depName, release string) (string, bool) {
	ev := d.bazelEvaluator()
	if depName != "" {
		if c, ok := ev.bundleChart(dir, depName); ok {
			return c, true
		}
		for _, c := range ev.dependencyCharts(dir, depName) {
			return c, true
		}
		return "", false
	}
	// The bundle the service definition builds for the deployment, the chart
	// beside the deploy.yaml, then the bundles its package defines rather
	// than refers to.
	if built := uniqueStrings(d.serviceBundleCharts(dir)); len(built) == 1 {
		return built[0], true
	}
	if own, ok := d.idx.chartDir(dir); ok {
		return own, true
	}
	for _, own := range []bool{true, false} {
		candidates := uniqueStrings(ev.packageCharts(dir, own))
		if len(candidates) == 1 {
			return candidates[0], true
		}
		for _, c := range candidates {
			if d.idx.charts[c].name == release {
				return c, true
			}
		}
	}
	return "", false
}

// serviceBundleCharts returns the charts of the bundles the service definition
// beside a deploy.yaml, or above it, builds for it.
func (d *discovery) serviceBundleCharts(dir string) []string {
	var out []string
	ev := d.bazelEvaluator()
	for cur, i := dir, 0; i < 4; i++ {
		def := filepath.Join(cur, serviceDefinitionName)
		if fileExists(d.fsys(), def) {
			for _, doc := range yamlDocuments(d.read(def)) {
				for _, label := range ciBazelTargets(doc) {
					ws := ev.workspaceOf(cur)
					pkgDir, name, ok := ev.splitLabel(label, ws, cur)
					if !ok {
						continue
					}
					if c, ok := ev.bundleChart(pkgDir, name); ok {
						out = append(out, c)
					}
				}
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return out
}

// ciBazelTargets returns the ci_bazel_targets labels anywhere in doc.
func ciBazelTargets(v interface{}) []string {
	var out []string
	switch x := v.(type) {
	case map[string]interface{}:
		for _, k := range sortedKeys(x) {
			if k == "ci_bazel_targets" {
				out = append(out, labelsOf(x[k])...)
				continue
			}
			out = append(out, ciBazelTargets(x[k])...)
		}
	case []interface{}:
		for _, e := range x {
			out = append(out, ciBazelTargets(e)...)
		}
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// chartFileList lists the files of a chart, relative to it, the files a
// values function can select.
func (d *discovery) chartFileList(chartDir string) []string {
	if files, ok := d.chartFiles[chartDir]; ok {
		return files
	}
	files := walkFiles(d.fsys(), chartDir)
	sort.Strings(files)
	if d.chartFiles == nil {
		d.chartFiles = map[string][]string{}
	}
	d.chartFiles[chartDir] = files
	return files
}

// deployRequest is the object values functions receive for an installation.
// What only the deployment knows of a cluster is a placeholder.
func deployRequest(release, namespace, target string, c deployCluster, chartFiles []string) map[string]interface{} {
	var valuesFiles []interface{}
	for _, f := range chartFiles {
		if strings.HasPrefix(f, "values/") {
			valuesFiles = append(valuesFiles, f)
		}
	}
	return map[string]interface{}{
		"release":     release,
		"namespace":   firstNonEmpty(namespace, "<namespace>"),
		"target":      target,
		"valuesFiles": valuesFiles,
		"cluster": map[string]interface{}{
			"name": firstNonEmpty(c.name, "<cluster>"), "fqdn": firstNonEmpty(c.fqdn, "<cluster>"),
			"isZonal": false, "pciTier": 0, "family": "<family>", "isCnpEnforced": false,
			"zones": []interface{}{},
		},
		"datacenter": map[string]interface{}{
			"name": firstNonEmpty(c.datacenter, "<datacenter>"), "environment": firstNonEmpty(c.environment, "<environment>"),
			"env":           firstNonEmpty(c.environment, "<environment>"),
			"cloudProvider": "<cloudProvider>", "site": "<site>",
		},
	}
}

// valuesFilesJS runs a valuesFilesJs function and returns the files of the
// chart it selects.
func (d *discovery) valuesFilesJS(src string, req map[string]interface{}, chartFiles []string, path string) []string {
	res, ok := d.runValuesJS(src, req, chartFiles, path)
	if !ok {
		return nil
	}
	var out []string
	switch list := res.(type) {
	case []string:
		// The list glob returns, as it is.
		for _, f := range list {
			out = append(out, strings.TrimPrefix(f, "./"))
		}
	case []interface{}:
		for _, f := range list {
			if s, ok := f.(string); ok {
				out = append(out, strings.TrimPrefix(s, "./"))
			}
		}
	}
	return out
}

// chartGlob is the glob function of values functions: the files of the chart
// each pattern matches, with or without a values file extension, pattern by
// pattern. It stops at the deadline of the function, which cannot interrupt
// it.
func chartGlob(patterns, chartFiles []string, deadline time.Time) []string {
	var out []string
	for _, p := range patterns {
		if time.Now().After(deadline) {
			break
		}
		var res []*regexp.Regexp
		for _, ext := range []string{"", ".yaml", ".yml", ".json"} {
			if re := globRegexp(p + ext); re != nil {
				res = append(res, re)
			}
		}
		var matched []string
		for _, f := range chartFiles {
			for _, re := range res {
				if re.MatchString(f) {
					matched = append(matched, f)
					break
				}
			}
		}
		sort.Strings(matched)
		out = append(out, matched...)
	}
	return out
}

// valuesMapJS runs a valuesMapJs function and returns the values it makes,
// where a top-level key may be a dotted path.
func (d *discovery) valuesMapJS(src string, req map[string]interface{}, path string) map[string]interface{} {
	res, ok := d.runValuesJS(src, req, nil, path)
	if !ok {
		return nil
	}
	m, ok := normalizeYAML(res).(map[string]interface{})
	if !ok {
		return nil
	}
	out := map[string]interface{}{}
	for _, k := range sortedKeys(m) {
		v := m[k]
		if !strings.Contains(k, ".") {
			out = MergeValues(out, map[string]interface{}{k: v})
			continue
		}
		keys := strings.Split(k, ".")
		nested := map[string]interface{}{keys[len(keys)-1]: v}
		for i := len(keys) - 2; i >= 0; i-- {
			nested = map[string]interface{}{keys[i]: nested}
		}
		out = MergeValues(out, nested)
	}
	values, _ := helmValues(out)
	return values
}

// runValuesJS evaluates a values function for req, in a sandbox holding no
// more than the glob function over the chart's files, and returns its result.
func (d *discovery) runValuesJS(src string, req map[string]interface{}, chartFiles []string, path string) (interface{}, bool) {
	vm := goja.New()
	deadline := time.Now().Add(valuesJSTimeout)
	if err := vm.Set("glob", func(patterns []string) []string {
		return chartGlob(patterns, chartFiles, deadline)
	}); err != nil {
		return nil, false
	}
	timer := time.AfterFunc(valuesJSTimeout, func() { vm.Interrupt("timeout") })
	defer timer.Stop()
	fnValue, err := vm.RunString("(" + strings.TrimSpace(src) + "\n)")
	if err != nil {
		d.debugf("Could not evaluate a values function of %s: %v", path, err)
		return nil, false
	}
	fn, ok := goja.AssertFunction(fnValue)
	if !ok {
		return nil, false
	}
	res, err := fn(goja.Undefined(), vm.ToValue(req))
	if err != nil {
		d.debugf("A values function of %s failed: %v", path, err)
		return nil, false
	}
	return res.Export(), true
}
