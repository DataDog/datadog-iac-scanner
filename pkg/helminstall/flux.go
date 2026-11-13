/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package helminstall

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// A Flux HelmRelease installs a chart of a GitRepository, at a path of this
// repository, directly or through a HelmChart. Its release name defaults to
// [<targetNamespace>-]<name>, shortened past Helm's 53 characters as Flux
// shortens it. Its values are the chart's, or its valuesFiles in their place,
// then those of its valuesFrom ConfigMaps and Secrets, then its inline values.

const (
	maxReleaseNameLen = 53
	fluxShortHashLen  = 12
	fluxDefaultValues = "values.yaml"
)

// fluxReleaseName is the release name Flux gives a HelmRelease.
func fluxReleaseName(spec map[string]interface{}, name string) string {
	if rel := str(spec, "releaseName"); rel != "" {
		return rel
	}
	rel := name
	if ns := str(spec, "targetNamespace"); ns != "" {
		rel = ns + "-" + name
	}
	if len(rel) <= maxReleaseNameLen {
		return rel
	}
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(rel)))
	return rel[:maxReleaseNameLen-(fluxShortHashLen+1)] + "-" + sum[:fluxShortHashLen]
}

func (d *discovery) fluxRelease(r manifestDoc) {
	spec := r.spec()
	namespace := r.namespace()
	chartPath, valuesFiles, ok := d.fluxChartSource(spec, namespace)
	if !ok {
		return
	}
	chartDir, ok := d.idx.chartDir(d.repoPath(chartPath))
	if !ok {
		return
	}
	inst := Installation{
		Release:   fluxReleaseName(spec, r.name()),
		Namespace: str(spec, "targetNamespace"),
		Source:    "Flux HelmRelease " + r.path,
		Origin:    OriginDescriptor,
	}
	if inst.Namespace == "" {
		inst.Namespace = namespace
	}
	for _, vf := range valuesFiles {
		file := d.repoPath(vf)
		if !fileExists(d.fsys(), file) {
			continue
		}
		inst.Layers = append(inst.Layers, Layer{File: file})
		inst.ReplaceChartValues = true
	}
	for _, ref := range listOf(spec, "valuesFrom") {
		if layer, ok := d.fluxValuesFrom(asMap(ref), namespace); ok {
			inst.Layers = append(inst.Layers, layer)
		}
	}
	if values, ok := helmValues(spec["values"]); ok {
		inst.Layers = append(inst.Layers, Layer{Values: values})
	}
	d.idx.add(chartDir, &inst)
}

// fluxChartSource returns the path of the chart a HelmRelease installs, and
// its valuesFiles, when the chart is in a GitRepository of this repository.
func (d *discovery) fluxChartSource(spec map[string]interface{}, namespace string) (chart string, valuesFiles []string, ok bool) {
	chartSpec := mapOf(mapOf(spec, "chart"), "spec")
	if chartSpec == nil {
		ref := mapOf(spec, "chartRef")
		if str(ref, "kind") != kindHelmChart {
			return "", nil, false
		}
		ns := str(ref, "namespace")
		if ns == "" {
			ns = namespace
		}
		hc, ok := d.pending.fluxCharts[configKey{kindHelmChart, ns, str(ref, "name")}]
		if !ok {
			return "", nil, false
		}
		chartSpec, namespace = hc.spec(), hc.namespace()
	}
	source := mapOf(chartSpec, "sourceRef")
	if str(source, "kind") != kindGitRepository {
		return "", nil, false
	}
	ns := str(source, "namespace")
	if ns == "" {
		ns = namespace
	}
	if url, known := d.pending.gitRepos[configKey{kindGitRepository, ns, str(source, "name")}]; known && !d.sameRepository(url) {
		return "", nil, false
	}
	files := strList(chartSpec, "valuesFiles")
	if f := str(chartSpec, "valuesFile"); f != "" && len(files) == 0 {
		files = []string{f}
	}
	return str(chartSpec, "chart"), files, str(chartSpec, "chart") != ""
}

// fluxTargetPathLayer sets the value at path, as Flux does: a quoted value is
// the string within the quotes, anything else is parsed as by --set.
func fluxTargetPathLayer(path, value string) Layer {
	quoted := len(value) >= 2 &&
		(strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) ||
			strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'"))
	if quoted {
		value = strings.ReplaceAll(strings.Trim(value, `"'`), ",", `\,`)
		return Layer{SetString: []string{path + "=" + value}}
	}
	return Layer{Set: []string{path + "=" + value}}
}

// fluxValuesFrom reads the values a HelmRelease takes from a ConfigMap or
// Secret of the scan.
func (d *discovery) fluxValuesFrom(ref map[string]interface{}, namespace string) (Layer, bool) {
	kind := str(ref, "kind")
	if kind != kindConfigMap && kind != kindSecret {
		return Layer{}, false
	}
	key := str(ref, "valuesKey")
	if key == "" {
		key = fluxDefaultValues
	}
	content, ok := d.idx.configValue(kind, namespace, str(ref, "name"), key)
	if !ok {
		d.debugf("The %s %s a Flux HelmRelease takes values from is not in the scan", kind, str(ref, "name"))
		return Layer{}, false
	}
	if target := str(ref, "targetPath"); target != "" {
		return fluxTargetPathLayer(target, content), true
	}
	values, err := ParseValues([]byte(content))
	if err != nil {
		return Layer{}, false
	}
	return Layer{Values: values}, true
}
