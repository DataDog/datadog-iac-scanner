/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package helminstall

import (
	"path/filepath"
	"strings"
)

// A Rancher Fleet fleet.yaml installs the chart of its directory, or the one
// its helm.chart names, with its helm values and valuesFiles, and each target
// customization installs it again with its own on top. Without a releaseName,
// Fleet names the release after the bundle, the GitRepo name, only known to
// the cluster, and the bundle's path.

func (d *discovery) fleet(path string) {
	data := d.read(path)
	if data == nil {
		return
	}
	docs := yamlDocuments(data)
	if len(docs) == 0 {
		return
	}
	doc := docs[0]
	dir := filepath.Dir(path)
	helm := mapOf(doc, "helm")
	chart := str(helm, "chart")
	if str(helm, "repo") != "" || strings.Contains(chart, "://") {
		return
	}
	chartDir, ok := d.idx.chartDir(localPath(dir, chart))
	if !ok {
		return
	}
	base := Installation{
		Release:   str(helm, "releaseName"),
		Namespace: fleetNamespace(doc, "default"),
		Layers:    d.fleetLayers(dir, helm),
		Source:    "Fleet bundle " + path,
		Origin:    OriginDescriptor,
	}
	if base.Release == "" {
		base.Release = d.fleetBundleName(dir)
	}
	d.idx.add(chartDir, &base)
	for _, c := range listOf(doc, "targetCustomizations") {
		custom := asMap(c)
		ch := mapOf(custom, "helm")
		inst := base
		inst.Layers = append(append([]Layer{}, base.Layers...), d.fleetLayers(dir, ch)...)
		inst.Namespace = fleetNamespace(custom, base.Namespace)
		if rel := str(ch, "releaseName"); rel != "" {
			inst.Release = rel
		}
		inst.Source = "Fleet bundle " + path + " (target " + str(custom, "name") + ")"
		d.idx.add(chartDir, &inst)
	}
}

func fleetNamespace(m map[string]interface{}, def string) string {
	if ns := str(m, "namespace"); ns != "" {
		return ns
	}
	if ns := str(m, "defaultNamespace"); ns != "" {
		return ns
	}
	return def
}

func (d *discovery) fleetLayers(dir string, helm map[string]interface{}) []Layer {
	var layers []Layer
	for _, f := range strList(helm, "valuesFiles") {
		file := localPath(dir, f)
		if fileExists(d.fsys(), file) {
			layers = append(layers, Layer{File: file})
		}
	}
	if values, ok := helmValues(helm["values"]); ok {
		layers = append(layers, Layer{Values: values})
	}
	return layers
}

// fleetBundleName is the release name Fleet gives a bundle at dir: the name of
// the GitRepo, then the bundle's path in the repository, dashed.
func (d *discovery) fleetBundleName(dir string) string {
	name := "<fleet-gitrepo>"
	rel, err := filepath.Rel(d.idx.root, dir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return name
	}
	return name + "-" + strings.ToLower(strings.ReplaceAll(filepath.ToSlash(rel), "/", "-"))
}
