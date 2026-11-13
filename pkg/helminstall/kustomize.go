/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package helminstall

import (
	"fmt"
	"path/filepath"
	"strings"

	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/yaml"
)

// A kustomization inflates the charts its helmCharts lists, kept under its
// chart home, with the values its entries give, as kustomize runs
// "helm template". Its configMapGenerator entries are also the ConfigMaps a
// Flux HelmRelease may take values from.

// The valuesMerge modes of kustomize.
const (
	valuesMergeMerge   = "merge"
	valuesMergeReplace = "replace"
)

func (d *discovery) kustomization(path string) {
	data := d.read(path)
	if data == nil {
		return
	}
	var k types.Kustomization
	if yaml.Unmarshal(data, &k) != nil {
		return
	}
	dir := filepath.Dir(path)
	d.recordConfigMapGenerators(dir, &k)
	chartHome := "charts"
	if k.HelmGlobals != nil && k.HelmGlobals.ChartHome != "" {
		chartHome = k.HelmGlobals.ChartHome
	}
	charts := append([]types.HelmChart{}, k.HelmCharts...)
	if len(k.HelmChartInflationGenerator) > 0 {
		more, globals := types.SplitHelmParameters(k.HelmChartInflationGenerator)
		charts = append(charts, more...)
		if (k.HelmGlobals == nil || k.HelmGlobals.ChartHome == "") && globals.ChartHome != "" {
			chartHome = globals.ChartHome
		}
	}
	for i := range charts {
		d.kustomizeChart(path, dir, chartHome, &charts[i], k.Namespace)
	}
}

func (d *discovery) kustomizeChart(path, dir, chartHome string, hc *types.HelmChart, namespace string) {
	home := localPath(dir, chartHome)
	if hc.Version != "" && hc.Repo != "" {
		home = filepath.Join(home, fmt.Sprintf("%s-%s", hc.Name, hc.Version))
	}
	chartDir, ok := d.idx.chartDir(filepath.Join(home, hc.Name))
	if !ok {
		return
	}
	release := hc.ReleaseName
	if release == "" {
		// kustomize runs helm template --generate-name.
		release = hc.Name + "-<generated>"
	}
	ns := hc.Namespace
	if ns == "" {
		ns = namespace
	}
	inst := Installation{
		Release: release, Namespace: ns,
		Source: "kustomization " + path, Origin: OriginDescriptor,
	}
	inst.Layers = d.kustomizeValues(dir, chartDir, hc)
	for _, f := range hc.AdditionalValuesFiles {
		inst.Layers = append(inst.Layers, Layer{File: localPath(dir, f)})
	}
	d.idx.add(chartDir, &inst)
}

// kustomizeValues returns the values kustomize gives helm: its values file,
// the chart's values.yaml when it names none, with the inline values merged
// in by its valuesMerge mode.
func (d *discovery) kustomizeValues(dir, chartDir string, hc *types.HelmChart) []Layer {
	valuesFile := filepath.Join(chartDir, "values.yaml")
	if hc.ValuesFile != "" {
		valuesFile = localPath(dir, hc.ValuesFile)
	}
	inline, _ := helmValues(normalizeYAML(hc.ValuesInline))
	if len(inline) == 0 {
		if hc.ValuesFile == "" {
			return nil
		}
		return []Layer{{File: valuesFile}}
	}
	if hc.ValuesMerge == valuesMergeReplace {
		return []Layer{{Values: inline}}
	}
	fileValues := map[string]interface{}{}
	if data := d.read(valuesFile); data != nil {
		if parsed, err := ParseValues(data); err == nil {
			fileValues = parsed
		}
	}
	// kustomize writes the values file merged with the inline values, which
	// win by default; with valuesMerge: merge, the values file wins.
	if hc.ValuesMerge == valuesMergeMerge {
		return []Layer{{Values: MergeValues(inline, fileValues)}}
	}
	return []Layer{{Values: MergeValues(fileValues, inline)}}
}

// recordConfigMapGenerators records the ConfigMaps and Secrets a kustomization
// generates from files and literals, for Flux values.
func (d *discovery) recordConfigMapGenerators(dir string, k *types.Kustomization) {
	disableHash := k.GeneratorOptions != nil && k.GeneratorOptions.DisableNameSuffixHash
	record := func(kind string, args *types.GeneratorArgs) {
		if args.Name == "" {
			return
		}
		data := map[string]string{}
		for _, lit := range args.LiteralSources {
			if key, value, ok := strings.Cut(lit, "="); ok {
				data[key] = value
			}
		}
		for _, src := range args.FileSources {
			key, file, ok := strings.Cut(src, "=")
			if !ok {
				file, key = src, filepath.Base(src)
			}
			if content := d.read(localPath(dir, file)); content != nil {
				data[key] = string(content)
			}
		}
		ns := args.Namespace
		if ns == "" {
			ns = k.Namespace
		}
		// A generated name gets a hash suffix the HelmRelease cannot know, so a
		// reference by its base name is the generator's.
		d.idx.addConfigData(kind, ns, args.Name, data, !disableHash)
	}
	for i := range k.ConfigMapGenerator {
		record(kindConfigMap, &k.ConfigMapGenerator[i].GeneratorArgs)
	}
	for i := range k.SecretGenerator {
		record(kindSecret, &k.SecretGenerator[i].GeneratorArgs)
	}
}

// localPath resolves a path a descriptor in dir names.
func localPath(dir, p string) string {
	p = filepath.FromSlash(p)
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(dir, p)
}
