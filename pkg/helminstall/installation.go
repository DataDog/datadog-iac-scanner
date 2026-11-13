/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package helminstall finds how the Helm charts of a scan are installed: the
// release name, namespace and values each one is deployed with. A chart's
// templates are not what runs in a cluster, an installation of them is, and
// the names of its resources usually come from the release name and from
// values the chart does not hold.
//
// Installations are read from the deployment descriptors the repository holds
// (helmfile, Argo CD, Flux, Kustomize, Terraform, Fleet, Bazel and Datadog
// deploy.yaml), and a chart deployed through an umbrella chart inherits the
// installations of its parent. A chart no descriptor names falls back on
// conventions: its name as release name, and the values files beside it.
package helminstall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"helm.sh/helm/v3/pkg/strvals"
	"sigs.k8s.io/yaml"
)

// Origin is how an installation was found.
type Origin int

const (
	// OriginDescriptor is an installation a deployment descriptor declares.
	OriginDescriptor Origin = iota
	// OriginParent is a chart installed as a dependency of an umbrella chart.
	OriginParent
	// OriginConvention is an installation inferred from the chart alone.
	OriginConvention
)

func (o Origin) String() string {
	switch o {
	case OriginDescriptor:
		return "descriptor"
	case OriginParent:
		return "parent chart"
	default:
		return "convention"
	}
}

// Installation is one deployment of a chart.
type Installation struct {
	// Release is the Helm release name. It may hold placeholders, as
	// "<gitrepo>-apps-web", where a part of it is only known when deployed.
	Release string
	// Namespace is the release namespace, empty when unknown.
	Namespace string
	// Layers are merged over the chart's values, in order.
	Layers []Layer
	// ReplaceChartValues makes the first layers that are files the chart's
	// values in place of its values.yaml, as Flux valuesFiles do.
	ReplaceChartValues bool
	// Source says where the installation comes from, for logs.
	Source string
	Origin Origin
}

// Layer is one source of values of an installation.
type Layer struct {
	// File is a values file of the scan.
	File string
	// Values are inline values.
	Values map[string]interface{}
	// Set are --set expressions, SetString --set-string ones.
	Set, SetString []string
	// Fill only takes the keys no layer below, nor the chart, sets: test and
	// lint values stand in for what is supplied when deployed, they never
	// override what the chart or a deployment says.
	Fill bool
}

// String describes the installation for logs.
func (i *Installation) String() string {
	ns := i.Namespace
	if ns == "" {
		ns = "?"
	}
	return fmt.Sprintf("release %q in namespace %q (%s, %s)", i.Release, ns, i.Origin, i.Source)
}

// ReadValuesFile reads a values file as Helm reads one given with -f.
func ReadValuesFile(fsys vfs.FS, path string) (map[string]interface{}, error) {
	data, err := fsys.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseValues(data)
}

// ParseValues parses values as Helm does. An empty document is no values.
func ParseValues(data []byte) (map[string]interface{}, error) {
	values := map[string]interface{}{}
	if err := yaml.Unmarshal(data, &values); err != nil {
		return nil, err
	}
	if values == nil {
		values = map[string]interface{}{}
	}
	return values, nil
}

// MergeValues merges override over base as Helm merges values files: maps
// merge key by key, anything else replaces.
func MergeValues(base, override map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(base)+len(override))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range override {
		if vm, ok := v.(map[string]interface{}); ok {
			if bm, ok := out[k].(map[string]interface{}); ok {
				out[k] = MergeValues(bm, vm)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// Missing returns the part of fill that set does not hold: the keys it lacks,
// and within maps both hold, the keys missing from set's.
func Missing(set, fill map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range fill {
		have, ok := set[k]
		if !ok {
			out[k] = v
			continue
		}
		hm, hok := have.(map[string]interface{})
		fm, fok := v.(map[string]interface{})
		if hok && fok {
			if sub := Missing(hm, fm); len(sub) > 0 {
				out[k] = sub
			}
		}
	}
	return out
}

// ApplySet applies --set (or --set-string when asString) expressions to values.
func ApplySet(values map[string]interface{}, exprs []string, asString bool) error {
	for _, expr := range exprs {
		var err error
		if asString {
			err = strvals.ParseIntoString(expr, values)
		} else {
			err = strvals.ParseInto(expr, values)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Each tool passes a value to --set its own way, which decides whether a
// comma or braces in it make a list.
var (
	// literalEscaper makes strvals read a value whole, as --set-file does.
	literalEscaper = strings.NewReplacer(`\`, `\\`, `,`, `\,`, `{`, `\{`, `}`, `\}`)
	// helmfileEscaper escapes a value as helmfile does.
	helmfileEscaper = strings.NewReplacer(`{`, `\{`, `}`, `\}`, `,`, `\,`)
)

// SetExpr is the --set expression giving name the value as written, which
// strvals parses: "{a,b}" is a list, as Terraform's helm provider passes it.
func SetExpr(name, value string) string {
	return name + "=" + value
}

// literalSetExpr is the --set-string expression giving name the value as it
// is, braces and commas included.
func literalSetExpr(name, value string) string {
	return name + "=" + literalEscaper.Replace(value)
}

// helmfileSetExpr is the --set expression helmfile passes for a value.
func helmfileSetExpr(name, value string) string {
	return name + "=" + helmfileEscaper.Replace(value)
}

// argoSetExpr is the --set expression Argo CD passes for a parameter: its
// commas escaped, unless it is a list.
func argoSetExpr(name, value string) string {
	if strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}") {
		return name + "=" + value
	}
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == ',' && (i == 0 || value[i-1] != '\\') {
			b.WriteByte('\\')
		}
		b.WriteByte(value[i])
	}
	return name + "=" + b.String()
}

// setListExpr is the --set expression giving name the list items, escaped by
// escape.
func setListExpr(name string, items []string, escape func(string) string) string {
	escaped := make([]string, len(items))
	for i, item := range items {
		escaped[i] = escape(item)
	}
	return name + "={" + strings.Join(escaped, ",") + "}"
}

// Resolve merges the layers of the installation that are not fills into user
// values, and returns them with the fill layers, which the caller applies once
// it knows the chart's own values. Unreadable files are reported through warn
// and skipped.
func (i *Installation) Resolve(fsys vfs.FS, warn func(error)) (values map[string]interface{}, fills []map[string]interface{}) {
	values = map[string]interface{}{}
	for _, layer := range i.Layers {
		layerValues, err := layer.read(fsys)
		if err != nil {
			warn(err)
			continue
		}
		if layer.Fill {
			fills = append(fills, layerValues)
			continue
		}
		values = MergeValues(values, layerValues)
		if err := ApplySet(values, layer.Set, false); err != nil {
			warn(err)
		}
		if err := ApplySet(values, layer.SetString, true); err != nil {
			warn(err)
		}
	}
	return values, fills
}

func (l *Layer) read(fsys vfs.FS) (map[string]interface{}, error) {
	values := map[string]interface{}{}
	if l.File != "" {
		read, err := ReadValuesFile(fsys, l.File)
		if err != nil {
			return nil, fmt.Errorf("values file %s: %w", l.File, err)
		}
		values = read
	}
	if l.Values != nil {
		// A copy: the values merged are written to, and the installation's
		// are shared by every render of it.
		values = MergeValues(values, copyValues(l.Values))
	}
	return values, nil
}

// copyValues returns a deep copy of values.
func copyValues(values map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(values))
	for k, v := range values {
		out[k] = copyValue(v)
	}
	return out
}

func copyValue(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		return copyValues(x)
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, e := range x {
			out[i] = copyValue(e)
		}
		return out
	default:
		return v
	}
}

// key identifies what the installation renders: two installations with the
// same key render the same documents.
func (i *Installation) key() string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%s\x00%t\x00", i.Release, i.Namespace, i.ReplaceChartValues)
	for _, l := range i.Layers {
		data, _ := json.Marshal(l.Values)
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%q\x00%q\x00%t\x00", filepath.Clean(l.File), data, l.Set, l.SetString, l.Fill)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// selectInstallations drops the installations identical to another one, the
// same release, namespace and layers. Installations with other values are all
// kept: each one can name resources the others do not.
func selectInstallations(installs []Installation) []Installation {
	seen := map[string]bool{}
	var out []Installation
	for _, inst := range installs {
		k := inst.key()
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, inst)
	}
	return out
}

// sortedKeys returns the keys of m in order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
