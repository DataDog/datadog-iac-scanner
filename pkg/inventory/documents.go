/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/helmmarker"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	yamlparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml"
	"gopkg.in/yaml.v3"
)

// Platform values of the document rows, the values findings carry.
const (
	PlatformKubernetes = "kubernetes"
	PlatformDockerfile = "dockerfile"
)

// DocumentResources returns the rows of the parsed documents of every
// platform but Terraform, whose rows come from module evaluation. The files
// of one path must be in the order their parser returned them, as a scan
// stores them.
func DocumentResources(ctx context.Context, files model.FileMetadatas) []Resource {
	e := documentEnumerator{ctx: ctx, charts: make(map[string]chartInfo)}
	var rows []Resource
	docIndex := make(map[string]int)
	for _, f := range files {
		if f == nil || f.Document == nil {
			continue
		}
		index := docIndex[f.FilePath]
		docIndex[f.FilePath] = index + 1
		switch {
		case f.Kind == model.KindDOCKER:
			rows = append(rows, dockerfileResource(f))
		case f.Platform == PlatformKubernetes:
			if row, ok := e.kubernetesResource(f, index); ok {
				rows = append(rows, row)
			}
		}
	}
	return rows
}

type documentEnumerator struct {
	ctx context.Context
	// lines caches the document line ranges of each multi-document file.
	lines  map[string][]lineRange
	charts map[string]chartInfo
}

type lineRange struct{ start, end int }

type chartInfo struct{ name, version string }

func (e *documentEnumerator) kubernetesResource(f *model.FileMetadata, index int) (Resource, bool) {
	apiVersion, _ := f.Document["apiVersion"].(string)
	kind, _ := f.Document["kind"].(string)
	metadata, _ := f.Document["metadata"].(map[string]interface{})
	name, _ := metadata["name"].(string)
	if apiVersion == "" || kind == "" || name == "" {
		return Resource{}, false
	}
	namespace, _ := metadata["namespace"].(string)
	row := Resource{
		ResourcePath: apiVersion + "/" + kind + "/" + namespace + "/" + name,
		Platform:     PlatformKubernetes,
		ResourceType: kind,
		ResourceName: name,
		File:         f.FilePath,
		Completeness: CompletenessComplete,
	}
	if f.Kind == model.KindHELM {
		row.LineStart = helmDocumentStart(f)
		e.addHelmOrigin(&row, f)
		return row, true
	}
	if r, ok := e.documentLines(f, index); ok {
		row.LineStart, row.LineEnd = r.start, r.end
	} else {
		row.LineStart = e.firstKeyLine(f)
	}
	return row, true
}

// documentLines returns the line range of the index-th document of f's file,
// counted as the YAML parser counts them.
func (e *documentEnumerator) documentLines(f *model.FileMetadata, index int) (lineRange, bool) {
	if e.lines == nil {
		e.lines = make(map[string][]lineRange)
	}
	ranges, ok := e.lines[f.FilePath]
	if !ok {
		ranges = yamlDocumentLines(f.OriginalData)
		e.lines[f.FilePath] = ranges
	}
	if index >= len(ranges) {
		return lineRange{}, false
	}
	return ranges[index], true
}

// yamlDocumentLines returns the line range of each non-empty document of a
// YAML file. A document ends at its last line that is neither blank, a
// comment nor a document marker, before the next document.
func yamlDocumentLines(content string) []lineRange {
	dec := yaml.NewDecoder(strings.NewReader(content))
	var starts []int
	for {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			break
		}
		if yamlparser.IsEmptyDocument(&node) {
			continue
		}
		starts = append(starts, node.Content[0].Line)
	}
	lines := strings.Split(content, "\n")
	ranges := make([]lineRange, len(starts))
	for i, start := range starts {
		// A document ends before the next document marker, which starts a
		// line, or at the end of the file.
		end := len(lines)
		for n := start + 1; n <= len(lines); n++ {
			if isDocumentMarker(lines[n-1]) {
				end = n - 1
				break
			}
		}
		for end > start && isYAMLFiller(lines[end-1]) {
			end--
		}
		ranges[i] = lineRange{start: start, end: end}
	}
	return ranges
}

func isDocumentMarker(line string) bool {
	for _, marker := range []string{"---", "..."} {
		if rest, ok := strings.CutPrefix(line, marker); ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t' || rest[0] == '\r') {
			return true
		}
	}
	return false
}

func isYAMLFiller(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "---") || strings.HasPrefix(trimmed, "...")
}

// firstKeyLine returns the line of the document's first key, from its line
// information, when its position in the file is not known.
func (e *documentEnumerator) firstKeyLine(f *model.FileMetadata) int {
	loaded := f.LineInfoDocument != nil
	if err := f.EnsureLineInfoDocument(e.ctx); err != nil {
		return 1
	}
	if !loaded {
		defer f.DiscardLineInfoDocument()
	}
	first := math.MaxInt
	lines, _ := f.LineInfoDocument["_dd_lines"].(map[string]interface{})
	for _, v := range lines {
		if line := lineObjectLine(v); line > 0 && line < first {
			first = line
		}
	}
	if first == math.MaxInt {
		return 1
	}
	return first
}

func lineObjectLine(v interface{}) int {
	switch o := v.(type) {
	case model.LineObject:
		return o.Line
	case *model.LineObject:
		if o != nil {
			return o.Line
		}
	case map[string]interface{}:
		return numberValue(o["_dd_line"])
	}
	return 0
}

// helmDocumentStart is the template line a rendered document starts at: the
// line after its stamp when the template holds it, else the first include's.
func helmDocumentStart(f *model.FileMetadata) int {
	source := 0
	for _, line := range strings.Split(f.OriginalData, "\n") {
		if _, ok := helmmarker.ParseIDLine(line); !ok {
			source++
		} else if f.HelmID != "" && strings.TrimSpace(line) == strings.TrimSpace(f.HelmID) {
			return source + 1
		}
	}
	if f.HelmAttribution != nil && len(f.HelmAttribution.Invocations) > 0 {
		return max(f.HelmAttribution.Invocations.First().Line, 1)
	}
	return 1
}

// addHelmOrigin fills the origin of a document rendered from a chart: the
// chart holding the template and the template's path in it.
func (e *documentEnumerator) addHelmOrigin(row *Resource, f *model.FileMetadata) {
	row.OriginGenerator = "helm"
	path := filepath.ToSlash(f.FilePath)
	dir, rel, ok := splitChartPath(path)
	if !ok {
		return
	}
	row.OriginChartPath = filepath.FromSlash(dir)
	row.OriginTemplate = rel
	info, cached := e.charts[dir]
	if !cached {
		info = readChart(filepath.FromSlash(dir))
		e.charts[dir] = info
	}
	row.OriginChartName = info.name
	row.OriginChartVersion = info.version
}

// splitChartPath splits a template path into its chart directory and the
// template's path in the chart.
func splitChartPath(path string) (chartDir, template string, ok bool) {
	for _, dir := range []string{"/templates/", "/crds/"} {
		if i := strings.LastIndex(path, dir); i > 0 {
			return path[:i], path[i+1:], true
		}
	}
	return "", "", false
}

// readChart reads a chart's name and version from its Chart.yaml, falling
// back to the directory name when the chart is not on disk, as for a packaged
// dependency.
func readChart(dir string) chartInfo {
	info := chartInfo{name: filepath.Base(dir)}
	data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "Chart.yaml")))
	if err != nil {
		return info
	}
	var chart struct {
		Name    string `yaml:"name"`
		Version string `yaml:"version"`
	}
	if yaml.Unmarshal(data, &chart) == nil {
		if chart.Name != "" {
			info.name = chart.Name
		}
		info.version = chart.Version
	}
	return info
}

// dockerfileResource is the one row of a Dockerfile, spanning its
// instructions.
func dockerfileResource(f *model.FileMetadata) Resource {
	start, end := math.MaxInt, 0
	var visit func(v interface{})
	visit = func(v interface{}) {
		switch t := v.(type) {
		case map[string]interface{}:
			if line := numberValue(t["_dd_line"]); line > 0 {
				start = min(start, line)
				end = max(end, line, numberValue(t["EndLine"]))
			}
			for _, child := range t {
				visit(child)
			}
		case []interface{}:
			for _, child := range t {
				visit(child)
			}
		}
	}
	visit(map[string]interface{}(f.Document))
	if start == math.MaxInt {
		start, end = 1, 0
	}
	return Resource{
		ResourcePath: "Dockerfile",
		Platform:     PlatformDockerfile,
		ResourceType: "dockerfile",
		ResourceName: filepath.Base(f.FilePath),
		File:         f.FilePath,
		LineStart:    start,
		LineEnd:      end,
		Completeness: CompletenessComplete,
	}
}

func numberValue(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}
