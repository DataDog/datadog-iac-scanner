/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package occurrence

import (
	"cmp"
	"context"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/helmmarker"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	yamlparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml"
	"github.com/DataDog/datadog-iac-scanner/pkg/platforms"
	"gopkg.in/yaml.v3"
)

// Documents emits occurrences from parsed documents. Terraform occurrences
// come from module evaluation. Documents of the same file must be in the
// order their parser returned them.
func Documents(ctx context.Context, files model.FileMetadatas, add func(*model.FileMetadata, *model.ResourceOccurrence)) {
	e := documentEnumerator{ctx: ctx, charts: make(map[string]chartInfo)}
	// One path at a time, so that only one decoded file is held at once. The
	// documents of a path need not be next to each other in files, as
	// concurrent parsers store them; the stable sort keeps their order.
	byPath := make([]*model.FileMetadata, 0, len(files))
	for _, f := range files {
		if f != nil && f.Document != nil {
			byPath = append(byPath, f)
		}
	}
	slices.SortStableFunc(byPath, func(a, b *model.FileMetadata) int { return strings.Compare(a.FilePath, b.FilePath) })

	index := 0
	for i, f := range byPath {
		if i > 0 && f.FilePath == byPath[i-1].FilePath {
			index++
		} else {
			index = 0
		}
		rows := e.documentOccurrences(f, index)
		for j := range rows {
			rows[j].DocumentID = f.ID
			rows[j].DocumentIndex = index
			add(f, &rows[j])
		}
	}
}

type documentEnumerator struct {
	ctx context.Context
	// yaml is the file at yamlPath, decoded once for all its documents.
	yamlPath string
	yaml     *yamlFile
	charts   map[string]chartInfo
}

type lineRange struct{ start, end int }

// yamlFile is a YAML file decoded as the parser decodes it: its non-empty
// documents, their line ranges and the file's lines.
type yamlFile struct {
	nodes  []*yaml.Node
	ranges []lineRange
	lines  []string
}

type chartInfo struct{ name, version string }

// documentOccurrences returns the occurrences of the index-th document of f's file.
func (e *documentEnumerator) documentOccurrences(f *model.FileMetadata, index int) []model.ResourceOccurrence {
	switch {
	case f.Kind == model.KindDOCKER:
		return []model.ResourceOccurrence{dockerfileOccurrence(f)}
	case f.Platform == platforms.Kubernetes:
		return e.kubernetesOccurrences(f, index)
	case f.Platform == platforms.CloudFormation:
		return e.cloudFormationOccurrences(f, index)
	case f.Platform == platforms.DockerCompose:
		return e.keyedOccurrences(f, index, "services", lineInfoKey, composeServiceOccurrence)
	case f.Platform == platforms.CICD:
		return e.cicdOccurrences(f, index)
	case f.Platform == platforms.Ansible:
		return e.ansibleOccurrences(f, index)
	}
	return nil
}

// kubernetesObject is an object of a Kubernetes document: the document
// itself, or a member of a list it is.
type kubernetesObject struct {
	fields map[string]interface{}
	// node is the object in the decoded file, nil when unknown; span is its
	// lines, known only when aligned with the decoded document.
	node    *yaml.Node
	span    lineRange
	aligned bool
	// path addresses a list member within the parsed document. The root
	// object has an empty path.
	path model.SourcePath
	// apiVersion and kind are what a typed list gives a member that omits
	// them.
	apiVersion, kind string
}

// kubernetesOccurrences returns one occurrence per object, including members
// of list documents.
func (e *documentEnumerator) kubernetesOccurrences(f *model.FileMetadata, index int) []model.ResourceOccurrence {
	object := kubernetesObject{fields: f.Document}
	if node, span, found := e.documentNode(f, index); found {
		object.node, object.span = node, span
		// The decoded document must be this one; else its lines are not known.
		kind, _ := f.Document["kind"].(string)
		object.aligned = scalarValue(node, "kind") == kind
	}
	var rows []model.ResourceOccurrence
	e.kubernetesObjects(f, &object, &rows)
	return rows
}

// kubernetesObjects visits objects recursively through lists. A nested
// object such as a pod template stays part of its declaring resource.
func (e *documentEnumerator) kubernetesObjects(f *model.FileMetadata, object *kubernetesObject, rows *[]model.ResourceOccurrence) {
	apiVersion := cmp.Or(stringField(object.fields, "apiVersion"), object.apiVersion)
	kind := cmp.Or(stringField(object.fields, "kind"), object.kind)
	items, isList := kubernetesListItems(object.fields, kind)
	if !isList {
		if row, ok := e.kubernetesOccurrence(f, object, apiVersion, kind); ok {
			*rows = append(*rows, row)
		}
		return
	}
	var itemNodes []*yaml.Node
	var spans []lineRange
	if object.node != nil && object.aligned && f.Kind != model.KindHELM {
		lines := e.yamlFile(f).lines
		bound := sectionEnd(childSpans(object.node, object.span.end, lines), "items", object.span.end)
		if _, itemsNode := mappingEntry(object.node, "items"); itemsNode != nil && itemsNode.Kind == yaml.SequenceNode {
			itemNodes, spans = itemsNode.Content, itemSpans(itemsNode, bound, lines)
		}
	}
	// A typed list, such as a PodList, gives its members their kind.
	memberKind := strings.TrimSuffix(kind, "List")
	if kind == "List" {
		memberKind = ""
	}
	for i, item := range items {
		fields, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		member := kubernetesObject{
			fields:     fields,
			path:       extendPath(object.path, model.PathSegment{Key: "items"}, model.PathSegment{Index: i, IsIndex: true}),
			apiVersion: apiVersion,
			kind:       memberKind,
		}
		if i < len(itemNodes) && i < len(spans) {
			member.node, member.span, member.aligned = itemNodes[i], spans[i], true
		}
		e.kubernetesObjects(f, &member, rows)
	}
}

// kubernetesOccurrence records an object if it has a name.
func (e *documentEnumerator) kubernetesOccurrence(
	f *model.FileMetadata, object *kubernetesObject, apiVersion, kind string,
) (model.ResourceOccurrence, bool) {
	metadata, _ := object.fields["metadata"].(map[string]interface{})
	name := e.metadataField(f, object, metadata, "name")
	if name == "" {
		// A resource created with a generated name has only its prefix.
		name = e.metadataField(f, object, metadata, "generateName")
	}
	if apiVersion == "" || kind == "" || name == "" {
		return model.ResourceOccurrence{}, false
	}
	namespace := e.metadataField(f, object, metadata, "namespace")
	row := model.ResourceOccurrence{
		ResourcePath:   apiVersion + "/" + kind + "/" + namespace + "/" + name,
		Platform:       platforms.Kubernetes,
		ResourceType:   kind,
		ResourceName:   name,
		File:           f.FilePath,
		StructuralPath: object.path,
	}
	switch {
	case f.Kind == model.KindHELM:
		row.Source = lineSource(helmDocumentStart(f), 0)
		e.addHelmOrigin(&row, f)
	case object.node != nil && object.aligned:
		row.Source = lineSource(object.span.start, object.span.end)
		row.LegacySource = row.Source
	default:
		row.Source = lineSource(e.firstKeyLine(f), 0)
	}
	return row, true
}

func stringField(fields map[string]interface{}, key string) string {
	s, _ := fields[key].(string)
	return s
}

// kubernetesListItems returns the objects of a list, such as a kind: List
// or a typed PodList, which holds separate objects rather than being one. A
// named object is one object, whatever its kind ends with, such as an
// AllowList.
func kubernetesListItems(fields map[string]interface{}, kind string) ([]interface{}, bool) {
	metadata, _ := fields["metadata"].(map[string]interface{})
	if metadata["name"] != nil || metadata["generateName"] != nil {
		return nil, false
	}
	items, ok := fields["items"].([]interface{})
	return items, ok && strings.HasSuffix(kind, "List")
}

// scalarValue returns the value of key in a mapping node, "" when it is not a
// scalar.
func scalarValue(node *yaml.Node, key string) string {
	if _, value := mappingEntry(node, key); value != nil && value.Kind == yaml.ScalarNode {
		return value.Value
	}
	return ""
}

// metadataField returns a metadata field of a Kubernetes object. A value
// that is not a string, such as an unrendered template the YAML reads as a
// mapping ({{ .Name }}), is taken as written in the file.
func (e *documentEnumerator) metadataField(
	f *model.FileMetadata, object *kubernetesObject, metadata map[string]interface{}, key string,
) string {
	value, ok := metadata[key]
	if !ok {
		return ""
	}
	if s, ok := value.(string); ok {
		return s
	}
	if f.Kind == model.KindHELM || object.node == nil {
		return ""
	}
	_, metadataNode := mappingEntry(object.node, "metadata")
	_, valueNode := mappingEntry(metadataNode, key)
	return writtenValue(e.yamlFile(f).lines, valueNode)
}

// commentStart returns where a YAML comment starts in written, a # after a
// space and outside quotes, or its length when there is none.
func commentStart(written []rune) int {
	var quote rune
	for i, r := range written {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '#' && i > 0 && (written[i-1] == ' ' || written[i-1] == '\t'):
			return i
		}
	}
	return len(written)
}

// writtenValue returns a value as the file writes it. An unrendered
// {{ template }}, which YAML reads as a flow mapping, runs from its opening
// brace to the one that closes it, across lines if it spans several. Any
// other value runs from where it starts to the end of its line, less a
// trailing comment and the quotes around it.
func writtenValue(lines []string, value *yaml.Node) string {
	if value == nil || value.Line < 1 || value.Line > len(lines) || value.Column < 1 {
		return ""
	}
	line := []rune(lines[value.Line-1])
	if value.Column > len(line) {
		return ""
	}
	if value.Kind == yaml.MappingNode && line[value.Column-1] == '{' {
		return flowValue(lines, value.Line-1, value.Column-1)
	}
	written := line[value.Column-1:]
	text := strings.TrimSpace(string(written[:commentStart(written)]))
	for _, q := range []string{`"`, "'"} {
		if len(text) >= 2 && strings.HasPrefix(text, q) && strings.HasSuffix(text, q) {
			return text[1 : len(text)-1]
		}
	}
	return text
}

// flowValue returns the braced value that starts at lines[row][col], as
// written: up to the brace that closes it, quotes respected, the line breaks
// and whitespace inside kept. An unclosed value gives "".
func flowValue(lines []string, row, col int) string {
	var b strings.Builder
	depth := 0
	var quote rune
	for ; row < len(lines); row, col = row+1, 0 {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		for _, r := range []rune(lines[row])[col:] {
			b.WriteRune(r)
			switch {
			case quote != 0:
				if r == quote {
					quote = 0
				}
			case r == '"' || r == '\'':
				quote = r
			case r == '{':
				depth++
			case r == '}':
				depth--
				if depth == 0 {
					return b.String()
				}
			}
		}
	}
	return ""
}

// documentNode returns the root node of the index-th document of f's file,
// and the document's line range.
func (e *documentEnumerator) documentNode(f *model.FileMetadata, index int) (*yaml.Node, lineRange, bool) {
	file := e.yamlFile(f)
	if index >= len(file.nodes) {
		return nil, lineRange{}, false
	}
	return file.nodes[index], file.ranges[index], true
}

func (e *documentEnumerator) yamlFile(f *model.FileMetadata) *yamlFile {
	if e.yaml == nil || e.yamlPath != f.FilePath {
		e.yamlPath, e.yaml = f.FilePath, parseYAMLFile(f.OriginalData)
	}
	return e.yaml
}

// parseYAMLFile decodes the documents of a YAML file. A document ends at its
// last line that is neither blank, a comment nor a document marker, before
// the next document.
func parseYAMLFile(content string) *yamlFile {
	dec := yaml.NewDecoder(strings.NewReader(content))
	var nodes []*yaml.Node
	var starts []int
	for {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			break
		}
		// The parser keeps a mapping or a sequence and skips the rest.
		if yamlparser.IsEmptyDocument(&node) || node.Content[0].Kind == yaml.ScalarNode {
			continue
		}
		nodes = append(nodes, node.Content[0])
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
	return &yamlFile{nodes: nodes, ranges: ranges, lines: lines}
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
func (e *documentEnumerator) addHelmOrigin(row *model.ResourceOccurrence, f *model.FileMetadata) {
	origin := &model.HelmResourceOrigin{}
	row.Helm = origin
	path := filepath.ToSlash(f.FilePath)
	dir, rel, ok := splitChartPath(path)
	if !ok {
		return
	}
	origin.ChartPath = filepath.FromSlash(dir)
	origin.Template = rel
	info, cached := e.charts[dir]
	if !cached {
		info = readChart(filepath.FromSlash(dir))
		e.charts[dir] = info
	}
	origin.ChartName = info.name
	origin.ChartVersion = info.version
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

// dockerfileOccurrence is the one resource of a Dockerfile, spanning its
// instructions.
func dockerfileOccurrence(f *model.FileMetadata) model.ResourceOccurrence {
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
	return model.ResourceOccurrence{
		ResourcePath: "Dockerfile",
		Platform:     platforms.Dockerfile,
		ResourceType: "dockerfile",
		ResourceName: filepath.Base(f.FilePath),
		File:         f.FilePath,
		Source:       lineSource(start, end),
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

func extendPath(base model.SourcePath, next ...model.PathSegment) model.SourcePath {
	return append(slices.Clone(base), next...)
}

func lineSource(start, end int) model.ResourceLocation {
	return model.ResourceLocation{Start: model.ResourceLine{Line: start}, End: model.ResourceLine{Line: end}}
}

func writtenSpan(span lineRange, known bool) model.ResourceLocation {
	if !known {
		return model.ResourceLocation{}
	}
	return lineSource(span.start, span.end)
}
