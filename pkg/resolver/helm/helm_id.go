package helm

import (
	"path"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/helmmarker"
	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/chart"
)

// stampedSources holds each template's data once stamped with ID lines and
// before invocation markers are added: the source findings are located in.
// Keys are the chart files themselves, which stay the same objects while Helm
// renders and the resolver renames them.
type stampedSources map[*chart.File][]byte

// of returns the stamped source of file, or its data for a file that was not
// recorded, such as a CRD.
func (s stampedSources) of(file *chart.File) []byte {
	if data, ok := s[file]; ok {
		return data
	}
	return file.Data
}

// invocationMarks decides which templates get invocation markers and records
// what the stamping did, by template name as Helm reports it (the chart's full
// path joined with the template's). A nil one marks every template.
type invocationMarks struct {
	// none leaves every template unmarked.
	none bool
	// unmarked are the templates left unmarked.
	unmarked map[string]bool
	// seen are the templates the stamping visited, marked are those of them
	// that received a marker.
	seen, marked map[string]bool
}

func newInvocationMarks() *invocationMarks {
	return &invocationMarks{unmarked: map[string]bool{}, seen: map[string]bool{}, marked: map[string]bool{}}
}

// mark adds invocation markers to the template file named template, unless it
// is left unmarked, and records it.
func (m *invocationMarks) mark(template string, file *chart.File) {
	if m == nil {
		addHelmInvocationMarkers(file)
		return
	}
	if m.seen != nil {
		m.seen[template] = true
	}
	if m.none || m.unmarked[template] {
		return
	}
	stamped := len(file.Data)
	if len(addHelmInvocationMarkers(file).Data) > stamped && m.marked != nil {
		m.marked[template] = true
	}
}

// setID will add auxiliary lines for each template as well as its dependencies,
// and returns their sources as they were before invocation markers were added.
// Invocation markers are only added to the templates marks allows.
func setID(chartReq *chart.Chart, marks *invocationMarks) stampedSources {
	sources := stampedSources{}
	stampChart(chartReq, sources, marks, new(int))
	return sources
}

// stampChart stamps each template and YAML CRD of the chart and its
// dependencies. Every file takes the next number of templates, so a stamp is
// unique across the whole chart: a document emitted by an include carries the
// stamp of the partial it comes from, which must never equal one of the
// template that includes it.
func stampChart(chartReq *chart.Chart, sources stampedSources, marks *invocationMarks, templates *int) {
	next := func() int {
		*templates++
		return *templates - 1
	}
	for _, temp := range chartReq.Templates {
		sources[temp] = addID(temp, next()).Data
		marks.mark(path.Join(chartReq.ChartFullPath(), temp.Name), temp)
	}
	// Stamp YAML CRDs for line mapping; JSON CRDs are skipped (YAML comments corrupt JSON).
	for _, f := range localCRDFiles(chartReq) {
		if isYAMLCRD(f.Name) {
			addID(f, next())
		}
	}
	for _, dep := range chartReq.Dependencies() {
		stampChart(dep, sources, marks, templates)
	}
}

// addID will add auxiliary lines used to detect line: one for each top-level
// "apiVersion:", naming the template and its 0-based source line index (see
// helmmarker.ID).
func addID(file *chart.File, template int) *chart.File {
	split := strings.Split(string(file.Data), "\n")
	apiVersionLines := topLevelAPIVersionLines(split, isYAMLCRD(file.Name))

	stamped := make([]byte, 0, len(file.Data)+len(apiVersionLines)*24)
	nextAPIVersion := 0
	for i, line := range split {
		if nextAPIVersion < len(apiVersionLines) && apiVersionLines[nextAPIVersion] == i {
			stamped = helmmarker.ID{Template: template, Line: i}.Append(stamped)
			nextAPIVersion++
		}
		stamped = append(stamped, line...)
		if i+1 < len(split) {
			stamped = append(stamped, '\n')
		}
	}
	file.Data = stamped
	return file
}

func topLevelAPIVersionLines(lines []string, exhaustive bool) []int {
	var result []int
	for documentStart := 0; documentStart < len(lines); {
		documentEnd := documentStart
		for documentEnd < len(lines) && !isYAMLDocumentBoundary(lines[documentEnd]) {
			documentEnd++
		}
		result = appendDocumentAPIVersionLine(result, lines, documentStart, documentEnd, exhaustive)

		documentStart = documentEnd + 1
		if documentEnd == len(lines) {
			break
		}
	}
	return result
}

func appendDocumentAPIVersionLine(
	result []int, lines []string, documentStart, documentEnd int, exhaustive bool,
) []int {
	minIndent := -1
	for lineNumber := documentStart; lineNumber < documentEnd; lineNumber++ {
		line := lines[lineNumber]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "%") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if minIndent < 0 || indent < minIndent {
			minIndent = indent
		}
	}

	resultStart := len(result)
	mayNeedFallback := false
	for lineNumber := documentStart; lineNumber < documentEnd; lineNumber++ {
		line := lines[lineNumber]
		mayNeedFallback = mayNeedFallback || strings.Contains(line, "apiVersion")
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == minIndent && isAPIVersionKey(line[indent:]) {
			result = append(result, lineNumber)
		}
	}
	if len(result) == resultStart && (exhaustive || mayNeedFallback) {
		if lineNumber, ok := parsedAPIVersionLine(lines[documentStart:documentEnd]); ok {
			result = append(result, documentStart+lineNumber)
		}
	}
	return result
}

func parsedAPIVersionLine(lines []string) (int, bool) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(strings.Join(lines, "\n")), &document); err != nil ||
		len(document.Content) == 0 {
		return 0, false
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return 0, false
	}
	for index := 0; index+1 < len(root.Content); index += 2 {
		key := root.Content[index]
		if key.Value == "apiVersion" {
			return key.Line - 1, true
		}
	}
	return 0, false
}

func isYAMLDocumentBoundary(line string) bool {
	line = strings.TrimRight(line, " \t\r")
	if len(line) < 3 || (line[:3] != "---" && line[:3] != "...") {
		return false
	}
	return len(line) == 3 || strings.HasPrefix(strings.TrimSpace(line[3:]), "#")
}

func isAPIVersionKey(line string) bool {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "{") {
		line = strings.TrimSpace(line[1:])
	}
	explicitKey := strings.HasPrefix(line, "?")
	if explicitKey {
		line = strings.TrimSpace(line[1:])
	}

	var remainder string
	switch {
	case strings.HasPrefix(line, "'apiVersion'"):
		remainder = line[len("'apiVersion'"):]
	case strings.HasPrefix(line, `"apiVersion"`):
		remainder = line[len(`"apiVersion"`):]
	case strings.HasPrefix(line, "apiVersion"):
		remainder = line[len("apiVersion"):]
	default:
		return false
	}
	remainder = strings.TrimSpace(remainder)
	if explicitKey {
		return remainder == "" || strings.HasPrefix(remainder, "#")
	}
	return strings.HasPrefix(remainder, ":")
}
