package helm

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/chart"
)

const helmIDNumberBase = 10

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

// setID will add auxiliary lines for each template as well as its dependencies,
// and returns their sources as they were before invocation markers were added.
func setID(chartReq *chart.Chart) stampedSources {
	sources := stampedSources{}
	stampChart(chartReq, sources)
	return sources
}

func stampChart(chartReq *chart.Chart, sources stampedSources) {
	for _, temp := range chartReq.Templates {
		sources[temp] = addID(temp).Data
		addHelmInvocationMarkers(temp)
	}
	// Stamp YAML CRDs for line mapping; JSON CRDs are skipped (YAML comments corrupt JSON).
	for _, f := range localCRDFiles(chartReq) {
		if isYAMLCRD(f.Name) {
			addID(f)
		}
	}
	for _, dep := range chartReq.Dependencies() {
		stampChart(dep, sources)
	}
}

// addID will add auxiliary lines used to detect line
// one for each top-level "apiVersion:" where the id is the source line index.
func addID(file *chart.File) *chart.File {
	split := strings.Split(string(file.Data), "\n")
	apiVersionLines := topLevelAPIVersionLines(split, isYAMLCRD(file.Name))

	stamped := make([]byte, 0, len(file.Data)+len(apiVersionLines)*24)
	nextAPIVersion := 0
	for i, line := range split {
		if nextAPIVersion < len(apiVersionLines) && apiVersionLines[nextAPIVersion] == i {
			stamped = append(stamped, "# KICS_HELM_ID_"...)
			stamped = strconv.AppendInt(stamped, int64(i), helmIDNumberBase)
			stamped = append(stamped, ':', '\n')
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
