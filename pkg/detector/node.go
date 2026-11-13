package detector

import (
	"strconv"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// NodeLocation is what a rule contract finding resolves to: the deepest
// source range and resource identity on the way to the node it names.
type NodeLocation struct {
	Source       model.Source
	ResourceType string
	ResourceName string
}

// LocateNode walks pointer, a list of object keys and array indices, from
// root. It reports false when the pointer leaves the model or crosses no
// node carrying a source.
func LocateNode(root any, pointer []string) (NodeLocation, bool) {
	var location NodeLocation
	found := false
	node := root
	for i := 0; ; i++ {
		if object, ok := node.(map[string]any); ok {
			if source, ok := decodeSource(object["source"]); ok {
				location.Source, found = source, true
			}
			if resourceType, ok := object["resource_type"].(string); ok {
				location.ResourceType = resourceType
			}
			if resourceName, ok := object["resource_name"].(string); ok {
				location.ResourceName = resourceName
			}
		}
		if i == len(pointer) {
			return location, found
		}
		switch typed := node.(type) {
		case map[string]any:
			next, ok := typed[pointer[i]]
			if !ok {
				return location, false
			}
			node = next
		case []any:
			index, err := strconv.Atoi(pointer[i])
			if err != nil || index < 0 || index >= len(typed) {
				return location, false
			}
			node = typed[index]
		default:
			return location, false
		}
	}
}

func decodeSource(value any) (model.Source, bool) {
	object, ok := value.(map[string]any)
	if !ok {
		return model.Source{}, false
	}
	field := func(name string) int {
		number, _ := object[name].(float64)
		return int(number)
	}
	source := model.Source{
		Line: field("line"), Column: field("column"), EndLine: field("end_line"), EndColumn: field("end_column"),
	}
	return source, source.Line > 0
}

// SourceLines reports a source range of file as the location of a finding.
func SourceLines(file *model.FileMetadata, source model.Source, outputLines int) model.VulnerabilityLines {
	lines := file.Lines()
	result := model.VulnerabilityLines{
		Line:         source.Line,
		VulnLines:    GetAdjacentVulnLines(source.Line-1, outputLines, lines),
		ResolvedFile: file.FilePath,
		VulnerablilityLocation: model.ResourceLocation{
			Start: model.ResourceLine{Line: source.Line, Col: source.Column},
			End:   model.ResourceLine{Line: source.EndLine, Col: source.EndColumn},
		},
	}
	if source.Line <= len(lines) {
		result.LineWithVulnerability = lines[source.Line-1]
	}
	return result
}
