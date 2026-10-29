package detector

import (
	"context"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// KustomizeDetectLine finds the line of a finding raised on a document
// Kustomize rendered, in the file it was rendered from. Search keys name the
// rendered resource; they are rewritten to its name and namespace as written.
// A generated object is reported on its generator entry, whose line alone is
// shown so that generator literals never reach the output.
type KustomizeDetectLine struct{}

// DetectLine resolves the vulnerability line for a finding.
func (KustomizeDetectLine) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string,
	outputLines int) model.VulnerabilityLines {
	a := file.Kustomize
	if a == nil {
		return defaultDetectLine{}.DetectLine(ctx, file, searchKey, outputLines)
	}
	if a.Generator != nil {
		return generatorLine(file, a)
	}
	return defaultDetectLine{}.DetectLine(ctx, file, SourceSearchKey(a, searchKey), outputLines)
}

// SourceSearchKey rewrites the rendered name and namespace of a's resource in
// searchKey's bracketed values to the ones written in its source file.
func SourceSearchKey(a *model.KustomizeAttribution, searchKey string) string {
	if a.SourceName != "" && a.RenderedName != a.SourceName {
		searchKey = strings.ReplaceAll(searchKey, "{{"+a.RenderedName+"}}", "{{"+a.SourceName+"}}")
	}
	if a.RenderedNamespace != a.SourceNamespace {
		to := ""
		if a.SourceNamespace != "" {
			to = "{{" + a.SourceNamespace + "}}"
		}
		if a.RenderedNamespace != "" && to != "" {
			searchKey = strings.ReplaceAll(searchKey, "{{"+a.RenderedNamespace+"}}", to)
		}
	}
	return searchKey
}

func generatorLine(file *model.FileMetadata, a *model.KustomizeAttribution) model.VulnerabilityLines {
	lines := file.Lines()
	line := 1
	for i, l := range lines {
		t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "- "))
		if t == "name: "+a.Generator.Name || t == `name: "`+a.Generator.Name+`"` {
			line = i + 1
			break
		}
	}
	text := ""
	if line <= len(lines) {
		text = lines[line-1]
	}
	loc := model.ResourceLocation{
		Start: model.ResourceLine{Line: line, Col: 1},
		End:   model.ResourceLine{Line: line, Col: len(text) + 1},
	}
	return model.VulnerabilityLines{
		Line:                   line,
		VulnLines:              &[]model.CodeLine{{Position: line, Line: text}},
		LineWithVulnerability:  text,
		ResolvedFile:           file.FilePath,
		VulnerablilityLocation: loc,
		RemediationLocation:    loc,
		BlockLocation:          loc,
		ResourceSource:         text,
		FileSource:             []string{text},
	}
}
