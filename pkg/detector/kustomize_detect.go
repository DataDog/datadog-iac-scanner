package detector

import (
	"context"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"gopkg.in/yaml.v3"
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
	return detectSourceLine(ctx, file, SourceSearchKey(a, searchKey), outputLines, a.SourceDocumentIndex)
}

// SourceSearchKey rewrites the rendered metadata name and namespace of a's
// resource in searchKey to the ones written in its source file; other values
// that happen to equal them, such as a container name, are left alone.
func SourceSearchKey(a *model.KustomizeAttribution, searchKey string) string {
	if a.SourceName != "" && a.RenderedName != a.SourceName {
		searchKey = strings.ReplaceAll(searchKey, "metadata.name={{"+a.RenderedName+"}}", "metadata.name={{"+a.SourceName+"}}")
	}
	if a.RenderedNamespace != "" && a.SourceNamespace != "" && a.RenderedNamespace != a.SourceNamespace {
		searchKey = strings.ReplaceAll(searchKey, "metadata.namespace={{"+a.RenderedNamespace+"}}",
			"metadata.namespace={{"+a.SourceNamespace+"}}")
	}
	return searchKey
}

func generatorLine(file *model.FileMetadata, a *model.KustomizeAttribution) model.VulnerabilityLines {
	lines := file.Lines()
	// Without a matching entry line, line 1 is reported with no source text:
	// any line of a kustomization may hold generator literals.
	line, text := 1, ""
	for i, l := range lines {
		t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "- "))
		if t == "name: "+a.Generator.Name || t == `name: "`+a.Generator.Name+`"` {
			line, text = i+1, l
			break
		}
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

// detectSourceLine scopes the text search to the document the resource was
// rendered from, so a same-name document of another kind cannot win, and
// translates the offsets back to the whole file.
func detectSourceLine(ctx context.Context, file *model.FileMetadata, key string,
	outputLines, docIndex int) model.VulnerabilityLines {
	if docIndex < 0 {
		return defaultDetectLine{}.DetectLine(ctx, file, key, outputLines)
	}
	start, end, ok := documentSpan(file.OriginalData, docIndex)
	if !ok {
		return defaultDetectLine{}.DetectLine(ctx, file, key, outputLines)
	}
	lines := file.Lines()
	if start < 1 || end > len(lines) || start > end {
		return defaultDetectLine{}.DetectLine(ctx, file, key, outputLines)
	}
	span := append([]string(nil), lines[start-1:end]...)
	sub := &model.FileMetadata{FilePath: file.FilePath, OriginalData: strings.Join(span, "\n"), Kind: file.Kind}
	sub.LinesOriginalData = &span
	got := defaultDetectLine{}.DetectLine(ctx, sub, key, outputLines)
	if got.Line < 1 {
		// The mapped document does not hold the key: report nothing rather
		// than a line from another document of the same file.
		return got
	}
	shift(&got, start-1)
	return got
}

// documentSpan returns the 1-based start and end lines of the index-th
// document of a multi-document YAML file: each document ends where the next
// one starts, not at EOF.
func documentSpan(content string, index int) (start, end int, ok bool) {
	dec := yaml.NewDecoder(strings.NewReader(content))
	var starts []int
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			break
		}
		starts = append(starts, doc.Line)
	}
	if index < 0 || index >= len(starts) {
		return 0, 0, false
	}
	start = starts[index]
	if start < 1 {
		start = 1
	}
	end = strings.Count(content, "\n") + 1
	if index+1 < len(starts) && starts[index+1] > start {
		end = starts[index+1] - 1
	}
	return start, end, true
}

func shift(v *model.VulnerabilityLines, by int) {
	if by == 0 {
		return
	}
	v.Line += by
	v.VulnerablilityLocation.Start.Line += by
	v.VulnerablilityLocation.End.Line += by
	v.RemediationLocation.Start.Line += by
	v.RemediationLocation.End.Line += by
	v.BlockLocation.Start.Line += by
	v.BlockLocation.End.Line += by
	if v.VulnLines != nil {
		shifted := make([]model.CodeLine, len(*v.VulnLines))
		for i, l := range *v.VulnLines {
			l.Position += by
			shifted[i] = l
		}
		v.VulnLines = &shifted
	}
}
