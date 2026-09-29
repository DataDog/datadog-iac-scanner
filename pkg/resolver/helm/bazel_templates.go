package helm

import (
	"bytes"
	"path"
	"regexp"
	"strings"

	"helm.sh/helm/v3/pkg/chart"
)

// Only a literal exports_files([...]) declaration is recognized. In particular,
// do not exclude every BUILD.bazel by name: a misnamed real manifest, Helm
// actions, or mixed/unknown contents must retain normal rendering semantics.
const bazelStringLiteral = `(?:"[^"\\\r\n{}]*"|'[^'\\\r\n{}]*')`

var bazelExportsFileRE = regexp.MustCompile(`^\s*exports_files\s*\(\s*\[\s*(?:` +
	bazelStringLiteral + `\s*,\s*)*` + bazelStringLiteral + `?\s*\]\s*,?\s*\)\s*$`)

func isBazelExportsFile(file *chart.File) bool {
	if path.Base(file.Name) != "BUILD.bazel" || bytes.Contains(file.Data, []byte("{{")) {
		return false
	}
	var content strings.Builder
	for _, line := range strings.Split(string(file.Data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		content.WriteString(line)
		content.WriteByte('\n')
	}
	return bazelExportsFileRE.MatchString(content.String())
}

// Source-tree charts can carry Bazel package metadata that is not part of the
// packaged Helm chart. Filter only proven metadata from the render input, after
// either loader, recursively including directory and archive dependencies.
// Raw and Files remain intact for exclusions, attribution and .Files access.
func excludeBazelTemplates(ch *chart.Chart) {
	templates := ch.Templates[:0]
	for _, file := range ch.Templates {
		if !isBazelExportsFile(file) {
			templates = append(templates, file)
		}
	}
	ch.Templates = templates
	for _, dependency := range ch.Dependencies() {
		excludeBazelTemplates(dependency)
	}
}
