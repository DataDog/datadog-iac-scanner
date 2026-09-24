/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// dockerComposeDetectLine resolves compose findings structurally from the
// document's _dd_lines first: text matching walks the file lines in order and
// misattributes values merged in from sibling files (e.g. an image inherited
// via extends). Text matching stays as the fallback for other YAML platforms
// and for failed lookups.
type DockerComposeDetectLine struct{}

// DetectLine resolves the vulnerability line for a finding.
func (d DockerComposeDetectLine) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string,
	outputLines int) model.VulnerabilityLines {
	if strings.EqualFold(file.Platform, "dockercompose") && file.LineInfoDocument != nil {
		if result := detectDockerComposeLine(searchKey, file, file.Lines(), outputLines); result != nil {
			return *result
		}
	}
	return defaultDetectLine{}.DetectLine(ctx, file, searchKey, outputLines)
}

// detectDockerComposeLine resolves the line from _dd_lines; the second
// candidate drops the first path component for search keys carrying a
// platform prefix (e.g. "dockerCompose.services.web.image").
func detectDockerComposeLine(searchKey string, file *model.FileMetadata, lines []string,
	outputLines int) *model.VulnerabilityLines {
	path := ComposeSearchPath(searchKey)
	// The first attempt uses the full path; the second drops the leading
	// component, which covers search keys rooted at a platform prefix that is
	// not part of the document (e.g. "dockerCompose.services.web.image").
	for _, candidates := range [][]string{path, dropFirst(path)} {
		if len(candidates) == 0 {
			continue
		}
		lineNr := GetLineBySearchLine(candidates, file)
		if lineNr <= 0 || lineNr > len(lines) {
			continue
		}
		return &model.VulnerabilityLines{
			Line:         lineNr,
			VulnLines:    GetAdjacentVulnLines(lineNr-1, outputLines, lines),
			ResolvedFile: file.FilePath,
			VulnerablilityLocation: model.ResourceLocation{
				Start: model.ResourceLine{Line: lineNr},
				End:   model.ResourceLine{Line: lineNr},
			},
		}
	}
	return nil
}

// ComposeSearchPath turns a search key into structural path components using
// the shared search-key expansion (anchor stripping, top-level dot split,
// bracket group expansion), the same rules the Terraform plan path uses.
func ComposeSearchPath(searchKey string) []string {
	return expandSearchKeyPath(searchKey)
}

// dropFirst returns path without its first component, or nil when there is
// nothing left (the caller skips empty candidates).
func dropFirst(path []string) []string {
	if len(path) < 2 {
		return nil
	}
	return path[1:]
}
