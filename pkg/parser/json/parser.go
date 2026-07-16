/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	platformreg "github.com/DataDog/datadog-iac-scanner/pkg/platform"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/file"
)

// Parser parses JSON documents.
type Parser struct{}

// Resolve expands file references.
func (p *Parser) Resolve(ctx context.Context, fileContent []byte, filename string,
	resolveReferences bool, maxResolverDepth int) (resolved []byte, resolvedFiles map[string]model.ResolvedFile, err error) {
	res := file.NewResolver(json.Unmarshal, json.Marshal, p.SupportedExtensions())
	resolvedFilesCache := make(map[string]file.ResolvedFile)
	resolved = res.Resolve(ctx, fileContent, filename, 0, maxResolverDepth, resolvedFilesCache, resolveReferences)

	if len(res.ResolvedFiles) == 0 {
		return fileContent, res.ResolvedFiles, nil
	}

	return resolved, res.ResolvedFiles, nil
}

// Parse parses a JSON document.
func (p *Parser) Parse(ctx context.Context, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	return p.parse(ctx, fileContent, filePath, resolveReferences, maxResolverDepth, false)
}

// ParseCNI parses structurally validated CNI JSON using the shared JSON metadata path.
func (p *Parser) ParseCNI(ctx context.Context, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	return p.parse(ctx, fileContent, filePath, resolveReferences, maxResolverDepth, true)
}

func (p *Parser) parse(ctx context.Context, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int, allowCNI bool) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	resolved, resolvedFiles, err = p.Resolve(ctx, fileContent, filePath, resolveReferences, maxResolverDepth)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	r := model.Document{}
	err = json.Unmarshal(resolved, &r)
	if err != nil {
		var r []model.Document
		err = json.Unmarshal(resolved, &r)
		return nil, r, nil, resolvedFiles, err
	}
	if _, ok := platformreg.ClassifyStructuredContent(".json", resolved); ok && !allowCNI {
		return resolved, []model.Document{}, nil, resolvedFiles, nil
	}

	jLine := initializeJSONLine(resolved)
	jsonDoc := jLine.setLineInfo(r)

	if !looksLikeTerraformPlan(fileContent) {
		// JSON is not a tf plan
		return resolved, []model.Document{jsonDoc}, nil, resolvedFiles, nil
	}

	// Try to parse JSON as Terraform plan
	tfPlan, err := parseTFPlan(jsonDoc)
	if err != nil {
		// Fallback to regular json
		return resolved, []model.Document{jsonDoc}, nil, resolvedFiles, nil
	}

	return resolved, []model.Document{tfPlan}, nil, resolvedFiles, nil
}

// SupportedExtensions returns extensions supported by this parser, which is json extension
func (p *Parser) SupportedExtensions() []string {
	return []string{".json"}
}

// GetKind returns JSON constant kind
func (p *Parser) GetKind() model.FileKind {
	return model.KindJSON
}

// KindForContent overrides the static kind for Terraform plan JSON so line
// detection can resolve plan resources structurally instead of by text match.
func (p *Parser) KindForContent(content []byte) (model.FileKind, bool) {
	if looksLikeTerraformPlan(content) {
		return model.KindTerraformPlan, true
	}
	return "", false
}

// SupportedTypes returns types supported by this parser, which are cloudFormation
func (p *Parser) SupportedTypes() map[string]bool {
	return map[string]bool{
		"ansible":              true,
		"cloudformation":       true,
		"openapi":              true,
		"azureresourcemanager": true,
		"terraform":            true,
		"kubernetes":           true,
	}
}

// GetCommentToken return an empty string, since JSON does not have comment token
func (p *Parser) GetCommentToken() string {
	return ""
}

// StringifyContent converts original content into string formatted version
func (p *Parser) StringifyContent(content []byte) (string, error) {
	if looksLikeTerraformPlan(content) {
		var out bytes.Buffer
		if err := json.Indent(&out, content, "", "  "); err != nil {
			return "", err
		}
		return out.String(), nil
	}
	return string(content), nil
}

// looksLikeTerraformPlan is a fast byte-level heuristic that avoids a full
// JSON parse. Both keys are required by the Terraform plan JSON spec, so their
// co-presence is a reliable signal. Used by KindForContent and StringifyContent
// where a full parseTFPlan call would be redundant (Parse already does it).
func looksLikeTerraformPlan(content []byte) bool {
	return bytes.Contains(content, []byte(`"format_version"`)) &&
		bytes.Contains(content, []byte(`"planned_values"`))
}
