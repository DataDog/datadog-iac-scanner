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
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/file"
)

// Parser defines a parser type
type Parser struct{}

// Resolve - replace or modifies in-memory content before parsing
func (p *Parser) Resolve(ctx context.Context, fileContent []byte, filename string,
	resolveReferences bool, maxResolverDepth int) (resolved []byte, resolvedFiles map[string]model.ResolvedFile, err error) {
	// Resolve files passed as arguments with file resolver (e.g. file://)
	res := file.NewResolver(json.Unmarshal, json.Marshal, p.SupportedExtensions())
	resolvedFilesCache := make(map[string]file.ResolvedFile)
	resolved = res.Resolve(ctx, fileContent, filename, 0, maxResolverDepth, resolvedFilesCache, resolveReferences)

	if len(res.ResolvedFiles) == 0 {
		return fileContent, res.ResolvedFiles, nil
	}

	return resolved, res.ResolvedFiles, nil
}

// Parse parses json file and returns it as a Document
func (p *Parser) Parse(ctx context.Context, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int) (
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

	jLine := initializeJSONLine(resolved)
	jsonDoc := jLine.setLineInfo(r)

	// Try to parse JSON as Terraform plan
	tfPlan, err := parseTFPlan(jsonDoc)
	if err != nil {
		// JSON is not a tf plan
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
	if contentIsTerraformPlan(content) {
		var out bytes.Buffer
		if err := json.Indent(&out, content, "", "  "); err != nil {
			return "", err
		}
		return out.String(), nil
	}
	return string(content), nil
}

// contentIsTerraformPlan reports whether content parses as a Terraform plan,
// using the same check as Parse. Stateless and per-call. Recovers from panics
// in plan parsing (malformed/partial plans) and treats them as "not a plan".
func contentIsTerraformPlan(content []byte) (isPlan bool) {
	defer func() {
		if recover() != nil {
			isPlan = false
		}
	}()
	var doc model.Document
	if err := json.Unmarshal(content, &doc); err != nil {
		return false
	}
	if _, err := parseTFPlan(doc); err != nil {
		return false
	}
	return true
}
