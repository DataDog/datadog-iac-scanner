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
	"slices"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/file"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

// Parser defines a parser type
type Parser struct {
	// FS supplies referenced files. Nil uses the real filesystem.
	FS vfs.FS
}

// Resolve - replace or modifies in-memory content before parsing
func (p *Parser) Resolve(ctx context.Context, fileContent []byte, filename string,
	resolveReferences bool, maxResolverDepth int) (resolved []byte, resolvedFiles map[string]model.ResolvedFile, err error) {
	res := file.NewResolver(p.FS, json.Unmarshal, json.Marshal, p.SupportedExtensions())
	if !res.MayResolve(ctx, fileContent, filename) {
		// The resolution would decode, walk and re-encode the whole file to
		// return fileContent unchanged.
		return fileContent, make(map[string]model.ResolvedFile), nil
	}
	// Resolve files passed as arguments with file resolver (e.g. file://)
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
	out, err := p.ParsePlan(ctx, fileContent, filePath, resolveReferences, maxResolverDepth)
	return out.Resolved, out.Documents, out.IgnoreLines, out.ResolvedFiles, err
}

// ParsePlan is Parse that also reports whether the file parsed as a Terraform
// plan. TerraformPlan is false for content that only looks like a plan, which
// falls back to a plain JSON document while keeping the plan kind (see
// KindForContent).
func (p *Parser) ParsePlan(ctx context.Context, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int) (model.ParseOutput, error) {
	resolved, resolvedFiles, err := p.Resolve(ctx, fileContent, filePath, resolveReferences, maxResolverDepth)
	if err != nil {
		return model.ParseOutput{}, err
	}

	r := model.Document{}
	err = json.Unmarshal(resolved, &r)
	if err != nil {
		var r []model.Document
		err = json.Unmarshal(resolved, &r)
		return model.ParseOutput{Documents: r, ResolvedFiles: resolvedFiles}, err
	}

	jLine := initializeJSONLine(resolved)
	jsonDoc := jLine.setLineInfo(r)
	out := model.ParseOutput{Resolved: resolved, Documents: []model.Document{jsonDoc}, ResolvedFiles: resolvedFiles}

	if !looksLikeTerraformPlan(fileContent) {
		// JSON is not a tf plan
		return out, nil
	}

	// Try to parse JSON as Terraform plan
	tfPlan, err := parseTFPlan(jsonDoc)
	if err != nil {
		// Fallback to regular json
		return out, nil
	}

	out.Documents = []model.Document{tfPlan}
	out.TerraformPlan = true
	return out, nil
}

// ParseLineInfo returns the line-info documents of a Terraform plan. Line
// detection only reads a plan's resource and configuration lines, so they
// are rebuilt alone instead of the whole plan for every rule with findings.
// ok is false for other content, and for a plan referencing files, whose
// resolved values only a full parse holds; those are parsed whole.
func (p *Parser) ParseLineInfo(fileContent []byte, filePath string) (documents []model.Document, ok bool) {
	return p.planDocuments(fileContent, filePath, parseTFPlanLineInfo)
}

// ParseUnannotated returns the documents of a Terraform plan without line
// markers, for a scan that rebuilds line info with ParseLineInfo: annotating
// the plan was most of its parse. ok is false as for ParseLineInfo.
func (p *Parser) ParseUnannotated(fileContent []byte, filePath string) (documents []model.Document, ok bool) {
	return p.planDocuments(fileContent, filePath, parseTFPlanContent)
}

// ParseLineInfoSection returns a line-info section that ParseLineInfo leaves
// out (see lazyLineInfoSections), annotated as a whole parse annotates it.
// ok is false for any other section or content, and for a plan referencing
// files, whose line-info document comes from a whole parse that holds every
// section.
func (p *Parser) ParseLineInfoSection(fileContent []byte, filePath, name string) (annotated interface{}, ok bool) {
	if !slices.Contains(lazyLineInfoSections, name) ||
		!looksLikeTerraformPlan(fileContent) || p.mayResolve(fileContent, filePath) {
		return nil, false
	}
	sections, ok := topLevelSections(fileContent)
	if !ok {
		return nil, false
	}
	if name == "data" {
		return parseTFPlanDataLineInfo(fileContent, sections)
	}
	section, ok := sections[name]
	if !ok {
		return nil, false
	}
	return annotatedSection(fileContent, name, &section)
}

// planDocuments parses fileContent with parse when it is a Terraform plan
// that references no file.
func (p *Parser) planDocuments(fileContent []byte, filePath string,
	parse func([]byte) (model.Document, bool)) ([]model.Document, bool) {
	if !looksLikeTerraformPlan(fileContent) || p.mayResolve(fileContent, filePath) {
		return nil, false
	}
	doc, ok := parse(fileContent)
	if !ok {
		return nil, false
	}
	return []model.Document{doc}, true
}

// mayResolve reports whether resolving fileContent can change it (see
// file.Resolver.MayResolve).
func (p *Parser) mayResolve(fileContent []byte, filename string) bool {
	return file.NewResolver(p.FS, json.Unmarshal, json.Marshal, p.SupportedExtensions()).
		MayResolve(context.Background(), fileContent, filename)
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
