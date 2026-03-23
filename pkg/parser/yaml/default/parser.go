/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package defaultYaml

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	yamlParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml"
)

// Parser defines a parser type
type Parser struct {
}

// Parse parses yaml/yml file and returns it as a Document
func (p *Parser) Parse(ctx context.Context, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	resolved, documents, ignoreLines, resolvedFiles, err = yamlParser.Parse(ctx, fileContent, filePath, resolveReferences, maxResolverDepth)

	if err != nil {
		return nil, nil, nil, nil, err
	}

	// UnmarshalYAML already adds line tracking, so we can use documents directly
	return resolved, yamlParser.ConvertKeysToString(yamlParser.AddExtraInfo(ctx, documents, filePath)), ignoreLines, resolvedFiles, nil
}

// SupportedExtensions returns extensions supported by this parser, which are yaml and yml extension
func (p *Parser) SupportedExtensions() []string {
	return yamlParser.SupportedExtensions()
}

// SupportedTypes returns types supported by this parser, which are ansible, cloudFormation, k8s
func (p *Parser) SupportedTypes() map[string]bool {
	return map[string]bool{
		"ansible":                 true,
		"cloudformation":          true,
		"kubernetes":              true,
		"crossplane":              true,
		"knative":                 true,
		"openapi":                 true,
		"googledeploymentmanager": true,
		"pulumi":                  true,
		"serverlessfw":            true,
	}
}

// GetKind returns YAML constant kind
func (p *Parser) GetKind() model.FileKind {
	return model.KindYAML
}

// GetCommentToken return the comment token of YAML - #
func (p *Parser) GetCommentToken() string {
	return "#"
}

// StringifyContent converts original content into string formatted version
func (p *Parser) StringifyContent(content []byte) (string, error) {
	return string(content), nil
}
