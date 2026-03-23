/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package defaultYaml

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/utils"

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
	return resolved, yamlParser.ConvertKeysToString(addExtraInfo(ctx, documents, filePath)), ignoreLines, resolvedFiles, nil
}

// SupportedExtensions returns extensions supported by this parser, which are yaml and yml extension
func (p *Parser) SupportedExtensions() []string {
	return []string{".yaml", ".yml"}
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

func processCertContent(ctx context.Context, elements map[string]interface{}, content, filePath string) {
	var certInfo map[string]interface{}
	if content != "" {
		certInfo = utils.AddCertificateInfo(ctx, filePath, content)
		if certInfo != nil {
			elements["certificate"] = certInfo
		}
	}
}

func processElements(ctx context.Context, elements map[string]interface{}, filePath string) {
	if elements["certificate"] != nil {
		processCertContent(ctx, elements, utils.CheckCertificate(elements["certificate"].(string)), filePath)
	}
}

func addExtraInfo(ctx context.Context, documents []model.Document, filePath string) []model.Document {
	for _, documentPlaybooks := range documents { // iterate over documents
		if playbooks, ok := documentPlaybooks["playbooks"]; ok {
			processPlaybooks(ctx, playbooks, filePath)
		}
	}

	return documents
}

func processPlaybooks(ctx context.Context, playbooks interface{}, filePath string) {
	contextLogger := logger.FromContext(ctx)
	sliceResources, ok := playbooks.([]interface{})
	if !ok { // prevent panic if playbooks is not a slice
		contextLogger.Warn().Msgf("Failed to parse playbooks: %s", filePath)
		return
	}
	for _, resources := range sliceResources { // iterate over playbooks
		processPlaybooksElements(ctx, resources, filePath)
	}
}

func processPlaybooksElements(ctx context.Context, resources interface{}, filePath string) {
	contextLogger := logger.FromContext(ctx)
	mapResources, ok := resources.(map[string]interface{})
	if !ok {
		contextLogger.Warn().Msgf("Failed to parse playbooks elements: %s", filePath)
		return
	}
	for _, value := range mapResources {
		mapValue, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		processElements(ctx, mapValue, filePath)
	}
}

// GetCommentToken return the comment token of YAML - #
func (p *Parser) GetCommentToken() string {
	return "#"
}

// StringifyContent converts original content into string formatted version
func (p *Parser) StringifyContent(content []byte) (string, error) {
	return string(content), nil
}
