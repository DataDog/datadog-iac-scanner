/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package cni

import (
	"context"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	jsonparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	platformreg "github.com/DataDog/datadog-iac-scanner/pkg/platform"
)

// Parser parses CNI JSON configuration files.
type Parser struct {
	json jsonparser.Parser
}

func (p *Parser) Parse(
	ctx context.Context,
	fileContent []byte,
	filePath string,
	resolveReferences bool,
	maxResolverDepth int,
) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error,
) {
	if _, ok := platformreg.ClassifyStructuredContent(filepath.Ext(filePath), fileContent); !ok {
		return fileContent, []model.Document{}, []int{}, nil, nil
	}
	return p.json.ParseCNI(ctx, fileContent, filePath, resolveReferences, maxResolverDepth)
}

func (*Parser) SupportedExtensions() []string {
	return []string{".json", ".conf", ".conflist"}
}

func (*Parser) SupportedTypes() map[string]bool {
	return map[string]bool{
		string(platformreg.Kubernetes): true,
	}
}

func (*Parser) GetKind() model.FileKind {
	return model.KindJSON
}

func (p *Parser) GetCommentToken() string {
	return p.json.GetCommentToken()
}

func (p *Parser) StringifyContent(content []byte) (string, error) {
	return p.json.StringifyContent(content)
}
