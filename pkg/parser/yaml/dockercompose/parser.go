/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package dockercompose

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	yamlParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/dockercompose/names"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"gopkg.in/yaml.v3"
)

// envFileName is the default Compose environment file, read from the
// compose file's directory.
const envFileName = ".env"

// Parser is the DockerCompose-flavored YAML parser: shared YAML handling plus
// Compose-spec interpolation resolved from the sibling .env file (never the
// host environment). Unresolvable references stay in place so rules see the
// original expression instead of a fabricated empty value.
type Parser struct {
	fsys vfs.FS
}

// NewDefaultWithFS returns a Parser reading sibling files (like .env) through
// fsys. A nil fsys falls back to the real disk.
func NewDefaultWithFS(fsys vfs.FS) *Parser {
	if fsys == nil {
		fsys = vfs.DiskFS{}
	}
	return &Parser{fsys: fsys}
}

// Parse parses a Compose YAML file and returns it as Documents, with
// interpolation applied before line tracking so every rewritten value keeps
// the line it was declared on.
func (p *Parser) Parse(ctx context.Context, fileContent []byte, filePath string,
	resolveReferences bool, maxResolverDepth int) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	// Cheap byte scans decide whether the semantic path (sibling reads) pays
	// off; deliberately loose: a false positive only costs the extra work.
	needsEnv := bytes.IndexByte(fileContent, '$') >= 0 || bytes.Contains(fileContent, []byte("env_file"))
	needsSiblings := needsEnv || bytes.Contains(fileContent, []byte("extends")) ||
		names.IsDefaultBaseFileName(filePath)
	if !needsSiblings {
		resolved, documents, ignoreLines, resolvedFiles, err = yamlParser.Parse(
			ctx, fileContent, filePath, resolveReferences, maxResolverDepth)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return resolved, yamlParser.ConvertKeysToString(yamlParser.AddExtraInfo(ctx, documents, filePath)), ignoreLines, resolvedFiles, nil
	}

	t := &transformer{
		ctx:    ctx,
		fsys:   p.fsys,
		dir:    filepath.Dir(filePath),
		self:   filePath,
		logger: logger.FromContext(ctx),
	}
	if needsEnv {
		t.env = p.loadEnv(ctx, filePath)
	}
	if names.IsDefaultBaseFileName(filePath) {
		t.overrideContent = p.loadOverride(ctx, filePath)
	}

	transform := func(node *yaml.Node) {
		t.transform(node)
	}

	documents, ignoreLines, err = yamlParser.ParseWithNodeTransformNoResolve(
		ctx, fileContent, filePath, transform)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return fileContent, yamlParser.ConvertKeysToString(yamlParser.AddExtraInfo(ctx, documents, filePath)), ignoreLines, resolvedFiles, nil
}

// loadEnv reads the .env file next to the compose file, returning nil when it
// does not exist or cannot be read (Compose also just proceeds without it).
func (p *Parser) loadEnv(ctx context.Context, filePath string) map[string]string {
	contextLogger := logger.FromContext(ctx)
	content, err := p.fsys.ReadFile(filepath.Join(filepath.Dir(filePath), envFileName))
	if err != nil {
		contextLogger.Debug().Msgf("dockercompose: no .env loaded for %s: %s", filePath, err)
		return nil
	}
	return ParseEnvFile(content)
}

// loadOverride reads the sibling Compose override file when one exists,
// returning nil content otherwise. Only the default names are auto-merged.
func (p *Parser) loadOverride(ctx context.Context, filePath string) []byte {
	contextLogger := logger.FromContext(ctx)
	dir := filepath.Dir(filePath)
	for _, name := range names.OverrideFileNames {
		content, err := p.fsys.ReadFile(filepath.Join(dir, name))
		if err == nil {
			return content
		}
		if !errors.Is(err, fs.ErrNotExist) {
			contextLogger.Debug().Msgf("dockercompose: could not read override %s: %s", name, err)
		}
	}
	return nil
}

// SupportedExtensions returns extensions supported by this parser, which are yaml and yml extension
func (p *Parser) SupportedExtensions() []string {
	return yamlParser.SupportedExtensions()
}

// SupportedTypes returns types supported by this parser, which is dockercompose
func (p *Parser) SupportedTypes() map[string]bool {
	return map[string]bool{
		"dockercompose": true,
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
