/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/comment"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	masterUtils "github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/pkg/errors"
)

const (
	// RetriesDefaultValue is default number of times a parser will retry to execute
	RetriesDefaultValue     = 50
	terraformDataIdentifier = "data"
)

// Converter returns content json, error line, error
type Converter func(
	ctx context.Context,
	file *hcl.File,
	inputVariables converter.VariableMap,
	opts converter.Options,
) (model.Document, error)

// Parser struct that contains the function to parse file and the number of retries if something goes wrong
type Parser struct {
	convertFunc  Converter
	numOfRetries int
	sciInfo      model.SCIInfo

	// fsys is the filesystem used to read files the parsed file refers to.
	// Defaults to the real disk; the HTTP server injects an in-memory FS
	// populated from pushed content.
	fsys vfs.FS
}

// NewDefault initializes a parser with Parser default values
func NewDefault() *Parser {
	return &Parser{
		numOfRetries: RetriesDefaultValue,
		convertFunc:  converter.Convert,
		fsys:         vfs.DiskFS{},
	}
}

// nolint:gocritic
func NewDefaultWithParams(fsys vfs.FS, sciInfo model.SCIInfo) *Parser {
	parser := NewDefault()
	if fsys != nil {
		parser.fsys = fsys
	}
	parser.sciInfo = sciInfo
	return parser
}

// Resolve - replace or modifies in-memory content before parsing
func (p *Parser) Resolve(ctx context.Context,
	fileContent []byte,
	filename string, _ bool, _ int) (resolved []byte, vars converter.VariableMap, err error) {
	// handle panic during resolve process
	defer func() {
		if r := recover(); r != nil {
			errMessage := "Recovered from panic during resolve of file " + filename
			masterUtils.HandlePanic(ctx, r, errMessage)
		}
	}()
	fileContent, err = tfmodules.ResolveConfigContent(ctx, p.fsys, filename, "", fileContent)
	if err != nil {
		return nil, nil, err
	}
	return fileContent, nil, nil
}

// Parse execute parser for the content in a file
func (p *Parser) Parse(ctx context.Context, fileContent []byte, path string,
	resolveReferences bool, maxResolverDepth int) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error) {
	contextLogger := logger.FromContext(ctx)
	resolved, inputVariables, err := p.Resolve(ctx, fileContent, path, resolveReferences, maxResolverDepth)
	if errors.Is(err, tfmodules.ErrSkippedLinkPlaceholder) {
		return nil, nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if tfpath.IsJSONConfig(path) {
		fc, parseErr := parseJSONConfig(resolved, path)
		return resolved, []model.Document{fc}, nil, resolvedFiles, errors.Wrap(parseErr, "failed terraform parse")
	}

	file, diagnostics := hclsyntax.ParseConfig(resolved, filepath.Base(path), hcl.Pos{Byte: 0, Line: 1, Column: 1})
	defer func() {
		if r := recover(); r != nil {
			errMessage := "Recovered from panic during parsing of file " + path
			masterUtils.HandlePanic(ctx, r, errMessage)
			err = fmt.Errorf("%s: %v", errMessage, r)
		}
	}()
	if diagnostics != nil && diagnostics.HasErrors() && len(diagnostics.Errs()) > 0 {
		err := diagnostics.Errs()[0]
		return nil, nil, nil, nil, err
	}

	ignore, err := comment.ParseComments(resolved, path)
	if err != nil {
		contextLogger.Err(err).Msg("failed to parse comments")
	}

	linesToIgnore := comment.GetIgnoreLines(ignore, file.Body.(*hclsyntax.Body))

	fc, parseErr := p.convertFunc(ctx, file, inputVariables, converter.Options{
		BaseDir: filepath.Dir(path),
		FS:      p.fsys,
	})
	return resolved, []model.Document{fc}, linesToIgnore, resolvedFiles, errors.Wrap(parseErr, "failed terraform parse")
}

// SupportedExtensions returns Terraform/OpenTofu extensions.
func (p *Parser) SupportedExtensions() []string {
	return []string{tfpath.ExtTF, tfpath.ExtTofu, tfpath.ExtTFJSON, tfpath.ExtTofuJSON, tfpath.ExtTFVars}
}

// SupportedTypes returns types supported by this parser, which are terraform
func (p *Parser) SupportedTypes() map[string]bool {
	return map[string]bool{"terraform": true}
}

// GetKind returns Terraform kind parser
func (p *Parser) GetKind() model.FileKind {
	return model.KindTerraform
}

// GetCommentToken return the comment token of Terraform - #
func (p *Parser) GetCommentToken() string {
	return "#"
}

// StringifyContent converts original content into string formatted version
func (p *Parser) StringifyContent(content []byte) (string, error) {
	return string(content), nil
}
