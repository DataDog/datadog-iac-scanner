/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/comment"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/terragrunt"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// parseTerragrunt parses a Terragrunt file into the Terraform its generate
// and remote_state blocks write, one document per generated file, with the
// lines they have in the Terragrunt file. Its other blocks never become
// documents: rules run on the modules units call. A file writing nothing
// yields one empty document, so its ignore comments still apply to findings
// attributed to it.
func (p *Parser) parseTerragrunt(ctx context.Context, content []byte, path string) (
	resolved []byte,
	documents []model.Document,
	ignoreLines []int,
	resolvedFiles map[string]model.ResolvedFile,
	err error,
) {
	file, diags := hclsyntax.ParseConfig(content, filepath.Base(path), hcl.Pos{Byte: 0, Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, nil, nil, nil, diags.Errs()[0]
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return content, []model.Document{{}}, nil, nil, nil
	}
	ignore, commentErr := comment.ParseComments(content, path)
	if commentErr != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Err(commentErr).Msgf("failed to parse comments of %s", path)
	}
	documents = p.terragruntDocuments(ctx, path)
	if len(documents) == 0 {
		documents = []model.Document{{}}
	}
	return content, documents, comment.GetIgnoreLines(ignore, body), nil, nil
}

// terragruntDocuments converts what the file's own generate and remote_state
// blocks write; blocks of included files belong to those files.
func (p *Parser) terragruntDocuments(ctx context.Context, path string) []model.Document {
	abs, err := p.fsys.Abs(path)
	if err != nil {
		abs = filepath.Clean(path)
	}
	root := p.sciInfo.RepositoryDir
	if root == "" {
		root = filepath.Dir(abs)
	}
	unit, err := terragrunt.New(p.fsys, root).EvaluateUnit(ctx, abs)
	if err != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Debug().Err(err).Msgf("terragrunt: not converting the files %s generates", path)
		return nil
	}
	var documents []model.Document
	for i := range unit.Generated {
		generated := &unit.Generated[i]
		if generated.Filename != unit.ConfigFile || !tfpath.IsHCLConfig(generated.Path) {
			continue
		}
		if doc, ok := p.terraformDocument(ctx, alignedSource(generated.Contents, generated.ContentsStart), path); ok {
			documents = append(documents, doc)
		}
	}
	if state := unit.RemoteState; state != nil && state.Range.Filename == unit.ConfigFile {
		if doc, ok := p.terraformDocument(ctx, backendSource(state), path); ok {
			documents = append(documents, doc)
		}
	}
	return documents
}

// terraformDocument converts Terraform source like a .tf file of path's
// directory, without its variables.
func (p *Parser) terraformDocument(ctx context.Context, src []byte, path string) (model.Document, bool) {
	file, diags := hclsyntax.ParseConfig(src, filepath.Base(path), hcl.Pos{Byte: 0, Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, false
	}
	doc, err := p.convertFunc(ctx, file, converter.VariableMap{}, converter.Options{BaseDir: filepath.Dir(path), FS: p.fsys})
	if err != nil {
		return nil, false
	}
	docs, err := addExtraInfo(ctx, []model.Document{doc}, path)
	if err != nil || len(docs) == 0 {
		return nil, false
	}
	return docs[0], true
}

// alignedSource places src so its first line is at start's line.
func alignedSource(src string, start hcl.Pos) []byte {
	return []byte(strings.Repeat("\n", max(start.Line-1, 0)) + src)
}

// backendSource is the backend block remote_state configures, written at the
// remote_state block's line.
func backendSource(state *terragrunt.RemoteState) []byte {
	var b strings.Builder
	b.WriteString("terraform {\n  backend " + string(hclwrite.TokensForValue(cty.StringVal(state.Backend)).Bytes()) + " {\n")
	if state.Config.IsWhollyKnown() && !state.Config.IsNull() && state.Config.CanIterateElements() {
		config := state.Config.AsValueMap()
		names := make([]string, 0, len(config))
		for name := range config {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if !hclsyntax.ValidIdentifier(name) {
				continue
			}
			b.WriteString("    " + name + " = " + string(hclwrite.TokensForValue(config[name]).Bytes()) + "\n")
		}
	}
	b.WriteString("  }\n}\n")
	return alignedSource(b.String(), state.Range.Start)
}
