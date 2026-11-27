/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"io/fs"
	"path/filepath"
	"slices"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/comment"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/hclcache"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/terragrunt"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/pkg/errors"
)

// EnableTerragrunt makes the parser accept terragrunt.hcl units (--x-terragrunt).
func (p *Parser) EnableTerragrunt() {
	p.terragrunt = true
}

// SetFetchedModules gives the parser the directories the pre-scan fetched for
// the remote modules of units.
func (p *Parser) SetFetchedModules(dirs terragrunt.ModuleDirs) {
	p.fetchedModules = dirs
}

func (p *Parser) isTerragruntUnit(path string) bool {
	return p.terragrunt && tfpath.IsTerragruntUnit(path)
}

// ParseUnit parses a Terragrunt unit: the documents are those of its
// translation, with line information in the lines of the unit's files, and
// the original content stays the unit file. handled is false for any other
// file, or when Terragrunt is not enabled.
func (p *Parser) ParseUnit(ctx context.Context, fileContent []byte, path string) (model.ParseOutput, bool, error) {
	if !p.isTerragruntUnit(path) {
		return model.ParseOutput{}, false, nil
	}
	resolved, err := tfmodules.ResolveConfigContent(ctx, p.fsys, path, "", fileContent)
	if errors.Is(err, tfmodules.ErrSkippedLinkPlaceholder) {
		return model.ParseOutput{}, true, nil
	}
	if err != nil {
		return model.ParseOutput{}, true, err
	}

	unit, err := terragrunt.Evaluate(ctx, p.fsys, p.sciInfo.RepositoryDir, path, resolved, p.fetchedModules)
	if err != nil {
		return model.ParseOutput{}, true, errors.Wrap(err, "failed terragrunt parse")
	}
	translation := unit.Translation

	out := model.ParseOutput{
		Resolved:              resolved,
		Documents:             []model.Document{{}},
		TerragruntTranslation: translation,
		TerragruntInputs:      unit.Inputs,
	}
	if !model.IsLineInfoOnly(ctx) {
		out.IgnoreLines = fileIgnoreLines(ctx, resolved, path)
		p.readIncluded(ctx, translation, path)
	}
	if translation == nil {
		return out, true, nil
	}

	virtual := filepath.Join(filepath.Dir(path), translation.FileName)
	file, diags := hclcache.ParseConfig(ctx, []byte(translation.Text), virtual)
	if diags.HasErrors() {
		return model.ParseOutput{}, true, errors.Wrap(diags.Errs()[0], "failed terragrunt parse")
	}
	doc, err := p.convertFunc(ctx, file, converter.VariableMap{}, converter.Options{
		BaseDir:      filepath.Dir(path),
		FS:           p.fsys,
		SkipLineInfo: model.IsLazyLineInfo(ctx),
	})
	if err != nil {
		return model.ParseOutput{}, true, errors.Wrap(err, "failed terragrunt parse")
	}
	terragrunt.RemapLines(doc, translation.Lines, path)
	out.Documents = []model.Document{doc}
	return out, true, nil
}

// readIncluded records the ignore lines and commands of each file other than
// the unit that the line table points at.
func (p *Parser) readIncluded(ctx context.Context, t *model.TerragruntTranslation, unit string) {
	if t == nil {
		return
	}
	for _, m := range t.Lines {
		name := m.Real.Filename
		if _, done := t.Included[name]; done || name == "" || name == unit {
			continue
		}
		content, err := p.fsys.ReadFile(name)
		if err != nil {
			continue
		}
		if t.Included == nil {
			t.Included = make(map[string]model.IncludedFile)
		}
		t.Included[name] = model.IncludedFile{
			LinesIgnore: fileIgnoreLines(ctx, content, name),
			Commands:    comment.FileCommands("#", name, string(content)),
		}
	}
}

// fileIgnoreLines reads the ignore comments of an HCL file.
func fileIgnoreLines(ctx context.Context, content []byte, path string) []int {
	file, diags := hclcache.ParseConfig(ctx, content, path)
	if diags.HasErrors() {
		return nil
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil
	}
	ignore, err := comment.ParseComments(content, path)
	if err != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Err(err).Msg("failed to parse comments")
	}
	return comment.GetIgnoreLines(ignore, body)
}

// unitInputs returns the inputs of the directory's terragrunt.hcl: its .tf
// files take them as TF_VAR_*. It is nil with the flag off, without a unit,
// or when the unit is skipped.
func (p *Parser) unitInputs(ctx context.Context, dir string) converter.VariableMap {
	if !p.terragrunt {
		return nil
	}
	key := filepath.Clean(dir)
	if v, ok := p.unitInputsCache.Load(key); ok {
		return v.(converter.VariableMap)
	}
	inputs := p.readUnitInputs(ctx, dir)
	p.unitInputsCache.Store(key, inputs)
	return inputs
}

func (p *Parser) readUnitInputs(ctx context.Context, dir string) converter.VariableMap {
	entries, err := p.fsys.ReadDir(dir)
	if err != nil || !slices.ContainsFunc(entries, func(e fs.DirEntry) bool {
		return !e.IsDir() && e.Name() == tfpath.TerragruntUnit
	}) {
		return nil
	}
	path := filepath.Join(dir, tfpath.TerragruntUnit)
	src, err := tfmodules.ReadConfigFile(ctx, p.fsys, path, "")
	if err != nil {
		return nil
	}
	unit, err := terragrunt.Evaluate(ctx, p.fsys, p.sciInfo.RepositoryDir, path, src, nil)
	if err != nil || len(unit.Inputs) == 0 {
		return nil
	}
	return converter.VariableMap(unit.Inputs)
}
