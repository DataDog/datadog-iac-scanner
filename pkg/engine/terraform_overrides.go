/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"context"
	"errors"
	"maps"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

const (
	terraformResourceBlock  = "resource"
	terraformLifecycleBlock = "lifecycle"
)

type overrideDefinition struct {
	path string
	model.TerraformBlock
}

func (d overrideDefinition) indexType() string {
	if d.Kind == dataRoot {
		return dataTypePrefix + d.Type
	}
	return d.Type
}

type overrideProjection struct {
	config   tfeval.ResourceOverride
	decl     *model.FileMetadata
	live     bool
	remove   bool
	document map[string]interface{}
}

// unitOverride is an override a Terragrunt unit's files make to a module's
// block. It holds for the calls whose call chain starts with chain.
type unitOverride struct {
	chain  string
	config tfeval.ResourceOverride
}

type terraformOverrides struct {
	repoPath string
	byPath   map[string]*model.FileMetadata
	// unitSources are the override sources that only hold for the calls of a
	// unit, by call chain prefix, declaration file ID and block.
	unitSources map[string]map[string]map[model.TerraformBlock]*model.TerraformOverrideSource
	definitions map[overrideDefinition]*overrideProjection
	fragments   instantiatedIndex
}

func scanTerraformOverrides(
	ctx context.Context, evaluator *tfeval.Evaluator, byPath map[string]*model.FileMetadata,
	filesByDir map[string][]*model.FileMetadata, repoPath string, unitConfigs []unitOverride,
) *terraformOverrides {
	var overrides *terraformOverrides
	for _, u := range unitConfigs {
		if overrides == nil {
			overrides = newTerraformOverrides(repoPath, byPath)
		}
		overrides.addUnit(u)
	}
	for dir, files := range filesByDir {
		for _, f := range files {
			if !tfpath.IsOverrideFile(f.FilePath) {
				continue
			}
			for _, config := range evaluator.ResourceOverrides(ctx, dir) {
				if overrides == nil {
					overrides = newTerraformOverrides(repoPath, byPath)
				}
				overrides.add(config)
			}
			break
		}
	}
	return overrides
}

func newTerraformOverrides(repoPath string, byPath map[string]*model.FileMetadata) *terraformOverrides {
	return &terraformOverrides{repoPath: repoPath, byPath: byPath,
		definitions: make(map[overrideDefinition]*overrideProjection), fragments: make(instantiatedIndex)}
}

// addUnit records the override of a unit: its other fragments are no longer
// scanned where they are written, and its sources apply to the unit's call only.
func (o *terraformOverrides) addUnit(u unitOverride) {
	decl := u.config.Declaration
	file := o.byPath[absPath(decl.TypeRange.Filename, o.repoPath)]
	if file == nil {
		return
	}
	for _, fragment := range u.config.Contributions {
		if f := o.byPath[absPath(fragment.TypeRange.Filename, o.repoPath)]; f != nil {
			kind := fragment.Labels[0]
			if fragment.Type == dataRoot {
				kind = dataTypePrefix + kind
			}
			o.fragments.add(f.ID, kind, fragment.Labels[1])
		}
	}
	key, source := o.overrideSource(file, model.TerraformBlock{Kind: decl.Type, Type: decl.Labels[0], Name: decl.Labels[1]}, &u.config)
	if o.unitSources == nil {
		o.unitSources = make(map[string]map[string]map[model.TerraformBlock]*model.TerraformOverrideSource)
	}
	if o.unitSources[u.chain] == nil {
		o.unitSources[u.chain] = make(map[string]map[model.TerraformBlock]*model.TerraformOverrideSource)
	}
	if o.unitSources[u.chain][file.ID] == nil {
		o.unitSources[u.chain][file.ID] = make(map[model.TerraformBlock]*model.TerraformOverrideSource)
	}
	o.unitSources[u.chain][file.ID][key] = source
}

// unitSourcesFor returns the sources of base with those of the unit that owns
// callChain on top.
func (o *terraformOverrides) unitSourcesFor(
	fileID, callChain string, base map[model.TerraformBlock]*model.TerraformOverrideSource,
) map[model.TerraformBlock]*model.TerraformOverrideSource {
	for chain, byFile := range o.unitSources {
		if !strings.HasPrefix(callChain, chain+"|") || byFile[fileID] == nil {
			continue
		}
		merged := maps.Clone(base)
		if merged == nil {
			merged = make(map[model.TerraformBlock]*model.TerraformOverrideSource)
		}
		maps.Copy(merged, byFile[fileID])
		return merged
	}
	return base
}

func (o *terraformOverrides) add(config tfeval.ResourceOverride) {
	decl := config.Declaration
	path := absPath(decl.TypeRange.Filename, o.repoPath)
	file := o.byPath[path]
	if file == nil {
		return // the declaration is outside the scan input
	}
	key := model.TerraformBlock{Kind: decl.Type, Type: decl.Labels[0], Name: decl.Labels[1]}
	o.definitions[overrideDefinition{path, key}] = &overrideProjection{config: config, decl: file}
	for _, fragment := range config.Contributions {
		if f := o.byPath[absPath(fragment.TypeRange.Filename, o.repoPath)]; f != nil {
			kind := fragment.Labels[0]
			if fragment.Type == dataRoot {
				kind = dataTypePrefix + kind
			}
			o.fragments.add(f.ID, kind, fragment.Labels[1])
		}
	}
}

func (o *terraformOverrides) record(
	ctx context.Context, evaluator *tfeval.Evaluator, resources []tfeval.ResolvedResource,
) {
	if o == nil || len(o.definitions) == 0 {
		return
	}
	for i := range resources {
		r := &resources[i]
		kind := terraformResourceBlock
		if r.Data {
			kind = dataRoot
		}
		key := model.TerraformBlock{Kind: kind, Type: r.Type, Name: tfeval.ResourceBaseName(r.Name)}
		p := o.definitions[overrideDefinition{absPath(r.DefinedIn, o.repoPath), key}]
		if p == nil {
			continue
		}
		p.live = true
		if r.ModuleAddress == "" && p.document == nil {
			p.document = evaluator.OverrideDocument(ctx, &p.config, r.Scope)
		}
	}
}

// prepare renders the standalone fallback for unevaluated or untargeted
// modules inside the same panic boundary as module evaluation.
func (o *terraformOverrides) prepare(
	ctx context.Context, evaluator *tfeval.Evaluator, res *moduleResolutionResult, evaluatedChildren map[string]bool,
) {
	if o == nil {
		return
	}
	fallbackScopes := make(map[string]*tfeval.ModuleScope)
	for def, projection := range o.definitions {
		dir := filepath.Dir(def.path)
		evaluated := res.successfulRoots[dir] || evaluatedChildren[dir]
		unresolved := res.unresolvedModuleDirs[dir]
		projection.remove = !projection.live && evaluated && !unresolved
		replaced := res.suppressed[projection.decl.ID][def.indexType()][def.Name] && !unresolved
		if projection.remove || replaced {
			projection.document = nil
		} else if projection.document == nil {
			scope, ok := fallbackScopes[dir]
			if !ok {
				scope = evaluator.StandaloneOverrideScope(ctx, dir)
				fallbackScopes[dir] = scope
			}
			projection.document = evaluator.OverrideDocument(ctx, &projection.config, scope)
		}
	}
}

func (o *terraformOverrides) apply(files model.FileMetadatas, docs []model.Document, syntheticFiles []*model.FileMetadata) {
	if o == nil {
		return
	}
	for _, file := range files {
		if file != nil {
			removeInstantiatedResources(file.Document, o.fragments[file.ID])
		}
	}
	for def, projection := range o.definitions {
		file := projection.decl
		if projection.remove {
			removeInstantiatedResources(file.Document, map[string]map[string]bool{def.indexType(): {def.Name: true}})
			continue
		}
		o.setSource(file, def.TerraformBlock, &projection.config)
		if projection.document != nil {
			setTerraformBlock(file, def.TerraformBlock, projection.document)
		}
	}
	for i, synthetic := range syntheticFiles {
		if file := o.byPath[absPath(synthetic.FilePath, o.repoPath)]; file != nil {
			sources := o.unitSourcesFor(file.ID, synthetic.ModuleCallChain, file.TerraformOverrides)
			synthetic.TerraformOverrides = withUnqualifiedDataOverrides(sources, docs[i])
		}
	}
	for _, file := range files {
		if file != nil && len(file.TerraformOverrides) > 0 {
			file.TerraformOverrides = withUnqualifiedDataOverrides(file.TerraformOverrides, file.Document)
		}
	}
}

// Some legacy rules name data blocks without a data prefix. Record that alias
// only in documents where the data block has no same-named managed resource.
// The document itself may be released before finding source lookup.
func withUnqualifiedDataOverrides(
	sources map[model.TerraformBlock]*model.TerraformOverrideSource, document model.Document,
) map[model.TerraformBlock]*model.TerraformOverrideSource {
	var aliased map[model.TerraformBlock]*model.TerraformOverrideSource
	data := docAsMap(document[dataRoot])
	resources := docAsMap(document[terraformResourceBlock])
	for key, source := range sources {
		if key.Kind == dataRoot && docAsMap(data[key.Type])[key.Name] != nil && docAsMap(resources[key.Type])[key.Name] == nil {
			if aliased == nil {
				aliased = maps.Clone(sources)
			}
			key.Kind = ""
			aliased[key] = source
		}
	}
	if aliased != nil {
		return aliased
	}
	return sources
}

func setTerraformBlock(file *model.FileMetadata, key model.TerraformBlock, document map[string]interface{}) {
	if file.Document == nil {
		file.Document = make(model.Document)
	}
	kind := docAsMap(file.Document[key.Kind])
	if kind == nil {
		kind = make(model.Document)
		file.Document[key.Kind] = kind
	}
	byName := docAsMap(kind[key.Type])
	if byName == nil {
		byName = make(model.Document)
		kind[key.Type] = byName
	}
	byName[key.Name] = document
}

func (o *terraformOverrides) setSource(
	file *model.FileMetadata, key model.TerraformBlock, config *tfeval.ResourceOverride,
) {
	_, source := o.overrideSource(file, key, config)
	if file.TerraformOverrides == nil {
		file.TerraformOverrides = make(map[model.TerraformBlock]*model.TerraformOverrideSource)
	}
	file.TerraformOverrides[key] = source
}

func (o *terraformOverrides) overrideSource(
	file *model.FileMetadata, key model.TerraformBlock, config *tfeval.ResourceOverride,
) (model.TerraformBlock, *model.TerraformOverrideSource) {
	decl := config.Declaration
	line := decl.TypeRange.Start.Line
	source := &model.TerraformOverrideSource{
		DeclarationStart: model.ResourceLine{Line: line, Col: decl.TypeRange.Start.Column},
		Fields:           make(map[string]string),
	}
	o.sourceFields(file.ID, config.Effective.Body, "", source.Fields)
	return key, source
}

func (o *terraformOverrides) sourceFields(
	declarationID string, body *hclsyntax.Body, prefix string, fields map[string]string,
) {
	record := func(key string, loc hcl.Range) {
		file := o.byPath[absPath(loc.Filename, o.repoPath)]
		if file != nil && file.ID != declarationID {
			fields[prefix+key] = file.ID
		}
	}
	for key, attr := range body.Attributes {
		record(key, attr.SrcRange)
	}
	for _, block := range body.Blocks {
		record(block.Type, block.TypeRange)
		if block.Type == terraformLifecycleBlock {
			o.sourceFields(declarationID, block.Body, prefix+terraformLifecycleBlock+".", fields)
		}
		if dynamicblock.Is(block) {
			record(dynamicblock.GeneratedType(block), block.TypeRange)
		}
	}
}

// terraformFindingSource selects the source file for a finding on an effective
// block and returns the declaration key for inventory association.
func terraformFindingSource(
	file *model.FileMetadata, path model.SourcePath, searchKey string,
) (*model.TerraformOverrideFinding, model.TerraformBlock) {
	if len(file.TerraformOverrides) == 0 {
		return nil, model.TerraformBlock{}
	}
	key, field := overrideFindingPath(path, searchKey)
	source := file.TerraformOverrides[key]
	if key.Kind == "" {
		if source != nil {
			key.Kind = dataRoot
		} else {
			key.Kind = terraformResourceBlock
			source = file.TerraformOverrides[key]
		}
	}
	if source == nil {
		return nil, model.TerraformBlock{}
	}
	sourceID := source.Fields[field]
	return &model.TerraformOverrideFinding{
		SourceFileID: sourceID, DeclarationStart: source.DeclarationStart,
	}, key
}

func overrideFindingPath(path model.SourcePath, searchKey string) (block model.TerraformBlock, property string) {
	if len(path) >= 3 && !path[0].IsIndex && !path[1].IsIndex && !path[2].IsIndex {
		key := model.TerraformBlock{Kind: path[0].Key, Type: path[1].Key, Name: path[2].Key}
		if len(path) > 3 && !path[3].IsIndex {
			field := path[3].Key
			if field == terraformLifecycleBlock && len(path) > 4 && !path[4].IsIndex {
				field += "." + path[4].Key
			}
			return key, field
		}
		return key, ""
	}
	return legacyOverrideFindingPath(searchKey)
}

func legacyOverrideFindingPath(searchKey string) (block model.TerraformBlock, property string) {
	key, kind := searchKey, ""
	if rest, explicit := strings.CutPrefix(key, "resource."); explicit {
		kind, key = terraformResourceBlock, rest
	} else if rest, explicit := strings.CutPrefix(key, "data."); explicit {
		kind, key = dataRoot, rest
	}
	typ, name, tail := legacyTerraformBlockPath(key)
	tail = strings.TrimLeft(tail, "./")
	field := tail
	if end := strings.IndexAny(tail, "[./"); end >= 0 {
		field = tail[:end]
		if field == terraformLifecycleBlock {
			if next := strings.IndexAny(tail[end:], "./"); next >= 0 {
				member := tail[end+next+1:]
				if stop := strings.IndexAny(member, "[./"); stop >= 0 {
					member = member[:stop]
				}
				field += "." + member
			}
		}
	}
	return model.TerraformBlock{Kind: kind, Type: typ, Name: name}, field
}

// Legacy rules use both type[name].field and type.name.field, including
// bracketed indices below the field.
func legacyTerraformBlockPath(key string) (typ, name, tail string) {
	end := strings.IndexAny(key, "[./")
	if end < 0 {
		return key, "", ""
	}
	typ, label := key[:end], key[end+1:]
	if key[end] == '[' {
		name, tail, _ = strings.Cut(label, "]")
		name = strings.Trim(strings.TrimSuffix(strings.TrimPrefix(name, "{{"), "}}"), `"'`)
		return typ, name, tail
	}
	if split := strings.IndexAny(label, "[./"); split >= 0 {
		return typ, label[:split], label[split:]
	}
	return typ, label, ""
}

func (q *QueryContext) findingSourceFile(file *model.FileMetadata, override *model.TerraformOverrideFinding) *model.FileMetadata {
	if override != nil && override.SourceFileID != "" {
		if written := q.Files[override.SourceFileID]; written != nil {
			return written
		}
	}
	return file
}

func (q *QueryContext) locateStructuredFinding(
	ctx context.Context, file *model.FileMetadata, override *model.TerraformOverrideFinding, path model.SourcePath, d *detector.DetectLine,
) (model.VulnerabilityLines, error) {
	if override == nil || override.SourceFileID == "" || !tfpath.IsJSONConfig(file.FilePath) {
		return q.locateWrittenSource(ctx, file, path, d)
	}
	// Use the existing JSON detector when an effective HCL path leads to a
	// JSON override. The written-path resolver currently supports native HCL.
	key := terraformLegacyPath(path)
	if key == "" {
		// This error deliberately drops the finding because its written location is unknown.
		return model.VulnerabilityLines{}, errors.New("incomplete Terraform block path")
	}
	lines := d.DetectLine(ctx, file, key)
	if lines.Line < 1 {
		return lines, errors.New("no written location in the Terraform JSON override")
	}
	return lines, nil
}

func terraformLegacyPath(path model.SourcePath) string {
	if len(path) < 3 {
		return ""
	}
	var key strings.Builder
	if path[0].Key == dataRoot {
		key.WriteString(dataTypePrefix)
	}
	key.WriteString(path[1].Key)
	key.WriteString("[{{" + path[2].Key + "}}]")
	for _, part := range path[3:] {
		if part.IsIndex {
			key.WriteString("[" + strconv.Itoa(part.Index) + "]")
			continue
		}
		key.WriteByte('.')
		key.WriteString(part.Key)
	}
	return key.String()
}
