/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/modulegraph"
)

const (
	moduleDependencyDirect     = "direct"
	moduleDependencyTransitive = "transitive"
)

type moduleIndex struct {
	repoPath        string
	extractionMap   map[string]model.ExtractedPathObject
	resolved        []modulegraph.ResolvedModule
	byLocalPath     []modulegraph.ResolvedModule
	parsedByAbsPath map[string][]tfmodules.ParsedModule
}

func newModuleIndex(opts *WalkOptions, files model.FileMetadatas) *moduleIndex {
	if opts == nil || opts.RepoPath == "" {
		return nil
	}
	idx := &moduleIndex{
		repoPath:      filepath.Clean(opts.RepoPath),
		extractionMap: opts.ExtractionMap,
		resolved:      append([]modulegraph.ResolvedModule(nil), opts.ResolvedModules...),
	}
	sort.Slice(idx.resolved, func(i, j int) bool {
		return len(idx.resolved[i].LocalPath) > len(idx.resolved[j].LocalPath)
	})
	idx.byLocalPath = idx.resolved

	if len(opts.ParsedModules) > 0 {
		idx.parsedByAbsPath = indexParsedModulesByAbsSource(opts.ParsedModules)
	} else {
		ctx := opts.Ctx
		if ctx == nil {
			ctx = context.Background()
		}
		parsed, err := tfmodules.ParseTerraformModules(
			ctx, nil, normalizeFilesForModuleParse(files, opts.RepoPath), 0)
		if err == nil && len(parsed) > 0 {
			idx.parsedByAbsPath = indexParsedModulesByAbsSource(parsed)
		}
	}
	return idx
}

func indexParsedModulesByAbsSource(
	parsed map[string]tfmodules.ParsedModule,
) map[string][]tfmodules.ParsedModule {
	if len(parsed) == 0 {
		return nil
	}
	indexed := make(map[string][]tfmodules.ParsedModule)
	for key := range parsed {
		mod := parsed[key]
		if mod.AbsSource == "" {
			continue
		}
		abs := filepath.Clean(mod.AbsSource)
		indexed[abs] = append(indexed[abs], mod)
	}
	return indexed
}

func enrichTerraformModules(resources []Resource, idx *moduleIndex) {
	if idx == nil {
		return
	}
	for i := range resources {
		if resources[i].Platform != platformTerraform {
			continue
		}
		switch resources[i].BlockType {
		case BlockModule:
			enrichModuleBlock(&resources[i], idx)
		case BlockResource, BlockData:
			enrichModuleResource(&resources[i], idx)
		}
	}
}

func enrichModuleBlock(r *Resource, idx *moduleIndex) {
	if resolved := idx.matchResolvedDeclaration(r.File, r.Name, r.StartLine); resolved != nil {
		r.Module = moduleDeclarationPayload(resolved, idx.repoPath, false)
		r.ModuleSource = r.Module.Source
		if r.Module.Version != "" {
			r.ModuleVersion = r.Module.Version
		} else {
			r.ModuleVersion = stringAttrFromResource(r, "version")
		}
		return
	}
	if parsed := idx.matchParsedDeclaration(r.File, r.Name, r.StartLine); parsed != nil {
		r.Module = moduleDeclarationFromParsed(parsed, idx.repoPath)
		r.ModuleSource = r.Module.Source
		r.ModuleVersion = parsed.Version
		return
	}
	if r.ModuleSource != "" {
		sourceType, _ := tfmodules.DetectModuleSourceType(r.ModuleSource)
		r.Module = &model.ModuleAttributionSARIF{
			Name:           r.Name,
			Source:         model.ModuleAttributionForSARIF(&model.ModuleAttribution{Source: r.ModuleSource}).Source,
			SourceType:     sourceType,
			DependencyType: moduleDependencyDirect,
			ModuleCodeLocation: model.SourceLocation{
				Filename:  repoRelativeFile(r.File, idx.repoPath),
				LineStart: r.StartLine,
				LineEnd:   r.EndLine,
			},
		}
	}
}

func enrichModuleResource(r *Resource, idx *moduleIndex) {
	chain := idx.resolvedChain(r.File)
	if len(chain) > 0 {
		attr := attributionFromResolvedChain(chain, r, idx.repoPath)
		if attr == nil {
			return
		}
		r.Module = model.ModuleAttributionForSARIF(attr)
		anchor := chain[0]
		r.File = repoRelativeFile(anchor.CallerFile, idx.repoPath)
		r.StartLine = anchor.CallerLine
		r.EndLine = anchor.CallerEndLine
		return
	}
	parsedChain := idx.parsedChain(r.File)
	if len(parsedChain) == 0 {
		return
	}
	attr := attributionFromParsedChain(parsedChain, r, idx.repoPath)
	if attr == nil {
		return
	}
	r.Module = model.ModuleAttributionForSARIF(attr)
	root := parsedChain[0]
	r.File = repoRelativeFile(root.FileName, idx.repoPath)
	r.StartLine = root.DefLine
	r.EndLine = root.DefEndLine
}

func (idx *moduleIndex) matchResolvedDeclaration(filePath, name string, line int) *modulegraph.ResolvedModule {
	absFile := absPath(filePath, idx.repoPath)
	for i := range idx.resolved {
		mod := &idx.resolved[i]
		if mod.Name != name {
			continue
		}
		if !samePath(mod.CallerFile, absFile) {
			continue
		}
		if line > 0 && mod.CallerLine > 0 && line < mod.CallerLine {
			continue
		}
		if line > 0 && mod.CallerEndLine > 0 && line > mod.CallerEndLine {
			continue
		}
		return mod
	}
	return nil
}

func (idx *moduleIndex) matchParsedDeclaration(filePath, name string, line int) *tfmodules.ParsedModule {
	absFile := absPath(filePath, idx.repoPath)
	for _, mods := range idx.parsedByAbsPath {
		for i := range mods {
			mod := &mods[i]
			if mod.Name != name || !samePath(mod.FileName, absFile) {
				continue
			}
			if line > 0 && mod.DefLine > 0 && line < mod.DefLine {
				continue
			}
			if line > 0 && mod.DefEndLine > 0 && line > mod.DefEndLine {
				continue
			}
			return mod
		}
	}
	return nil
}

func (idx *moduleIndex) resolvedChain(filePath string) []modulegraph.ResolvedModule {
	absFile := absPath(filePath, idx.repoPath)
	var matches []modulegraph.ResolvedModule
	for _, mod := range idx.resolved {
		if mod.LocalPath == "" {
			continue
		}
		if pathWithinRoot(absFile, mod.LocalPath) {
			matches = append(matches, mod)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Depth != matches[j].Depth {
			return matches[i].Depth < matches[j].Depth
		}
		return len(matches[i].LocalPath) < len(matches[j].LocalPath)
	})
	return matches
}

func (idx *moduleIndex) parsedChain(filePath string) []tfmodules.ParsedModule {
	absFile := absPath(filePath, idx.repoPath)
	var owner *tfmodules.ParsedModule
	var bestSource string
	for absSource, mods := range idx.parsedByAbsPath {
		if !pathWithinRoot(absFile, absSource) {
			continue
		}
		if len(absSource) <= len(bestSource) {
			continue
		}
		bestSource = absSource
		owner = &mods[0]
	}
	if owner == nil {
		return nil
	}
	chain := []tfmodules.ParsedModule{*owner}
	for {
		parent := idx.parentParsedModule(chain[len(chain)-1])
		if parent == nil {
			break
		}
		chain = append([]tfmodules.ParsedModule{*parent}, chain...)
	}
	return chain
}

func (idx *moduleIndex) parentParsedModule(child tfmodules.ParsedModule) *tfmodules.ParsedModule {
	childRoot := filepath.Clean(child.AbsSource)
	for _, mods := range idx.parsedByAbsPath {
		for i := range mods {
			mod := &mods[i]
			if mod.AbsSource == childRoot {
				continue
			}
			if !pathWithinRoot(childRoot, mod.AbsSource) {
				continue
			}
			return mod
		}
	}
	return nil
}

func attributionFromResolvedChain(chain []modulegraph.ResolvedModule, r *Resource, repoPath string) *model.ModuleAttribution {
	if len(chain) == 0 {
		return nil
	}
	path := make([]model.ModulePathHop, 0, len(chain))
	for i, mod := range chain {
		path = append(path, hopFromResolvedModule(mod, repoPath, i > 0))
	}
	leaf := chain[len(chain)-1]
	sourceType, _ := tfmodules.DetectModuleSourceType(leaf.Source)
	dependencyType := moduleDependencyDirect
	if len(chain) > 1 {
		dependencyType = moduleDependencyTransitive
	}
	bodyFile := moduleRelativePath(r.File, leaf.LocalPath, repoPath)
	var modulePath []model.ModulePathHop
	if len(path) > 1 {
		modulePath = path
	}
	return &model.ModuleAttribution{
		Name:           leaf.Name,
		Source:         leafSource(leaf),
		SourceType:     sourceType,
		Version:        leafVersion(leaf),
		DependencyType: dependencyType,
		CodeLocation:   path[0].CodeLocation,
		ModuleCodeLocation: model.SourceLocation{
			Filename:  bodyFile,
			LineStart: r.StartLine,
			LineEnd:   r.EndLine,
		},
		ModulePath: modulePath,
	}
}

func attributionFromParsedChain(chain []tfmodules.ParsedModule, r *Resource, repoPath string) *model.ModuleAttribution {
	if len(chain) == 0 {
		return nil
	}
	path := make([]model.ModulePathHop, 0, len(chain))
	for i, mod := range chain {
		path = append(path, hopFromParsedModule(mod, repoPath, i > 0))
	}
	leaf := chain[len(chain)-1]
	dependencyType := moduleDependencyDirect
	if len(chain) > 1 {
		dependencyType = moduleDependencyTransitive
	}
	bodyFile := moduleRelativePath(r.File, leaf.AbsSource, repoPath)
	var modulePath []model.ModulePathHop
	if len(path) > 1 {
		modulePath = path
	}
	return &model.ModuleAttribution{
		Name:           leaf.Name,
		Source:         path[len(path)-1].Source,
		SourceType:     path[len(path)-1].SourceType,
		Version:        path[len(path)-1].Version,
		DependencyType: dependencyType,
		CodeLocation:   path[0].CodeLocation,
		ModuleCodeLocation: model.SourceLocation{
			Filename:  bodyFile,
			LineStart: r.StartLine,
			LineEnd:   r.EndLine,
		},
		ModulePath: modulePath,
	}
}

func moduleDeclarationPayload(mod *modulegraph.ResolvedModule, repoPath string, nested bool) *model.ModuleAttributionSARIF {
	sourceType, _ := tfmodules.DetectModuleSourceType(mod.Source)
	attr := &model.ModuleAttribution{
		Name:           mod.Name,
		Source:         leafSource(*mod),
		SourceType:     sourceType,
		Version:        leafVersion(*mod),
		DependencyType: moduleDependencyDirect,
		ModuleCodeLocation: hopFromResolvedModule(*mod, repoPath, nested).CodeLocation,
	}
	return model.ModuleAttributionForSARIF(attr)
}

func moduleDeclarationFromParsed(mod *tfmodules.ParsedModule, repoPath string) *model.ModuleAttributionSARIF {
	attr := &model.ModuleAttribution{
		Name:           mod.Name,
		Source:         hopFromParsedModule(*mod, repoPath, false).Source,
		SourceType:     mod.SourceType,
		Version:        mod.Version,
		DependencyType: moduleDependencyDirect,
		ModuleCodeLocation: model.SourceLocation{
			Filename:  repoRelativeFile(mod.FileName, repoPath),
			LineStart: mod.DefLine,
			LineEnd:   mod.DefEndLine,
		},
	}
	return model.ModuleAttributionForSARIF(attr)
}

func hopFromResolvedModule(mod modulegraph.ResolvedModule, repoPath string, nested bool) model.ModulePathHop {
	sourceType, _ := tfmodules.DetectModuleSourceType(mod.Source)
	filename := repoRelativeFile(mod.CallerFile, repoPath)
	if nested {
		filename = filepath.ToSlash(filepath.Base(mod.CallerFile))
	}
	return model.ModulePathHop{
		Name:       mod.Name,
		Source:     model.ModuleAttributionForSARIF(&model.ModuleAttribution{Source: leafSource(mod)}).Source,
		SourceType: sourceType,
		Version:    leafVersion(mod),
		CodeLocation: model.SourceLocation{
			Filename:  filename,
			LineStart: mod.CallerLine,
			LineEnd:   mod.CallerEndLine,
		},
	}
}

func hopFromParsedModule(mod tfmodules.ParsedModule, repoPath string, nested bool) model.ModulePathHop {
	source := mod.Source
	if mod.SourceType == "local" && mod.AbsSource != "" {
		if rel, err := filepath.Rel(filepath.Clean(repoPath), filepath.Clean(mod.AbsSource)); err == nil {
			source = filepath.ToSlash(rel)
		}
	}
	filename := repoRelativeFile(mod.FileName, repoPath)
	if nested {
		filename = filepath.ToSlash(filepath.Base(mod.FileName))
	}
	return model.ModulePathHop{
		Name:       mod.Name,
		Source:     model.ModuleAttributionForSARIF(&model.ModuleAttribution{Source: source}).Source,
		SourceType: mod.SourceType,
		Version:    mod.Version,
		CodeLocation: model.SourceLocation{
			Filename:  filename,
			LineStart: mod.DefLine,
			LineEnd:   mod.DefEndLine,
		},
	}
}

func leafSource(mod modulegraph.ResolvedModule) string {
	if mod.CanonicalSource != "" {
		return mod.CanonicalSource
	}
	return mod.Source
}

func leafVersion(mod modulegraph.ResolvedModule) string {
	sourceType, _ := tfmodules.DetectModuleSourceType(mod.Source)
	switch sourceType {
	case "registry":
		return strings.TrimSpace(mod.ResolvedVersion)
	case "git":
		return strings.TrimSpace(mod.ResolvedRef)
	default:
		return ""
	}
}

func stringAttrFromResource(r *Resource, key string) string {
	if r.Attributes == nil {
		return ""
	}
	value, ok := r.Attributes[key].(string)
	if !ok {
		return ""
	}
	return value
}

func repoRelativeFile(filePath, repoPath string) string {
	abs := absPath(filePath, repoPath)
	rel, err := filepath.Rel(filepath.Clean(repoPath), abs)
	if err != nil {
		return filepath.ToSlash(filepath.Base(abs))
	}
	return filepath.ToSlash(rel)
}

func moduleRelativePath(filePath, moduleRoot, repoPath string) string {
	absFile := absPath(filePath, repoPath)
	if moduleRoot != "" {
		rel, err := filepath.Rel(filepath.Clean(moduleRoot), absFile)
		if err == nil && pathWithinRoot(absFile, moduleRoot) {
			return filepath.ToSlash(rel)
		}
	}
	return repoRelativeFile(absFile, repoPath)
}

func absPath(path, repoPath string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(repoPath, path))
}

func pathWithinRoot(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func samePath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

func normalizeFilesForModuleParse(files model.FileMetadatas, repoPath string) model.FileMetadatas {
	if repoPath == "" {
		return files
	}
	out := make(model.FileMetadatas, 0, len(files))
	for _, f := range files {
		if f == nil || f.Kind != model.KindTerraform {
			continue
		}
		clone := f.ShallowCopy()
		clone.FilePath = absPath(f.FilePath, repoPath)
		out = append(out, clone)
	}
	return out
}
