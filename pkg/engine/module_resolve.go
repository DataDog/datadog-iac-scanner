/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
)

// instantiateLocalModules evaluates local modules and injects resolved resource
// documents. Called module body files are suppressed (their resources are
// emitted instantiated instead), and the "module" key is stripped from root
// documents so call-site rule branches don't fire alongside the instantiated ones.
//
// It mutates the input FileMetadata slice in place (clears Document /
// LineInfoDocument for suppressed files; strips module blocks on other .tf files).
func (c *Inspector) instantiateLocalModules(ctx context.Context, files model.FileMetadatas) (out []model.Document) {
	defer func() {
		if r := recover(); r != nil {
			contextLogger := logger.FromContext(ctx)
			contextLogger.Error().Interface("panic", r).Msg(
				"instantiateLocalModules: recovered from panic; skipping synthetic module docs (input files may be partially updated)",
			)
			out = nil
		}
	}()

	moduleDocs, suppressed, calledDirs, ok := resolveModuleDocuments(ctx, files, c.repoPath)
	if !ok {
		return nil
	}
	for _, f := range files {
		if f == nil {
			continue
		}
		if suppressed[f.ID] {
			f.Document = model.Document{}
			f.LineInfoDocument = nil
		} else if isTerraformFile(f.FilePath) {
			// Only remove local module call-sites that were instantiated; remote/registry
			// module blocks must remain so the corresponding Rego branches can still fire.
			stripLocalModuleCalls(f.Document, f.FilePath, c.repoPath, calledDirs)
		}
	}
	contextLogger := logger.FromContext(ctx)
	if len(moduleDocs) > 0 {
		contextLogger.Info().Msgf("Instantiated %d local module resources", len(moduleDocs))
	} else {
		contextLogger.Debug().Msg("Instantiated 0 local module resources")
	}
	return moduleDocs
}

// resolveModuleDocuments instantiates all local modules referenced by the
// scanned files and returns synthetic resource documents (one per resolved
// resource, attributed to its defining file) and the set of FileMetadata IDs
// that should be suppressed to avoid double-scanning. Uncalled modules are
// left untouched and continue to be scanned standalone.
//
// The boolean is true when at least one root module evaluated successfully and
// the caller should apply call-site / suppression mutations; otherwise false
// and the returned maps are nil.
func resolveModuleDocuments(
	ctx context.Context,
	files model.FileMetadatas,
	repoPath string,
) (extra []model.Document, suppressed, calledDirs map[string]bool, ok bool) {
	byAbsPath, filesByDir, dirsWithTf := indexTerraformFiles(ctx, files, repoPath)
	if len(dirsWithTf) == 0 {
		return nil, nil, nil, false
	}

	// staticCalledDirs is used only to classify root vs. child dirs before evaluation.
	// Suppression and stripping are driven by actualCalledDirs (evaluation results).
	staticCalledDirs := make(map[string]bool)
	for dir := range dirsWithTf {
		for _, called := range tfeval.CalledLocalDirs(dir) {
			staticCalledDirs[called] = true
		}
	}

	contextLogger := logger.FromContext(ctx)
	evaluator := tfeval.New()
	seen := make(map[string]bool)
	var rootEvalOK int
	actualCalledDirs := make(map[string]bool)

	for dir := range dirsWithTf {
		if staticCalledDirs[dir] {
			continue // instantiated via a module call, not a root
		}
		resources, _, childDirs, err := evaluator.EvaluateModule(ctx, dir, tfeval.LoadRootVars(dir))
		if err != nil {
			contextLogger.Warn().Err(err).Msgf("tfeval: failed to evaluate root module %s", dir)
			continue
		}
		rootEvalOK++
		for d := range childDirs {
			actualCalledDirs[d] = true
		}
		// evalRootDir distinguishes the same child module reached from different roots
		// (different variable bindings) so synthetic documents are not incorrectly deduped.
		extra = append(extra, instantiatedDocs(resources, byAbsPath, repoPath, seen, dir)...)
	}

	// If every root evaluation failed, do not strip or suppress module bodies: that would
	// remove coverage with no synthetic replacement.
	if rootEvalOK == 0 {
		return nil, nil, nil, false
	}

	suppressed = make(map[string]bool)
	for dir := range actualCalledDirs {
		for _, f := range filesByDir[dir] {
			suppressed[f.ID] = true
		}
	}

	// Only strip call sites for dirs that contributed synthetic documents (i.e.,
	// their files are present in the scan input). If a module was read from disk
	// by EvaluateModule but its files are absent from the scan, instantiatedDocs
	// drops its resources; stripping the call site would remove the only payload
	// those files provide without any synthetic replacement.
	strippedDirs := make(map[string]bool, len(actualCalledDirs))
	for dir := range actualCalledDirs {
		if len(filesByDir[dir]) > 0 {
			strippedDirs[dir] = true
		}
	}

	return extra, suppressed, strippedDirs, true
}

// instantiatedDocs builds a synthetic resource document for each resolved
// module resource, attributed to its defining file. Root resources and those
// whose file is out of scope are skipped. seen dedupes across multiple roots.
//
// v1 limitation: count/for_each and multiple calls to the same module directory
// are not expanded into separate instances; dedupe and document id attribution
// use the defining file only, so distinct instances can collapse to one synthetic doc.
func instantiatedDocs(
	resources []tfeval.ResolvedResource,
	byAbsPath map[string]*model.FileMetadata,
	repoPath string,
	seen map[string]bool,
	evalRootDir string,
) []model.Document {
	var docs []model.Document
	for i := range resources {
		r := &resources[i]
		if r.ModuleAddress == "" {
			continue
		}
		abs := absPath(r.DefinedIn, repoPath)
		fm, ok := byAbsPath[abs]
		if !ok {
			continue
		}
		key := strings.Join([]string{evalRootDir, abs, r.ModuleAddress, r.Type, r.Name, strconv.Itoa(r.DefLine)}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true

		docs = append(docs, model.Document{
			"id":   fm.ID,
			"file": fm.FilePath,
			"resource": map[string]interface{}{
				r.Type: map[string]interface{}{
					r.Name: tfeval.AttributesToDocument(r),
				},
			},
		})
	}
	return docs
}

// stripLocalModuleCalls removes module entries from doc whose source resolves
// to one of calledDirs. Remote/registry sources are left intact so existing
// Rego branches that match call-site attributes continue to work.
//
// The Terraform parser stores nested HCL blocks as model.Document (a named map
// type), so we accept both model.Document and map[string]interface{} to handle
// either representation safely.
func stripLocalModuleCalls(doc model.Document, filePath, repoPath string, calledDirs map[string]bool) {
	modules := docAsMap(doc["module"])
	if modules == nil {
		return
	}
	fileDir := filepath.Dir(absPath(filePath, repoPath))
	for name, callRaw := range modules {
		call := docAsMap(callRaw)
		if call == nil {
			continue
		}
		source, _ := call["source"].(string)
		if source == "" {
			continue
		}
		cleanSource := tfeval.StripGetterPrefix(source)
		if !tfmodules.LooksLikeLocalModuleSource(cleanSource) {
			continue
		}
		if calledDirs[filepath.Clean(filepath.Join(fileDir, cleanSource))] {
			delete(modules, name)
		}
	}
	if len(modules) == 0 {
		delete(doc, "module")
	}
}

// indexTerraformFiles builds lookup maps from a flat FileMetadatas slice.
func indexTerraformFiles(ctx context.Context, files model.FileMetadatas, repoPath string) (
	byAbsPath map[string]*model.FileMetadata,
	filesByDir map[string][]*model.FileMetadata,
	dirsWithTf map[string]bool,
) {
	contextLogger := logger.FromContext(ctx)
	byAbsPath = make(map[string]*model.FileMetadata)
	filesByDir = make(map[string][]*model.FileMetadata)
	dirsWithTf = make(map[string]bool)
	for _, f := range files {
		if f == nil || !isTerraformFile(f.FilePath) {
			continue
		}
		abs := absPath(f.FilePath, repoPath)
		dir := filepath.Dir(abs)
		if prev, exists := byAbsPath[abs]; exists && prev != nil && prev.ID != f.ID {
			contextLogger.Warn().Msgf(
				"duplicate terraform file path in scan input %s (file ids %s and %s); using the latter",
				abs, prev.ID, f.ID,
			)
		}
		byAbsPath[abs] = f
		filesByDir[dir] = append(filesByDir[dir], f)
		dirsWithTf[dir] = true
	}
	return
}

// docAsMap coerces v to a string-keyed map regardless of whether it is a
// model.Document (the Terraform parser's named type) or a plain map.
func docAsMap(v interface{}) map[string]interface{} {
	switch m := v.(type) {
	case model.Document:
		return map[string]interface{}(m)
	case map[string]interface{}:
		return m
	}
	return nil
}

// absPath returns a cleaned path. Relative paths are resolved against base
// (typically the scan repo root), not the process working directory.
func absPath(p, base string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(base, p))
}

func isTerraformFile(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".tf")
}
