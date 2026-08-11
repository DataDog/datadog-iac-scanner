/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"encoding/json"
	"maps"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/cespare/xxhash/v2"
)

// extraCallerInfo records a deduplicated module caller so its findings can be
// cloned from the primary OPA doc after eval without adding a separate doc to input.document.
type extraCallerInfo struct {
	callChain string
	docID     string
}

// moduleResolutionResult bundles all outputs of resolveModuleDocuments.
type moduleResolutionResult struct {
	docs           []model.Document
	syntheticFiles []*model.FileMetadata
	suppressed     map[string]bool
	calledDirs     map[string]bool
	extras         map[string][]extraCallerInfo
	ok             bool
}

// instantiateLocalModules evaluates local modules and injects resolved resource
// documents. In a called module body only the resource blocks are dropped (they
// are re-emitted instantiated, with caller-resolved values); variable, output,
// data and locals blocks are kept so their rules still fire exactly as in a
// standalone scan. The instantiated local "module" call-sites are stripped from
// root documents so call-site rule branches don't fire alongside the
// instantiated resources.
//
// It mutates the input FileMetadata documents in place. Mutations are applied
// only after evaluation succeeds (see resolveModulesSafely); a panic during
// evaluation leaves the scan input untouched rather than removing coverage
// without a synthetic replacement.
// Returns synthetic docs and matching FileMetadata (call chain for fingerprints).
// Caller must append the files before Combine/ToMap. extras lists duplicate callers for post-OPA finding expansion.
func (c *Inspector) instantiateLocalModules(
	ctx context.Context,
	files model.FileMetadatas,
) ([]model.Document, []*model.FileMetadata, map[string][]extraCallerInfo) {
	resolver := c.buildRemoteResolver()
	res := c.resolveModulesSafely(ctx, files, resolver)
	totalCallers := instantiatedModuleResourceCount(&res)
	contextLogger := logger.FromContext(ctx)
	contextLogger.Info().
		Int("module_resources_instantiated", totalCallers).
		Msgf(
			"Instantiated %d module resources (%d unique OPA docs, %d deduplicated callers)",
			totalCallers,
			len(res.docs),
			totalCallers-len(res.docs),
		)
	if !res.ok {
		return nil, nil, nil
	}
	for _, f := range files {
		if f == nil || !isTerraformFile(f.FilePath) {
			continue
		}
		if res.suppressed[f.ID] {
			// Resource blocks are re-emitted as instantiated synthetic docs, so
			// drop only those to avoid double-counting; keep the rest of the body
			// (variable/output/data/locals) so those rules still fire.
			delete(f.Document, "resource")
			delete(f.LineInfoDocument, "resource")
		}
		// Only remove local module call-sites that were instantiated; remote/registry
		// module blocks must remain so the corresponding Rego branches can still fire.
		stripModuleCalls(f.Document, f.FilePath, c.repoPath, res.calledDirs, resolver)
	}
	return res.docs, res.syntheticFiles, res.extras
}

func instantiatedModuleResourceCount(res *moduleResolutionResult) int {
	count := len(res.docs)
	for _, extras := range res.extras {
		count += len(extras)
	}
	return count
}

func (c *Inspector) buildRemoteResolver() tfeval.RemoteResolver {
	if len(c.remoteModuleDirs) == 0 {
		return nil
	}
	dirs := c.remoteModuleDirs
	return func(source, version, callerFile, moduleName string) (string, bool) {
		root := remoteModuleRoot(callerFile, c.repoPath)
		return lookupRemoteDir(dirs, root, source, version, moduleName)
	}
}

func (c *Inspector) buildModuleMetadataResolver() tfmodules.RemoteResolver {
	if len(c.remoteModuleDirs) == 0 {
		return nil
	}
	return moduleMetadataResolver{dirs: c.remoteModuleDirs, repoPath: c.repoPath}
}

type moduleMetadataResolver struct {
	dirs     map[string]string
	repoPath string
}

func (r moduleMetadataResolver) Resolve(_ context.Context, mod *tfmodules.ParsedModule) (string, error) {
	root := remoteModuleRoot(mod.FileName, r.repoPath)
	dir, ok := lookupRemoteDir(r.dirs, root, mod.Source, mod.Version, mod.Name)
	if !ok {
		return "", &tfmodules.UnresolvedError{Reason: "module was not resolved during pre-scan"}
	}
	return dir, nil
}

func lookupRemoteDir(dirs map[string]string, root, source, version, name string) (string, bool) {
	if d, ok := dirs[RemoteModuleCallKey(root, source, version, name)]; ok {
		return d, true
	}
	if d, ok := dirs[RemoteModuleCallKey(root, source, "", name)]; ok {
		return d, true
	}
	if d, ok := dirs[RemoteModuleKey(root, source, version)]; ok {
		return d, true
	}
	if version != "" {
		if d, ok := dirs[RemoteModuleKey(root, source, "")]; ok {
			return d, true
		}
	}
	return "", false
}

func RemoteModuleKey(root, source, version string) string {
	return filepath.Clean(root) + "\x00" + strings.TrimSpace(source) + "\x00" + strings.TrimSpace(version)
}

func RemoteModuleCallKey(root, source, version, moduleName string) string {
	return RemoteModuleKey(root, source, version) + "\x00" + strings.TrimSpace(moduleName)
}

func remoteModuleRoot(fileName, repoPath string) string {
	if fileName == "" {
		return filepath.Clean(repoPath)
	}
	return filepath.Clean(filepath.Dir(absPath(fileName, repoPath)))
}

// resolveModulesSafely runs the panic-prone module evaluation under a recover so
// a malformed module aborts only the synthetic-doc injection, not the scan. It
// performs no in-place mutation of files, so returning ok=false on panic leaves
// the scan input untouched and the caller skips all document mutations.
func (c *Inspector) resolveModulesSafely(
	ctx context.Context,
	files model.FileMetadatas,
	resolver tfeval.RemoteResolver,
) (res moduleResolutionResult) {
	defer func() {
		if r := recover(); r != nil {
			contextLogger := logger.FromContext(ctx)
			contextLogger.Error().Interface("panic", r).Msg(
				"instantiateLocalModules: recovered from panic; skipping synthetic module docs",
			)
			res = moduleResolutionResult{}
		}
	}()
	return resolveModuleDocuments(ctx, files, c.repoPath, resolver)
}

// resolveModuleDocuments instantiates all local modules referenced by the
// scanned files and returns synthetic resource documents (one per resolved
// resource, attributed to its defining file) and the set of FileMetadata IDs
// that should be suppressed to avoid double-scanning. Uncalled modules are
// left untouched and continue to be scanned standalone.
//
// `ok` is true when at least one root module evaluated successfully and the
// caller should apply call-site / suppression mutations; otherwise it is false
// and the returned maps are nil.
func resolveModuleDocuments(
	ctx context.Context,
	files model.FileMetadatas,
	repoPath string,
	resolver tfeval.RemoteResolver,
) moduleResolutionResult {
	byAbsPath, filesByDir, dirsWithTf := indexTerraformFiles(ctx, files, repoPath)
	if len(dirsWithTf) == 0 {
		return moduleResolutionResult{}
	}

	contextLogger := logger.FromContext(ctx)
	evaluator := tfeval.New()
	if resolver != nil {
		evaluator.SetRemoteResolver(resolver)
	}

	// staticCalledDirs is used only to classify root vs. child dirs before evaluation.
	// Suppression and stripping are driven by actualCalledDirs (evaluation results).
	staticCalledDirs := make(map[string]bool)
	for dir := range dirsWithTf {
		calledDirs := discoverCalledModuleDirs(evaluator, filesByDir[dir], repoPath, resolver, dir)
		for _, called := range calledDirs {
			staticCalledDirs[called] = true
		}
	}

	// seen maps a content-based key to the primary docID so duplicate callers can
	// be recorded in extras rather than emitted as separate OPA documents.
	seen := make(map[string]string)
	extras := make(map[string][]extraCallerInfo)
	var rootEvalOK bool
	actualCalledDirs := make(map[string]bool)
	var extra []model.Document
	var syntheticFiles []*model.FileMetadata

	for dir := range dirsWithTf {
		if staticCalledDirs[dir] {
			continue // instantiated via a module call, not a root
		}
		resources, _, childDirs, err := evaluator.EvaluateModule(ctx, dir, tfeval.LoadRootVars(dir))
		if err != nil {
			contextLogger.Warn().Err(err).Msgf("tfeval: failed to evaluate root module %s", dir)
			continue
		}
		rootEvalOK = true
		for d := range childDirs {
			actualCalledDirs[d] = true
		}
		docs, syn := instantiatedDocs(resources, byAbsPath, repoPath, seen, extras)
		extra = append(extra, docs...)
		syntheticFiles = append(syntheticFiles, syn...)
	}
	evaluator.ReleaseCaches()

	// If every root evaluation failed, do not strip or suppress module bodies: that would
	// remove coverage with no synthetic replacement.
	if !rootEvalOK {
		return moduleResolutionResult{}
	}

	suppressed := make(map[string]bool)
	for dir := range actualCalledDirs {
		for _, f := range filesByDir[dir] {
			suppressed[f.ID] = true
		}
	}

	// Only strip call sites when that module's files are in the scan (avoid dropping sole coverage).
	strippedDirs := make(map[string]bool, len(actualCalledDirs))
	for dir := range actualCalledDirs {
		if len(filesByDir[dir]) > 0 {
			strippedDirs[dir] = true
		}
	}

	return moduleResolutionResult{
		docs:           extra,
		syntheticFiles: syntheticFiles,
		suppressed:     suppressed,
		calledDirs:     strippedDirs,
		extras:         extras,
		ok:             true,
	}
}

// moduleRefEntry holds resolved resource data for _refs injection and dedup.
type moduleRefEntry struct {
	typ, name, definedIn, defLine string
	attrs                         interface{}
}

// instantiatedDocs emits one synthetic OPA doc per resolved module resource instance.
// Identical callers are recorded in extras for post-eval finding cloning.
func instantiatedDocs(
	resources []tfeval.ResolvedResource,
	byAbsPath map[string]*model.FileMetadata,
	repoPath string,
	seen map[string]string,
	extras map[string][]extraCallerInfo,
) (docs []model.Document, synthetic []*model.FileMetadata) {
	// Pass 1: index resources per call chain.
	cckRefs := make(map[string][]moduleRefEntry)
	for i := range resources {
		r := &resources[i]
		if r.ModuleAddress == "" {
			continue
		}
		cck := callChainKey(r, repoPath)
		cckRefs[cck] = append(cckRefs[cck], moduleRefEntry{
			typ:       r.Type,
			name:      r.Name,
			definedIn: absPath(r.DefinedIn, repoPath),
			defLine:   strconv.Itoa(r.DefLine),
			attrs:     tfeval.AttributesToDocument(r),
		})
	}
	callContentKeys := make(map[string]string, len(cckRefs))
	for cck, refs := range cckRefs {
		callContentKeys[cck] = moduleCallRefsKey(refs)
	}

	// Pass 2: emit one doc per instance.
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

		cck := callChainKey(r, repoPath)
		docID := fm.ID + "\x00" + cck + "\x00" + r.Name

		// Identical resolved attributes dedupe to one OPA doc; extras get cloned findings after OPA.
		contentKey := moduleCallContentKey(r, callContentKeys[cck], repoPath)
		if primaryDocID, dup := seen[contentKey]; dup {
			extras[primaryDocID] = append(extras[primaryDocID], extraCallerInfo{callChain: cck, docID: docID})
			continue
		}
		seen[contentKey] = docID

		refsMap := buildRefsMap(r, cckRefs[cck])

		doc := model.Document{
			"id":   docID,
			"file": fm.FilePath,
			"resource": map[string]interface{}{
				r.Type: map[string]interface{}{
					tfeval.ResourceBaseName(r.Name): tfeval.AttributesToDocument(r),
				},
			},
		}
		if len(refsMap) > 0 {
			doc["_refs"] = map[string]interface{}{"resource": refsMap}
		}
		docs = append(docs, doc)
		synthetic = append(synthetic, newInstanceFileMetadata(fm, docID, cck))
	}
	return docs, synthetic
}

func moduleCallRefsKey(allInCall []moduleRefEntry) string {
	type row struct{ typ, name, definedIn, defLine, attrKey string }
	rows := make([]row, 0, len(allInCall))
	for _, e := range allInCall {
		b, _ := json.Marshal(e.attrs)
		rows = append(rows, row{e.typ, e.name, e.definedIn, e.defLine, strconv.FormatUint(xxhash.Sum64(b), 16)})
	}
	sort.Slice(rows, func(i, j int) bool {
		for _, pair := range [][2]string{
			{rows[i].typ, rows[j].typ},
			{rows[i].name, rows[j].name},
			{rows[i].definedIn, rows[j].definedIn},
			{rows[i].defLine, rows[j].defLine},
			{rows[i].attrKey, rows[j].attrKey},
		} {
			if pair[0] != pair[1] {
				return pair[0] < pair[1]
			}
		}
		return false
	})
	var parts []string
	for _, r := range rows {
		parts = append(parts, r.typ, r.name, r.definedIn, r.defLine, r.attrKey)
	}
	return strings.Join(parts, "\x00")
}

func moduleCallContentKey(self *tfeval.ResolvedResource, refsKey, repoPath string) string {
	return strings.Join([]string{
		self.ModuleAddress, self.Type, self.Name,
		absPath(self.DefinedIn, repoPath), strconv.Itoa(self.DefLine), refsKey,
	}, "\x00")
}

// buildRefsMap returns sibling resources in the same module call (for walk-based rules).
func buildRefsMap(self *tfeval.ResolvedResource, allInCall []moduleRefEntry) map[string]interface{} {
	refs := make(map[string]interface{})
	for _, e := range allInCall {
		if e.typ == self.Type && e.name == self.Name {
			continue
		}
		inner, _ := refs[e.typ].(map[string]interface{})
		if inner == nil {
			inner = make(map[string]interface{})
			refs[e.typ] = inner
		}
		inner[e.name] = e.attrs
	}
	return refs
}

// newInstanceFileMetadata clones fm for a synthetic doc (empty Document so Combine skips it).
func newInstanceFileMetadata(fm *model.FileMetadata, id, callChain string) *model.FileMetadata {
	clone := *fm
	clone.ID = id
	clone.Document = model.Document{}
	clone.ModuleCallChain = callChain
	if fm.LineInfoDocument != nil {
		clone.LineInfoDocument = maps.Clone(fm.LineInfoDocument)
	}
	return &clone
}

// callChainKey is repo-relative outer caller + "|" + module address (no line numbers, to keep fingerprints stable).
func callChainKey(r *tfeval.ResolvedResource, repoPath string) string {
	if len(r.CallChain) == 0 {
		return r.ModuleAddress
	}
	root := absPath(r.CallChain[0].CalledFrom, repoPath)
	rel := root
	if rp, err := filepath.Rel(repoPath, root); err == nil {
		rel = rp
	}
	return filepath.ToSlash(rel) + "|" + r.ModuleAddress
}

// stripModuleCalls drops module blocks whose target dir is in calledDirs.
// Remote/registry sources stay so existing Rego call-site rules still match.
func stripModuleCalls(doc model.Document, filePath, repoPath string, calledDirs map[string]bool, resolver tfeval.RemoteResolver) {
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
		version, _ := call["version"].(string)
		resolvedDir, _ := resolveModuleTargetDir(fileDir, source, version, filePath, name, resolver)

		if resolvedDir != "" && calledDirs[resolvedDir] {
			delete(modules, name)
		}
	}
	if len(modules) == 0 {
		delete(doc, "module")
	}
}

func discoverCalledModuleDirs(
	evaluator *tfeval.Evaluator,
	files []*model.FileMetadata,
	repoPath string,
	resolver tfeval.RemoteResolver,
	dir string,
) []string {
	calledDirs, ok := calledModuleDirsFromDocuments(files, repoPath, resolver)
	if ok {
		return calledDirs
	}
	return evaluator.CalledModuleDirs(dir)
}

func calledModuleDirsFromDocuments(
	files []*model.FileMetadata,
	repoPath string,
	resolver tfeval.RemoteResolver,
) ([]string, bool) {
	var dirs []string
	for _, file := range files {
		if file == nil || len(file.Document) == 0 {
			return nil, false
		}
		modules := docAsMap(file.Document["module"])
		fileDir := filepath.Dir(absPath(file.FilePath, repoPath))
		for name, callRaw := range modules {
			call := docAsMap(callRaw)
			source, _ := call["source"].(string)
			if source == "" {
				continue
			}
			version, _ := call["version"].(string)
			if dir, ok := resolveModuleTargetDir(fileDir, source, version, file.FilePath, name, resolver); ok {
				dirs = append(dirs, dir)
			}
		}
	}
	return dirs, true
}

func resolveModuleTargetDir(
	callerDir, source, version, callerFile, moduleName string,
	resolver tfeval.RemoteResolver,
) (string, bool) {
	cleanSource := tfeval.StripGetterPrefix(source)
	if tfmodules.LooksLikeLocalModuleSource(cleanSource) {
		if filepath.IsAbs(cleanSource) {
			return filepath.Clean(cleanSource), true
		}
		return filepath.Clean(filepath.Join(callerDir, cleanSource)), true
	}
	if resolver == nil {
		return "", false
	}
	return resolver(source, version, callerFile, moduleName)
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
