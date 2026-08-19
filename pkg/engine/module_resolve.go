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
	// resourceCount is how many module resources were instantiated. Documents
	// hold many resources each, so it cannot be derived from the document count.
	resourceCount int
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
		Int("module_documents_instantiated", len(res.docs)).
		Msgf(
			"Instantiated %d module resources into %d OPA documents (%d deduplicated callers)",
			totalCallers,
			len(res.docs),
			dedupedCallers(&res),
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
			if err := f.EnsureLineInfoDocument(ctx); err != nil {
				contextLogger.Err(err).Msgf("failed to build line-info document for file %s", f.FilePath)
			} else {
				delete(f.LineInfoDocument, "resource")
			}
		}
		// Only remove local module call-sites that were instantiated; remote/registry
		// module blocks must remain so the corresponding Rego branches can still fire.
		stripModuleCalls(f.Document, f.FilePath, c.repoPath, res.calledDirs, resolver)
	}
	return res.docs, res.syntheticFiles, res.extras
}

func instantiatedModuleResourceCount(res *moduleResolutionResult) int {
	return res.resourceCount
}

// dedupedCallers counts the callers that collapsed onto another caller's
// document and get their findings cloned after evaluation.
func dedupedCallers(res *moduleResolutionResult) int {
	var n int
	for _, extras := range res.extras {
		n += len(extras)
	}
	return n
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
		calledDirs := discoverCalledModuleDirs(ctx, evaluator, filesByDir[dir], repoPath, resolver, dir)
		for _, called := range calledDirs {
			staticCalledDirs[called] = true
		}
	}

	// seen maps a content-based key to the primary docID so duplicate callers can
	// be recorded in extras rather than emitted as separate OPA documents.
	seen := make(map[string]string)
	extras := make(map[string][]extraCallerInfo)
	var rootEvalOK bool
	var resourceCount int
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
		docs, syn, n := instantiatedDocs(resources, byAbsPath, repoPath, seen, extras)
		extra = append(extra, docs...)
		syntheticFiles = append(syntheticFiles, syn...)
		resourceCount += n
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
		resourceCount:  resourceCount,
	}
}

// instantiatedResource is one resolved resource as it is placed into a document.
type instantiatedResource struct {
	typ, baseName, defLine string
	attrs                  interface{}
}

// moduleRefEntry holds resolved resource data for _refs injection and dedup.
type moduleRefEntry struct {
	typ, name, definedIn, defLine string
	attrs                         interface{}
}

// docGroup collects every resource that one module call contributes to a single
// defining file.
type docGroup struct {
	fm            *model.FileMetadata
	callChain     string
	moduleAddress string
	layer         int
	entries       []instantiatedResource
}

// instantiatedDocs emits one synthetic OPA doc per (module call, defining file),
// holding every resource that call resolved in that file. This mirrors how an
// ordinary Terraform file reaches Rego - one document, many resources - so rules
// matching a resource against same-file siblings behave as they do anywhere else.
//
// _refs carries the rest of the call's resources so cross-file references inside
// a module still resolve, and is shared by every doc in the call. Grouping is
// what makes that affordable: emitting one doc per resource attaches an N-entry
// map to each of N docs, which is O(N^2) both in memory and in the traversal
// every walk-based rule performs. Per file it is O(files x N) instead.
//
// Identical callers are recorded in extras for post-eval finding cloning.
func instantiatedDocs(
	resources []tfeval.ResolvedResource,
	byAbsPath map[string]*model.FileMetadata,
	repoPath string,
	seen map[string]string,
	extras map[string][]extraCallerInfo,
) (docs []model.Document, synthetic []*model.FileMetadata, resourceCount int) {
	groups := make(map[string]*docGroup)
	var order []string
	cckRefs := make(map[string][]moduleRefEntry)
	// A base name repeats within one call and file whenever count/for_each
	// expands a block. Document keys have to stay base-named for line detection
	// to resolve them against the file's HCL, so repeats spill into another
	// layer rather than overwriting each other.
	layers := make(map[string]int)

	for i := range resources {
		r := &resources[i]
		if r.ModuleAddress == "" {
			continue
		}
		fm, ok := byAbsPath[absPath(r.DefinedIn, repoPath)]
		if !ok {
			continue
		}
		cck := callChainKey(r, repoPath)
		base := tfeval.ResourceBaseName(r.Name)
		attrs := tfeval.AttributesToDocument(r)

		cckRefs[cck] = append(cckRefs[cck], moduleRefEntry{
			typ:       r.Type,
			name:      r.Name,
			definedIn: absPath(r.DefinedIn, repoPath),
			defLine:   strconv.Itoa(r.DefLine),
			attrs:     attrs,
		})

		slot := cck + "\x00" + fm.ID + "\x00" + r.Type + "\x00" + base
		layer := layers[slot]
		layers[slot] = layer + 1

		key := cck + "\x00" + fm.ID + "\x00" + strconv.Itoa(layer)
		g, exists := groups[key]
		if !exists {
			g = &docGroup{fm: fm, callChain: cck, moduleAddress: r.ModuleAddress, layer: layer}
			groups[key] = g
			order = append(order, key)
		}
		g.entries = append(g.entries, instantiatedResource{
			typ:      r.Type,
			baseName: base,
			defLine:  strconv.Itoa(r.DefLine),
			attrs:    attrs,
		})
		resourceCount++
	}

	// One _refs map per call chain, shared by every doc in it.
	callRefKeys := make(map[string]uint64, len(cckRefs))
	callRefs := make(map[string]map[string]interface{}, len(cckRefs))
	for cck, refs := range cckRefs {
		callRefKeys[cck] = xxhash.Sum64String(moduleCallRefsKey(refs))
		callRefs[cck] = buildSharedRefsMap(refs)
	}

	for _, key := range order {
		g := groups[key]
		docID := g.fm.ID + "\x00" + g.callChain + "\x00" + strconv.Itoa(g.layer)

		// Calls that resolve this file to identical content share one OPA doc;
		// the others are recorded so their findings are cloned after eval.
		contentKey := groupContentKey(g, callRefKeys[g.callChain])
		if primaryDocID, dup := seen[contentKey]; dup {
			extras[primaryDocID] = append(extras[primaryDocID], extraCallerInfo{
				callChain: g.callChain,
				docID:     docID,
			})
			continue
		}
		seen[contentKey] = docID

		resource := make(map[string]interface{})
		for _, e := range g.entries {
			byName, ok := resource[e.typ].(map[string]interface{})
			if !ok {
				byName = make(map[string]interface{})
				resource[e.typ] = byName
			}
			byName[e.baseName] = e.attrs
		}

		doc := model.Document{
			"id":       docID,
			"file":     g.fm.FilePath,
			"resource": resource,
		}
		if refsMap := callRefs[g.callChain]; len(refsMap) > 0 {
			doc["_refs"] = map[string]interface{}{"resource": refsMap}
		}
		docs = append(docs, doc)
		synthetic = append(synthetic, newInstanceFileMetadata(g.fm, docID, g.callChain))
	}
	return docs, synthetic, resourceCount
}

// groupContentKey identifies a document by its module address, defining file,
// the content it resolved to, and the call's reference set.
//
// The module address keeps two distinct calls in one configuration apart even
// when they resolve identically, since an aggregating rule must still see both;
// leaving out the calling root is what lets the same call dedup across roots.
// The reference set has to be part of the identity because it is part of the
// document: two calls resolving this file identically can still expose
// different siblings through _refs.
func groupContentKey(g *docGroup, refsKey uint64) string {
	rows := make([]string, 0, len(g.entries))
	for _, e := range g.entries {
		b, _ := json.Marshal(e.attrs)
		rows = append(rows, strings.Join(
			[]string{e.typ, e.baseName, e.defLine, strconv.FormatUint(xxhash.Sum64(b), 16)},
			"\x1f",
		))
	}
	sort.Strings(rows)
	return strings.Join([]string{
		g.moduleAddress,
		g.fm.ID,
		strconv.Itoa(g.layer),
		strconv.FormatUint(refsKey, 16),
		strings.Join(rows, "\x1e"),
	}, "\x00")
}

func moduleCallRefsKey(allInCall []moduleRefEntry) string {
	rows := make([]string, 0, len(allInCall))
	for _, e := range allInCall {
		b, _ := json.Marshal(e.attrs)
		rows = append(rows, strings.Join(
			[]string{e.typ, e.name, e.definedIn, e.defLine, strconv.FormatUint(xxhash.Sum64(b), 16)},
			"\x1f",
		))
	}
	sort.Strings(rows)
	return strings.Join(rows, "\x00")
}

// buildSharedRefsMap returns every resource in a module call, for rules that
// resolve a reference against another file of the same module. It is built once
// per call chain and shared by all of that call's docs, so unlike a
// self-excluding map it also includes the doc's own resources.
func buildSharedRefsMap(allInCall []moduleRefEntry) map[string]interface{} {
	refs := make(map[string]interface{})
	for _, e := range allInCall {
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
	clone := fm.ShallowCopy()
	clone.ID = id
	clone.Document = model.Document{}
	clone.ModuleCallChain = callChain
	if fm.LineInfoDocument != nil {
		// Already materialized: shallow-clone so later mutations on the
		// parent (e.g. deleting a suppressed "resource" key) don't alias
		// into this synthetic instance's copy.
		clone.LineInfoDocument = maps.Clone(fm.LineInfoDocument)
	}
	return clone
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
	ctx context.Context,
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
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Str("dir", dir).Msg(
		"module resolve: falling back to directory parse for called module discovery",
	)
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
