/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/cespare/xxhash/v2"
	"github.com/rs/zerolog"
)

// extraCallerInfo records a deduplicated module caller so its findings can be
// cloned from the primary OPA doc after eval without adding a separate doc to input.document.
type extraCallerInfo struct {
	callChain    string
	docID        string
	attributions map[string]*model.ModuleAttribution
}

// moduleResolutionResult bundles all outputs of resolveModuleDocuments.
type moduleResolutionResult struct {
	docs                 []model.Document
	syntheticFiles       []*model.FileMetadata
	suppressed           instantiatedIndex
	calledDirs           map[string]bool
	successfulRoots      map[string]bool
	rootDirs             []string
	unresolvedModuleDirs map[string]bool
	extras               map[string][]extraCallerInfo
	// moduleFiles holds, by file ID, the calls reaching each external module file.
	moduleFiles   map[string]*moduleFileCalls
	resourceCount int
	rootCount     int
	// report counts what evaluation did across every root.
	report tfeval.Report
	ok     bool
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
// Caller must append the files before Combine/ToMap. extras lists duplicate callers for post-OPA finding expansion,
// and moduleFiles the calls reaching each external module file.
func (c *Inspector) instantiateLocalModules(
	ctx context.Context,
	files model.FileMetadatas,
	targets *ruleTargets,
) (
	docs []model.Document,
	syntheticFiles []*model.FileMetadata,
	extras map[string][]extraCallerInfo,
	moduleFiles map[string]*moduleFileCalls,
) {
	resolver := c.buildRemoteResolver()
	res := c.resolveModulesSafely(ctx, files, resolver, targets)
	c.moduleReport = res.report
	contextLogger := logger.FromContext(ctx)
	contextLogger.Info().
		Int("module_resources_instantiated", res.resourceCount).
		Int("module_documents", len(res.docs)).
		Msgf(
			"Instantiated %d module resources into %d documents (%d deduplicated callers)",
			res.resourceCount,
			len(res.docs),
			deduplicatedCallerCount(&res),
		)
	logModuleInstantiationSummary(&contextLogger, &res)
	if !res.ok {
		return nil, nil, nil, nil
	}
	rootDirs := newRootIndex(res.rootDirs)
	for _, f := range files {
		if f == nil || !tfpath.IsConfig(f.FilePath) {
			continue
		}
		if replaced := res.suppressed[f.ID]; len(replaced) > 0 {
			if res.unresolvedModuleDirs[moduleFileDir(f.FilePath, c.repoPath)] {
				continue
			}
			// Only the blocks that came back as instantiated documents are
			// dropped, so nothing loses its coverage: a resource the evaluator
			// could not resolve, or one that expanded to no instances, keeps
			// being scanned where it is written. The rest of the body
			// (variable/output/data/locals) is always kept so its rules fire as
			// they do in a standalone scan.
			removeInstantiatedResources(f.Document, replaced)
			if err := f.EnsureLineInfoDocument(ctx); err != nil {
				contextLogger.Err(err).Msgf("failed to build line-info document for file %s", f.FilePath)
			} else {
				removeInstantiatedResources(f.LineInfoDocument, replaced)
			}
		}
		// Only remove local module call-sites that were instantiated; remote/registry
		// module blocks must remain so the corresponding Rego branches can still fire.
		stripModuleCalls(f.Document, f.FilePath, c.repoPath, res.calledDirs, res.successfulRoots, rootDirs, resolver, c.fsys)
	}
	for _, f := range files {
		if f == nil {
			continue
		}
		if calls := res.moduleFiles[f.ID]; calls != nil {
			calls.writtenResourceTypes = documentResourceTypes(f.Document)
		}
	}
	return res.docs, res.syntheticFiles, res.extras, res.moduleFiles
}

// logModuleInstantiationSummary emits the fields an on-call search needs at warn
// level. Production runs at warn, so the info-level count above is invisible there;
// without this, a scan on its way to OOM looks identical to one that never ran
// module evaluation.
func logModuleInstantiationSummary(log *zerolog.Logger, res *moduleResolutionResult) {
	if res.resourceCount == 0 {
		return
	}
	log.Warn().
		Int("module_resources_instantiated", res.resourceCount).
		Int("module_root_count", res.rootCount).
		Int("module_documents", len(res.docs)).
		Int("module_instances_evaluated", res.report.ModuleEvaluations).
		Int("instance_evaluations", res.report.InstanceEvaluations).
		Int("eval_cache_entries", res.report.CacheEntries).
		Int("eval_cache_hits", res.report.CacheHits).
		Msg("tfeval: module instantiation summary")
}

// declaresTargetedResource reports whether any scanned Terraform file declares
// a resource or data type some rule can match by name.
func declaresTargetedResource(files model.FileMetadatas, targets *ruleTargets) bool {
	if targets == nil {
		return true
	}
	for _, f := range files {
		if f == nil || !tfpath.IsConfig(f.FilePath) {
			continue
		}
		for _, key := range [...]string{"resource", "data"} {
			blocks, ok := asStringMap(f.Document[key])
			if !ok {
				continue
			}
			for typ := range blocks {
				if targets.matches(typ) {
					return true
				}
			}
		}
	}
	return false
}

// dataTypePrefix marks a data block's type wherever data and resource blocks
// share a namespace, as it does in the resourceType of a finding.
const dataTypePrefix = "data."

// blockKind is the type a resolved block is indexed and attributed under.
func blockKind(r *tfeval.ResolvedResource) string {
	if r.Data {
		return dataTypePrefix + r.Type
	}
	return r.Type
}

// instantiatedIndex records which resource and data blocks of a file were
// re-emitted as instantiated documents, as file ID -> block kind -> block name.
type instantiatedIndex map[string]map[string]map[string]bool

func (idx instantiatedIndex) add(fileID, typ, name string) {
	byType, ok := idx[fileID]
	if !ok {
		byType = make(map[string]map[string]bool)
		idx[fileID] = byType
	}
	names, ok := byType[typ]
	if !ok {
		names = make(map[string]bool)
		byType[typ] = names
	}
	names[name] = true
}

// removeInstantiatedResources deletes the named resource and data blocks from
// a parsed file so they are not scanned twice, once where they are written and
// once instantiated.
func removeInstantiatedResources(doc map[string]interface{}, replaced map[string]map[string]bool) {
	var resources, data map[string]map[string]bool
	for kind, names := range replaced {
		if typ, ok := strings.CutPrefix(kind, dataTypePrefix); ok {
			if data == nil {
				data = make(map[string]map[string]bool)
			}
			data[typ] = names
			continue
		}
		if resources == nil {
			resources = make(map[string]map[string]bool, len(replaced))
		}
		resources[kind] = names
	}
	removeInstantiatedBlocks(doc, "resource", resources)
	removeInstantiatedBlocks(doc, "data", data)
}

func removeInstantiatedBlocks(doc map[string]interface{}, key string, replaced map[string]map[string]bool) {
	if len(replaced) == 0 {
		return
	}
	resources, ok := asStringMap(doc[key])
	if !ok {
		return
	}
	for typ, names := range replaced {
		byName, ok := asStringMap(resources[typ])
		if !ok {
			// A nameless resource block parses to a list, leaving no name to
			// match on; drop the type so nothing is counted twice.
			delete(resources, typ)
			continue
		}
		for name := range names {
			delete(byName, name)
		}
		if onlyMetadataKeys(byName) {
			delete(resources, typ)
		}
	}
	if onlyMetadataKeys(resources) {
		delete(doc, key)
	}
}

// asStringMap accepts either shape a parsed document uses for an object.
func asStringMap(value interface{}) (map[string]interface{}, bool) {
	switch m := value.(type) {
	case model.Document:
		return m, true
	case map[string]interface{}:
		return m, true
	default:
		return nil, false
	}
}

// onlyMetadataKeys reports whether a map holds nothing but the parser's own
// bookkeeping (line numbers and the like), which describes content that is no
// longer there.
func onlyMetadataKeys(m map[string]interface{}) bool {
	for key := range m {
		if !strings.HasPrefix(key, "_") {
			return false
		}
	}
	return true
}

func deduplicatedCallerCount(res *moduleResolutionResult) int {
	count := 0
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
	return func(source, version, callerFile, moduleName string) (string, string, bool) {
		root := remoteModuleRoot(callerFile, c.repoPath)
		resolved, ok := lookupRemoteDir(dirs, root, source, version, moduleName)
		return resolved.Path, resolved.PackageRoot, ok
	}
}

func (c *Inspector) buildModuleMetadataResolver() tfmodules.RemoteResolver {
	if len(c.remoteModuleDirs) == 0 {
		return nil
	}
	return moduleMetadataResolver{dirs: c.remoteModuleDirs, repoPath: c.repoPath}
}

type moduleMetadataResolver struct {
	dirs     map[string]RemoteModuleDirectory
	repoPath string
}

func (r moduleMetadataResolver) Resolve(_ context.Context, mod *tfmodules.ParsedModule) (string, error) {
	root := remoteModuleRoot(mod.FileName, r.repoPath)
	resolved, ok := lookupRemoteDir(r.dirs, root, mod.Source, mod.Version, mod.Name)
	if !ok {
		return "", &tfmodules.UnresolvedError{Reason: "module was not resolved during pre-scan"}
	}
	return resolved.Path, nil
}

type RemoteModuleDirectory struct {
	Path        string
	PackageRoot string
}

func lookupRemoteDir(
	dirs map[string]RemoteModuleDirectory,
	root, source, version, name string,
) (RemoteModuleDirectory, bool) {
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
	return RemoteModuleDirectory{}, false
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
	targets *ruleTargets,
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
	var externalModuleFile func(string) bool
	if len(c.externalPathRoots) > 0 {
		externalModuleFile = c.isExternalModulePath
	}
	return resolveModuleDocuments(
		ctx, files, c.repoPath, resolver, targets, c.buildModuleProvenanceLookup(), c.mergeAllow, c.fsys,
		externalModuleFile,
	)
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
func evaluateRootModules(
	ctx context.Context,
	evaluator *tfeval.Evaluator,
	roots []string,
	filesByDir map[string][]*model.FileMetadata,
	repoPath string,
	resolver tfeval.RemoteResolver,
	targets *ruleTargets,
	lookup moduleProvenanceLookup,
	byAbsPath map[string]*model.FileMetadata,
	seen map[docContentKey]string,
	extras map[string][]extraCallerInfo,
	instantiated instantiatedIndex,
	successfulRoots map[string]bool,
	unresolvedModuleDirs map[string]bool,
	actualCalledDirs map[string]bool,
	extra *[]model.Document,
	syntheticFiles *[]*model.FileMetadata,
	resourceCount *int,
	rootEvalOK *bool,
	moduleCalls *moduleCallIndex,
) {
	m := &rootMerge{
		ctx: ctx, evaluator: evaluator, filesByDir: filesByDir, repoPath: repoPath, resolver: resolver,
		targets: targets, lookup: lookup, byAbsPath: byAbsPath, seen: seen, extras: extras,
		instantiated: instantiated, successfulRoots: successfulRoots, unresolvedModuleDirs: unresolvedModuleDirs,
		actualCalledDirs: actualCalledDirs, extra: extra, syntheticFiles: syntheticFiles,
		resourceCount: resourceCount, rootEvalOK: rootEvalOK, moduleCalls: moduleCalls,
	}
	if workers := min(rootEvalWorkers, runtime.GOMAXPROCS(0), len(roots)); workers > 1 {
		m.evaluateConcurrently(roots, workers)
		return
	}
	for _, dir := range roots {
		resources, _, childDirs, err := evaluator.EvaluateModule(ctx, dir, evaluator.LoadRootVars(dir))
		var prepared preparedRoot
		if err == nil {
			prepared = m.prepare(resources)
		}
		m.merge(dir, prepared, evaluator.TakeModuleInstances(), childDirs, err)
		if err == nil {
			// prepare has copied everything this root needs into plain
			// documents, so the evaluator's cty values are dead here. Another root
			// could in principle reuse them, but each root passes its own values to
			// the modules it shares, so the hit rate does not pay for a peak that
			// grows with the whole repository rather than the largest single root.
			evaluator.ReleaseEvalCache()
		}
	}
}

// rootEvalWorkers bounds the roots evaluated at once. Each holds its own
// evaluation values until it is merged, so this also bounds the memory
// concurrency adds.
var rootEvalWorkers = 4

// rootMerge folds root evaluations into the scan's documents, in root order.
type rootMerge struct {
	ctx                  context.Context
	evaluator            *tfeval.Evaluator
	filesByDir           map[string][]*model.FileMetadata
	repoPath             string
	resolver             tfeval.RemoteResolver
	targets              *ruleTargets
	lookup               moduleProvenanceLookup
	byAbsPath            map[string]*model.FileMetadata
	seen                 map[docContentKey]string
	extras               map[string][]extraCallerInfo
	instantiated         instantiatedIndex
	successfulRoots      map[string]bool
	unresolvedModuleDirs map[string]bool
	actualCalledDirs     map[string]bool
	extra                *[]model.Document
	syntheticFiles       *[]*model.FileMetadata
	resourceCount        *int
	rootEvalOK           *bool
	moduleCalls          *moduleCallIndex
	lineInfo             instanceLineInfo
}

// preparedRoot is a root's documents prepared, with the attribution cache
// they were prepared with.
type preparedRoot struct {
	docs         rootDocs
	attributions *moduleAttributionCache
}

// prepare prepares a root's documents. It only reads what the merge shares,
// so it runs on the worker that evaluated the root.
func (m *rootMerge) prepare(resources []tfeval.ResolvedResource) preparedRoot {
	attributions := newModuleAttributionCache()
	return preparedRoot{
		docs:         prepareRootDocs(resources, m.byAbsPath, m.repoPath, m.targets, m.lookup, attributions),
		attributions: attributions,
	}
}

func (m *rootMerge) merge(
	dir string,
	prepared preparedRoot,
	instances []tfeval.ModuleInstance,
	childDirs map[string]bool,
	err error,
) {
	defer m.evaluator.ForgetRootParse(dir)
	if err != nil {
		contextLogger := logger.FromContext(m.ctx)
		if errors.Is(err, tfeval.ErrEvaluationStopped) {
			// The scan was canceled and ends with its context's error.
			contextLogger.Debug().Msgf("tfeval: evaluation of root module %s canceled", dir)
		} else {
			contextLogger.Warn().Err(err).Msgf("tfeval: failed to evaluate root module %s", dir)
		}
		for _, called := range discoverCalledModuleClosure(
			m.ctx, m.evaluator, m.filesByDir, m.repoPath, m.resolver, dir,
		) {
			m.unresolvedModuleDirs[called] = true
		}
		return
	}
	*m.rootEvalOK = true
	m.successfulRoots[dir] = true
	for d := range childDirs {
		m.actualCalledDirs[d] = true
	}
	if m.lineInfo == nil {
		m.lineInfo = make(instanceLineInfo)
	}
	docs, syn := mergeRootDocs(prepared.docs, m.seen, m.extras, m.instantiated, m.lineInfo)
	m.moduleCalls.record(instances, m.repoPath, m.lookup, prepared.attributions)
	*m.extra = append(*m.extra, docs...)
	*m.syntheticFiles = append(*m.syntheticFiles, syn...)
	*m.resourceCount += prepared.docs.resourceCount
}

// rootResult is a root evaluated by a worker, its documents prepared.
type rootResult struct {
	prepared     preparedRoot
	instances    []tfeval.ModuleInstance
	childDirs    map[string]bool
	err          error
	notEvaluated []string
	report       tfeval.Report
	panicked     any
}

// evaluateConcurrently evaluates roots on workers and merges them in order, so
// shared documents get the same owners as when roots are evaluated one by one.
// A root is evaluated apart from the roots before it, so merging in order
// yields what evaluating them one by one would.
func (m *rootMerge) evaluateConcurrently(roots []string, workers int) {
	results := make([]chan rootResult, len(roots))
	for i := range results {
		results[i] = make(chan rootResult, 1)
	}
	// Tokens bound the roots evaluated but not yet merged. Workers take a token
	// before an index, so the roots in flight are always the next ones to merge.
	window := make(chan struct{}, 2*workers)
	stop := make(chan struct{})
	var (
		mu       sync.Mutex
		nextRoot int
		wg       sync.WaitGroup
	)
	for range workers {
		worker := m.evaluator.Fork()
		wg.Go(func() {
			for {
				select {
				case window <- struct{}{}:
				case <-stop:
					return
				}
				mu.Lock()
				i := nextRoot
				nextRoot++
				mu.Unlock()
				if i >= len(roots) {
					return
				}
				select {
				case <-stop:
					return
				default:
				}
				results[i] <- m.evaluateRoot(worker, roots[i])
			}
		})
	}
	defer func() {
		close(stop)
		wg.Wait()
	}()

	for i, dir := range roots {
		r := <-results[i]
		<-window
		if r.panicked != nil {
			panic(r.panicked)
		}
		m.evaluator.AddNotEvaluatedDirs(r.notEvaluated)
		m.evaluator.Report().Merge(&r.report)
		m.merge(dir, r.prepared, r.instances, r.childDirs, r.err)
	}
}

// evaluateRoot evaluates a root on a worker and prepares its documents there,
// so that merging it only adds them to those of the roots before it.
func (m *rootMerge) evaluateRoot(worker *tfeval.Evaluator, dir string) (r rootResult) {
	defer func() {
		if p := recover(); p != nil {
			r = rootResult{panicked: p}
		}
		r.notEvaluated = worker.TakeNotEvaluatedDirs()
		r.report = worker.TakeReport()
		worker.ReleaseEvalCache()
	}()
	var resources []tfeval.ResolvedResource
	resources, _, r.childDirs, r.err = worker.EvaluateModule(m.ctx, dir, worker.LoadRootVars(dir))
	r.instances = worker.TakeModuleInstances()
	if r.err == nil {
		r.prepared = m.prepare(resources)
	}
	return r
}

// collectNotEvaluatedDirs marks the directories the evaluator skipped, and
// everything they call, as unresolved.
//
// A directory is reached from several call sites, and cycle stops apply to
// one call site at a time, so a directory can come out of a scan
// with some instances resolved and others skipped. Suppression is decided per
// directory, so without this the resolved instances would suppress the body and
// the skipped ones would be represented by nothing at all — a silent false
// negative for exactly the inputs that were never evaluated. Keeping the body
// costs a finding that also appears on a resolved instance, which is the safe
// side of that trade. The subtree is included because a skipped call site did
// not materialize any of the modules underneath it either.
func collectNotEvaluatedDirs(
	ctx context.Context,
	evaluator *tfeval.Evaluator,
	filesByDir map[string][]*model.FileMetadata,
	repoPath string,
	resolver tfeval.RemoteResolver,
	unresolvedModuleDirs map[string]bool,
) {
	// One walk over every skipped directory at once, using the result set as the
	// visited set: the subtrees overlap heavily, and dirs marked by a failed root
	// already had their own subtree walked.
	var queue []string
	for _, dir := range evaluator.NotEvaluatedDirs() {
		if unresolvedModuleDirs[dir] {
			continue
		}
		unresolvedModuleDirs[dir] = true
		queue = append(queue, dir)
	}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		for _, called := range discoverCalledModuleDirs(
			ctx, evaluator, filesByDir[dir], repoPath, resolver, dir,
		) {
			if unresolvedModuleDirs[called] {
				continue
			}
			unresolvedModuleDirs[called] = true
			queue = append(queue, called)
		}
	}
}

func scrubInstantiatedForUnresolvedDirs(
	instantiated instantiatedIndex,
	files model.FileMetadatas,
	unresolvedModuleDirs map[string]bool,
	repoPath string,
) {
	for _, f := range files {
		if f == nil {
			continue
		}
		if unresolvedModuleDirs[moduleFileDir(f.FilePath, repoPath)] {
			delete(instantiated, f.ID)
		}
	}
}

func resolveModuleDocuments(
	ctx context.Context,
	files model.FileMetadatas,
	repoPath string,
	resolver tfeval.RemoteResolver,
	targets *ruleTargets,
	lookup moduleProvenanceLookup,
	mergeAllow map[string]struct{},
	fsys vfs.FS,
	externalModuleFile func(string) bool,
) moduleResolutionResult {
	byAbsPath, filesByDir, dirsWithTf := indexTerraformFiles(ctx, files, repoPath)
	if len(dirsWithTf) == 0 {
		return moduleResolutionResult{}
	}
	// Evaluating a module tree is the expensive part, and it is pure waste when
	// the repository declares nothing any rule can match by name. The block
	// labels are already in the parsed documents, so this costs nothing.
	// External module files still need their calls, whatever they declare.
	moduleCalls := newModuleCallIndex(filesByDir, externalModuleFile)
	declaresResource := declaresTargetedResource(files, targets)
	if moduleCalls == nil && !declaresResource {
		return moduleResolutionResult{}
	}
	// With no resource to resolve, a root only matters for the calls it makes
	// to external module directories, so the others are not evaluated.
	onlyExternalCalls := moduleCalls != nil && !declaresResource

	evaluator := tfeval.NewWithFS(fsys)
	evaluator.SetMergeAllow(mergeAllow)
	evaluator.SetTrackModuleInstances(moduleCalls != nil)
	if resolver != nil {
		evaluator.SetRemoteResolver(resolver)
	}

	// staticCalledDirs is used only to classify root vs. child dirs before evaluation.
	// Suppression and stripping are driven by actualCalledDirs (evaluation results).
	staticCalledDirs, staticCalls := discoverStaticCalls(
		ctx, evaluator, filesByDir, dirsWithTf, repoPath, resolver, onlyExternalCalls)

	// seen maps a content-based key to the primary docID so duplicate callers can
	// be recorded in extras rather than emitted as separate OPA documents.
	seen := make(map[docContentKey]string)
	extras := make(map[string][]extraCallerInfo)
	instantiated := make(instantiatedIndex)
	var rootEvalOK bool
	actualCalledDirs := make(map[string]bool)
	successfulRoots := make(map[string]bool)
	unresolvedModuleDirs := make(map[string]bool)
	var extra []model.Document
	var syntheticFiles []*model.FileMetadata
	var resourceCount int

	// Roots are taken in a fixed order: which of several identical callers ends
	// up owning a shared document decides that document's id, and ids reach
	// finding fingerprints.
	roots := make([]string, 0, len(dirsWithTf))
	for dir := range dirsWithTf {
		if staticCalledDirs[dir] {
			continue // instantiated via a module call, not a root
		}
		roots = append(roots, dir)
	}
	sort.Strings(roots)

	evaluatedRoots := roots
	if onlyExternalCalls {
		evaluatedRoots = rootsReaching(roots, staticCalls, moduleCalls.files)
	}

	evaluateRootModules(
		ctx, evaluator, evaluatedRoots, filesByDir, repoPath, resolver, targets, lookup,
		byAbsPath, seen, extras, instantiated,
		successfulRoots, unresolvedModuleDirs, actualCalledDirs,
		&extra, &syntheticFiles, &resourceCount, &rootEvalOK, moduleCalls,
	)
	collectNotEvaluatedDirs(
		ctx, evaluator, filesByDir, repoPath, resolver, unresolvedModuleDirs,
	)
	evaluator.ReleaseCaches()
	report := evaluator.TakeReport()

	// If every root evaluation failed, do not strip or suppress module bodies: that would
	// remove coverage with no synthetic replacement.
	if !rootEvalOK {
		return moduleResolutionResult{report: report}
	}

	// A call site is only stripped once the module behind it actually produced
	// instantiated documents. Stripping it otherwise — because evaluation
	// resolved nothing, or because the module's files are not part of the scan
	// — would remove the call-site rule branches without putting anything in
	// their place.
	strippedDirs := make(map[string]bool, len(actualCalledDirs))
	for dir := range actualCalledDirs {
		// A directory with any unevaluated call site keeps its call sites too. The
		// resolved instances no longer stand in for the whole directory, so removing
		// the call-site blocks would drop the rules that match them for an instance
		// that has nothing else representing it.
		if unresolvedModuleDirs[dir] {
			continue
		}
		for _, f := range filesByDir[dir] {
			if len(instantiated[f.ID]) > 0 {
				strippedDirs[dir] = true
				break
			}
		}
	}

	scrubInstantiatedForUnresolvedDirs(instantiated, files, unresolvedModuleDirs, repoPath)

	return moduleResolutionResult{
		docs:                 extra,
		syntheticFiles:       syntheticFiles,
		suppressed:           instantiated,
		calledDirs:           strippedDirs,
		successfulRoots:      successfulRoots,
		rootDirs:             roots,
		unresolvedModuleDirs: unresolvedModuleDirs,
		extras:               extras,
		moduleFiles:          moduleCalls.fileCalls(unresolvedModuleDirs),
		resourceCount:        resourceCount,
		rootCount:            len(roots),
		report:               report,
		ok:                   true,
	}
}

// discoverStaticCalls returns the directories some scanned directory calls,
// and, when withGraph is set, the calls of each directory.
func discoverStaticCalls(
	ctx context.Context,
	evaluator *tfeval.Evaluator,
	filesByDir map[string][]*model.FileMetadata,
	dirsWithTf map[string]bool,
	repoPath string,
	resolver tfeval.RemoteResolver,
	withGraph bool,
) (called map[string]bool, graph staticCallGraph) {
	called = make(map[string]bool)
	if withGraph {
		graph = staticCallGraph{
			calls:  make(map[string][]string, len(dirsWithTf)),
			opaque: make(map[string]bool),
		}
	}
	for dir := range dirsWithTf {
		calledDirs := discoverCalledModuleDirs(ctx, evaluator, filesByDir[dir], repoPath, resolver, dir)
		if withGraph {
			graph.calls[dir] = calledDirs
			graph.opaque[dir] = hasUnresolvableModuleCall(filesByDir[dir])
		}
		for _, calledDir := range calledDirs {
			called[calledDir] = true
		}
	}
	return called, graph
}

// staticCallGraph is the module calls readable without evaluating anything.
type staticCallGraph struct {
	calls map[string][]string
	// opaque holds the directories making a call the graph cannot follow, such
	// as a source built from a variable. What they reach is unknown.
	opaque map[string]bool
}

// hasUnresolvableModuleCall reports whether files make a module call whose
// source is not a literal. Files without a parsed document are unreadable here
// and count as unresolvable.
func hasUnresolvableModuleCall(files []*model.FileMetadata) bool {
	for _, file := range files {
		if file == nil {
			continue
		}
		if len(file.Document) == 0 {
			return true
		}
		for _, callRaw := range docAsMap(file.Document["module"]) {
			source, ok := docAsMap(callRaw)["source"].(string)
			if !ok || strings.Contains(source, "${") || strings.Contains(source, "%{") {
				return true
			}
		}
	}
	return false
}

// rootsReaching returns the roots whose module calls lead, through any depth
// of local or remote calls, to one of the target directories. A root reaching
// a directory with a call the graph cannot follow is kept: it may reach them.
func rootsReaching(roots []string, graph staticCallGraph, targets map[string][]*model.FileMetadata) []string {
	callers := make(map[string][]string, len(graph.calls))
	for dir, called := range graph.calls {
		for _, c := range called {
			callers[c] = append(callers[c], dir)
		}
	}
	// Walking the calls backwards from the directories of interest is safe on
	// cycles and does not depend on the order roots are visited in.
	reaches := make(map[string]bool, len(graph.calls))
	var queue []string
	mark := func(dir string) {
		if !reaches[dir] {
			reaches[dir] = true
			queue = append(queue, dir)
		}
	}
	for dir := range targets {
		mark(dir)
	}
	for dir, opaque := range graph.opaque {
		if opaque {
			mark(dir)
		}
	}
	for len(queue) > 0 {
		dir := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for _, caller := range callers[dir] {
			mark(caller)
		}
	}
	var out []string
	for _, root := range roots {
		if reaches[root] {
			out = append(out, root)
		}
	}
	return out
}

// instantiatedResource is one resolved resource or data block as it is placed
// into a document.
type instantiatedResource struct {
	// typ is the block kind, the type prefixed with "data." for a data block.
	typ       string
	baseName  string
	fullName  string
	defLine   int
	attrs     map[string]interface{}
	attrsHash uint64
}

// docGroup collects every resource one module call resolved in one defining file.
// callKey is a module call in one of the files it instantiates.
type callKey struct{ callChain, fileID string }

type docGroup struct {
	fm            *model.FileMetadata
	callChain     string
	moduleAddress string
	layer         int
	call          callKey
	entries       []instantiatedResource
	attributions  map[string]*model.ModuleAttribution
	// ownAttributions is set once attributions is the group's own map rather
	// than the one its call shares.
	ownAttributions bool
	// docID, contentKey and doc are the group's document, its id and the key
	// of its content.
	docID      string
	contentKey docContentKey
	doc        model.Document
}

// setAttribution records the attribution of a resource of the group.
func (g *docGroup) setAttribution(key string, attr *model.ModuleAttribution) {
	existing, ok := g.attributions[key]
	if ok && existing == attr {
		return
	}
	if ok && !g.ownAttributions {
		g.attributions = maps.Clone(g.attributions)
		g.ownAttributions = true
	}
	g.attributions[key] = attr
}

// docContentKey identifies a document by its content. Two independent digests
// keep the collision probability negligible across the hundreds of thousands of
// documents a large repository resolves: a collision would silently merge two
// different resources into one finding.
type docContentKey struct{ a, b uint64 }

// rootDocs is what prepareRootDocs makes of one root's resources apart from
// the roots merged before it: every document the root resolved to, keyed by
// its content, to be deduplicated against those roots by mergeRootDocs.
type rootDocs struct {
	groups        []*docGroup
	resourceCount int
}

// Instantiated resources are emitted as one synthetic OPA document per (module
// call, defining file), holding every resource that call resolved in that file.
//
// This is exactly the shape an ordinary Terraform file has in the payload: one
// document, all of the file's resources, nothing from its siblings. A rule
// therefore cannot tell whether a resource was written inline or reached
// through a module, and cross-file rules are neither better nor worse inside a
// module than they already are outside one.
//
// The shape is also what keeps the payload proportional to the configuration
// rather than to the call graph. A document per resource, or a document
// carrying an index of its siblings, ties each document to the call it came
// from and defeats the deduplication below: on a repository where 77 roots call
// the same modules, that is the difference between 20k and 197k documents, and
// every document costs a synthetic file, a payload entry and a pass of every
// rule.
//
// Callers whose resolved content is identical share one document; the rest are
// recorded in extras so their findings are cloned after evaluation, keeping
// per-call-site attribution without re-evaluating identical input.
//
// prepareRootDocs groups a root's resources into those documents and builds
// them. It reads nothing another root writes, so roots are prepared
// concurrently.
func prepareRootDocs(
	resources []tfeval.ResolvedResource,
	byAbsPath map[string]*model.FileMetadata,
	repoPath string,
	targets *ruleTargets,
	lookup moduleProvenanceLookup,
	attributions *moduleAttributionCache,
) rootDocs {
	var resourceCount int
	// Keys are structs of strings the resources already hold, not strings
	// built per resource.
	type slotKey struct{ callChain, fileID, kind, base string }
	type groupKey struct {
		callChain, fileID string
		layer             int
	}
	// Sized for one document per resource, the most there can be, so they
	// do not grow one entry at a time over hundreds of thousands of them.
	groups := make(map[groupKey]*docGroup, len(resources))
	order := make([]groupKey, 0, len(resources))
	// The attributions of one call in one file are shared by the documents
	// holding its instances. An instance's attribution is usually its block's,
	// the same pointer for every instance; a group meeting one that differs,
	// because it depends on the iteration, takes its own copy of the map.
	callAttributions := make(map[callKey]map[string]*model.ModuleAttribution)
	// A base name repeats within one call and file whenever count/for_each
	// expands a block. Document keys stay base-named so line detection can
	// resolve them against the file's HCL, so repeats spill into a further
	// document rather than overwriting each other.
	layers := make(map[slotKey]int, len(resources))
	converted := convertInstances(resources, targets)
	files := make(map[string]*model.FileMetadata)
	type chainKey struct {
		first   *tfeval.CallSite
		n       int
		address string
	}
	chainKeys := make(map[chainKey]string)

	for i := range resources {
		r := &resources[i]
		if !converted[i].ok {
			continue
		}
		attrs := converted[i].attrs
		kind := blockKind(r)
		fm, ok := files[r.DefinedIn]
		if !ok {
			fm = byAbsPath[absPath(r.DefinedIn, repoPath)]
			files[r.DefinedIn] = fm
		}
		if fm == nil {
			continue
		}
		// Every resource of a module instance shares its chain, so its call
		// chain key is built once.
		ck := chainKey{n: len(r.CallChain), address: r.ModuleAddress}
		if len(r.CallChain) > 0 {
			ck.first = &r.CallChain[0]
		}
		cck, ok := chainKeys[ck]
		if !ok {
			cck = callChainKey(r, repoPath)
			chainKeys[ck] = cck
		}
		base := tfeval.ResourceBaseName(r.Name)
		entry := instantiatedResource{
			typ:       kind,
			baseName:  base,
			fullName:  r.Name,
			defLine:   r.DefLine,
			attrs:     attrs,
			attrsHash: converted[i].hash,
		}

		slot := slotKey{callChain: cck, fileID: fm.ID, kind: kind, base: base}
		layer := layers[slot]
		layers[slot] = layer + 1

		key := groupKey{callChain: cck, fileID: fm.ID, layer: layer}
		g, exists := groups[key]
		if !exists {
			call := callKey{callChain: cck, fileID: fm.ID}
			shared, ok := callAttributions[call]
			if !ok {
				shared = make(map[string]*model.ModuleAttribution)
				callAttributions[call] = shared
			}
			g = &docGroup{
				fm: fm, callChain: cck, moduleAddress: r.ModuleAddress, layer: layer,
				attributions: shared, call: call,
			}
			groups[key] = g
			order = append(order, key)
		}
		g.setAttribution(moduleAttributionKey(kind, r.DefLine, r.DefColumn), attributions.attribution(r, repoPath, lookup))
		g.entries = append(g.entries, entry)
		resourceCount++
	}

	prepared := rootDocs{groups: make([]*docGroup, 0, len(order)), resourceCount: resourceCount}
	for _, key := range order {
		g := groups[key]
		g.docID = g.fm.ID + "\x00" + g.callChain + "\x00" + strconv.Itoa(g.layer)
		g.contentKey = groupContentKey(g)
		g.doc = groupDocument(g)
		prepared.groups = append(prepared.groups, g)
	}
	return prepared
}

// groupDocument builds the document holding a group's resources.
func groupDocument(g *docGroup) model.Document {
	resource := make(map[string]interface{})
	var data map[string]interface{}
	for i := range g.entries {
		e := &g.entries[i]
		blocks, typ := resource, e.typ
		if dataType, ok := strings.CutPrefix(e.typ, dataTypePrefix); ok {
			if data == nil {
				data = make(map[string]interface{})
			}
			blocks, typ = data, dataType
		}
		byName, ok := blocks[typ].(map[string]interface{})
		if !ok {
			byName = make(map[string]interface{})
			blocks[typ] = byName
		}
		byName[e.baseName] = e.attrs
	}
	doc := model.Document{
		"id":       g.docID,
		"file":     g.fm.FilePath,
		"resource": resource,
	}
	if data != nil {
		doc["data"] = data
	}
	return doc
}

// mergeRootDocs adds a prepared root's documents to those of the roots merged
// before it: a document whose content one of them already has is recorded as
// an extra caller of that one instead.
//
// synthetic holds, at each document's position, the file the document stands
// for; documents of one call in one file share it, its ID being the first
// one's document id.
func mergeRootDocs(
	prepared rootDocs,
	seen map[docContentKey]string,
	extras map[string][]extraCallerInfo,
	instantiated instantiatedIndex,
	lineInfo instanceLineInfo,
) (docs []model.Document, synthetic []*model.FileMetadata) {
	// The documents of one call in one file stand for that file through one
	// synthetic file, as they share its attributions: they only differ by
	// document id, which their findings take as their file id.
	callFiles := make(map[callKey]*model.FileMetadata)
	docs = make([]model.Document, 0, len(prepared.groups))
	synthetic = make([]*model.FileMetadata, 0, len(prepared.groups))
	for _, g := range prepared.groups {
		// Recorded before deduplication: a document that dedupes away still
		// covers its resources, through findings cloned onto its call site.
		for i := range g.entries {
			instantiated.add(g.fm.ID, g.entries[i].typ, g.entries[i].baseName)
		}
		if primaryDocID, dup := seen[g.contentKey]; dup {
			extras[primaryDocID] = append(extras[primaryDocID], extraCallerInfo{
				callChain:    g.callChain,
				docID:        g.docID,
				attributions: g.attributions,
			})
			continue
		}
		seen[g.contentKey] = g.docID
		docs = append(docs, g.doc)
		// A group holding attributions of its own has a file of its own.
		sf, ok := callFiles[g.call]
		if !ok || g.ownAttributions {
			sf = newInstanceFileMetadata(g.fm, lineInfo.of(g.fm), g.docID, g.callChain, g.attributions)
			if !g.ownAttributions {
				callFiles[g.call] = sf
			}
		}
		synthetic = append(synthetic, sf)
	}
	return docs, synthetic
}

// convertedInstance is a resolved resource's document and its content hash;
// ok is false for a resource that is not instantiated.
type convertedInstance struct {
	attrs map[string]interface{}
	hash  uint64
	ok    bool
}

// parallelInstanceConversion is how many resources each conversion worker
// takes at least; below twice that, one worker converts them all.
var parallelInstanceConversion = 4096

// convertInstances converts every instantiated resource to its document.
// Conversion only reads what evaluation produced, so a large set is split
// across workers.
func convertInstances(resources []tfeval.ResolvedResource, targets *ruleTargets) []convertedInstance {
	out := make([]convertedInstance, len(resources))
	convert := func(from, to int) {
		for i := from; i < to; i++ {
			r := &resources[i]
			if r.ModuleAddress == "" {
				// A root module block, expanded or not, is scanned where it is
				// written: the parsed file already holds it, and its rules count
				// it once, as written.
				continue
			}
			if !targets.matches(r.Type) {
				// No rule can match this type by name, so resolving its values
				// cannot change a finding. It keeps being scanned where it is
				// written, exactly as it is without module evaluation.
				continue
			}
			attrs := tfeval.AttributesToDocument(r)
			out[i] = convertedInstance{attrs: attrs, hash: hashAttributes(attrs), ok: true}
		}
	}
	workers := min(runtime.GOMAXPROCS(0), len(resources)/parallelInstanceConversion)
	if workers <= 1 {
		convert(0, len(resources))
		return out
	}
	var wg sync.WaitGroup
	chunk := (len(resources) + workers - 1) / workers
	for from := 0; from < len(resources); from += chunk {
		to := min(from+chunk, len(resources))
		wg.Go(func() { convert(from, to) })
	}
	wg.Wait()
	return out
}

// groupContentKey identifies a document by the module call address it belongs
// to, its defining file, and the content it resolved to.
//
// The module address keeps two distinct calls in one configuration apart even
// when they resolve identically, since a rule that aggregates across documents
// must still see both; leaving out the calling root is what lets the same call
// deduplicate across roots.
func groupContentKey(g *docGroup) docContentKey {
	sortInstantiated(g.entries)

	h := newContentHasher()
	h.str(g.moduleAddress)
	h.str(g.fm.ID)
	h.u64(uint64(g.layer))
	for i := range g.entries {
		e := &g.entries[i]
		h.str(e.typ)
		h.str(e.baseName)
		h.u64(uint64(e.defLine))
		h.u64(e.attrsHash)
	}
	return h.key()
}

func sortInstantiated(entries []instantiatedResource) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].typ != entries[j].typ {
			return entries[i].typ < entries[j].typ
		}
		if entries[i].fullName != entries[j].fullName {
			return entries[i].fullName < entries[j].fullName
		}
		return entries[i].defLine < entries[j].defLine
	})
}

// hashAttributes digests a resource's document. Equal documents digest equal:
// maps are walked in key order, and every value is tagged with its kind and
// length so different shapes do not run together. The digest is streamed:
// marshaling each of hundreds of thousands of resources to JSON first
// allocates more than the documents themselves.
func hashAttributes(attrs map[string]interface{}) uint64 {
	d := xxhash.New()
	hashValue(d, attrs)
	return d.Sum64()
}

func hashValue(d *xxhash.Digest, v interface{}) {
	var buf [9]byte
	tag := func(kind byte, n int) {
		buf[0] = kind
		binary.LittleEndian.PutUint64(buf[1:], uint64(n))
		_, _ = d.Write(buf[:])
	}
	str := func(kind byte, s string) {
		tag(kind, len(s))
		_, _ = d.WriteString(s)
	}
	switch x := v.(type) {
	case nil:
		tag('z', 0)
	case string:
		str('s', x)
	case json.Number:
		str('n', string(x))
	case bool:
		if x {
			tag('t', 0)
		} else {
			tag('f', 0)
		}
	case map[string]interface{}:
		hashMap(d, x, tag, str)
	case model.Document:
		hashMap(d, x, tag, str)
	case []interface{}:
		tag('l', len(x))
		for _, e := range x {
			hashValue(d, e)
		}
	default:
		str('?', fmt.Sprintf("%T:%v", x, x))
	}
}

func hashMap(d *xxhash.Digest, m map[string]interface{}, tag func(byte, int), str func(byte, string)) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tag('m', len(keys))
	for _, k := range keys {
		str('k', k)
		hashValue(d, m[k])
	}
}

// contentHasher folds fields into a 128-bit key using two independent digests.
// The digests are held by value so a hasher needs no allocation.
type contentHasher struct{ a, b xxhash.Digest }

func newContentHasher() contentHasher {
	var h contentHasher
	h.a.Reset()
	h.b.Reset()
	_, _ = h.b.WriteString("\x00datadog-iac-scanner\x00")
	return h
}

func (h *contentHasher) str(s string) {
	for _, d := range [...]*xxhash.Digest{&h.a, &h.b} {
		_, _ = d.WriteString(s)
		_, _ = d.WriteString("\x1f")
	}
}

func (h *contentHasher) u64(v uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	for _, d := range [...]*xxhash.Digest{&h.a, &h.b} {
		_, _ = d.Write(buf[:])
	}
}

func (h *contentHasher) key() docContentKey {
	return docContentKey{a: h.a.Sum64(), b: h.b.Sum64()}
}

// instanceLineInfo holds, by file ID, the line info every synthetic document
// of a file shares: line detection reparses a file once, not once per instance.
type instanceLineInfo map[string]*model.SharedLineInfo

func (l instanceLineInfo) of(fm *model.FileMetadata) *model.SharedLineInfo {
	shared, ok := l[fm.ID]
	if !ok {
		// Captured before suppression edits fm's own line info, so instances
		// keep resolving lines of the blocks they replace.
		shared = model.NewSharedLineInfo(fm)
		l[fm.ID] = shared
	}
	return shared
}

// newInstanceFileMetadata clones fm for a synthetic doc (empty Document so Combine skips it).
func newInstanceFileMetadata(
	fm *model.FileMetadata, lineInfo *model.SharedLineInfo, id, callChain string,
	attributions map[string]*model.ModuleAttribution,
) *model.FileMetadata {
	clone := fm.DerivedCopy(lineInfo)
	clone.ID = id
	clone.Document = model.Document{}
	clone.ModuleCallChain = callChain
	// Shared, not copied: attributions are only read, through
	// moduleAttributionForResource, which copies what it narrows.
	clone.ModuleAttributions = attributions
	return clone
}

// callChainKey is repo-relative outer caller + "|" + module address (no line numbers, to keep fingerprints stable).
func callChainKey(r *tfeval.ResolvedResource, repoPath string) string {
	return moduleCallChainKey(r.CallChain, r.ModuleAddress, repoPath)
}

func moduleCallChainKey(chain []tfeval.CallSite, moduleAddress, repoPath string) string {
	if len(chain) == 0 {
		return moduleAddress
	}
	root := absPath(chain[0].CalledFrom, repoPath)
	rel := root
	if rp, err := filepath.Rel(repoPath, root); err == nil {
		rel = rp
	}
	return filepath.ToSlash(rel) + "|" + moduleAddress
}

// stripModuleCalls drops module blocks whose target dir is in calledDirs.
// Remote/registry sources stay so existing Rego call-site rules still match.
// Call sites under a root whose evaluation failed are left in place so a
// failed instantiation does not remove coverage with no synthetic replacement.
func stripModuleCalls(
	doc model.Document,
	filePath, repoPath string,
	calledDirs map[string]bool,
	successfulRoots map[string]bool,
	rootDirs rootIndex,
	resolver tfeval.RemoteResolver,
	fsys vfs.FS,
) {
	// Checked before ownership because most files declare no module calls at all,
	// and resolving the owning root is the more expensive of the two guards.
	modules := docAsMap(doc["module"])
	if modules == nil {
		return
	}
	fileDir := filepath.Dir(absPath(filePath, repoPath))
	if root := rootDirs.owningRoot(fileDir); root == "" || !successfulRoots[root] {
		return
	}
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
		resolvedDir, _ := resolveModuleTargetDir(fsys, fileDir, source, version, filePath, name, resolver)

		if resolvedDir != "" && calledDirs[resolvedDir] {
			delete(modules, name)
		}
	}
	if len(modules) == 0 {
		delete(doc, "module")
	}
}

// moduleFileDir returns the absolute directory containing a scanned Terraform file.
func moduleFileDir(filePath, repoPath string) string {
	return filepath.Dir(absPath(filePath, repoPath))
}

// rootIndex resolves which root module directory owns a file. Roots are already
// absolute and cleaned, so ownership is a walk up the file's parents rather than
// a scan of every root: on a repository with thousands of independent stacks the
// scan is the dominant cost of the whole instantiation pass.
type rootIndex map[string]bool

func newRootIndex(roots []string) rootIndex {
	idx := make(rootIndex, len(roots))
	for _, root := range roots {
		idx[root] = true
	}
	return idx
}

// owningRoot returns the innermost root module directory containing fileDir,
// or "" when no root does.
func (idx rootIndex) owningRoot(fileDir string) string {
	for dir := fileDir; ; {
		if idx[dir] {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
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
	calledDirs, ok := calledModuleDirsFromDocuments(evaluator.FS(), files, repoPath, resolver)
	if ok {
		return calledDirs
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Str("dir", dir).Msg(
		"module resolve: falling back to directory parse for called module discovery",
	)
	return evaluator.CalledModuleDirs(dir)
}

// discoverCalledModuleClosure returns every module transitively reachable from
// dir. It is used when a call chain was not evaluated and suppression must be
// conservative, because no synthetic documents exist for anything under it.
func discoverCalledModuleClosure(
	ctx context.Context,
	evaluator *tfeval.Evaluator,
	filesByDir map[string][]*model.FileMetadata,
	repoPath string,
	resolver tfeval.RemoteResolver,
	dir string,
) []string {
	seen := map[string]bool{dir: true}
	queue := []string{dir}
	var closure []string

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, called := range discoverCalledModuleDirs(
			ctx, evaluator, filesByDir[current], repoPath, resolver, current,
		) {
			if seen[called] {
				continue
			}
			seen[called] = true
			closure = append(closure, called)
			queue = append(queue, called)
		}
	}
	return closure
}

func calledModuleDirsFromDocuments(
	fsys vfs.FS,
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
			if dir, ok := resolveModuleTargetDir(fsys, fileDir, source, version, file.FilePath, name, resolver); ok {
				dirs = append(dirs, dir)
			}
		}
	}
	return dirs, true
}

func resolveModuleTargetDir(
	fsys vfs.FS,
	callerDir, source, version, callerFile, moduleName string,
	resolver tfeval.RemoteResolver,
) (string, bool) {
	if dir, ok := tfmodules.LocalModuleDir(fsys, callerDir, source); ok {
		return dir, true
	}
	if resolver == nil {
		return "", false
	}
	dir, _, ok := resolver(source, version, callerFile, moduleName)
	return dir, ok
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
		if f == nil || !tfpath.IsConfig(f.FilePath) {
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
