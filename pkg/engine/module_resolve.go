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
	"fmt"
	"maps"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
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
	docID string
	// rootModule is this caller's own root module directory (K9CODESEC-7158).
	// The resource's address is the same as the primary's (content dedup keys
	// on moduleAddress, which a caller's own root never changes), only the
	// root differs, so only this needs to be carried.
	rootModule   string
	attributions map[string]*model.ModuleAttribution
}

// extraInstanceInfo records a count/for_each instance document whose
// rule-visible content is identical to the primary's, so its findings are
// cloned from the primary after eval without a document of its own in
// input.document. Unlike a deduplicated module caller, a member differs from
// the primary only in which instance of each block it is: the finding's
// address is rebuilt with the member's suffix, and its root module directory
// can differ from the primary's when two roots expand identical blocks.
type extraInstanceInfo struct {
	docID      string
	rootModule string
	// instances maps each expanded block to the instance suffix this member
	// represents. It carries the same blocks as the primary's scope with the
	// member's own keys.
	instances map[model.TerraformBlock]string
	// scope is the primary document's TerraformScope, which the member's
	// findings are resolved against (the members declare the same blocks).
	scope *model.TerraformScope
}

// instancePrimary records the document an all-instances group folds into: its
// docID and the synthetic scope its findings resolve against.
type instancePrimary struct {
	docID string
	scope *model.TerraformScope
}

// moduleResolutionResult bundles all outputs of resolveModuleDocuments.
type moduleResolutionResult struct {
	docs                 []model.Document
	syntheticFiles       []*model.FileMetadata
	suppressed           instantiatedIndex
	successfulRoots      map[string]bool
	rootDirs             []string
	unresolvedModuleDirs map[string]bool
	extras               map[string][]extraCallerInfo
	instanceExtras       map[string][]extraInstanceInfo
	// moduleFiles holds, by file ID, the calls reaching each external module file.
	moduleFiles   map[string]*moduleFileCalls
	resourceCount int
	rootCount     int
	ok            bool
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
// instanceExtras the identical-content instance documents folded into a
// primary's, and moduleFiles the calls reaching each external module file.
func (c *Inspector) instantiateLocalModules(
	ctx context.Context,
	files model.FileMetadatas,
	targets *ruleTargets,
) (
	docs []model.Document,
	syntheticFiles []*model.FileMetadata,
	extras map[string][]extraCallerInfo,
	instanceExtras map[string][]extraInstanceInfo,
	moduleFiles map[string]*moduleFileCalls,
) {
	resolver := c.buildRemoteResolver()
	res := c.resolveModulesSafely(ctx, files, resolver, targets)
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
		return nil, nil, nil, nil, nil
	}
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
		// Module call blocks stay in the scan: rules matching the call block
		// itself (source, version, arguments) fire there, addressed
		// <module path>.module.<name> (K9CODESEC-7158). The instantiated
		// resources the call resolves to are separate blocks with their own
		// addresses, so a rule with both a call-site and a resource branch
		// reports both blocks rather than one finding standing in for two.
	}
	for _, f := range files {
		if f == nil {
			continue
		}
		if calls := res.moduleFiles[f.ID]; calls != nil {
			calls.writtenResourceTypes = documentResourceTypes(f.Document)
		}
	}
	return res.docs, res.syntheticFiles, res.extras, res.instanceExtras, res.moduleFiles
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
		for _, key := range [...]string{"resource", "data", ephemeralSection} {
			blocks, ok := asStringMap(f.Document[key])
			if !ok {
				continue
			}
			for typ := range blocks {
				// Ephemeral rules name the type with its namespace prefix.
				if targets.matches(typ) || targets.matches(ephemeralPrefix+typ) {
					return true
				}
			}
		}
	}
	return false
}

// dataTypePrefix and ephemeralPrefix mark a data or ephemeral block's type
// wherever the block kinds and resource blocks share a namespace, as they do
// in the resourceType of a finding.
const (
	dataTypePrefix   = "data."
	ephemeralPrefix  = "ephemeral."
	ephemeralSection = "ephemeral"
)

// blockKind is the type a resolved block is indexed and attributed under.
// The evaluator carries the block kind from HCL, so a managed resource and an
// ephemeral one sharing type and name never conflate, however they expand.
func blockKind(r *tfeval.ResolvedResource, _ *model.TerraformScope) string {
	switch {
	case r.Data:
		return dataTypePrefix + r.Type
	case r.Ephemeral:
		return ephemeralPrefix + r.Type
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
	var resources, data, ephemeral map[string]map[string]bool
	for kind, names := range replaced {
		if typ, ok := strings.CutPrefix(kind, dataTypePrefix); ok {
			if data == nil {
				data = make(map[string]map[string]bool)
			}
			data[typ] = names
			continue
		}
		if typ, ok := strings.CutPrefix(kind, ephemeralPrefix); ok {
			if ephemeral == nil {
				ephemeral = make(map[string]map[string]bool)
			}
			ephemeral[typ] = names
			continue
		}
		if resources == nil {
			resources = make(map[string]map[string]bool, len(replaced))
		}
		resources[kind] = names
	}
	removeInstantiatedBlocks(doc, "resource", resources)
	removeInstantiatedBlocks(doc, "data", data)
	removeInstantiatedBlocks(doc, ephemeralSection, ephemeral)
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
// longer there. Skipped exactly: a block label that merely starts with an
// underscore is legal Terraform and is content.
func onlyMetadataKeys(m map[string]interface{}) bool {
	for key := range m {
		if !bookkeepingKeys[key] && key != "_dd__default" {
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
	relDir := func(dir string) string {
		return repoRelativeDir(dir, c.repoPath, c.externalPathRoots)
	}
	return resolveModuleDocuments(
		ctx, files, c.repoPath, relDir, resolver, targets, c.buildModuleProvenanceLookup(), c.mergeAllow, c.fsys,
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
	relDir func(string) string,
	resolver tfeval.RemoteResolver,
	targets *ruleTargets,
	lookup moduleProvenanceLookup,
	byAbsPath map[string]*model.FileMetadata,
	seen map[docContentKey]string,
	extras map[string][]extraCallerInfo,
	instanceSeen map[docContentKey]instancePrimary,
	instanceExtras map[string][]extraInstanceInfo,
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
		ctx: ctx, evaluator: evaluator, filesByDir: filesByDir, repoPath: repoPath, relDir: relDir, resolver: resolver,
		targets: targets, lookup: lookup, byAbsPath: byAbsPath, seen: seen, extras: extras,
		instanceSeen: instanceSeen, instanceExtras: instanceExtras,
		instantiated: instantiated, successfulRoots: successfulRoots, unresolvedModuleDirs: unresolvedModuleDirs,
		actualCalledDirs: actualCalledDirs, extra: extra, syntheticFiles: syntheticFiles,
		resourceCount: resourceCount, rootEvalOK: rootEvalOK, moduleCalls: moduleCalls,
	}
	next := 0
	if workers := min(rootEvalWorkers, runtime.GOMAXPROCS(0), len(roots)); workers > 1 {
		next = m.evaluateConcurrently(roots, workers)
	}
	for _, dir := range roots[next:] {
		resources, _, childDirs, err := evaluator.EvaluateModule(ctx, dir, evaluator.LoadRootVarsWithContext(ctx, dir))
		m.merge(dir, resources, evaluator.TakeModuleInstances(), childDirs, err)
		// The cache key includes rootDir, so the next root cannot reuse these
		// evaluations, and keyMemo pins every collection they hashed.
		evaluator.ReleaseEvalCache()
	}
}

// rootEvalWorkers bounds the roots evaluated at once. Each holds its own
// evaluation values until it is merged, so this also bounds the memory
// concurrency adds.
var rootEvalWorkers = 4

// rootMerge folds root evaluations into the scan's documents, in root order.
type rootMerge struct {
	ctx        context.Context
	evaluator  *tfeval.Evaluator
	filesByDir map[string][]*model.FileMetadata
	repoPath   string
	// relDir names a directory relative to the scanned repository (see
	// repoRelativeDir), for the root module a resolved resource belongs to.
	relDir               func(string) string
	resolver             tfeval.RemoteResolver
	targets              *ruleTargets
	lookup               moduleProvenanceLookup
	byAbsPath            map[string]*model.FileMetadata
	seen                 map[docContentKey]string
	extras               map[string][]extraCallerInfo
	instanceSeen         map[docContentKey]instancePrimary
	instanceExtras       map[string][]extraInstanceInfo
	instantiated         instantiatedIndex
	successfulRoots      map[string]bool
	unresolvedModuleDirs map[string]bool
	actualCalledDirs     map[string]bool
	extra                *[]model.Document
	syntheticFiles       *[]*model.FileMetadata
	resourceCount        *int
	rootEvalOK           *bool
	moduleCalls          *moduleCallIndex
}

func (m *rootMerge) merge(
	dir string,
	resources []tfeval.ResolvedResource,
	instances []tfeval.ModuleInstance,
	childDirs map[string]bool,
	err error,
) {
	defer m.evaluator.ForgetRootParse(dir)
	if err != nil {
		contextLogger := logger.FromContext(m.ctx)
		contextLogger.Warn().Err(err).Msgf("tfeval: failed to evaluate root module %s", dir)
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
	attributions := newModuleAttributionCache()
	docs, syn, count := instantiatedDocs(
		resources, m.byAbsPath, m.repoPath, m.relDir, m.targets, m.seen, m.extras,
		m.instanceSeen, m.instanceExtras, m.instantiated, m.lookup, attributions)
	m.moduleCalls.record(instances, m.repoPath, m.relDir, m.lookup, attributions)
	*m.extra = append(*m.extra, docs...)
	*m.syntheticFiles = append(*m.syntheticFiles, syn...)
	*m.resourceCount += count
}

// rootResult is a root evaluated by a worker.
type rootResult struct {
	resources    []tfeval.ResolvedResource
	instances    []tfeval.ModuleInstance
	childDirs    map[string]bool
	err          error
	notEvaluated []string
	panicked     any
}

// evaluateConcurrently evaluates roots on workers and merges them in order, so
// shared documents get the same owners as when roots are evaluated one by one.
// Only roots after the first are evaluated apart from it; a root is merged as
// soon as its worker delivers it, and any root that fails to deliver (a
// panic) aborts the merge in root order.
func (m *rootMerge) evaluateConcurrently(roots []string, workers int) int {
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
				results[i] <- evaluateRoot(m.ctx, worker, roots[i])
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
		m.merge(dir, r.resources, r.instances, r.childDirs, r.err)
	}
	return len(roots)
}

func evaluateRoot(ctx context.Context, worker *tfeval.Evaluator, dir string) (r rootResult) {
	defer func() {
		if p := recover(); p != nil {
			r = rootResult{panicked: p}
		}
		r.notEvaluated = worker.TakeNotEvaluatedDirs()
		worker.ReleaseEvalCache()
	}()
	r.resources, _, r.childDirs, r.err = worker.EvaluateModule(ctx, dir, worker.LoadRootVarsWithContext(ctx, dir))
	r.instances = worker.TakeModuleInstances()
	return r
}

// collectNotEvaluatedDirs marks the directories the evaluator skipped, and
// everything they call, as unresolved.
//
// A directory is reached from several call sites, and depth and cycle
// stops apply to one call site at a time, so a directory can come out of a scan
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
	relDir func(string) string,
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
	// instanceSeen is the same for root-file count/for_each instance documents,
	// whose content key ignores the instance identity: two maps keep module
	// callers (keyed on full names) and instance members (keyed on base names)
	// from ever colliding.
	seen := make(map[docContentKey]string)
	extras := make(map[string][]extraCallerInfo)
	instanceSeen := make(map[docContentKey]instancePrimary)
	instanceExtras := make(map[string][]extraInstanceInfo)
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
		ctx, evaluator, evaluatedRoots, filesByDir, repoPath, relDir, resolver, targets, lookup,
		byAbsPath, seen, extras, instanceSeen, instanceExtras, instantiated,
		successfulRoots, unresolvedModuleDirs, actualCalledDirs,
		&extra, &syntheticFiles, &resourceCount, &rootEvalOK, moduleCalls,
	)
	collectNotEvaluatedDirs(
		ctx, evaluator, filesByDir, repoPath, resolver, unresolvedModuleDirs,
	)
	evaluator.ReleaseCaches()

	// If every root evaluation failed, do not strip or suppress module bodies: that would
	// remove coverage with no synthetic replacement.
	if !rootEvalOK {
		return moduleResolutionResult{}
	}

	scrubInstantiatedForUnresolvedDirs(instantiated, files, unresolvedModuleDirs, repoPath)

	return moduleResolutionResult{
		docs:                 extra,
		syntheticFiles:       syntheticFiles,
		suppressed:           instantiated,
		successfulRoots:      successfulRoots,
		rootDirs:             roots,
		unresolvedModuleDirs: unresolvedModuleDirs,
		extras:               extras,
		instanceExtras:       instanceExtras,
		moduleFiles:          moduleCalls.fileCalls(unresolvedModuleDirs),
		resourceCount:        resourceCount,
		rootCount:            len(roots),
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
type docGroup struct {
	fm            *model.FileMetadata
	moduleAddress string
	layer         int
	entries       []instantiatedResource
	attributions  map[string]*model.ModuleAttribution
	// rootModule is the repository-relative root module directory the group's
	// resources are instantiated under: the outermost caller's directory
	// (K9CODESEC-7158). It is the same for every entry: all come from the same
	// call chain, which is what it is derived from.
	rootModule string
	// instances maps an expanded block to the one instance key this document
	// represents (K9CODESEC-7158). One document holds at most one instance of
	// a block, so the lookup is exact.
	instances map[model.TerraformBlock]string
	// borrowed marks blocks this document carries only for context: a sibling
	// copied into a later expanded-root layer, reported by the owning layer.
	borrowed map[model.TerraformBlock]bool
}

// docContentKey identifies a document by its content. Two independent digests
// keep the collision probability negligible across the hundreds of thousands of
// documents a large repository resolves: a collision would silently merge two
// different resources into one finding.
type docContentKey struct{ a, b uint64 }

// instantiatedDocs emits one synthetic OPA document per (module call, defining
// file), holding every resource that call resolved in that file.
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
func instantiatedDocs(
	resources []tfeval.ResolvedResource,
	byAbsPath map[string]*model.FileMetadata,
	repoPath string,
	relDir func(string) string,
	targets *ruleTargets,
	seen map[docContentKey]string,
	extras map[string][]extraCallerInfo,
	instanceSeen map[docContentKey]instancePrimary,
	instanceExtras map[string][]extraInstanceInfo,
	instantiated instantiatedIndex,
	lookup moduleProvenanceLookup,
	attributions *moduleAttributionCache,
) (docs []model.Document, synthetic []*model.FileMetadata, resourceCount int) {
	groups := make(map[string]*docGroup)
	var order []string
	// A base name repeats within one call and file whenever count/for_each
	// expands a block. Document keys stay base-named so line detection can
	// resolve them against the file's HCL, so repeats spill into a further
	// document rather than overwriting each other.
	layers := make(map[string]int)

	// plainRoots are root resources with no instance suffix. They stay on the
	// file they were written in, unless that file also has an expanded root
	// resource: a same-document rule must still see the sibling next to each
	// instance, so those are copied into every layer below.
	var plainRoots []rootResource
	expandedRoot := make(map[string]bool)

	for i := range resources {
		r := &resources[i]
		fm, ok := byAbsPath[absPath(r.DefinedIn, repoPath)]
		if !ok {
			continue
		}
		kind := blockKind(r, fm.TerraformScope)
		if r.ModuleAddress == "" {
			if !targets.matches(r.Type) && !targets.matches(kind) {
				// No rule matches this root block by name, so it keeps being
				// scanned where it is written, exactly as it is.
				continue
			}
			if r.Name == tfeval.ResourceBaseName(r.Name) {
				plainRoots = append(plainRoots, rootResource{r: r, fm: fm, kind: kind})
				continue
			}
			expandedRoot[fm.ID] = true
		} else if !targets.matches(r.Type) && !targets.matches(kind) {
			// No rule can match this type by name, so resolving its values
			// cannot change a finding. It keeps being scanned where it is
			// written, exactly as it is without module evaluation.
			continue
		}

		base := tfeval.ResourceBaseName(r.Name)
		// The root module directory keys the group alongside the call: two
		// roots calling the same module path resolve it with their own inputs,
		// and their documents must not collide (K9CODESEC-7158). Content
		// deduplication below is unaffected: identical content still merges
		// into one document with the other caller recorded in extras.
		callRoot := resourceRootModule(r, relDir, repoPath)
		slot := callRoot + "\x00" + r.ModuleAddress + "\x00" + fm.ID + "\x00" + kind + "\x00" + base
		layer := layers[slot]
		layers[slot] = layer + 1

		key := callRoot + "\x00" + r.ModuleAddress + "\x00" + fm.ID + "\x00" + strconv.Itoa(layer)
		g, exists := groups[key]
		if !exists {
			g = &docGroup{
				fm:            fm,
				moduleAddress: r.ModuleAddress,
				layer:         layer,
				rootModule:    callRoot,
				attributions:  make(map[string]*model.ModuleAttribution),
			}
			groups[key] = g
			order = append(order, key)
		}
		addGroupEntry(g, r, kind, repoPath, lookup, attributions)
		// Recorded before deduplication: a document that dedupes away still
		// covers its resource, through a finding cloned onto its call site.
		instantiated.add(fm.ID, kind, base)
		resourceCount++
	}
	resourceCount += joinPlainRootSiblings(
		plainRoots, expandedRoot, groups, order, repoPath, instantiated, lookup, attributions,
	)

	for _, key := range order {
		g := groups[key]
		docID := docGroupID(g)

		if allEntriesInstanced(g) {
			// Every entry is one count/for_each instance of a root-file block:
			// the documents differ only in which instance of each block they
			// carry, so documents whose rule-visible content matches are
			// folded into the first one and their findings cloned after eval.
			contentKey := instanceGroupContentKey(g)
			if primary, dup := instanceSeen[contentKey]; dup {
				instanceExtras[primary.docID] = append(instanceExtras[primary.docID], extraInstanceInfo{
					docID:      docID,
					rootModule: g.rootModule,
					instances:  cloneInstanceSuffixes(g.instances),
					scope:      primary.scope,
				})
				continue
			}
			scope := groupScope(g)
			instanceSeen[contentKey] = instancePrimary{docID: docID, scope: scope}

			doc := groupDocument(g)
			docs = append(docs, doc)
			synthetic = append(synthetic, newFileMetadataWithScope(g, scope))
		} else {
			contentKey := groupContentKey(g)
			if primaryDocID, dup := seen[contentKey]; dup {
				extras[primaryDocID] = append(extras[primaryDocID], extraCallerInfo{
					docID:        docID,
					rootModule:   g.rootModule,
					attributions: cloneModuleAttributions(g.attributions),
				})
				continue
			}
			seen[contentKey] = docID

			doc := groupDocument(g)
			docs = append(docs, doc)
			synthetic = append(synthetic, newInstanceFileMetadata(g))
		}
	}
	return docs, synthetic, resourceCount
}

// allEntriesInstanced reports whether every entry of the group can take part
// in identity-free content deduplication: no module call resolved the group,
// and every entry is either one count/for_each instance of a root-file block
// or a plain sibling root. Plain siblings (joined for context by
// joinPlainRootSiblings) carry no instance suffix and are identical in every
// layer, so they fold with the rest: their findings belong to the layer that
// owns them, the primary, and a member never re-reports them — the clone step
// substitutes suffixes only for blocks the members instance.
func allEntriesInstanced(g *docGroup) bool {
	// Every root-file entry is either a count/for_each instance (it carries a
	// suffix) or a plain root (it does not); module-scoped entries are the
	// only ones that need the exact content key.
	return g.moduleAddress == ""
}

// instanceGroupContentKey identifies an all-instances document by the module
// call address it belongs to, its defining file, and the content it resolved
// to — with the per-instance identity left out: entries are hashed under
// their base name, so two documents carrying the same blocks at the same
// resolved attributes share a key however their instance keys differ. The
// layer index and the calling root are left out as in groupContentKey: a
// root's second instance of a block, and another root's first, both fold into
// the first document, whose extras record what each member stands for.
//
// It must never be compared against a groupContentKey value: the two key
// spaces live in separate maps, so a module-scoped group and an all-instances
// group cannot collide.
func instanceGroupContentKey(g *docGroup) docContentKey {
	sortInstantiated(g.entries)

	h := newContentHasher()
	h.str(g.moduleAddress)
	h.str(g.fm.ID)
	for i := range g.entries {
		e := &g.entries[i]
		h.str(e.typ)
		h.str(e.baseName)
		h.u64(uint64(e.defLine))
		h.u64(e.attrsHash)
	}
	return h.key()
}

func cloneInstanceSuffixes(instances map[model.TerraformBlock]string) map[model.TerraformBlock]string {
	if len(instances) == 0 {
		return nil
	}
	out := make(map[model.TerraformBlock]string, len(instances))
	maps.Copy(out, instances)
	return out
}

// rootResource is a root block that has no count/for_each instance suffix.
type rootResource struct {
	r    *tfeval.ResolvedResource
	fm   *model.FileMetadata
	kind string
}

// joinPlainRootSiblings copies each unexpanded root resource into every
// expanded-root layer of its file and drops it from the original document.
// A file with no expanded root resource keeps the resource where it was
// written. The first layer owns the copy: later layers carry it only for
// context, marked borrowed, so each sibling yields one finding per rule.
// Returns how many resources were copied.
func joinPlainRootSiblings(
	plain []rootResource,
	expandedRoot map[string]bool,
	groups map[string]*docGroup,
	order []string,
	repoPath string,
	instantiated instantiatedIndex,
	lookup moduleProvenanceLookup,
	attributions *moduleAttributionCache,
) int {
	added := 0
	for i := range plain {
		p := &plain[i]
		if !expandedRoot[p.fm.ID] {
			// The block stays scanned where it is written; its identity is
			// resolved from the file's own scope (see stampTerraformScopes).
			continue
		}
		owned := false
		joined := false
		for _, key := range order {
			g := groups[key]
			if g.fm.ID != p.fm.ID || g.moduleAddress != "" {
				continue
			}
			addGroupEntry(g, p.r, p.kind, repoPath, lookup, attributions)
			if !owned {
				owned = true
			} else {
				kindBlock, typ := addressKindOf(p.kind)
				b := address.Block{Kind: kindBlock, Type: typ, Name: tfeval.ResourceBaseName(p.r.Name)}
				if g.borrowed == nil {
					g.borrowed = make(map[model.TerraformBlock]bool)
				}
				g.borrowed[b] = true
			}
			joined = true
		}
		if !joined {
			continue
		}
		instantiated.add(p.fm.ID, p.kind, tfeval.ResourceBaseName(p.r.Name))
		added++
	}
	return added
}

func addGroupEntry(
	g *docGroup,
	r *tfeval.ResolvedResource,
	kind, repoPath string,
	lookup moduleProvenanceLookup,
	attributions *moduleAttributionCache,
) {
	attrs := tfeval.AttributesToDocument(r)
	key := moduleAttributionKey(kind, r.DefLine, r.DefColumn)
	// Clone: one root sibling is copied into every layer, and a finding may
	// narrow the attribution it is given.
	g.attributions[key] = cloneModuleAttribution(attributions.attribution(r, repoPath, lookup))
	base := tfeval.ResourceBaseName(r.Name)
	if base != r.Name {
		kindBlock, typ := addressKindOf(kind)
		b := address.Block{Kind: kindBlock, Type: typ, Name: base}
		if g.instances == nil {
			g.instances = make(map[model.TerraformBlock]string)
		}
		g.instances[b] = r.Name[len(base):]
	}
	g.entries = append(g.entries, instantiatedResource{
		typ:       kind,
		baseName:  base,
		fullName:  r.Name,
		defLine:   r.DefLine,
		attrs:     attrs,
		attrsHash: hashAttributes(attrs),
	})
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
		h.str(e.fullName)
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

func hashAttributes(attrs map[string]interface{}) uint64 {
	b, err := json.Marshal(attrs)
	if err != nil {
		// Unmarshalable attributes must never collapse onto each other, so fall
		// back to a value that cannot match another resource's content.
		return xxhash.Sum64String(fmt.Sprintf("%v", attrs))
	}
	return xxhash.Sum64(b)
}

// contentHasher folds fields into a 128-bit key using two independent digests.
type contentHasher struct{ a, b *xxhash.Digest }

func newContentHasher() contentHasher {
	h := contentHasher{a: xxhash.New(), b: xxhash.New()}
	_, _ = h.b.WriteString("\x00datadog-iac-scanner\x00")
	return h
}

func (h contentHasher) str(s string) {
	for _, d := range [...]*xxhash.Digest{h.a, h.b} {
		_, _ = d.WriteString(s)
		_, _ = d.WriteString("\x1f")
	}
}

func (h contentHasher) u64(v uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	for _, d := range [...]*xxhash.Digest{h.a, h.b} {
		_, _ = d.Write(buf[:])
	}
}

func (h contentHasher) key() docContentKey {
	return docContentKey{a: h.a.Sum64(), b: h.b.Sum64()}
}

// groupDocument renders a group's instantiated entries as one synthetic OPA
// document: managed resources under resource, data sources under data and
// ephemeral resources under their own section, base-named like a written
// file's document so line detection resolves them.
func groupDocument(g *docGroup) model.Document {
	resource := make(map[string]interface{})
	var data, ephemeral map[string]interface{}
	for i := range g.entries {
		e := &g.entries[i]
		blocks, typ := resource, e.typ
		if dataType, ok := strings.CutPrefix(e.typ, dataTypePrefix); ok {
			if data == nil {
				data = make(map[string]interface{})
			}
			blocks, typ = data, dataType
		}
		if ephemeralType, ok := strings.CutPrefix(e.typ, ephemeralPrefix); ok {
			if ephemeral == nil {
				ephemeral = make(map[string]interface{})
			}
			blocks, typ = ephemeral, ephemeralType
		}
		byName, ok := blocks[typ].(map[string]interface{})
		if !ok {
			byName = make(map[string]interface{})
			blocks[typ] = byName
		}
		byName[e.baseName] = e.attrs
	}

	doc := model.Document{
		"id":       docGroupID(g),
		"file":     g.fm.FilePath,
		"resource": resource,
	}
	if data != nil {
		doc["data"] = data
	}
	if ephemeral != nil {
		doc[ephemeralSection] = ephemeral
	}
	return doc
}

// docGroupID is the synthetic document id of a group: root module directory,
// defining file, module instance address and expansion layer.
func docGroupID(g *docGroup) string {
	return g.rootModule + "\x00" + g.fm.ID + "\x00" + g.moduleAddress + "\x00" + strconv.Itoa(g.layer)
}

// newInstanceFileMetadata clones fm for a synthetic doc (empty Document so
// Combine skips it), carrying the group's Terraform identity context
// (K9CODESEC-7158): the module instance address its blocks are evaluated
// under, the outermost caller's root module, which block instance this
// document represents, and which blocks it only borrows for context.
func newInstanceFileMetadata(g *docGroup) *model.FileMetadata {
	return newFileMetadataWithScope(g, groupScope(g))
}

// groupScope builds the Terraform identity context of a synthetic instance
// document (K9CODESEC-7158): the module instance address its blocks are
// evaluated under, the outermost caller's root module, which block instance
// this document represents, and which blocks it only borrows for context.
func groupScope(g *docGroup) *model.TerraformScope {
	return &model.TerraformScope{
		RootModule:    g.rootModule,
		ModuleAddress: g.moduleAddress,
		Instances:     g.instances,
		Borrowed:      g.borrowed,
		Blocks:        groupBlocks(g),
	}
}

func newFileMetadataWithScope(g *docGroup, scope *model.TerraformScope) *model.FileMetadata {
	clone := g.fm.ShallowCopy()
	clone.ID = docGroupID(g)
	clone.Document = model.Document{}
	clone.ModuleAttributions = cloneModuleAttributions(g.attributions)
	clone.TerraformScope = scope
	if g.fm.LineInfoDocument != nil {
		// Already materialized: shallow-clone so later mutations on the
		// parent (e.g. deleting a suppressed "resource" key) don't alias
		// into this synthetic instance's copy.
		clone.LineInfoDocument = maps.Clone(g.fm.LineInfoDocument)
	}
	return clone
}

// addressKindOf converts the combined kind a document indexes a block under
// (the type, prefixed with "data." for a data block) into the address block
// kind and type.
func addressKindOf(kind string) (blockKind, typ string) {
	if rest, ok := strings.CutPrefix(kind, dataTypePrefix); ok {
		return address.KindData, rest
	}
	if rest, ok := strings.CutPrefix(kind, ephemeralPrefix); ok {
		return address.KindEphemeral, rest
	}
	return address.KindResource, kind
}

// groupBlocks records the blocks a synthetic document holds, so a finding's
// resourceType and resourceName are verified the same way as on a file.
func groupBlocks(g *docGroup) map[model.TerraformBlock]bool {
	blocks := make(map[model.TerraformBlock]bool, len(g.entries))
	for i := range g.entries {
		kind, typ := addressKindOf(g.entries[i].typ)
		blocks[model.TerraformBlock{Kind: kind, Type: typ, Name: g.entries[i].baseName}] = true
	}
	return blocks
}

// moduleFileDir returns the absolute directory containing a scanned Terraform file.
func moduleFileDir(filePath, repoPath string) string {
	return filepath.Dir(absPath(filePath, repoPath))
}

// resourceRootModule is the repository-relative directory of the root module a
// resolved resource belongs to: its outermost caller's directory for a module
// resource, its own directory for a root resource (K9CODESEC-7158). A
// Terraform address is root-relative, so this pairs with the address to
// identify an instance in a repository that can call the same module path from
// several root stacks.
func resourceRootModule(r *tfeval.ResolvedResource, relDir func(string) string, repoPath string) string {
	definedIn := r.DefinedIn
	if len(r.CallChain) > 0 {
		definedIn = r.CallChain[0].CalledFrom
	}
	return relDir(filepath.Dir(absPath(definedIn, repoPath)))
}

func discoverCalledModuleDirs(
	ctx context.Context,
	evaluator *tfeval.Evaluator,
	files []*model.FileMetadata,
	repoPath string,
	resolver tfeval.RemoteResolver,
	dir string,
) []string {
	calledDirs, ok := calledModuleDirsFromDocuments(ctx, evaluator.FS(), files, repoPath, resolver)
	if ok {
		return calledDirs
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Str("dir", dir).Msg(
		"module resolve: falling back to directory parse for called module discovery",
	)
	return evaluator.CalledModuleDirsWithContext(ctx, dir)
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
	ctx context.Context,
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
			if dir, ok := resolveModuleTargetDir(ctx, fsys, fileDir, repoPath, source, version, file.FilePath, name, resolver); ok {
				dirs = append(dirs, dir)
			}
		}
	}
	return dirs, true
}

func resolveModuleTargetDir(
	ctx context.Context,
	fsys vfs.FS,
	callerDir, repoPath, source, version, callerFile, moduleName string,
	resolver tfeval.RemoteResolver,
) (string, bool) {
	ctx = tfmodules.WithLinkPlaceholderRoot(ctx, repoPath)
	if dir, local, err := tfmodules.LocalModuleDirWithContext(ctx, fsys, callerDir, source); local {
		return dir, err == nil
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
	// A path rooted without a volume ("/repo" on Windows) counts as absolute:
	// filepath.IsAbs is false for it, and joining it under base would
	// duplicate the root (see repoRelativeDir).
	if filepath.IsAbs(p) || path.IsAbs(filepath.ToSlash(p)) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(base, p))
}
