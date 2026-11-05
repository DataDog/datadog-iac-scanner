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
	callChain string
	docID     string
	// rootModule is this caller's own root module directory. The resource's
	// address is the same as the primary's (content dedup keys on
	// moduleAddress, which a caller's own root never changes), only the root
	// differs, so only this needs to be carried.
	rootModule   string
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
	contextLogger := logger.FromContext(ctx)
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
			if res.unresolvedModuleDirs[moduleFileDir(c.fsys, f.FilePath, c.repoPath)] {
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
		stripModuleCalls(ctx, f.Document, f.FilePath, c.repoPath, res.calledDirs, res.successfulRoots, rootDirs, resolver, c.fsys)
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

// logModuleInstantiationSummary emits the per-scan record of module
// instantiation at info level. A scan that never evaluated a module root stays quiet.
func logModuleInstantiationSummary(log *zerolog.Logger, res *moduleResolutionResult) {
	if res.rootCount == 0 && res.resourceCount == 0 {
		return
	}
	log.Info().
		Int("module_resources_instantiated", res.resourceCount).
		Int("module_root_count", res.rootCount).
		Int("module_documents", len(res.docs)).
		Int("deduplicated_callers", deduplicatedCallerCount(res)).
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
// wherever those blocks and resource blocks share a namespace, as they do in
// the resourceType of a finding.
const (
	dataTypePrefix   = "data."
	ephemeralPrefix  = "ephemeral."
	ephemeralSection = "ephemeral"
)

// blockSections are the document sections that hold typed, named blocks, with
// the prefix their type carries where the sections share a namespace and the
// address kind of their blocks.
var blockSections = [...]struct{ section, prefix, kind string }{
	{"resource", "", address.KindResource},
	{"data", dataTypePrefix, address.KindData},
	{ephemeralSection, ephemeralPrefix, address.KindEphemeral},
}

// splitBlockKind returns the document section, the bare type and the address
// kind of a block indexed under kind (see blockKind).
func splitBlockKind(kind string) (section, typ, addrKind string) {
	for _, bs := range blockSections[1:] {
		if t, ok := strings.CutPrefix(kind, bs.prefix); ok {
			return bs.section, t, bs.kind
		}
	}
	return blockSections[0].section, kind, blockSections[0].kind
}

// blockKind is the type a resolved block is indexed and attributed under. The
// evaluator carries the block kind from HCL, so a managed resource and an
// ephemeral one sharing type and name never conflate.
func blockKind(r *tfeval.ResolvedResource) string {
	return blockKindOf(r.Type, r.Data, r.Ephemeral)
}

func blockKindOf(typ string, data, ephemeral bool) string {
	switch {
	case data:
		return dataTypePrefix + typ
	case ephemeral:
		return ephemeralPrefix + typ
	}
	return typ
}

// writesExpansion reports whether a parsed block writes count or for_each,
// which its document leaves out but its line table records.
func writesExpansion(block interface{}) bool {
	attrs, _ := asStringMap(block)
	has := func(key string) bool {
		switch lines := attrs["_dd_lines"].(type) {
		case map[string]model.LineObject:
			_, ok := lines[key]
			return ok
		case map[string]interface{}:
			_, ok := lines[key]
			return ok
		}
		return false
	}
	return has("_dd_count") || has("_dd_for_each")
}

// declaresExpandedBlock reports whether any scanned Terraform file declares a
// block some rule can match by name with count or for_each, which may expand
// to no instance.
func declaresExpandedBlock(files model.FileMetadatas, targets *ruleTargets) bool {
	for _, f := range files {
		if f == nil || !tfpath.IsConfig(f.FilePath) {
			continue
		}
		for _, bs := range blockSections {
			blocks, _ := asStringMap(f.Document[bs.section])
			for typ, byName := range blocks {
				if !targets.matches(typ) && !targets.matches(bs.prefix+typ) {
					continue
				}
				names, _ := asStringMap(byName)
				for _, block := range names {
					if writesExpansion(block) {
						return true
					}
				}
			}
		}
	}
	return false
}

// addDroppedBlocks records in dropped the empty blocks no evaluation resolved
// to any instance, so they are removed from the files they are written in.
func addDroppedBlocks(
	dropped instantiatedIndex,
	empty []tfeval.EmptyBlock,
	resolved map[string]bool,
	failedRoots map[string]bool,
	byAbsPath map[string]*model.FileMetadata,
	fsys vfs.FS,
	repoPath string,
) {
	for _, b := range empty {
		file := absPath(b.DefinedIn, repoPath)
		kind := blockKindOf(b.Type, b.Data, b.Ephemeral)
		if resolved[resolvedBlockKey(file, kind, b.Name)] {
			continue
		}
		fm := fileByPath(byAbsPath, fsys, b.DefinedIn, repoPath)
		if fm == nil || failedRoots[moduleFileDir(fsys, fm.FilePath, repoPath)] {
			continue
		}
		// A list-shaped type cannot lose one block without losing all of them.
		if _, named := asStringMap(docAsMap(fm.Document[blockSection(b)])[b.Type]); !named {
			continue
		}
		dropped.add(fm.ID, kind, b.Name)
	}
}

func blockSection(b tfeval.EmptyBlock) string {
	switch {
	case b.Data:
		return "data"
	case b.Ephemeral:
		return ephemeralSection
	}
	return blockSections[0].section
}

func resolvedBlockKey(file, kind, name string) string {
	return file + "\x00" + kind + "\x00" + name
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

func (idx instantiatedIndex) merge(other instantiatedIndex) {
	for fileID, byType := range other {
		for typ, names := range byType {
			for name := range names {
				idx.add(fileID, typ, name)
			}
		}
	}
}

// removeInstantiatedResources deletes the named resource, data and ephemeral
// blocks from a parsed file so they are not scanned twice, once where they are
// written and once instantiated.
func removeInstantiatedResources(doc map[string]interface{}, replaced map[string]map[string]bool) {
	bySection := make(map[string]map[string]map[string]bool, len(blockSections))
	for kind, names := range replaced {
		section, typ, _ := splitBlockKind(kind)
		if bySection[section] == nil {
			bySection[section] = make(map[string]map[string]bool)
		}
		bySection[section][typ] = names
	}
	for section, byType := range bySection {
		removeInstantiatedBlocks(doc, section, byType)
	}
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
// longer there. Matched exactly: a block label that merely starts with an
// underscore is legal Terraform and is content.
func onlyMetadataKeys(m map[string]interface{}) bool {
	for key := range m {
		if !isParserBookkeepingKey(key) && key != "_dd__default" {
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
	instantiated instantiatedIndex,
	dropped instantiatedIndex,
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
		instantiated: instantiated, successfulRoots: successfulRoots, unresolvedModuleDirs: unresolvedModuleDirs,
		actualCalledDirs: actualCalledDirs, extra: extra, syntheticFiles: syntheticFiles,
		resourceCount: resourceCount, rootEvalOK: rootEvalOK, moduleCalls: moduleCalls,
		resolved: make(map[string]bool), failedRoots: make(map[string]bool),
	}
	if workers := min(rootEvalWorkers, runtime.GOMAXPROCS(0), len(roots)); workers > 1 {
		m.evaluateConcurrently(roots, workers)
	} else {
		for _, dir := range roots {
			resources, _, childDirs, err := evaluator.EvaluateModule(ctx, dir, evaluator.LoadRootVarsWithContext(ctx, dir))
			m.merge(dir, resources, evaluator.TakeModuleInstances(), evaluator.TakeEmptyBlocks(), childDirs, err)
			// The cache key includes rootDir, so the next root cannot reuse these
			// evaluations, and keyMemo pins every collection they hashed.
			evaluator.ReleaseEvalCache()
		}
	}
	addDroppedBlocks(dropped, m.emptyBlocks, m.resolved, m.failedRoots, byAbsPath, evaluator.FS(), repoPath)
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
	instantiated         instantiatedIndex
	successfulRoots      map[string]bool
	unresolvedModuleDirs map[string]bool
	actualCalledDirs     map[string]bool
	extra                *[]model.Document
	syntheticFiles       *[]*model.FileMetadata
	resourceCount        *int
	rootEvalOK           *bool
	moduleCalls          *moduleCallIndex
	// emptyBlocks are the blocks evaluations found empty; resolved holds the
	// blocks some evaluation did expand (see resolvedBlockKey), and failedRoots
	// the roots whose evaluation failed.
	emptyBlocks []tfeval.EmptyBlock
	resolved    map[string]bool
	failedRoots map[string]bool
}

func (m *rootMerge) merge(
	dir string,
	resources []tfeval.ResolvedResource,
	instances []tfeval.ModuleInstance,
	empty []tfeval.EmptyBlock,
	childDirs map[string]bool,
	err error,
) {
	defer m.evaluator.ForgetRootParse(dir)
	if err != nil {
		contextLogger := logger.FromContext(m.ctx)
		contextLogger.Warn().Err(err).Msgf("tfeval: failed to evaluate root module %s", dir)
		m.failedRoots[pathKey(dir)] = true
		for _, called := range discoverCalledModuleClosure(
			m.ctx, m.evaluator, m.filesByDir, m.repoPath, m.resolver, dir,
		) {
			m.unresolvedModuleDirs[pathKey(called)] = true
		}
		return
	}
	*m.rootEvalOK = true
	m.successfulRoots[pathKey(dir)] = true
	m.emptyBlocks = append(m.emptyBlocks, empty...)
	for i := range resources {
		r := &resources[i]
		m.resolved[resolvedBlockKey(absPath(r.DefinedIn, m.repoPath), blockKind(r), tfeval.ResourceBaseName(r.Name))] = true
	}
	for d := range childDirs {
		m.actualCalledDirs[pathKey(d)] = true
	}
	attributions := newModuleAttributionCache()
	rootModule := m.relDir(dir)
	docs, syn, count := instantiatedDocs(
		resources, m.byAbsPath, m.evaluator.FS(), m.repoPath, rootModule, m.targets, m.seen, m.extras, m.instantiated, m.lookup, attributions)
	m.moduleCalls.record(instances, m.repoPath, rootModule, m.lookup, attributions)
	*m.extra = append(*m.extra, docs...)
	*m.syntheticFiles = append(*m.syntheticFiles, syn...)
	*m.resourceCount += count
}

// rootResult is a root evaluated by a worker.
type rootResult struct {
	resources    []tfeval.ResolvedResource
	instances    []tfeval.ModuleInstance
	empty        []tfeval.EmptyBlock
	childDirs    map[string]bool
	err          error
	notEvaluated []string
	panicked     any
}

// evaluateConcurrently evaluates roots on workers and merges them in order, so
// shared documents get the same owners as when roots are evaluated one by one.
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
		m.merge(dir, r.resources, r.instances, r.empty, r.childDirs, r.err)
	}
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
	r.empty = worker.TakeEmptyBlocks()
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
		key := pathKey(dir)
		if unresolvedModuleDirs[key] {
			continue
		}
		unresolvedModuleDirs[key] = true
		queue = append(queue, key)
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
	fsys vfs.FS,
	repoPath string,
) {
	for _, f := range files {
		if f == nil {
			continue
		}
		if unresolvedModuleDirs[moduleFileDir(fsys, f.FilePath, repoPath)] {
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
	byAbsPath, filesByDir, dirsWithTf := indexTerraformFiles(ctx, files, repoPath, fsys)
	if len(dirsWithTf) == 0 {
		return moduleResolutionResult{}
	}
	// Evaluating a module tree is the expensive part, and it is pure waste when
	// the repository declares nothing any rule can match by name. The block
	// labels are already in the parsed documents, so this costs nothing.
	// External module files still need their calls, whatever they declare.
	moduleCalls := newModuleCallIndex(filesByDir, externalModuleFile)
	declaresResource := declaresTargetedResource(files, targets) || declaresExpandedBlock(files, targets)
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
	dropped := make(instantiatedIndex)
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
		byAbsPath, seen, extras, instantiated, dropped,
		successfulRoots, unresolvedModuleDirs, actualCalledDirs,
		&extra, &syntheticFiles, &resourceCount, &rootEvalOK, moduleCalls,
	)
	collectNotEvaluatedDirs(
		ctx, evaluator, filesByDir, repoPath, resolver, unresolvedModuleDirs,
	)
	evaluator.ReleaseCaches()

	// If every root evaluation failed, do not strip or suppress module bodies: that would
	// remove coverage with no synthetic replacement. Keep the root count so the
	// instantiation summary still records that evaluation ran and produced nothing.
	if !rootEvalOK {
		return moduleResolutionResult{rootCount: len(roots)}
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

	// Dropped blocks join the suppressed ones only now: a module whose blocks
	// all expand to nothing has no document standing in for its call site.
	instantiated.merge(dropped)
	scrubInstantiatedForUnresolvedDirs(instantiated, files, unresolvedModuleDirs, fsys, repoPath)

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
	callChain     string
	moduleAddress string
	layer         int
	entries       []instantiatedResource
	attributions  map[string]*model.ModuleAttribution
	// rootModule is the repository-relative directory of the root module the
	// group's resources are evaluated from.
	rootModule string
	// instances maps an expanded block to the one instance key this document
	// represents. One document holds at most one instance of a block, so the
	// lookup is exact.
	instances map[model.TerraformBlock]string
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
	fsys vfs.FS,
	repoPath, rootModule string,
	targets *ruleTargets,
	seen map[docContentKey]string,
	extras map[string][]extraCallerInfo,
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

	for i := range resources {
		r := &resources[i]
		if r.ModuleAddress == "" {
			// A root block stays in the document it is written in. Splitting
			// its instances across documents would hide its siblings from
			// rules that read one document.
			continue
		}
		kind := blockKind(r)
		if !targets.matches(r.Type) && !targets.matches(kind) {
			// No rule can match this type by name, so resolving its values
			// cannot change a finding. It keeps being scanned where it is
			// written, exactly as it is without module evaluation.
			continue
		}
		fm := fileByPath(byAbsPath, fsys, r.DefinedIn, repoPath)
		if fm == nil {
			continue
		}
		base := tfeval.ResourceBaseName(r.Name)
		cck := callChainKey(r, repoPath)

		slot := cck + "\x00" + fm.ID + "\x00" + kind + "\x00" + base
		layer := layers[slot]
		layers[slot] = layer + 1

		key := cck + "\x00" + fm.ID + "\x00" + strconv.Itoa(layer)
		g, exists := groups[key]
		if !exists {
			g = &docGroup{
				fm: fm, callChain: cck, moduleAddress: r.ModuleAddress, layer: layer, rootModule: rootModule,
				attributions: make(map[string]*model.ModuleAttribution),
			}
			groups[key] = g
			order = append(order, key)
		}
		addGroupEntry(g, r, kind, base, repoPath, lookup, attributions)
		// Recorded before deduplication: a document that dedupes away still
		// covers its resource, through a finding cloned onto its call site.
		instantiated.add(fm.ID, kind, base)
		resourceCount++
	}

	for _, key := range order {
		g := groups[key]
		docID := docGroupID(g)

		contentKey := groupContentKey(g)
		if primaryDocID, dup := seen[contentKey]; dup {
			extras[primaryDocID] = append(extras[primaryDocID], extraCallerInfo{
				callChain:    g.callChain,
				docID:        docID,
				rootModule:   g.rootModule,
				attributions: cloneModuleAttributions(g.attributions),
			})
			continue
		}
		seen[contentKey] = docID

		docs = append(docs, groupDocument(g, docID))
		synthetic = append(synthetic, newInstanceFileMetadata(g, docID))
	}
	return docs, synthetic, resourceCount
}

// addGroupEntry adds resolved block r, indexed under kind and base-named base,
// to g.
func addGroupEntry(
	g *docGroup,
	r *tfeval.ResolvedResource,
	kind, base, repoPath string,
	lookup moduleProvenanceLookup,
	attributions *moduleAttributionCache,
) {
	attrs := tfeval.AttributesToDocument(r)
	g.attributions[moduleAttributionKey(kind, r.DefLine, r.DefColumn)] = attributions.attribution(r, repoPath, lookup)
	if base != r.Name {
		_, typ, addrKind := splitBlockKind(kind)
		if g.instances == nil {
			g.instances = make(map[model.TerraformBlock]string)
		}
		g.instances[address.Block{Kind: addrKind, Type: typ, Name: base}] = r.Name[len(base):]
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

// groupDocument renders a group's entries as one synthetic OPA document, each
// block under its own section and base-named like a written file's document so
// line detection resolves them.
func groupDocument(g *docGroup, docID string) model.Document {
	doc := model.Document{
		"id":       docID,
		"file":     g.fm.FilePath,
		"resource": make(map[string]interface{}),
	}
	for i := range g.entries {
		e := &g.entries[i]
		section, typ, _ := splitBlockKind(e.typ)
		blocks, ok := doc[section].(map[string]interface{})
		if !ok {
			blocks = make(map[string]interface{})
			doc[section] = blocks
		}
		byName, ok := blocks[typ].(map[string]interface{})
		if !ok {
			byName = make(map[string]interface{})
			blocks[typ] = byName
		}
		byName[e.baseName] = e.attrs
	}
	return doc
}

// docGroupID is the synthetic document id of a group: defining file, call
// chain and expansion layer.
func docGroupID(g *docGroup) string {
	return g.fm.ID + "\x00" + g.callChain + "\x00" + strconv.Itoa(g.layer)
}

// writtenFileID is the id of the written file document docID was built from:
// the document itself, or the file a synthetic document's id starts with.
func writtenFileID(docID string) string {
	if i := strings.IndexByte(docID, 0); i >= 0 {
		return docID[:i]
	}
	return docID
}

// newInstanceFileMetadata clones the group's file for a synthetic doc (empty
// Document so Combine skips it), carrying the group's Terraform identity
// context: the module instance address its blocks are evaluated under, the
// root module and which instance of each expanded block it represents.
func newInstanceFileMetadata(g *docGroup, id string) *model.FileMetadata {
	clone := g.fm.ShallowCopy()
	clone.ID = id
	clone.Document = model.Document{}
	clone.ModuleCallChain = g.callChain
	clone.ModuleAttributions = cloneModuleAttributions(g.attributions)
	clone.TerraformScope = &model.TerraformScope{
		RootModule:    g.rootModule,
		ModuleAddress: g.moduleAddress,
		Instances:     g.instances,
	}
	if g.fm.LineInfoDocument != nil {
		// Already materialized: shallow-clone so later mutations on the
		// parent (e.g. deleting a suppressed "resource" key) don't alias
		// into this synthetic instance's copy.
		clone.LineInfoDocument = maps.Clone(g.fm.LineInfoDocument)
	}
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
	ctx context.Context,
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
	fileDir := moduleFileDir(fsys, filePath, repoPath)
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
		resolvedDir, _ := resolveModuleTargetDir(ctx, fsys, fileDir, repoPath, source, version, filePath, name, resolver)

		if resolvedDir != "" && calledDirs[pathKey(resolvedDir)] {
			delete(modules, name)
		}
	}
	if len(modules) == 0 {
		delete(doc, "module")
	}
}

// moduleFileDir returns the directory containing a scanned Terraform file,
// keyed as indexTerraformFiles keys it.
func moduleFileDir(fsys vfs.FS, filePath, repoPath string) string {
	return path.Dir(evaluatorPath(fsys, absPath(filePath, repoPath)))
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
		parent := path.Dir(dir)
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
	calledDirs, ok := calledModuleDirsFromDocuments(ctx, evaluator.FS(), files, repoPath, resolver)
	if ok {
		return calledDirs
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Str("dir", dir).Msg(
		"module resolve: falling back to directory parse for called module discovery",
	)
	dirs := evaluator.CalledModuleDirsWithContext(ctx, dir)
	for i, d := range dirs {
		dirs[i] = pathKey(d)
	}
	return dirs
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
		fileDir := moduleFileDir(fsys, file.FilePath, repoPath)
		for name, callRaw := range modules {
			call := docAsMap(callRaw)
			source, _ := call["source"].(string)
			if source == "" {
				continue
			}
			version, _ := call["version"].(string)
			if dir, ok := resolveModuleTargetDir(ctx, fsys, fileDir, repoPath, source, version, file.FilePath, name, resolver); ok {
				dirs = append(dirs, pathKey(dir))
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
func indexTerraformFiles(ctx context.Context, files model.FileMetadatas, repoPath string, fsys vfs.FS) (
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
		key := evaluatorPath(fsys, absPath(f.FilePath, repoPath))
		dir := path.Dir(key)
		if prev, exists := byAbsPath[key]; exists && prev != nil && prev.ID != f.ID {
			contextLogger.Warn().Msgf(
				"duplicate terraform file path in scan input %s (file ids %s and %s); using the latter",
				key, prev.ID, f.ID,
			)
		}
		byAbsPath[key] = f
		filesByDir[dir] = append(filesByDir[dir], f)
		dirsWithTf[dir] = true
	}
	return
}

// pathKey is the slash-form map key for a Terraform file or directory path:
// DiskFS paths on Windows use backslashes, MemFS paths slashes.
func pathKey(p string) string {
	return filepath.ToSlash(filepath.Clean(p))
}

// evaluatorPath returns p as the evaluator names files, so a relative scan
// path still matches the blocks it reports.
func evaluatorPath(fsys vfs.FS, p string) string {
	if fsys == nil {
		fsys = vfs.Default()
	}
	if a, err := fsys.Abs(p); err == nil {
		p = a
	}
	return pathKey(p)
}

// fileByPath looks up a Terraform file the way indexTerraformFiles keyed it.
func fileByPath(
	byAbsPath map[string]*model.FileMetadata, fsys vfs.FS, filePath, repoPath string,
) *model.FileMetadata {
	return byAbsPath[evaluatorPath(fsys, absPath(filePath, repoPath))]
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
	// A path rooted without a volume ("/repo" on Windows) is not filepath.IsAbs
	// but must not be joined under base.
	if filepath.IsAbs(p) || path.IsAbs(filepath.ToSlash(p)) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(base, p))
}
