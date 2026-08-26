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
	docs                 []model.Document
	syntheticFiles       []*model.FileMetadata
	suppressed           instantiatedIndex
	calledDirs           map[string]bool
	successfulRoots      map[string]bool
	rootDirs             []string
	unresolvedModuleDirs map[string]bool
	extras               map[string][]extraCallerInfo
	resourceCount        int
	ok                   bool
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
	targets *ruleTargets,
) ([]model.Document, []*model.FileMetadata, map[string][]extraCallerInfo) {
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
	if !res.ok {
		return nil, nil, nil
	}
	rootDirs := newRootIndex(res.rootDirs)
	for _, f := range files {
		if f == nil || !isTerraformFile(f.FilePath) {
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
		stripModuleCalls(f.Document, f.FilePath, c.repoPath, res.calledDirs, res.successfulRoots, rootDirs, resolver)
	}
	return res.docs, res.syntheticFiles, res.extras
}

// declaresTargetedResource reports whether any scanned Terraform file declares
// a resource type some rule can match by name.
func declaresTargetedResource(files model.FileMetadatas, targets *ruleTargets) bool {
	if targets == nil {
		return true
	}
	for _, f := range files {
		if f == nil || !isTerraformFile(f.FilePath) {
			continue
		}
		resources, ok := asStringMap(f.Document["resource"])
		if !ok {
			continue
		}
		for typ := range resources {
			if targets.matches(typ) {
				return true
			}
		}
	}
	return false
}

// instantiatedIndex records which resource blocks of a file were re-emitted as
// instantiated documents, as file ID -> resource type -> block name.
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

// removeInstantiatedResources deletes the named resource blocks from a parsed
// file so they are not scanned twice, once where they are written and once
// instantiated.
func removeInstantiatedResources(doc map[string]interface{}, replaced map[string]map[string]bool) {
	resources, ok := asStringMap(doc["resource"])
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
		delete(doc, "resource")
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
	return resolveModuleDocuments(ctx, files, c.repoPath, resolver, targets)
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
) {
	contextLogger := logger.FromContext(ctx)
	for _, dir := range roots {
		evaluator.ResetInstantiationBudget()
		resources, _, childDirs, err := evaluator.EvaluateModule(ctx, dir, tfeval.LoadRootVars(dir))
		if err != nil {
			contextLogger.Warn().Err(err).Msgf("tfeval: failed to evaluate root module %s", dir)
			for _, called := range discoverCalledModuleClosure(
				ctx, evaluator, filesByDir, repoPath, resolver, dir,
			) {
				unresolvedModuleDirs[called] = true
			}
			continue
		}
		*rootEvalOK = true
		successfulRoots[dir] = true
		for d := range childDirs {
			actualCalledDirs[d] = true
		}
		docs, syn, count := instantiatedDocs(
			resources, byAbsPath, repoPath, targets, seen, extras, instantiated)
		*extra = append(*extra, docs...)
		*syntheticFiles = append(*syntheticFiles, syn...)
		*resourceCount += count
		// instantiatedDocs has copied everything this root needs into plain
		// documents, so the evaluator's cty values are dead here. Another root
		// could in principle reuse them, but each root passes its own values to
		// the modules it shares, so the hit rate does not pay for a peak that
		// grows with the whole repository rather than the largest single root.
		evaluator.ReleaseEvalCache()
	}
}

// collectNotEvaluatedDirs marks the directories the evaluator skipped, and
// everything they call, as unresolved.
//
// A directory is reached from several call sites, and depth, cycle and budget
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
	resolver tfeval.RemoteResolver,
	targets *ruleTargets,
) moduleResolutionResult {
	byAbsPath, filesByDir, dirsWithTf := indexTerraformFiles(ctx, files, repoPath)
	if len(dirsWithTf) == 0 {
		return moduleResolutionResult{}
	}
	// Evaluating a module tree is the expensive part, and it is pure waste when
	// the repository declares nothing any rule can match by name. The block
	// labels are already in the parsed documents, so this costs nothing.
	if !declaresTargetedResource(files, targets) {
		return moduleResolutionResult{}
	}

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

	evaluateRootModules(
		ctx, evaluator, roots, filesByDir, repoPath, resolver, targets,
		byAbsPath, seen, extras, instantiated,
		successfulRoots, unresolvedModuleDirs, actualCalledDirs,
		&extra, &syntheticFiles, &resourceCount, &rootEvalOK,
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
		resourceCount:        resourceCount,
		ok:                   true,
	}
}

// instantiatedResource is one resolved resource as it is placed into a document.
type instantiatedResource struct {
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
	targets *ruleTargets,
	seen map[docContentKey]string,
	extras map[string][]extraCallerInfo,
	instantiated instantiatedIndex,
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
			continue
		}
		if !targets.matches(r.Type) {
			// No rule can match this type by name, so resolving its values
			// cannot change a finding. It keeps being scanned where it is
			// written, exactly as it is without module evaluation.
			continue
		}
		fm, ok := byAbsPath[absPath(r.DefinedIn, repoPath)]
		if !ok {
			continue
		}
		cck := callChainKey(r, repoPath)
		base := tfeval.ResourceBaseName(r.Name)
		attrs := tfeval.AttributesToDocument(r)
		entry := instantiatedResource{
			typ:       r.Type,
			baseName:  base,
			fullName:  r.Name,
			defLine:   r.DefLine,
			attrs:     attrs,
			attrsHash: hashAttributes(attrs),
		}

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
		g.entries = append(g.entries, entry)
		// Recorded before deduplication: a document that dedupes away still
		// covers its resource, through a finding cloned onto its call site.
		if !r.ExpansionTruncated {
			instantiated.add(fm.ID, r.Type, base)
		}
		resourceCount++
	}

	for _, key := range order {
		g := groups[key]
		docID := g.fm.ID + "\x00" + g.callChain + "\x00" + strconv.Itoa(g.layer)

		contentKey := groupContentKey(g)
		if primaryDocID, dup := seen[contentKey]; dup {
			extras[primaryDocID] = append(extras[primaryDocID], extraCallerInfo{
				callChain: g.callChain,
				docID:     docID,
			})
			continue
		}
		seen[contentKey] = docID

		resource := make(map[string]interface{})
		for i := range g.entries {
			e := &g.entries[i]
			byName, ok := resource[e.typ].(map[string]interface{})
			if !ok {
				byName = make(map[string]interface{})
				resource[e.typ] = byName
			}
			byName[e.baseName] = e.attrs
		}

		docs = append(docs, model.Document{
			"id":       docID,
			"file":     g.fm.FilePath,
			"resource": resource,
		})
		synthetic = append(synthetic, newInstanceFileMetadata(g.fm, docID, g.callChain))
	}
	return docs, synthetic, resourceCount
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
// Call sites under a root whose evaluation failed are left in place so a
// failed instantiation does not remove coverage with no synthetic replacement.
func stripModuleCalls(
	doc model.Document,
	filePath, repoPath string,
	calledDirs map[string]bool,
	successfulRoots map[string]bool,
	rootDirs rootIndex,
	resolver tfeval.RemoteResolver,
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
		resolvedDir, _ := resolveModuleTargetDir(fileDir, source, version, filePath, name, resolver)

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
