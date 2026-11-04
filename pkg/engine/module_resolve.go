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
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/metaargs"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/cespare/xxhash/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/rs/zerolog"
)

// extraCallerInfo records a deduplicated module caller so its findings can be
// cloned from the primary OPA doc after eval without adding a separate doc to input.document.
type extraCallerInfo struct {
	docID string
	// rootModule is this caller's own root module directory.
	// The resource's address is the same as the primary's (content dedup keys
	// on moduleAddress, which a caller's own root never changes), only the
	// root differs, so only this needs to be carried.
	rootModule   string
	attributions map[string]*model.ModuleAttribution
}

// moduleResolutionResult bundles all outputs of resolveModuleDocuments.
type moduleResolutionResult struct {
	docs                 []model.Document
	syntheticFiles       []*model.FileMetadata
	suppressed           instantiatedIndex
	successfulRoots      map[string]bool
	unresolvedModuleDirs map[string]bool
	// unresolvedRoots lists, by directory, the sorted repository-relative
	// roots whose calls reach a directory that could not be evaluated.
	unresolvedRoots map[string][]string
	extras          map[string][]extraCallerInfo
	// moduleFiles holds, by file ID, the calls reaching each external module file.
	moduleFiles map[string]*moduleFileCalls
	// docRoots holds, by document ID, the sorted roots each Terraform document stands for.
	docRoots map[string][]string
	// written holds the evaluated content of the plain root blocks kept in
	// their written files.
	written       writtenBlocks
	resourceCount int
	rootCount     int
	ok            bool
}

// instantiateLocalModules evaluates local modules and injects resolved resource
// documents. In a called module body only the resource blocks are dropped (they
// are re-emitted instantiated, with caller-resolved values); variable, output,
// data and locals blocks are kept so their rules still fire exactly as in a
// standalone scan. Module call blocks stay in the scan so rules matching the
// call itself fire there, separate from the instantiated resources.
//
// It mutates the input FileMetadata documents in place. Mutations are applied
// only after evaluation succeeds (see resolveModulesSafely); a panic during
// evaluation leaves the scan input untouched rather than removing coverage
// without a synthetic replacement.
// Returns synthetic docs and matching FileMetadata (call chain for fingerprints).
// Caller must append the files before Combine/ToMap. extras lists duplicate callers for post-OPA finding expansion,
// moduleFiles the calls reaching each external module file, and docRoots the roots each document stands for.
func (c *Inspector) instantiateLocalModules(
	ctx context.Context,
	files model.FileMetadatas,
	targets *ruleTargets,
) (
	docs []model.Document,
	syntheticFiles []*model.FileMetadata,
	extras map[string][]extraCallerInfo,
	moduleFiles map[string]*moduleFileCalls,
	docRoots map[string][]string,
) {
	resolver := c.buildRemoteResolver()
	res := c.resolveModulesSafely(ctx, files, resolver, targets)
	contextLogger := logger.FromContext(ctx)
	logModuleInstantiationSummary(&contextLogger, &res)
	if !res.ok {
		return nil, nil, nil, nil, documentRoots(files, nil, c.repoPath)
	}
	for _, f := range files {
		if f == nil || !tfpath.IsConfig(f.FilePath) {
			continue
		}
		if replaced := res.suppressed[f.ID]; len(replaced) > 0 {
			if res.unresolvedModuleDirs[moduleFileDir(f.FilePath, c.repoPath)] {
				continue
			}
			// Blocks that came back as instantiated documents, or are known to
			// expand to zero instances, are removed; blocks that could not be
			// resolved stay and are scanned where they are written. The rest of
			// the body (variable/output/data/locals) is always kept so its
			// rules fire as in a standalone scan.
			removeInstantiatedResources(f.Document, replaced)
			if err := f.EnsureLineInfoDocument(ctx); err != nil {
				contextLogger.Err(err).Msgf("failed to build line-info document for file %s", f.FilePath)
			} else {
				removeInstantiatedResources(f.LineInfoDocument, replaced)
			}
		}
	}
	for _, f := range files {
		if f == nil {
			continue
		}
		if calls := res.moduleFiles[f.ID]; calls != nil {
			calls.writtenResourceTypes = documentResourceTypes(f.Document)
		}
	}
	patchWrittenBlocks(files, res.written)
	routeModuleFileRoots(files, res.moduleFiles)
	res.docRoots = documentRoots(files, &res, c.repoPath)
	return res.docs, res.syntheticFiles, res.extras, res.moduleFiles, res.docRoots
}

// documentRoots lists, by document ID, the sorted roots each Terraform
// document stands for. res may be nil when no module was resolved.
func documentRoots(files model.FileMetadatas, res *moduleResolutionResult, repoPath string) map[string][]string {
	return documentRootsOpts(files, res, repoPath, true)
}

// evalDocumentRoots is documentRoots without unresolved-module caller fan-out.
// Per-root eval payloads must not paste every shared module body into every
// caller: that multiplied input size by the call graph. Finding routing still
// uses documentRoots so unresolved module findings keep their caller roots.
func evalDocumentRoots(files model.FileMetadatas, res *moduleResolutionResult, repoPath string) map[string][]string {
	return documentRootsOpts(files, res, repoPath, false)
}

func documentRootsOpts(
	files model.FileMetadatas, res *moduleResolutionResult, repoPath string, unresolvedCallers bool,
) map[string][]string {
	out := make(map[string][]string, len(files))
	var moduleFiles map[string]*moduleFileCalls
	var unresolvedRoots map[string][]string
	if res != nil {
		moduleFiles, unresolvedRoots = res.moduleFiles, res.unresolvedRoots
		for _, fm := range res.syntheticFiles {
			if fm == nil || fm.TerraformScope == nil {
				continue
			}
			roots := []string{fm.TerraformScope.RootModule}
			for _, ex := range res.extras[fm.ID] {
				roots = append(roots, ex.rootModule)
			}
			out[fm.ID] = nonEmptyRoots(roots)
		}
	}
	for _, f := range files {
		if f == nil || f.TerraformScope == nil || isSyntheticTerraformDoc(f) {
			continue
		}
		own := f.TerraformScope.RootModule
		roots := []string{own}
		if mf := moduleFiles[f.ID]; mf != nil && len(mf.calls) > 0 {
			roots = moduleFileRoots(f.Document, mf, own)
		}
		if unresolvedCallers {
			roots = appendUnresolvedCallers(roots, own, f, unresolvedRoots, repoPath)
		}
		out[f.ID] = nonEmptyRoots(roots)
	}
	return out
}

// appendUnresolvedCallers adds the roots of callers that reach an unresolved
// module file, keeping the file's own root so it still stands for itself.
func appendUnresolvedCallers(
	roots []string, own string, f *model.FileMetadata, unresolvedRoots map[string][]string, repoPath string,
) []string {
	if f == nil || !tfpath.IsConfig(f.FilePath) || len(unresolvedRoots) == 0 {
		return roots
	}
	callers := unresolvedRoots[moduleFileDir(f.FilePath, repoPath)]
	if len(callers) == 0 {
		return roots
	}
	roots = append(roots, callers...)
	if own != "" {
		roots = append(roots, own)
	}
	return roots
}

// nonEmptyRoots sorts roots and drops repeated and empty values.
func nonEmptyRoots(roots []string) []string {
	return slices.DeleteFunc(sortedUnique(roots), func(r string) bool { return r == "" })
}

// moduleFileRoots is the roots of an external module file reached by calls:
// the callers' roots for blocks the calls replace, and the file's own root
// for blocks kept as written.
func moduleFileRoots(doc model.Document, mf *moduleFileCalls, own string) []string {
	var roots []string
	keptOwn, routed := false, false
	rewriteBlockMeta(doc, func(b address.Block, addr string) (string, bool) {
		if mf.keptAsWritten(blockResourceType(b)) {
			keptOwn = true
		} else {
			routed = true
		}
		return addr, false
	})
	if routed {
		roots = append(roots, moduleFileCallRoots(mf)...)
	}
	if keptOwn || len(roots) == 0 {
		roots = append(roots, own)
	}
	return roots
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
// wherever the block kinds and resource blocks share a namespace, as they do
// in the resourceType of a finding.
const (
	dataTypePrefix   = "data."
	ephemeralPrefix  = "ephemeral."
	ephemeralSection = "ephemeral"
	resourceSection  = "resource"
	localsSection    = "locals"
	outputSection    = "output"
	providerSection  = "provider"
)

// blockKind is the type a resolved block is indexed and attributed under.
// The evaluator carries the block kind from HCL, so a managed resource and an
// ephemeral one sharing type and name never conflate, however they expand.
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
// block with count or for_each, which may expand to no instance.
func declaresExpandedBlock(files model.FileMetadatas, targets *ruleTargets) bool {
	for _, f := range files {
		if f == nil || !tfpath.IsConfig(f.FilePath) {
			continue
		}
		for _, key := range [...]string{"resource", "data", ephemeralSection} {
			blocks, _ := asStringMap(f.Document[key])
			for typ, byName := range blocks {
				if targets != nil && !targets.matches(typ) && !targets.matches(ephemeralPrefix+typ) && !targets.matches(dataTypePrefix+typ) {
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

// addDroppedBlocks records the empty blocks no evaluation resolved to any
// instance, so they are removed from the files they are written in.
func addDroppedBlocks(
	instantiated instantiatedIndex,
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
		if fm == nil || failedRoots[moduleFileDir(fm.FilePath, repoPath)] {
			continue
		}
		// A list-shaped type cannot lose one block without losing all of them.
		if _, named := asStringMap(docAsMap(fm.Document[blockSection(b)])[b.Type]); !named {
			continue
		}
		instantiated.add(fm.ID, kind, b.Name)
	}
}

func blockSection(b tfeval.EmptyBlock) string {
	switch {
	case b.Data:
		return "data"
	case b.Ephemeral:
		return ephemeralSection
	}
	return resourceSection
}

func resolvedBlockKey(file, kind, name string) string {
	return file + "\x00" + kind + "\x00" + name
}

// writtenBlock is the evaluated content and _dd_meta extras of a plain root
// block kept in its written file.
type writtenBlock struct {
	attrs  map[string]interface{}
	extras blockMetaExtras
	// hasExtras says extras replace the block's _dd_meta extras.
	hasExtras bool
}

// writtenBlocks maps the resolvedBlockKey of a plain root block, by file ID,
// to its evaluated content.
type writtenBlocks map[string]writtenBlock

func (w writtenBlocks) add(p *rootResource, attributions *moduleAttributionCache) {
	attrs := tfeval.AttributesToDocument(p.r)
	w[resolvedBlockKey(p.fm.ID, p.kind, p.r.BaseName)] = writtenBlock{
		attrs:     attrs,
		extras:    evaluatedMetaExtras(p.r, attrs, attributions),
		hasExtras: true,
	}
}

// evaluatedMetaExtras computes the _dd_meta extras of an evaluated instance
// whose document content is attrs.
func evaluatedMetaExtras(r *tfeval.ResolvedResource, attrs map[string]interface{}, attributions *moduleAttributionCache) blockMetaExtras {
	refs, ambiguous := attributions.resourceReferences(r)
	return blockMetaExtras{
		references: refs,
		unknown:    tfeval.Unknowns(r, attrs),
		ambiguous:  ambiguous,
		configured: configuredShape(r, attrs),
		provider:   resolvedProvider(r),
	}
}

// rootBlockSections are the non-resource sections of a root's written files
// patched from the root scope.
var rootBlockSections = [...]string{localsSection, moduleCallRoot, outputSection, providerSection}

// patchRootScope merges the evaluated content of the locals, module calls,
// outputs and provider blocks written in the root module's files into those
// files' documents. Locals are keyed by position in their file, providers by
// name and position. A root's files are its own, so patching them as the root
// is merged keeps one file's rendered blocks live instead of every root's
// until the resolution ends.
func patchRootScope(
	scope *tfeval.ModuleScope, byAbsPath map[string]*model.FileMetadata, fsys vfs.FS, repoPath string,
	attributions *moduleAttributionCache,
) {
	if scope == nil {
		return
	}
	written := make(writtenBlocks)
	for _, body := range scope.Bodies {
		if body == nil {
			continue
		}
		fm := fileByPath(byAbsPath, fsys, body.SrcRange.Filename, repoPath)
		if fm == nil {
			continue
		}
		clear(written)
		localsAt, providersAt := 0, map[string]int{}
		for _, b := range body.Blocks {
			var name string
			switch {
			case b.Type == localsSection:
				name = strconv.Itoa(localsAt)
				localsAt++
			case (b.Type == moduleCallRoot || b.Type == outputSection) && len(b.Labels) == 1:
				written[resolvedBlockKey(fm.ID, b.Type, b.Labels[0])] = callOrOutputBlock(scope, b, attributions)
				continue
			case b.Type == providerSection && len(b.Labels) == 1:
				name = rootBlockAt(b.Labels[0], providersAt[b.Labels[0]])
				providersAt[b.Labels[0]]++
				attrs, unknown := scope.RenderBodyUnknowns(b.Body)
				written[resolvedBlockKey(fm.ID, b.Type, name)] = writtenBlock{
					attrs: attrs, extras: blockMetaExtras{unknown: unknown}, hasExtras: true,
				}
				continue
			default:
				continue
			}
			written[resolvedBlockKey(fm.ID, b.Type, name)] = writtenBlock{attrs: scope.RenderBody(b.Body)}
		}
		patchRootScopeBlocks(fm, written)
	}
}

// callOrOutputBlock is the evaluated content of a root module call or output
// and its _dd_meta extras, as a plan has them: the unknown and referenced
// values of the call's arguments or of the output's value.
func callOrOutputBlock(scope *tfeval.ModuleScope, b *hclsyntax.Block, attributions *moduleAttributionCache) writtenBlock {
	attrs, unknown := scope.RenderBodyUnknowns(b.Body)
	a := attributions.analyzer(scope, nil)
	a.refs = &referenceTrace{frame: &referenceFrame{scope: scope}}
	refs, ambiguous := a.bodyReferences(b.Body)
	for name := range attrs {
		if !callOrOutputValue(b.Type, name) {
			delete(attrs, name)
		}
	}
	for _, extras := range [...]map[string]interface{}{unknown, refs, ambiguous} {
		for name := range extras {
			if !callOrOutputValue(b.Type, name) {
				delete(extras, name)
			}
		}
	}
	return writtenBlock{attrs: attrs, extras: blockMetaExtras{
		unknown: nilIfEmpty(unknown), references: refs, ambiguous: nilIfEmpty(ambiguous),
	}, hasExtras: true}
}

// callOrOutputValue reports whether name is a value a plan records for a
// module call (an argument) or an output (its value).
func callOrOutputValue(kind, name string) bool {
	if kind == outputSection {
		return name == "value"
	}
	return !metaargs.IsModule(name) && name != "source" && name != "version"
}

func rootBlockAt(name string, i int) string {
	return name + "\x00" + strconv.Itoa(i)
}

// patchRootScopeBlocks merges the evaluated content recorded by addRootScope
// into a written file's document. A section whose blocks the document does
// not hold one for one is left as written.
func patchRootScopeBlocks(f *model.FileMetadata, written writtenBlocks) {
	patch := func(kind, name string, raw interface{}) {
		block, ok := asStringMap(raw)
		if !ok {
			return
		}
		if wb, ok := written[resolvedBlockKey(f.ID, kind, name)]; ok {
			mergeEvaluated(block, wb.attrs, false)
			if !wb.hasExtras {
				return
			}
			meta, _ := asStringMap(block[ddMetaKey])
			if meta == nil {
				meta = map[string]interface{}{}
			}
			wb.extras.writeTo(meta)
			if len(meta) > 0 {
				block[ddMetaKey] = meta
			} else {
				delete(block, ddMetaKey)
			}
		}
	}
	for _, kind := range rootBlockSections {
		raw, ok := f.Document[kind]
		if !ok {
			continue
		}
		if kind == localsSection {
			for i, block := range blockList(raw) {
				patch(kind, strconv.Itoa(i), block)
			}
			continue
		}
		byName, _ := asStringMap(raw)
		for name, entry := range byName {
			if kind != providerSection {
				patch(kind, name, entry)
				continue
			}
			for i, block := range blockList(entry) {
				patch(kind, rootBlockAt(name, i), block)
			}
		}
	}
}

// blockList is the blocks of a section the converter holds as one block when
// written once and as a list otherwise.
func blockList(raw interface{}) []interface{} {
	if list, ok := raw.([]interface{}); ok {
		return list
	}
	return []interface{}{raw}
}

// patchWrittenBlocks merges the evaluated content of the plain root blocks
// into their written files' documents and adds the traced references and
// unknown paths to their _dd_meta.
func patchWrittenBlocks(files model.FileMetadatas, written writtenBlocks) {
	if len(written) == 0 {
		return
	}
	for _, f := range files {
		if f == nil {
			continue
		}
		for _, section := range [...]struct{ key, prefix string }{
			{resourceSection, ""},
			{dataRoot, dataTypePrefix},
			{ephemeralSection, ephemeralPrefix},
		} {
			byType, _ := asStringMap(f.Document[section.key])
			for typ, typeBlocks := range byType {
				byName, _ := asStringMap(typeBlocks)
				for name, raw := range byName {
					block, ok := asStringMap(raw)
					if !ok {
						continue
					}
					wb, ok := written[resolvedBlockKey(f.ID, section.prefix+typ, name)]
					if !ok {
						continue
					}
					mergeEvaluated(block, wb.attrs, true)
					meta, ok := block[ddMetaKey].(map[string]interface{})
					if !ok {
						continue
					}
					wb.extras.writeTo(meta)
				}
			}
		}
	}
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

var metadataOnlyKeys = map[string]bool{"_dd_lines": true, "_dd__default": true}

// onlyMetadataKeys reports whether a map holds nothing but the parser's own
// bookkeeping (line numbers and the like), which describes content that is no
// longer there. Skipped exactly: a block label that merely starts with an
// underscore is legal Terraform and is content.
func onlyMetadataKeys(m map[string]interface{}) bool {
	for key := range m {
		if !metadataOnlyKeys[key] {
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
	successfulRoots map[string]bool,
	failedRoots map[string]bool,
	unresolvedModuleDirs map[string]bool,
	actualCalledDirs map[string]bool,
	extra *[]model.Document,
	syntheticFiles *[]*model.FileMetadata,
	resourceCount *int,
	rootEvalOK *bool,
	moduleCalls *moduleCallIndex,
) writtenBlocks {
	m := &rootMerge{
		ctx: ctx, evaluator: evaluator, filesByDir: filesByDir, repoPath: repoPath, relDir: relDir, resolver: resolver,
		targets: targets, lookup: lookup, byAbsPath: byAbsPath, seen: seen, extras: extras,
		instantiated: instantiated, successfulRoots: successfulRoots, unresolvedModuleDirs: unresolvedModuleDirs,
		actualCalledDirs: actualCalledDirs, extra: extra, syntheticFiles: syntheticFiles,
		resourceCount: resourceCount, rootEvalOK: rootEvalOK, moduleCalls: moduleCalls,
		resolved: make(map[string]bool), failedRoots: failedRoots, written: make(writtenBlocks),
		refs: newRefIntern(),
	}
	next := 0
	if workers := min(rootEvalWorkers, runtime.GOMAXPROCS(0), len(roots)); workers > 1 {
		next = m.evaluateConcurrently(roots, workers)
	}
	for _, dir := range roots[next:] {
		resources, _, childDirs, err := evaluator.EvaluateModule(ctx, dir, evaluator.LoadRootVarsWithContext(ctx, dir))
		m.merge(dir, resources, evaluator.TakeModuleInstances(), evaluator.TakeEmptyBlocks(), evaluator.TakeRootScope(), childDirs, err)
		// The cache key includes rootDir, so the next root cannot reuse these
		// evaluations, and keyMemo pins every collection they hashed.
		evaluator.ReleaseEvalCache()
	}
	addDroppedBlocks(instantiated, m.emptyBlocks, m.resolved, m.failedRoots, byAbsPath, evaluator.FS(), repoPath)
	return m.written
}

// rootEvalWorkers bounds the roots evaluated at once. Each holds its own
// evaluation values until it is merged, so this also bounds the memory
// concurrency adds.
var rootEvalWorkers = 4

// windowSlack widens the token window beyond the workers: see
// evaluateConcurrently.
const windowSlack = 256

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
	emptyBlocks          []tfeval.EmptyBlock
	resolved             map[string]bool
	failedRoots          map[string]bool
	written              writtenBlocks
	refs                 *refIntern
}

func (m *rootMerge) merge(
	dir string,
	resources []tfeval.ResolvedResource,
	instances []tfeval.ModuleInstance,
	empty []tfeval.EmptyBlock,
	scope *tfeval.ModuleScope,
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
		m.resolved[resolvedBlockKey(absPath(r.DefinedIn, m.repoPath), blockKind(r), r.BaseName)] = true
	}
	for d := range childDirs {
		m.actualCalledDirs[pathKey(d)] = true
	}
	attributions := newModuleAttributionCache()
	attributions.refs = m.refs
	docs, syn, count := instantiatedDocs(
		resources, m.byAbsPath, m.evaluator.FS(), m.repoPath, m.relDir, m.targets, m.seen, m.extras, m.instantiated, m.lookup, attributions,
		m.written)
	m.moduleCalls.record(instances, m.repoPath, m.relDir, m.lookup, attributions)
	patchRootScope(scope, m.byAbsPath, m.evaluator.FS(), m.repoPath, attributions)
	*m.extra = append(*m.extra, docs...)
	*m.syntheticFiles = append(*m.syntheticFiles, syn...)
	*m.resourceCount += count
}

// rootResult is a root evaluated by a worker.
type rootResult struct {
	resources    []tfeval.ResolvedResource
	instances    []tfeval.ModuleInstance
	empty        []tfeval.EmptyBlock
	scope        *tfeval.ModuleScope
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
	// before an index, so the roots in flight are always the next ones to
	// merge. The slack keeps the merge's order from stalling the workers: a
	// slow root blocks the merge until it arrives, and a window that only
	// fits the workers would idle all of them for that whole duration with
	// fast roots queued behind it. Queued results are small — a worker
	// releases its evaluation caches once its root is evaluated, so what is
	// held is the resolved resources — and the heavy roots a repository has
	// are the ones the merge is waiting on anyway.
	window := make(chan struct{}, 2*workers+windowSlack)
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
		m.merge(dir, r.resources, r.instances, r.empty, r.scope, r.childDirs, r.err)
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
	r.empty = worker.TakeEmptyBlocks()
	r.scope = worker.TakeRootScope()
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
			ctx, evaluator, filesByDir[pathKey(dir)], repoPath, resolver, dir,
		) {
			key := pathKey(called)
			if unresolvedModuleDirs[key] {
				continue
			}
			unresolvedModuleDirs[key] = true
			queue = append(queue, key)
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
	byAbsPath, filesByDir, dirsWithTf := indexTerraformFiles(ctx, files, repoPath, fsys)
	if len(dirsWithTf) == 0 {
		return moduleResolutionResult{}
	}
	// Evaluating a module tree is the expensive part, and it is pure waste when
	// the repository declares nothing any rule can match by name. The block
	// labels are already in the parsed documents, so this costs nothing.
	// External module files still need their calls, whatever they declare.
	moduleCalls := newModuleCallIndex(filesByDir, externalModuleFile)
	// count/for_each only force evaluation when they sit on a type some rule
	// can match: expanding an unrelated vault_policy does not help an aws_s3 rule.
	declaresResource := declaresTargetedResource(files, targets) || declaresExpandedBlock(files, targets)
	nothingToEvaluate := moduleCalls == nil && !declaresResource
	if nothingToEvaluate && !declaresModuleCall(filesByDir) {
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
		ctx, evaluator, filesByDir, dirsWithTf, repoPath, resolver, true)

	if nothingToEvaluate {
		return moduleResolutionResult{}
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

	evaluatedRoots := roots
	if onlyExternalCalls {
		evaluatedRoots = rootsReaching(roots, staticCalls, moduleCalls.files)
	}

	failedRoots := make(map[string]bool)
	written := evaluateRootModules(
		ctx, evaluator, evaluatedRoots, filesByDir, repoPath, relDir, resolver, targets, lookup,
		byAbsPath, seen, extras, instantiated,
		successfulRoots, failedRoots, unresolvedModuleDirs, actualCalledDirs,
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
	scrubInstantiatedForUnresolvedDirs(instantiated, files, unresolvedModuleDirs, repoPath)
	unresolvedRoots := reachingRootsByDir(roots, staticCalls, unresolvedModuleDirs, relDir)

	return moduleResolutionResult{
		docs:                 extra,
		syntheticFiles:       syntheticFiles,
		suppressed:           instantiated,
		successfulRoots:      successfulRoots,
		unresolvedModuleDirs: unresolvedModuleDirs,
		unresolvedRoots:      unresolvedRoots,
		extras:               extras,
		moduleFiles:          moduleCalls.fileCalls(unresolvedModuleDirs),
		written:              written,
		resourceCount:        resourceCount,
		rootCount:            len(roots),
		ok:                   true,
	}
}

// reachingRootsByDir maps each unresolved directory to the sorted
// repository-relative roots whose calls reach it, leaving out directories no
// root reaches. The reverse call map and the roots above an opaque call are
// built once, so each directory costs only a walk over its own callers.
func reachingRootsByDir(
	roots []string,
	graph staticCallGraph,
	unresolvedModuleDirs map[string]bool,
	relDir func(string) string,
) map[string][]string {
	if len(unresolvedModuleDirs) == 0 {
		return nil
	}
	callers := reverseCalls(graph)
	isRoot := make(map[string]bool, len(roots))
	for _, r := range roots {
		isRoot[r] = true
	}
	opaqueReached := make(map[string]bool)
	walkCallers(callers, opaqueReached, opaqueDirs(graph)...)
	out := make(map[string][]string, len(unresolvedModuleDirs))
	for dir := range unresolvedModuleDirs {
		reached := make(map[string]bool)
		walkCallers(callers, reached, dir)
		var rel []string
		for _, r := range roots {
			if reached[r] || opaqueReached[r] {
				rel = append(rel, relDir(r))
			}
		}
		if len(rel) > 0 {
			out[dir] = sortedUnique(rel)
		}
	}
	return out
}

// sortedUnique sorts s in place and drops repeated values.
func sortedUnique(s []string) []string {
	sort.Strings(s)
	return slices.Compact(s)
}

// rewriteBlockMeta replaces the address in the _dd_meta of every resource,
// data and ephemeral block of doc with the address rewrite returns, keeping
// its other keys, and leaves the block as it is when rewrite reports false.
func rewriteBlockMeta(doc model.Document, rewrite func(b address.Block, addr string) (string, bool)) {
	for _, section := range [...]struct{ key, kind string }{
		{"resource", address.KindResource},
		{"data", address.KindData},
		{ephemeralSection, address.KindEphemeral},
	} {
		byType, _ := asStringMap(doc[section.key])
		for typ, typeBlocks := range byType {
			byName, _ := asStringMap(typeBlocks)
			for name, raw := range byName {
				block, _ := asStringMap(raw)
				meta, ok := asStringMap(block[ddMetaKey])
				if !ok {
					continue
				}
				addr, _ := meta["address"].(string)
				addr, ok = rewrite(address.Block{Kind: section.kind, Type: typ, Name: name}, addr)
				if !ok {
					continue
				}
				next := resourceMeta(addr, blockMetaExtras{})
				for k, v := range meta {
					if k == "root_modules" {
						continue
					}
					if _, rewritten := next[k]; !rewritten {
						next[k] = v
					}
				}
				block[ddMetaKey] = next
			}
		}
	}
}

// routeModuleFileRoots rewrites the address of each block of an external
// module file that its calls replace. A kept block stays as written.
//
// When every call shares one module instance address, the document can carry
// that prefix so rules joining on _dd_meta.address see the same form findings
// report. When calls disagree (two callers, or one for_each with several
// keys), no single prefix fits: the address stays as written and
// routeModuleFileFindings prefixes each finding per call. Instantiated
// resources are removed from this document and live only on the synthetic
// per-instance documents, which already carry the right address.
func routeModuleFileRoots(files model.FileMetadatas, moduleFiles map[string]*moduleFileCalls) {
	for _, f := range files {
		if f == nil {
			continue
		}
		mf := moduleFiles[f.ID]
		if mf == nil || len(mf.calls) == 0 {
			continue
		}
		sameAddress := true
		for i := range mf.calls {
			sameAddress = sameAddress && mf.calls[i].moduleAddress == mf.calls[0].moduleAddress
		}
		rewriteBlockMeta(f.Document, func(b address.Block, addr string) (string, bool) {
			if mf.keptAsWritten(blockResourceType(b)) {
				return addr, false
			}
			if sameAddress {
				addr = routedBlockAddress(mf.scope, b, mf.calls[0].moduleAddress)
			}
			return addr, true
		})
	}
}

// moduleFileCallRoots is the sorted root set of the blocks of an external
// module file that its calls replace: the calls' roots, plus the file's own
// root when the written block is kept too.
func moduleFileCallRoots(mf *moduleFileCalls) []string {
	roots := make([]string, 0, len(mf.calls)+1)
	for i := range mf.calls {
		roots = append(roots, mf.calls[i].rootModule)
	}
	if mf.keepWritten && mf.scope != nil {
		roots = append(roots, mf.scope.RootModule)
	}
	return sortedUnique(roots)
}

// blockResourceType is the resource type findings name b by.
func blockResourceType(b address.Block) string {
	switch b.Kind {
	case address.KindData:
		return dataTypePrefix + b.Type
	case address.KindEphemeral:
		return ephemeralPrefix + b.Type
	}
	return b.Type
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
		keyed := make([]string, len(calledDirs))
		for i, calledDir := range calledDirs {
			keyed[i] = pathKey(calledDir)
		}
		if withGraph {
			graph.calls[dir] = keyed
			graph.opaque[dir] = hasUnresolvableModuleCall(filesByDir[dir])
		}
		for i, calledDir := range keyed {
			if !called[calledDir] {
				// Reading a called directory is what reports one that was
				// never pushed, even when nothing is evaluated.
				_, _ = evaluator.FS().ReadDir(calledDirs[i])
			}
			called[calledDir] = true
		}
	}
	return called, graph
}

// declaresModuleCall reports whether any parsed file holds a module block.
func declaresModuleCall(filesByDir map[string][]*model.FileMetadata) bool {
	for _, files := range filesByDir {
		for _, file := range files {
			if file != nil && len(docAsMap(file.Document["module"])) > 0 {
				return true
			}
		}
	}
	return false
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
	seeds := opaqueDirs(graph)
	for dir := range targets {
		seeds = append(seeds, dir)
	}
	reaches := make(map[string]bool, len(graph.calls))
	walkCallers(reverseCalls(graph), reaches, seeds...)
	var out []string
	for _, root := range roots {
		if reaches[root] {
			out = append(out, root)
		}
	}
	return out
}

// reverseCalls maps each called directory to the directories calling it.
func reverseCalls(graph staticCallGraph) map[string][]string {
	callers := make(map[string][]string, len(graph.calls))
	for dir, called := range graph.calls {
		for _, c := range called {
			callers[c] = append(callers[c], dir)
		}
	}
	return callers
}

func opaqueDirs(graph staticCallGraph) []string {
	var dirs []string
	for dir, opaque := range graph.opaque {
		if opaque {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// walkCallers marks the seeds and every directory calling them, directly or
// not. Walking backwards is safe on cycles and does not depend on the order
// roots are visited in.
func walkCallers(callers map[string][]string, marked map[string]bool, seeds ...string) {
	var queue []string
	mark := func(dir string) {
		if !marked[dir] {
			marked[dir] = true
			queue = append(queue, dir)
		}
	}
	for _, dir := range seeds {
		mark(dir)
	}
	for len(queue) > 0 {
		dir := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for _, caller := range callers[dir] {
			mark(caller)
		}
	}
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
	// extras are the block's _dd_meta entries besides its address.
	extras   blockMetaExtras
	metaHash uint64
}

// docGroup collects every resource one module call resolved in one defining file.
type docGroup struct {
	fm            *model.FileMetadata
	moduleAddress string
	layer         int
	entries       []instantiatedResource
	attributions  map[string]*model.ModuleAttribution
	// rootModule is the repository-relative root module directory the group's
	// resources are instantiated under: the outermost caller's directory.
	// It is the same for every entry: all come from the same
	// call chain, which is what it is derived from.
	rootModule string
	// instances maps an expanded block to the one instance key this document
	// represents. One document holds at most one instance of
	// a block, so the lookup is exact.
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
	repoPath string,
	relDir func(string) string,
	targets *ruleTargets,
	seen map[docContentKey]string,
	extras map[string][]extraCallerInfo,
	instantiated instantiatedIndex,
	lookup moduleProvenanceLookup,
	attributions *moduleAttributionCache,
	written writtenBlocks,
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
		fm := fileByPath(byAbsPath, fsys, r.DefinedIn, repoPath)
		if fm == nil {
			continue
		}
		kind := blockKind(r)
		if r.ModuleAddress == "" && r.Key.Kind == tfeval.NoKey {
			// Every root block written once gets its evaluated content and
			// _dd_meta, whichever rules are loaded.
			written.add(&rootResource{r: r, fm: fm, kind: kind}, attributions)
			continue
		}
		if !targets.matches(r.Type) && !targets.matches(kind) {
			// No rule can match this type by name, so resolving its values
			// cannot change a finding. It keeps being scanned where it is
			// written, exactly as it is without module evaluation.
			// An untargeted source block is never a rule's subject; references still name it.
			continue
		}

		base := r.BaseName
		// The root module directory keys the group alongside the call: two
		// roots calling the same module path resolve it with their own inputs,
		// and their documents must not collide. Content
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

	for _, key := range order {
		g := groups[key]
		docID := docGroupID(g)

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
	return docs, synthetic, resourceCount
}

// rootResource is a root block that has no count/for_each instance suffix.
type rootResource struct {
	r    *tfeval.ResolvedResource
	fm   *model.FileMetadata
	kind string
}

func addGroupEntry(
	g *docGroup,
	r *tfeval.ResolvedResource,
	kind, repoPath string,
	lookup moduleProvenanceLookup,
	attributions *moduleAttributionCache,
) {
	attrs := tfeval.AttributesToDocument(r)
	extras := evaluatedMetaExtras(r, attrs, attributions)
	key := moduleAttributionKey(kind, r.DefLine, r.DefColumn)
	// Clone: a finding may narrow the attribution it is given.
	g.attributions[key] = cloneModuleAttribution(attributions.attribution(r, repoPath, lookup))
	base := r.BaseName
	if r.Key.Kind != tfeval.NoKey {
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
		extras:    extras,
		// configured is derived from attrs and the block body, which the
		// attributes hash and the defining file already identify.
		metaHash: hashAttributes(map[string]interface{}{
			referencesKey: extras.references, unknownKey: extras.unknown, ambiguousKey: extras.ambiguous,
			providerKey: extras.provider,
		}),
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
		h.u64(e.metaHash)
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
		attrs := maps.Clone(e.attrs)
		if attrs == nil {
			attrs = make(map[string]interface{})
		}
		kind, blockType := addressKindOf(e.typ)
		block := address.Block{Kind: kind, Type: blockType, Name: e.baseName}
		addr := address.Instance(g.moduleAddress, block, g.instances[block])
		attrs[ddMetaKey] = resourceMeta(addr, e.extras)
		byName[e.baseName] = attrs
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
// Combine skips it), carrying the group's Terraform identity context:
// the module instance address its blocks are evaluated
// under, the outermost caller's root module, which block instance this
// document represents, and which blocks it only borrows for context.
func newInstanceFileMetadata(g *docGroup) *model.FileMetadata {
	clone := g.fm.ShallowCopy()
	clone.ID = docGroupID(g)
	clone.Document = model.Document{}
	clone.ModuleAttributions = cloneModuleAttributions(g.attributions)
	clone.TerraformScope = &model.TerraformScope{
		RootModule:    g.rootModule,
		ModuleAddress: g.moduleAddress,
		Instances:     g.instances,
		Blocks:        groupBlocks(g),
	}
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
	return pathKey(filepath.Dir(absPath(filePath, repoPath)))
}

// resourceRootModule is the repository-relative directory of the root module a
// resolved resource belongs to: its outermost caller's directory for a module
// resource, its own directory for a root resource. A
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
	// CalledModuleDirs returns OS paths; pathKey matches the document-based
	// branch so unresolvedModuleDirs / filesByDir lookups stay consistent.
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
			ctx, evaluator, filesByDir[pathKey(current)], repoPath, resolver, current,
		) {
			key := pathKey(called)
			if seen[key] {
				continue
			}
			seen[key] = true
			closure = append(closure, key)
			queue = append(queue, key)
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
		fileDir := pathKey(filepath.Dir(absPath(file.FilePath, repoPath)))
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

// pathKey is the slash-form map key for a Terraform file or directory path.
// MemFS Abs already returns slash paths; DiskFS Abs and filepath.Clean on
// Windows return backslashes — without this, byAbsPath and filesByDir lookups
// miss on Windows content-push scans.
func pathKey(p string) string {
	return filepath.ToSlash(filepath.Clean(p))
}

// evaluatorPath returns p as the evaluator names files, so a relative scan
// path still matches the blocks it reports.
func evaluatorPath(fsys vfs.FS, p string) string {
	if fsys != nil {
		if a, err := fsys.Abs(p); err == nil {
			p = a
		}
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
	// A path rooted without a volume ("/repo" on Windows) counts as absolute:
	// filepath.IsAbs is false for it, and joining it under base would
	// duplicate the root (see repoRelativeDir).
	if filepath.IsAbs(p) || path.IsAbs(filepath.ToSlash(p)) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(base, p))
}
