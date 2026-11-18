/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	tfmodel "github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// contractLegacy is the metadata value of "contract" that forces a rule onto
// the legacy documents.
const contractLegacy = "legacy"

// legacyUnknown stands for an unknown part of a value in the legacy
// documents, which rules may print in their messages.
// legacyFileKey is the key of a document naming its file.
const (
	legacyFileKey      = "file"
	legacyIDKey        = "id"
	legacyRootScopeKey = "_dd_tf_root_scope"
)

const legacyUnknown = "${unknown}"

// contractCalls are the functions a rule calls to read the contract input.
var contractCalls = []string{"data.generic.common.finding", "data.generic.terraform.blocks"}

// isContractRule reports whether a Terraform rule reads the contract input:
// it calls one of contractCalls, whatever alias it imports them under, and its
// metadata does not set "contract" to "legacy". A rule that does not parse is
// not a contract rule.
func isContractRule(q *model.QueryMetadata) bool {
	if c, ok := q.Metadata["contract"].(string); ok && strings.EqualFold(c, contractLegacy) {
		return false
	}
	module, err := ast.ParseModule("rule.rego", q.Content)
	if err != nil {
		return false
	}
	imports := make(map[string]string, len(module.Imports))
	for _, imp := range module.Imports {
		ref, ok := imp.Path.Value.(ast.Ref)
		if !ok {
			continue
		}
		name := string(imp.Alias)
		if name == "" {
			name = string(ref[len(ref)-1].Value.(ast.String))
		}
		imports[name] = ref.String()
	}
	found := false
	ast.WalkRefs(module, func(r ast.Ref) bool {
		if found {
			return true
		}
		found = slices.Contains(contractCalls, resolvedRef(r, imports))
		return found
	})
	return found
}

// UsesTerraformContract reports whether a Terraform rule is routed to the
// contract input. It is also used by callers that need to select behavior
// based on the same per-rule routing decision as the engine.
func UsesTerraformContract(q *model.QueryMetadata) bool {
	return q != nil && strings.EqualFold(q.Platform, "terraform") && isContractRule(q)
}

// resolvedRef is the dotted name a reference reads through its imports, or
// the empty string when it is not a plain name.
func resolvedRef(r ast.Ref, imports map[string]string) string {
	head, ok := r[0].Value.(ast.Var)
	if !ok {
		return ""
	}
	name := string(head)
	if path, ok := imports[name]; ok {
		name = path
	}
	for _, t := range r[1:] {
		s, ok := t.Value.(ast.String)
		if !ok {
			return name
		}
		name += "." + string(s)
	}
	return name
}

// splitTerraformRules splits Terraform rules into contract and legacy ones.
func splitTerraformRules(queries []model.QueryMetadata) (contract, legacy []model.QueryMetadata) {
	for i := range queries {
		if isContractRule(&queries[i]) {
			contract = append(contract, queries[i])
		} else {
			legacy = append(legacy, queries[i])
		}
	}
	return contract, legacy
}

// evalLegacyWrittenDocuments runs queries on the scanned files as written,
// with no modeling. Used when modeling is skipped or the layout cannot load.
func (c *Inspector) evalLegacyWrittenDocuments(
	ctx context.Context, scanID string, files model.FileMetadatas, queries []model.QueryMetadata,
	othersReadDocuments bool,
) ([]model.Vulnerability, error) {
	written := c.terraformFiles(files)
	docs := c.addWrittenSections(nil, nil, written, false, nil)
	scopeLegacyDocuments(docs, written)
	return c.evalLegacyDocuments(ctx, scanID, files, queries, docs, files, nil, othersReadDocuments)
}

// evalLegacyDocuments runs queries on the legacy documents.
func (c *Inspector) evalLegacyDocuments(
	ctx context.Context, scanID string, files model.FileMetadatas, queries []model.QueryMetadata,
	docs []model.Document, allFiles model.FileMetadatas, moduleFiles map[string]*moduleFileCalls,
	othersReadDocuments bool,
) ([]model.Vulnerability, error) {
	contextLogger := logger.FromContext(ctx)
	filesMap := allFiles.ToMap()
	if othersReadDocuments {
		filesMap = copyFileMetadataOwners(filesMap)
	}
	payloads, err := c.buildPlatformPayloads(ctx, filesMap, docs, nil, queries)
	if err != nil {
		return nil, err
	}
	// common_lib.modules is not populated for Terraform (see Inspect).
	baseInputData := c.QueryLoader.precomputeBaseInputData()
	baseStores := precomputeBaseStores(baseInputData)
	baseDataHashes := hashBaseInputData(baseInputData)
	var sharedQueries map[int]*rego.PreparedEvalQuery
	if c.useRulesCache {
		sharedQueries, _, err = c.QueryLoader.loadSharedQueriesCached(ctx, queries, baseStores, baseDataHashes)
		if err != nil {
			return nil, err
		}
	} else {
		sharedQueries = c.QueryLoader.loadSharedQueries(ctx, queries, baseStores)
	}
	run := newQueryRun(scanID, filesMap, queries)
	run.baseStores, run.baseDataHashes = baseStores, baseDataHashes
	run.sharedQueries = sharedQueries
	run.routing = newFindingRouting(files, c.repoPath)
	run.routing.moduleFiles = moduleFiles
	vulns, err := c.evaluate(ctx, run, payloads)
	if err != nil {
		return nil, err
	}
	contextLogger.Info().Msgf("Evaluated %d legacy Terraform rules on %d documents", len(queries), len(docs))
	return vulns, nil
}

// copyFileMetadataOwners isolates Document release for this payload build.
// The maps stay shared and read-only; only nil assignments to Document belong
// to this build. A later platform may still need the original parsed maps.
func copyFileMetadataOwners(files map[string]*model.FileMetadata) map[string]*model.FileMetadata {
	copies := make(map[string]*model.FileMetadata, len(files))
	for id, file := range files {
		if file == nil {
			copies[id] = nil
			continue
		}
		fileCopy := *file
		copies[id] = &fileCopy
	}
	return copies
}

// inspectTerraformLegacyStream models one root at a time and drops it once
// its documents are built. It is the path taken when no contract rule needs
// every root resident together.
//
// When no loaded rule can match a declared resource type by name, modeling is
// skipped and files are scanned as written — the same short-circuit the
// previous module-instantiation path used. Evaluating every root's module
// tree is wasted work when it cannot change a finding.
func (c *Inspector) inspectTerraformLegacyStream(
	ctx context.Context, scanID string, files model.FileMetadatas, queries []model.QueryMetadata,
	othersReadDocuments bool,
) ([]model.Vulnerability, error) {
	if len(queries) == 0 {
		return nil, nil
	}
	c.stampTerraformScopes(files)
	written := c.terraformFiles(files)
	targets := ruleTargetedResourceTypes(queries, c.terraformRuleLibraries()...)
	if c.skipLegacyModeling(files, targets) {
		return c.evalLegacyWrittenDocuments(ctx, scanID, files, queries, othersReadDocuments)
	}
	layout, err := c.terraformLayout(ctx, files)
	if err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		// Main kept going on written documents when modules failed to load.
		return c.evalLegacyWrittenDocuments(ctx, scanID, files, queries, othersReadDocuments)
	}
	if layout == nil {
		return c.evalLegacyWrittenDocuments(ctx, scanID, files, queries, othersReadDocuments)
	}
	chainBase := c.repoPath
	if chainBase == "" {
		chainBase = layout.Base
	}
	ids := make(map[string]string, len(files))
	for path, f := range written {
		ids[path] = f.ID
	}
	instanceID := func(fileID string, m *tfmodel.Module) string {
		return fileID + "\x00" + legacyModuleCallChainKey(m.Chain, m.Address, chainBase) + "\x00" + m.Root.ID
	}
	opts := project.LegacyOptions{
		Base:        layout.Base,
		Placeholder: legacyUnknown,
		FileID: func(path string) (string, bool) {
			id, known := ids[path]
			return id, known
		},
		InstanceID: instanceID,
		Taken:      map[string]struct{}{},
	}
	resolver := c.buildRemoteResolver()
	lookup := c.buildModuleProvenanceLookup()
	built := &legacyBuild{files: slices.Clone(files), othersReadDocuments: othersReadDocuments}
	b := legacyRootBuild{
		base: layout.Base, chainBase: chainBase, opts: opts, written: written,
		byDir: writtenByDir(written), instanceID: instanceID, lookup: lookup,
	}
	built.moduleCalls = newModuleCallIndex(written, c.isModulePackageFile)
	modeled, asWritten := legacyModeledRoots(layout.Roots, written, b.byDir, targets)
	if err := layout.EachRoot(ctx, resolver, modeled, func(root *tfmodel.Root) error {
		c.takeLegacyRoot(built, &b, root)
		return nil
	}); err != nil {
		return nil, err
	}
	// A modeled root may expand every targeted block to no instance, so
	// takeLegacyRoot produces no document for its files. Mark those paths
	// covered anyway: the written resources must not come back, or a
	// count = 0 block would still report. Files that only carry sections
	// the model does not (moved, terraform, …) stay uncovered so
	// addWrittenSections can still contribute them.
	coverModeledExpandedFiles(built, modeled, written, b.byDir, targets)
	// Plan JSON keeps its written document for legacy rules (see takeLegacyRoot);
	// modeling plans here would cover those paths and drop the parser shape.
	docs := c.addWrittenSections(built.docs, built.covered, written, true, asWritten)
	scopeLegacyDocuments(docs, written)
	return c.evalLegacyDocuments(ctx, scanID, files, queries, docs, built.files,
		built.moduleCalls.fileCalls(), othersReadDocuments)
}

func scopeLegacyDocuments(docs []model.Document, written map[string]*model.FileMetadata) {
	for _, doc := range docs {
		if _, ok := doc[legacyRootScopeKey]; ok {
			continue
		}
		file, _ := doc[legacyFileKey].(string)
		if file == "" {
			continue
		}
		file = filepath.Clean(file)
		scope := ""
		meta := written[file]
		if (meta != nil && meta.Kind == model.KindTerraformPlan) || isTFVarsFile(file) {
			scope = file
		} else {
			scope = filepath.Dir(file)
		}
		doc[legacyRootScopeKey] = filepath.Clean(scope)
	}
}

// legacyModeledRoots splits roots into the ones the legacy documents need
// modeled and the paths of the files of the others, which are scanned as
// written. A root is modeled when one of its files calls a module, whose
// instances only the model expands, or declares a block some rule can match
// with count or for_each, which may expand to no instance. A root of plain
// blocks models to what its files already say, as main scanned them, so it
// is not evaluated. When the rules' targets are unknown every root is modeled.
func legacyModeledRoots(
	roots []string, written map[string]*model.FileMetadata, byDir map[string][]string, targets *ruleTargets,
) (modeled []string, asWritten map[string]bool) {
	if targets == nil {
		return roots, nil
	}
	asWritten = map[string]bool{}
	for _, dir := range roots {
		paths := byDir[filepath.Clean(dir)]
		if slices.ContainsFunc(paths, func(path string) bool { return needsLegacyModel(written[path], targets) }) {
			modeled = append(modeled, dir)
			continue
		}
		for _, path := range paths {
			asWritten[path] = true
		}
	}
	return modeled, asWritten
}

func needsLegacyModel(f *model.FileMetadata, targets *ruleTargets) bool {
	if f == nil || !isTerraformConfigFile(f) {
		return false
	}
	if calls, _ := asStringMap(f.Document["module"]); len(calls) > 0 {
		return true
	}
	return declaresExpandedBlock(model.FileMetadatas{f}, targets)
}

// coverModeledExpandedFiles records modeled-root files that declare a
// targeted count/for_each block as covered when expansion produced no
// legacy document, so their written resources cannot be revived.
func coverModeledExpandedFiles(
	built *legacyBuild, modeled []string, written map[string]*model.FileMetadata,
	byDir map[string][]string, targets *ruleTargets,
) {
	covered := make(map[string]bool, len(built.covered))
	for _, d := range built.covered {
		covered[d.Path] = true
	}
	for _, dir := range modeled {
		for _, path := range byDir[filepath.Clean(dir)] {
			if covered[path] {
				continue
			}
			f := written[path]
			if !declaresExpandedBlock(model.FileMetadatas{f}, targets) {
				continue
			}
			built.covered = append(built.covered, &project.LegacyDoc{Path: path})
			covered[path] = true
		}
	}
}

// legacyBuild accumulates the documents of roots evaluated one at a time.
type legacyBuild struct {
	docs                []model.Document
	files               model.FileMetadatas
	covered             []*project.LegacyDoc
	othersReadDocuments bool
	moduleCalls         *moduleCallIndex
}

// legacyRootBuild is what turning one root into legacy documents needs.
type legacyRootBuild struct {
	base      string
	chainBase string
	opts      project.LegacyOptions
	written   map[string]*model.FileMetadata
	// byDir is written indexed by cleaned directory, built once for the scan.
	byDir      map[string][]string
	instanceID func(string, *tfmodel.Module) string
	lookup     moduleProvenanceLookup
}

// takeLegacyRoot appends root's documents and drops the root's modules.
//
// Plan JSON files are left out: the model fills computed attributes with the
// unknown placeholder, which changes valid_key checks against the shape the
// JSON parser already built for rules. Those files stay uncovered so
// addWrittenSections contributes the written plan document, matching main.
func (c *Inspector) takeLegacyRoot(built *legacyBuild, b *legacyRootBuild, root *tfmodel.Root) {
	if root == nil {
		return
	}
	// Attribution caches contain HCL nodes and module scopes, so keep one only
	// while this root is being converted into detached model attributions.
	attribution := &terraformAttribution{lookup: b.lookup, cache: newModuleAttributionCache()}
	built.moduleCalls.recordModules(root.Modules, c.repoPath, b.chainBase, attribution)
	one := &tfmodel.Scan{Base: b.base, Roots: []*tfmodel.Root{root}}
	part := project.LegacyDocs(one.Roots, b.opts)
	part = slices.DeleteFunc(part, func(d *project.LegacyDoc) bool {
		f := b.written[d.Path]
		return f != nil && f.Kind == model.KindTerraformPlan
	})
	part = addModuleSectionsIndexed(part, one, b.written, b.byDir, b.instanceID)
	scope := filepath.Clean(root.Dir)
	moduleBlocks := legacyModuleBlockIndex{}
	for _, d := range part {
		d.Doc[legacyRootScopeKey] = scope
		built.docs = append(built.docs, d.Doc)
		file := b.written[d.Path]
		copyWrittenSections(d.Doc, file)
		built.covered = append(built.covered, &project.LegacyDoc{Path: d.Path})
		if d.Module == nil {
			keepWrittenExpandedBlocks(d.Doc, file, d.Instances)
			addLegacyInstances(file, d.Instances)
			continue
		}
		blocks := moduleBlocks.forFile(d.Module, b.base, d.Path)
		built.files = append(built.files, c.legacyModuleFile(file, d, blocks, b.chainBase, attribution))
	}
	if c.releaseDocumentsAfterPayload && !built.othersReadDocuments {
		releaseRootDocuments(part, b.written, filepath.Clean(root.Dir))
	}
	root.Modules = nil
}

// legacyModuleBlockIndex groups the blocks of a module instance by their
// scanned file. A module can produce one legacy document per file, so building
// this index once per root avoids rescanning every block for every document.
// The index is local to takeLegacyRoot: module models are released as soon as
// the root is handed off.
type legacyModuleBlockIndex map[*tfmodel.Module]map[string][]*tfmodel.Block

func (idx legacyModuleBlockIndex) forFile(m *tfmodel.Module, base, path string) []*tfmodel.Block {
	byFile, ok := idx[m]
	if !ok {
		byFile = make(map[string][]*tfmodel.Block)
		for _, block := range m.Blocks {
			if len(block.Instances) == 0 {
				continue
			}
			file := project.JoinRoot(base, block.File)
			byFile[file] = append(byFile[file], block)
		}
		idx[m] = byFile
	}
	return byFile[path]
}

// keepWrittenExpandedBlocks puts back, in the document of a root module file,
// the written entry of each block count or for_each expanded: the rules
// written before the contract input read a root block once, under its label,
// with count, for_each and the each and count references as written. A block
// the written document does not hold keeps its instances.
func keepWrittenExpandedBlocks(doc map[string]any, file *model.FileMetadata, instances map[project.LegacyKey]project.LegacyInstance) {
	if file == nil || len(instances) == 0 {
		return
	}
	for k, inst := range instances {
		byName, _ := doc[k.Kind].(map[string]any)[k.Type].(map[string]any)
		writtenByType, _ := asStringMap(file.Document[k.Kind])
		writtenByName, _ := asStringMap(writtenByType[k.Type])
		entry, ok := writtenByName[inst.Label]
		if byName == nil || !ok {
			continue
		}
		delete(byName, k.Name)
		byName[inst.Label] = entry
	}
}

// releaseRootDocuments drops the written documents of the files of the root
// at dir that its legacy documents stand for. Nothing reads them once the
// root is taken: the files are covered, so no written document is added for
// them. Files of module directories keep theirs, since later roots calling the
// module read their written sections.
func releaseRootDocuments(part []*project.LegacyDoc, written map[string]*model.FileMetadata, dir string) {
	for _, d := range part {
		if d.Module != nil || filepath.Dir(d.Path) != dir {
			continue
		}
		if f := written[d.Path]; f != nil && f.Kind == model.KindTerraform {
			f.Document = nil
		}
	}
}

// addLegacyInstances records the document keys of the expanded blocks written
// in file.
func addLegacyInstances(file *model.FileMetadata, instances map[project.LegacyKey]project.LegacyInstance) {
	if file == nil || len(instances) == 0 {
		return
	}
	if file.TerraformInstances == nil {
		file.TerraformInstances = make(map[model.TerraformInstanceKey]model.TerraformInstance, len(instances))
	}
	for k, inst := range instances {
		file.TerraformInstances[model.TerraformInstanceKey{Kind: k.Kind, Type: k.Type, Name: k.Name}] =
			model.TerraformInstance{Label: inst.Label, Suffix: inst.Suffix}
	}
}

// legacyModuleFile is the scanned file standing for the document of a module
// instance: the written file, reported under the instance's call chain and
// attributed to its root call.
func (c *Inspector) legacyModuleFile(
	written *model.FileMetadata, d *project.LegacyDoc, blocks []*tfmodel.Block, chainBase string,
	attribution *terraformAttribution,
) *model.FileMetadata {
	m := d.Module
	f := written.ShallowCopy()
	f.ID, _ = d.Doc[legacyIDKey].(string)
	f.Document = model.Document{}
	f.ModuleCallChain = legacyModuleCallChainKey(m.Chain, m.Address, chainBase)
	f.ModuleAttributions = map[string]*model.ModuleAttribution{}
	f.TerraformInstances = nil
	addLegacyInstances(f, d.Instances)
	f.TerraformScope = &model.TerraformScope{
		RootModule:    repoRelativeDir(m.Root.Dir, c.repoPath, c.externalPathRoots),
		ModuleAddress: m.Address,
		Blocks:        documentBlocks(labeledDocument(d.Doc, d.Instances)),
	}
	if written.TerraformScope != nil {
		f.TerraformScope.UnlabeledIndex = written.TerraformScope.UnlabeledIndex
	}
	if c.isModulePackageFile(d.Path) && len(m.Chain) > 0 {
		attribution.mu.Lock()
		f.ModuleAttributions[defaultModuleAttributionKey] = callAttribution(
			m.Chain, d.Path, c.repoPath, attribution.lookup, attribution.cache)
		attribution.mu.Unlock()
	}
	for _, b := range blocks {
		r, kind := resolvedBlock(b, b.Instances[0], m, d.Path)
		if r == nil {
			continue
		}
		if attr := attribution.resource(r, c.repoPath); attr != nil {
			f.ModuleAttributions[moduleAttributionKey(kind, r.DefLine, r.DefColumn)] = attr
		}
	}
	return f
}

// resolvedBlock is the resource, data or ephemeral instance inst of block b
// in module instance m, declared in file, as module attribution reads it, and
// the type it is keyed by; nil for other kinds.
func resolvedBlock(b *tfmodel.Block, inst *tfmodel.Instance, m *tfmodel.Module, file string) (r *tfeval.ResolvedResource, kind string) {
	switch b.Kind {
	case address.KindResource:
		kind = b.Type
	case address.KindData:
		kind = address.DataPrefix + b.Type
	case address.KindEphemeral:
		kind = address.EphemeralPrefix + b.Type
	default:
		return nil, ""
	}
	span := (&project.Located{Block: b}).Span()
	r = &tfeval.ResolvedResource{
		Type: b.Type, Name: b.Name + inst.Key, Label: b.Name,
		Scope: m.Scope, Iteration: inst.Iteration,
		DefinedIn: file, DefLine: span.Start.Line, DefEndLine: span.End.Line,
		DefColumn: span.Start.Column, DefEndColumn: span.End.Column,
		ModuleAddress: m.Address, CallChain: m.Chain,
		Data: b.Kind == address.KindData, Ephemeral: b.Kind == address.KindEphemeral,
	}
	if b.Syntax != nil {
		r.Body = b.Syntax.Body
	}
	return r, kind
}

// labeledDocument is doc with the blocks expanded by count or for_each under
// the label they are written with.
func labeledDocument(doc model.Document, instances map[project.LegacyKey]project.LegacyInstance) model.Document {
	if len(instances) == 0 {
		return doc
	}
	out := make(model.Document, len(doc))
	for section, v := range doc {
		out[section] = v
	}
	for _, kind := range [...]string{address.KindResource, address.KindData, address.KindEphemeral} {
		byType, ok := doc[kind].(map[string]any)
		if !ok {
			continue
		}
		relabeled := make(map[string]any, len(byType))
		for typ, names := range byType {
			byName, _ := names.(map[string]any)
			labels := make(map[string]any, len(byName))
			for name, attrs := range byName {
				if inst, ok := instances[project.LegacyKey{Kind: kind, Type: typ, Name: name}]; ok {
					name = inst.Label
				}
				labels[name] = attrs
			}
			relabeled[typ] = labels
		}
		out[kind] = relabeled
	}
	return out
}

// writtenSections are the kinds of block the model does not carry, which the
// legacy documents take from the parsed file as written.
var writtenSections = [...]string{platformTerraform, "moved", "import", "removed", "check"}

func copyWrittenSections(doc map[string]any, file *model.FileMetadata) {
	if file == nil {
		return
	}
	for _, section := range writtenSections {
		if v, ok := file.Document[section]; ok {
			doc[section] = v
		}
	}
}

// addWrittenSections adds a document for each scanned file the legacy docs do
// not already stand for. modeled tells the two cases apart: when the stream
// skipped modeling, every scanned file contributes its whole written document
// — the rules run on the files as they are written. When the model ran, config
// files contribute only the sections the model does not carry: their blocks
// reach the report through the root's modeled document, or, when an override
// merges them away, through the file they override, and a file whose every
// block expanded to no instance holds no resource at all, so its written
// document must not come back. A Terraform plan file is never covered for
// legacy: takeLegacyRoot skips it, so its whole written document (already
// shaped for rules by the JSON parser) is always contributed here. A path in
// asWritten belongs to a root the model run left out, so its whole written
// document stands for it as when modeling is skipped.
func (c *Inspector) addWrittenSections(
	docs []model.Document, raw []*project.LegacyDoc, written map[string]*model.FileMetadata, modeled bool,
	asWritten map[string]bool,
) []model.Document {
	covered := make(map[string]bool, len(raw))
	for _, d := range raw {
		// Module instance documents stand for their defining file too: the
		// file's blocks reach the report through them.
		covered[d.Path] = true
	}
	for _, path := range slices.Sorted(maps.Keys(written)) {
		f := written[path]
		if covered[path] || c.isModulePackageFile(path) {
			continue
		}
		doc := model.Document{legacyIDKey: f.ID, legacyFileKey: path}
		switch {
		case f.Kind == model.KindTerraformPlan || !modeled || asWritten[path]:
			maps.Copy(doc, f.Document)
			delete(doc, legacyRootScopeKey)
		case f.Kind == model.KindTerraform:
			copyWrittenSections(doc, f)
		default:
			continue
		}
		if len(doc) > 2 {
			docs = append(docs, doc)
		}
	}
	return docs
}

// addModuleSections adds a document for each module-directory file that
// carries sections the model does not (terraform {}, moved, etc.), once per
// path. The first calling instance attributes the document so ResourceIDs
// keep the module address without multiplying findings across roots.
// writtenByDir indexes the paths of written by cleaned directory, sorted.
func writtenByDir(written map[string]*model.FileMetadata) map[string][]string {
	out := map[string][]string{}
	for _, path := range slices.Sorted(maps.Keys(written)) {
		dir := filepath.Clean(filepath.Dir(path))
		out[dir] = append(out[dir], path)
	}
	return out
}

func addModuleSectionsIndexed(
	raw []*project.LegacyDoc, scan *tfmodel.Scan, written map[string]*model.FileMetadata, byDir map[string][]string,
	instanceID func(string, *tfmodel.Module) string,
) []*project.LegacyDoc {
	hasPath := make(map[string]bool, len(raw))
	for _, d := range raw {
		hasPath[d.Path] = true
	}
	first := map[string]*tfmodel.Module{}
	for _, r := range scan.Roots {
		for _, m := range r.Modules {
			if m.Address == "" {
				continue
			}
			for _, path := range byDir[filepath.Clean(m.Dir)] {
				if _, ok := first[path]; !ok {
					first[path] = m
				}
			}
		}
	}
	for _, path := range slices.Sorted(maps.Keys(first)) {
		f := written[path]
		m := first[path]
		if hasPath[path] || f.Kind != model.KindTerraform || isTFVarsFile(path) || !hasWrittenSections(f) {
			continue
		}
		raw = append(raw, &project.LegacyDoc{
			Doc:    map[string]any{legacyIDKey: instanceID(f.ID, m), legacyFileKey: path},
			Path:   path,
			Module: m,
		})
		hasPath[path] = true
	}
	return raw
}

func hasWrittenSections(f *model.FileMetadata) bool {
	for _, section := range writtenSections {
		if _, ok := f.Document[section]; ok {
			return true
		}
	}
	return false
}

// isModulePackageFile reports whether path is a file of an external or remote
// module package, which is scanned through the calls reaching it.
func (c *Inspector) isModulePackageFile(path string) bool {
	return c.isExternalModulePath(path) || c.isRemoteModulePackageFile(path)
}

// isRemoteModulePackageFile reports whether path is within a fetched module
// directory indexed by the resolver. Unlike external paths, these directories
// have concrete call ownership in remoteModuleDirs.
func (c *Inspector) isRemoteModulePackageFile(path string) bool {
	if len(c.remoteModuleRoots) == 0 && len(c.remoteModuleOtherRoots) == 0 {
		return false
	}
	cleanPath := filepath.Clean(path)
	if filepath.Separator == '/' && filepath.IsAbs(cleanPath) && filepath.VolumeName(cleanPath) == "" {
		for ancestor := cleanPath; ; {
			if _, ok := c.remoteModuleRoots[ancestor]; ok {
				return true
			}
			parent := filepath.Dir(ancestor)
			if parent == ancestor {
				break
			}
			ancestor = parent
		}
	}
	for _, root := range c.remoteModuleOtherRoots {
		if within(cleanPath, root) {
			return true
		}
	}
	return false
}

// planOverlayFS serves scanned plan files that the filesystem does not hold
// from their scanned content.
type planOverlayFS struct {
	vfs.FS
	content map[string][]byte
}

func (o planOverlayFS) ReadFile(name string) ([]byte, error) {
	data, err := o.FS.ReadFile(name)
	if err == nil {
		return data, nil
	}
	if b, ok := o.content[name]; ok {
		return b, nil
	}
	return nil, err
}

func (o planOverlayFS) Stat(name string) (fs.FileInfo, error) {
	info, err := o.FS.Stat(name)
	if err == nil {
		return info, nil
	}
	if b, ok := o.content[name]; ok {
		return planFileInfo{name: filepath.Base(name), size: int64(len(b))}, nil
	}
	return nil, err
}

type planFileInfo struct {
	name string
	size int64
}

const planFileMode fs.FileMode = 0o444

func (i planFileInfo) Name() string       { return i.name }
func (i planFileInfo) Size() int64        { return i.size }
func (i planFileInfo) Mode() fs.FileMode  { return planFileMode }
func (i planFileInfo) ModTime() time.Time { return time.Time{} }
func (i planFileInfo) IsDir() bool        { return false }
func (i planFileInfo) Sys() any           { return nil }

// withScannedPlans lets the plan files of files be read from their scanned
// content when the filesystem lacks them.
func (c *Inspector) withScannedPlans(files model.FileMetadatas, plans []string) vfs.FS {
	if len(plans) == 0 {
		return c.fsys
	}
	content := map[string][]byte{}
	for _, f := range files {
		if f == nil || f.Kind != model.KindTerraformPlan || f.OriginalData == "" {
			continue
		}
		if path, err := c.fsys.Abs(f.FilePath); err == nil {
			content[path] = []byte(f.OriginalData)
		}
	}
	return planOverlayFS{FS: c.fsys, content: content}
}
