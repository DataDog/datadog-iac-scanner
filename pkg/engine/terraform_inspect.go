/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	tfmodel "github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/value"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
)

const terraformPlatformName = "Terraform"

func isTerraformPlatform(platform string) bool {
	return strings.EqualFold(platform, terraformPlatformName)
}

// inspectTerraformPlatform evaluates the Terraform rules on their projected
// input and the other rules on the parsed documents.
func (c *Inspector) inspectTerraformPlatform(
	ctx context.Context, scanID string, files model.FileMetadatas, queries []model.QueryMetadata,
) ([]model.Vulnerability, error) {
	var terraformQueries, others []model.QueryMetadata
	for i := range queries {
		if isTerraformPlatform(queries[i].Platform) {
			terraformQueries = append(terraformQueries, queries[i])
		} else {
			others = append(others, queries[i])
		}
	}
	var vulns []model.Vulnerability
	if len(terraformQueries) > 0 {
		contract, legacy := splitTerraformRules(terraformQueries)
		// The contract evaluation reads roots from the filesystem and decodes
		// results from the files' line info; it never reads the scanned
		// documents. When nothing else does either — no legacy Terraform
		// payload and no other-platform payload is built from them, and the
		// scan does not export the plain JSON payload — release the documents
		// before evaluating, so their trees do not sit beside the contract
		// input for the whole scan.
		if len(legacy) == 0 && len(others) == 0 && c.releaseDocumentsAfterPayload {
			for _, f := range files {
				if f != nil {
					f.Document = nil
				}
			}
			runtime.GC()
		}
		// Absolute and relative paths are separate trees: each is modeled
		// from its own base. Roots are evaluated one at a time so a root's
		// model is gone before the next root.
		for _, group := range splitByPathKind(files) {
			found, err := c.inspectTerraformStream(ctx, scanID, group, contract, legacy)
			if err != nil {
				return nil, err
			}
			vulns = append(vulns, found...)
		}
	}
	if len(others) == 0 {
		c.releasePostEvalFileData(files.ToMap())
		return vulns, nil
	}
	// Decoding the Terraform results reads the files, which inspect releases
	// once it is done.
	rest, err := c.inspect(ctx, scanID, files, others)
	if err != nil {
		return nil, err
	}
	return append(vulns, rest...), nil
}

// inspectTerraformStream evaluates contract and legacy Terraform rules while
// keeping at most one root's model resident. Evidence for cross-root matches
// is indexed in a first pass that drops each root after indexing.
func (c *Inspector) inspectTerraformStream(
	ctx context.Context, scanID string, files model.FileMetadatas,
	contract, legacy []model.QueryMetadata,
) ([]model.Vulnerability, error) {
	if len(contract) == 0 {
		return c.inspectTerraformLegacyStream(ctx, scanID, files, legacy)
	}
	layout, err := c.terraformLayout(ctx, files)
	if err != nil || layout == nil {
		return nil, err
	}
	stream, err := c.newTerraformStream(ctx, scanID, files, layout, contract, legacy)
	if err != nil {
		return nil, err
	}
	return stream.execute(ctx)
}

// terraformLayout lists the roots of the scanned Terraform files. Only the
// scanned files and the modules they call are read, so a file the scan
// leaves out cannot add a root or turn a scanned root into a module.
func (c *Inspector) terraformLayout(ctx context.Context, files model.FileMetadatas) (*tfmodel.Layout, error) {
	configs := c.terraformConfigFiles(files)
	// Module packages live outside the scanned paths (a download cache), so
	// they do not widen the base.
	base, ok := configBase(configs, func(path string) bool { return !c.isModulePackageFile(path) })
	if !ok {
		base, ok = configBase(configs, func(string) bool { return true })
	}
	plans := c.terraformPlans(files)
	if !ok && len(plans) == 0 {
		return nil, nil
	}
	for _, plan := range plans {
		base = widen(base, filepath.Dir(plan))
	}
	layout, err := tfmodel.ScanLayout(ctx, base, &tfmodel.Options{
		FS: c.withScannedPlans(files, plans), Resolver: c.buildRemoteResolver(),
		Files: configs, Plans: plans, PlansOnly: !ok, VarsPath: c.terraformVarsPath,
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		contextLogger := logger.FromContext(ctx)
		contextLogger.Warn().Err(err).Msg("Terraform files could not be loaded, their rules are not evaluated")
		return nil, nil
	}
	return layout, nil
}

type terraformStream struct {
	c           *Inspector
	scanID      string
	files       model.FileMetadatas
	layout      *tfmodel.Layout
	contract    []model.QueryMetadata
	legacy      []model.QueryMetadata
	input       terraformInput
	opts        project.Options
	resolver    tfeval.RemoteResolver
	tfRun       *terraformRun
	legacyBuilt *legacyBuild
	legacyB     *legacyRootBuild
	written     map[string]*model.FileMetadata
}

func (c *Inspector) newTerraformStream(
	ctx context.Context, scanID string, files model.FileMetadatas, layout *tfmodel.Layout,
	contract, legacy []model.QueryMetadata,
) (*terraformStream, error) {
	literalKeys, err := project.LiteralKeysFromModules(c.QueryLoader.parsedGeneric)
	if err != nil {
		return nil, err
	}
	baseInputData := c.QueryLoader.precomputeBaseInputData(nil)
	baseStores := precomputeBaseStores(baseInputData)
	baseDataHashes := hashBaseInputData(baseInputData)
	s := &terraformStream{
		c: c, scanID: scanID, files: files, layout: layout, contract: contract, legacy: legacy,
		written: c.terraformFiles(files),
		input: terraformInput{
			base: layout.Base, files: keyedFiles(c.terraformFiles(files)), repoPath: c.repoPath,
			placeholder: value.NewPlaceholder(), outputLines: c.tracker.GetOutputLines(),
			attribution: &terraformAttribution{lookup: c.buildModuleProvenanceLookup(), cache: newModuleAttributionCache()},
			written:     newWrittenFindings(),
		},
		resolver: c.buildRemoteResolver(),
	}
	s.input.rules = c.newTerraformRules(ctx, contract, s.input.placeholder, baseStores)
	ready, prepared, err := c.prepareTerraformQueries(ctx, contract, baseStores, baseDataHashes)
	if err != nil {
		return nil, err
	}
	routing := newFindingRouting(files, c.repoPath)
	s.opts = project.Options{Placeholder: s.input.placeholder, LiteralKeys: literalKeys}
	s.opts.Cross = c.crossRootIndexLayout(ctx, &s.input, layout, s.resolver, s.opts)
	s.tfRun = &terraformRun{
		scanID: scanID, filesMap: files.ToMap(), ready: ready, prepared: prepared,
		baseStores: baseStores, baseDataHashes: baseDataHashes, routing: routing, rules: s.input.rules,
	}
	s.tfRun.queries = newQueryRun(scanID, s.tfRun.filesMap, ready)
	s.tfRun.queries.baseStores, s.tfRun.queries.baseDataHashes = baseStores, baseDataHashes
	s.tfRun.queries.sharedQueries, s.tfRun.queries.routing = prepared, routing
	s.initLegacy()
	return s, nil
}

func (s *terraformStream) initLegacy() {
	if len(s.legacy) == 0 {
		return
	}
	s.c.stampTerraformScopes(s.files)
	chainBase := s.c.repoPath
	if chainBase == "" {
		chainBase = s.layout.Base
	}
	ids := make(map[string]string, len(s.files))
	for path, f := range s.written {
		ids[path] = f.ID
	}
	instanceID := func(fileID string, m *tfmodel.Module) string {
		return fileID + "\x00" + moduleCallChainKey(m.Chain, m.Address, chainBase) + "\x00" + m.Root.ID
	}
	s.legacyBuilt = &legacyBuild{files: slices.Clone(s.files)}
	s.legacyB = &legacyRootBuild{
		base: s.layout.Base, chainBase: chainBase,
		opts: project.LegacyOptions{
			Base: s.layout.Base, Placeholder: legacyUnknown,
			FileID: func(path string) (string, bool) {
				id, known := ids[path]
				return id, known
			},
			InstanceID: instanceID, Taken: map[string]struct{}{},
		},
		written: s.written, byDir: writtenByDir(s.written), instanceID: instanceID,
		attribution: &terraformAttribution{lookup: s.c.buildModuleProvenanceLookup(), cache: newModuleAttributionCache()},
	}
}

func (s *terraformStream) execute(ctx context.Context) ([]model.Vulnerability, error) {
	if s.c.terraformReference {
		return s.executeReference(ctx)
	}
	var vulns []model.Vulnerability
	var chunk []*terraformRoot
	chunkBlocks, evaluated := 0, 0
	flush := func() error {
		found, err := s.c.evalChunk(ctx, s.tfRun, chunk)
		if err != nil {
			return err
		}
		vulns = append(vulns, found...)
		chunk, chunkBlocks = nil, 0
		return nil
	}
	take := func(root *tfmodel.Root) error {
		if root == nil {
			return nil
		}
		if !s.input.scanned(root) {
			root.Modules = nil
			return nil
		}
		evaluated++
		rootInput := s.input
		rootInput.projection = project.Project([]*tfmodel.Root{root}, s.opts)
		logCrossMatches(ctx, rootInput.projection)
		logIncompleteness(ctx, rootInput.projection)
		chunk = append(chunk, &terraformRoot{root: root, input: &rootInput})
		chunkBlocks += len(rootInput.projection.Blocks)
		if s.legacyB != nil {
			s.c.takeLegacyRoot(s.legacyBuilt, s.legacyB, root)
		} else {
			root.Modules = nil
		}
		if chunkBlocks >= terraformChunkBlocks {
			return flush()
		}
		return nil
	}
	for _, dir := range s.layout.Roots {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := take(s.root(ctx, dir)); err != nil {
			return nil, err
		}
	}
	for _, path := range s.layout.Plans {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := take(s.layout.Plan(ctx, path)); err != nil {
			return nil, err
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return s.finish(ctx, vulns, evaluated)
}

// executeReference evaluates each root alone with the same cross-root evidence
// and unknown gate as the optimized path, without chunking, merge, digests or
// fanout. Used to check that those optimizations keep the same findings.
func (s *terraformStream) executeReference(ctx context.Context) ([]model.Vulnerability, error) {
	var vulns []model.Vulnerability
	evaluated := 0
	take := func(root *tfmodel.Root) error {
		if root == nil {
			return nil
		}
		if !s.input.scanned(root) {
			root.Modules = nil
			return nil
		}
		evaluated++
		rootInput := s.input
		rootInput.projection = project.Project([]*tfmodel.Root{root}, s.opts)
		logCrossMatches(ctx, rootInput.projection)
		logIncompleteness(ctx, rootInput.projection)
		found, err := s.c.evalChunk(ctx, s.tfRun, []*terraformRoot{{root: root, input: &rootInput}})
		if err != nil {
			return err
		}
		vulns = append(vulns, found...)
		if s.legacyB != nil {
			s.c.takeLegacyRoot(s.legacyBuilt, s.legacyB, root)
		} else {
			root.Modules = nil
		}
		return nil
	}
	for _, dir := range s.layout.Roots {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := take(s.root(ctx, dir)); err != nil {
			return nil, err
		}
	}
	for _, path := range s.layout.Plans {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := take(s.layout.Plan(ctx, path)); err != nil {
			return nil, err
		}
	}
	return s.finish(ctx, vulns, evaluated)
}

func (s *terraformStream) finish(ctx context.Context, vulns []model.Vulnerability, evaluated int) ([]model.Vulnerability, error) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Info().Msgf("Evaluated %d Terraform rules on %d of %d roots",
		len(s.tfRun.ready), evaluated, len(s.layout.Roots)+len(s.layout.Plans))
	s.c.trackExecutions(s.tfRun.queries)
	s.input.rules.logSuppressed(ctx)
	if s.legacyBuilt == nil {
		return vulns, nil
	}
	docs := s.c.addWrittenSections(s.legacyBuilt.docs, s.legacyBuilt.covered, s.written)
	legacyVulns, err := s.c.evalLegacyDocuments(ctx, s.scanID, s.files, s.legacy, docs, s.legacyBuilt.files)
	if err != nil {
		return nil, err
	}
	return append(vulns, legacyVulns...), nil
}

// crossRootIndexLayout indexes evidence roots one at a time and drops each
// root before the next. Only the detached companion index is retained; full
// root models are not kept for the main pass, so root-by-root evaluation
// stays memory-bounded.
func (c *Inspector) crossRootIndexLayout(
	ctx context.Context, input *terraformInput, layout *tfmodel.Layout,
	resolver tfeval.RemoteResolver, opts project.Options,
) *project.CrossIndex {
	idx := project.NewCrossIndex()
	if len(opts.LiteralKeys) == 0 || len(layout.Roots) < 2 {
		return idx
	}
	// A root another root calls as a module (through the remote resolver)
	// is not evidence; module directories are discovered without resource
	// expansion, and each evidence root is modeled at most once.
	type candidate struct {
		dir string
		idx *project.CrossIndex
	}
	called := layout.CalledModuleDirectories(ctx, resolver)
	var candidates []candidate
	want := func(t string) bool { _, ok := opts.LiteralKeys[t]; return ok }
	for _, dir := range layout.Roots {
		if ctx.Err() != nil {
			return idx
		}
		if !layout.MayDeclareResource(ctx, resolver, dir, want) {
			continue
		}
		root := layout.Root(ctx, resolver, dir)
		if input.scanned(root) && project.EvidenceRoot(root, nil) && project.HoldsCompanion(root, opts.LiteralKeys) {
			one := project.NewCrossIndex()
			one.Add(project.Project([]*tfmodel.Root{root}, opts))
			candidates = append(candidates, candidate{dir: filepath.Clean(root.Dir), idx: one})
		}
		root.Modules = nil
		// The root has been modeled once; its parse and evaluation values are
		// of no further use, so they do not stay resident for the scan. A
		// directory another root calls as a module keeps its parse: the main
		// pass reuses it for every call.
		if !called[filepath.Clean(root.Dir)] {
			layout.ReleaseRootParse(dir)
		}
	}
	n := 0
	for _, cand := range candidates {
		if called[cand.dir] {
			continue
		}
		idx.Merge(cand.idx)
		n++
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Int("roots", n).Msg("Indexed the literal companions of the evidence roots")
	return idx
}

func (s *terraformStream) root(ctx context.Context, dir string) *tfmodel.Root {
	return s.layout.Root(ctx, s.resolver, dir)
}

// prepareTerraformQueries compiles every query once for all roots. A query
// that does not compile is recorded as failed and left out.
func (c *Inspector) prepareTerraformQueries(
	ctx context.Context, queries []model.QueryMetadata,
	baseStores map[string]storage.Store, baseDataHashes map[string]uint64,
) ([]model.QueryMetadata, map[int]*rego.PreparedEvalQuery, error) {
	var shared map[int]*rego.PreparedEvalQuery
	if c.useRulesCache {
		var err error
		shared, _, err = c.QueryLoader.loadSharedQueriesCached(ctx, queries, baseStores, baseDataHashes)
		if err != nil {
			return nil, nil, err
		}
	} else {
		shared = c.QueryLoader.loadSharedQueries(ctx, queries, baseStores)
	}
	ready := make([]model.QueryMetadata, 0, len(queries))
	prepared := make(map[int]*rego.PreparedEvalQuery, len(queries))
	for i := range queries {
		query, ok := shared[i]
		if !ok {
			var err error
			query, err = c.QueryLoader.LoadQuery(ctx, &queries[i], nil, baseStores, baseDataHashes, c.useRulesCache)
			if err != nil {
				contextLogger := logger.FromContext(ctx)
				contextLogger.Warn().Err(err).Msgf("failed to load query %s", queries[i].Query)
				c.failedQueriesMu.Lock()
				c.failedQueries[queries[i].Query] = err
				c.failedQueriesMu.Unlock()
				continue
			}
		}
		prepared[len(ready)] = query
		ready = append(ready, queries[i])
	}
	return ready, prepared, nil
}

// scanned reports whether a block of root is declared in a scanned file.
func (t *terraformInput) scanned(root *tfmodel.Root) bool {
	for _, m := range root.Modules {
		for _, b := range m.Blocks {
			if t.file(project.JoinRoot(t.base, b.File)) != nil {
				return true
			}
		}
	}
	return false
}

// terraformConfigFiles returns the set of cleaned absolute paths of the
// Terraform configuration files of files. The result is never nil.
func (c *Inspector) terraformConfigFiles(files model.FileMetadatas) map[string]bool {
	out := map[string]bool{}
	for _, f := range files {
		if f == nil || f.ModuleCallChain != "" || !isTerraformConfigFile(f) {
			continue
		}
		if path, err := c.fsys.Abs(f.FilePath); err == nil {
			out[path] = true
		}
	}
	return out
}

// configBase is the deepest directory holding every file of configs that
// keep accepts.
func configBase(configs map[string]bool, keep func(string) bool) (string, bool) {
	base, found := "", false
	for path := range configs {
		if keep(path) {
			base, found = widen(base, filepath.Dir(path)), true
		}
	}
	return base, found
}

// isTerraformConfigFile reports whether f is a Terraform/OpenTofu configuration
// file: a .tf / .tofu / .tf.json / .tofu.json path, or a plain .json file whose
// content is Terraform JSON configuration (for example CDKTF output).
func isTerraformConfigFile(f *model.FileMetadata) bool {
	if tfpath.IsConfig(f.FilePath) {
		return true
	}
	return tfpath.IsPlainJSON(f.FilePath) && tfpath.LooksLikeJSONConfig([]byte(f.OriginalData))
}

// widen returns the deepest ancestor of base that holds dir; an empty base
// gives dir.
func widen(base, dir string) string {
	if base == "" {
		return dir
	}
	for !within(dir, base) {
		parent := filepath.Dir(base)
		if parent == base {
			break
		}
		base = parent
	}
	return base
}

// terraformPlans returns the cleaned absolute paths of the Terraform plan
// JSON files of files.
func (c *Inspector) terraformPlans(files model.FileMetadatas) []string {
	var plans []string
	for _, f := range files {
		if f == nil || f.ModuleCallChain != "" || f.Kind != model.KindTerraformPlan {
			continue
		}
		if path, err := c.fsys.Abs(f.FilePath); err == nil {
			plans = append(plans, path)
		}
	}
	return plans
}

func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// terraformFiles indexes the scanned files written as they are by cleaned
// absolute path; module instance copies are left out.
func (c *Inspector) terraformFiles(files model.FileMetadatas) map[string]*model.FileMetadata {
	out := make(map[string]*model.FileMetadata, len(files))
	for _, f := range files {
		if f == nil || f.ModuleCallChain != "" {
			continue
		}
		path, err := c.fsys.Abs(f.FilePath)
		if err != nil {
			continue
		}
		if _, ok := out[path]; !ok {
			out[path] = f
		}
	}
	return out
}

// splitByPathKind groups files by whether their path is absolute; the scan
// order is kept within each group.
func splitByPathKind(files model.FileMetadatas) []model.FileMetadatas {
	var abs, rel model.FileMetadatas
	for _, f := range files {
		if f != nil && portablePathIsAbs(f.FilePath) {
			abs = append(abs, f)
		} else {
			rel = append(rel, f)
		}
	}
	var groups []model.FileMetadatas
	for _, g := range []model.FileMetadatas{rel, abs} {
		if len(g) > 0 {
			groups = append(groups, g)
		}
	}
	if len(groups) == 0 {
		return []model.FileMetadatas{files}
	}
	return groups
}
