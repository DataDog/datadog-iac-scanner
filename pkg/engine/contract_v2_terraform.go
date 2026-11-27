/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/hclcache"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	tfcontract "github.com/DataDog/datadog-iac-scanner/pkg/terraform/contract"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
)

// ContractV2RunStats is the per-scan completeness and failure summary exposed
// to the scanner's post-scan metadata writer.
type ContractV2RunStats struct {
	RootsFailed          int
	PlansFailed          int
	RootsScopeIncomplete int
}

const (
	contractV2ChunkMaxResources    = 1024
	contractV2PlatformTerraform    = "terraform"
	contractV2MaxBatchQueries      = 16
	contractV2BatchCacheEntryLimit = 128
	contractV2MaxRootWorkers       = 8
	contractV2RootWindowFactor     = 3
)

type contractV2BatchCacheKey struct {
	compiler *ast.Compiler
	packages string
}

type contractV2BatchCacheEntry struct {
	key      contractV2BatchCacheKey
	prepared *rego.PreparedEvalQuery
}

type contractV2EvalTask struct {
	rules    []*contractV2Rule
	prepared *rego.PreparedEvalQuery
}

// rootV2Hook receives each root's evaluated tfeval resources, root scope, and
// shared per-root attribution cache during single-pass coexistence evaluation.
type rootV2FailureHook func(dir string, err error)

type rootV2Hook func(
	dir string,
	resources []tfeval.ResolvedResource,
	instances []tfeval.ModuleInstance,
	rootScope *tfeval.ModuleScope,
	scopeIncomplete bool,
	attrCache *moduleAttributionCache,
	occurrences map[string]*model.ResourceOccurrence,
) error

// OnlyTerraformContractV2 reports whether every query applicable to platforms
// is a Terraform Contract v2 rule (so legacy Terraform document conversion can
// be bypassed when no legacy/Common rules or payload export need it).
func (c *Inspector) OnlyTerraformContractV2(platforms []string) bool {
	if c == nil || c.QueryLoader == nil {
		return false
	}
	queries := c.getQueriesByPlat(platforms)
	if len(queries) == 0 {
		return false
	}
	hasV2 := false
	for i := range queries {
		if !strings.EqualFold(queries[i].Platform, "terraform") {
			return false
		}
		if !UsesContractV2(&queries[i]) {
			return false
		}
		hasV2 = true
	}
	return hasV2
}

// splitContractQueries partitions queries into Contract v2 Terraform rules and
// all remaining (legacy Terraform + other platform) rules.
func splitContractQueries(queries []model.QueryMetadata) (v2Specs []*contractV2Rule, legacy []model.QueryMetadata) {
	for i := range queries {
		if strings.EqualFold(queries[i].Platform, "terraform") {
			if spec, ok := analyzeContractV2Rule(&queries[i]); ok {
				v2Specs = append(v2Specs, spec)
				continue
			}
		}
		legacy = append(legacy, queries[i])
	}
	return v2Specs, legacy
}

type contractV2PlanLineCache struct {
	byPath map[string][]string
}

// contractV2Runner evaluates Contract v2 Terraform rules over streaming roots
// (either fed from the shared single-pass coexistence tfeval loop or from its
// own 4-worker parallel tfeval pool in pure-v2 mode) and Terraform plan files.
type contractV2Runner struct {
	c       *Inspector
	scanID  string
	files   model.FileMetadatas
	rules   []*contractV2Rule
	lookup  moduleProvenanceLookup
	callers map[string]*model.FileMetadata

	rootRules               []*contractV2Rule
	resourceRules           []*contractV2Rule
	byTypeRoot              map[string][]*contractV2Rule
	byTypeResource          map[string][]*contractV2Rule
	wildcardRoot            []*contractV2Rule
	wildcardRes             []*contractV2Rule
	allowedTypes            map[string]bool
	jsonTypes               map[string]bool
	anyWildcard             bool
	hasNoResources          bool
	needRelations           bool
	needProviders           bool
	needStaticBlocks        bool
	needJSON                bool
	needFilterAST           bool
	filesByPath             map[string]*model.FileMetadata
	planFiles               []*model.FileMetadata
	baseRootOpts            tfcontract.RootOptions
	findings                *findingSet
	findingsMu              sync.Mutex
	batchCacheMu            sync.Mutex
	batchCache              map[contractV2BatchCacheKey]*list.Element
	batchCacheLRU           list.List
	chunk                   []*policy.Unit
	chunkProjectedResources map[*policy.Unit]ast.Object
	chunkResCount           int
	evaluatedRootCnt        int
	evaluatedPlanCnt        int
	firstEvalErr            error
	statsMu                 sync.Mutex
	runStatsData            ContractV2RunStats
	occurrencesMu           sync.RWMutex
	occurrencesByResourceID map[string]*model.ResourceOccurrence
}

func (r *contractV2Runner) runStats() ContractV2RunStats {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	return r.runStatsData
}

func (r *contractV2Runner) countRootFailure() {
	r.statsMu.Lock()
	r.runStatsData.RootsFailed++
	r.statsMu.Unlock()
}

func (r *contractV2Runner) recordPlanFailure(ctx context.Context, file string, err error) {
	r.statsMu.Lock()
	r.runStatsData.PlansFailed++
	r.statsMu.Unlock()
	contextLogger := logger.FromContext(ctx)
	contextLogger.Warn().Err(err).Str("plan", file).Msg("contract v2: failed to evaluate Terraform plan")
}

func (r *contractV2Runner) recordRootIncomplete(ctx context.Context, dir string) {
	r.statsMu.Lock()
	r.runStatsData.RootsScopeIncomplete++
	r.statsMu.Unlock()
	contextLogger := logger.FromContext(ctx)
	contextLogger.Warn().Str("root", dir).Msg("contract v2: Terraform root scope is incomplete")
}

func (r *contractV2Runner) recordRootResult(ctx context.Context, dir string, res *rootResult) {
	if res.scopeIncomplete {
		r.recordRootIncomplete(ctx, dir)
	}
	if res.panicked != nil {
		err := fmt.Errorf("terraform evaluation panicked: %v", res.panicked)
		r.countRootFailure()
		contextLogger := logger.FromContext(ctx)
		contextLogger.Warn().Err(err).Str("root", dir).Msg("contract v2: failed to evaluate Terraform root")
	} else if res.err != nil {
		r.countRootFailure()
		contextLogger := logger.FromContext(ctx)
		contextLogger.Warn().Err(res.err).Str("root", dir).Msg("contract v2: failed to evaluate Terraform root")
	}
}

// nolint:gocyclo
func (c *Inspector) newContractV2Runner(
	ctx context.Context,
	scanID string,
	files model.FileMetadatas,
	specs []*contractV2Rule,
) (*contractV2Runner, error) {
	baseInputData := c.QueryLoader.precomputeBaseInputData(nil)
	baseStores := precomputeBaseStores(baseInputData)
	rules, err := c.compileContractV2Rules(ctx, specs, baseStores, hashBaseInputData(baseInputData))
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, nil
	}

	routing := newFindingRouting(nil, nil, files, c.repoPath, c.isExternalModulePath)
	r := &contractV2Runner{
		c:              c,
		scanID:         scanID,
		files:          files,
		rules:          rules,
		lookup:         c.buildModuleProvenanceLookup(),
		callers:        routing.callers,
		byTypeRoot:     make(map[string][]*contractV2Rule),
		byTypeResource: make(map[string][]*contractV2Rule),
		allowedTypes:   make(map[string]bool),
		jsonTypes:      make(map[string]bool),
		filesByPath:    make(map[string]*model.FileMetadata, len(files)),
		// Route (filterAtCallSites + dropUnattributedExternalFindings) BEFORE
		// identity compaction so suppressed/excluded call sites never shadow siblings.
		findings:   newFindingSet(c.compactFindingsAtDecode, routing),
		batchCache: make(map[contractV2BatchCacheKey]*list.Element),
	}
	r.findings.recordDuplicates = c.inventory != nil

	relationJSONRule := false
	for _, rule := range rules {
		r.needRelations = r.needRelations || rule.needsRelations
		r.needProviders = r.needProviders || rule.needsProviders
		r.needStaticBlocks = r.needStaticBlocks || rule.needsStaticBlocks
		r.hasNoResources = r.hasNoResources || rule.hasNoResources
		r.needJSON = r.needJSON || rule.needsJSON
		r.needFilterAST = r.needFilterAST || rule.needsFilterAST
		if rule.needsRelations && rule.needsJSON {
			relationJSONRule = true
		}
		if rule.wildcard {
			r.anyWildcard = true
		} else {
			for t := range rule.types {
				r.allowedTypes[t] = true
				if rule.needsJSON {
					r.jsonTypes[t] = true
				}
			}
		}
		if rule.scopeRoot {
			r.rootRules = append(r.rootRules, rule)
			if rule.wildcard {
				r.wildcardRoot = append(r.wildcardRoot, rule)
			} else {
				for t := range rule.types {
					r.byTypeRoot[t] = append(r.byTypeRoot[t], rule)
				}
			}
		} else {
			r.resourceRules = append(r.resourceRules, rule)
			if rule.wildcard {
				r.wildcardRes = append(r.wildcardRes, rule)
			} else {
				for t := range rule.types {
					r.byTypeResource[t] = append(r.byTypeResource[t], rule)
				}
			}
		}
	}
	if r.anyWildcard {
		r.allowedTypes = nil
		r.jsonTypes = nil
	} else if relationJSONRule {
		// Rules that follow relations and inspect JSON (e.g. bucket -> bucket_policy)
		// need JSON derivation on traversed target/related resources too.
		r.jsonTypes = nil
	}

	for _, f := range files {
		if f == nil || f.ModuleCallChain != "" {
			continue
		}
		if f.LinesOriginalData == nil {
			f.SetLazyLines()
		}
		key := contractPathKey(f.FilePath, c.repoPath, c.fsys)
		if _, exists := r.filesByPath[key]; !exists {
			r.filesByPath[key] = f
		}
		if f.Kind == model.KindTerraformPlan {
			r.planFiles = append(r.planFiles, f)
		}
	}

	r.baseRootOpts = tfcontract.RootOptions{
		FS:               c.fsys,
		RepoPath:         c.repoPath,
		MergeAllow:       c.mergeAllow,
		ComputeRelations: true,
		NeedStaticBlocks: r.needStaticBlocks,
		NeedProviders:    r.needProviders,
		Derive: tfcontract.DeriveOptions{
			ParseJSON:      r.needJSON,
			JSONTypes:      r.jsonTypes,
			ParseFilterAST: r.needFilterAST,
		},
	}
	return r, nil
}

// rootMatchesRules checks in O(len(resources)) whether dir's evaluated
// resources contain any type targeted by a loaded Contract v2 rule, allowing
// non-matching roots to skip BuildUnitFromEval entirely.
func (r *contractV2Runner) rootMatchesRules(resources []tfeval.ResolvedResource) bool {
	if r.anyWildcard || r.hasNoResources || r.needStaticBlocks || r.needProviders || r.allowedTypes == nil {
		return true
	}
	for i := range resources {
		key := resources[i].Type
		if resources[i].Data {
			key = address.DataPrefix + key
		}
		if r.allowedTypes[key] {
			return true
		}
	}
	return false
}

// onRoot consumes one evaluated Terraform root (called in deterministic root
// order by either the coexistence tfeval driver or runStandalone).
func (r *contractV2Runner) onRoot(
	ctx context.Context,
	dir string,
	resources []tfeval.ResolvedResource,
	instances []tfeval.ModuleInstance,
	rootScope *tfeval.ModuleScope,
	scopeIncomplete bool,
	attrCache *moduleAttributionCache,
	occurrences map[string]*model.ResourceOccurrence,
) error {
	if scopeIncomplete {
		r.recordRootIncomplete(ctx, dir)
	}
	if r.firstEvalErr != nil {
		r.countRootFailure()
		return r.firstEvalErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if r.c.isExternalModulePath(dir) {
		return nil
	}
	r.evaluatedRootCnt++
	if !r.rootMatchesRules(resources) {
		return nil
	}
	unit, err := r.buildRootUnit(ctx, dir, resources, instances, rootScope, scopeIncomplete, attrCache)
	if err != nil {
		// The scan was canceled while the unit was built: drop the partial unit
		// rather than evaluate relations that were never finished.
		return err
	}
	r.indexResourceOccurrences(unit, occurrences)
	if err := r.processUnit(ctx, unit); err != nil {
		r.countRootFailure()
		r.firstEvalErr = err
		return err
	}
	return nil
}

func (r *contractV2Runner) rootDemandForResources(
	_ []tfeval.ResolvedResource,
) (computeRel, includeProv, includeStatic bool) {
	return true, r.needProviders, r.needStaticBlocks
}

func (r *contractV2Runner) buildRootUnit(
	ctx context.Context,
	dir string,
	resources []tfeval.ResolvedResource,
	instances []tfeval.ModuleInstance,
	rootScope *tfeval.ModuleScope,
	scopeIncomplete bool,
	attrCache *moduleAttributionCache,
) (*policy.Unit, error) {
	if attrCache == nil {
		attrCache = newModuleAttributionCache()
	}
	opts := r.baseRootOpts
	opts.ComputeRelations, opts.NeedProviders, opts.NeedStaticBlocks = r.rootDemandForResources(resources)
	opts.RootScope = rootScope
	opts.ModuleInstances = instances
	opts.ScopeIncomplete = scopeIncomplete
	opts.AttributionFunc = func(res *tfeval.ResolvedResource) *model.ModuleAttribution {
		return attrCache.attribution(res, r.c.repoPath, r.lookup)
	}
	opts.CallChainFunc = func(res *tfeval.ResolvedResource) string {
		return callChainKey(res, r.c.repoPath)
	}
	return tfcontract.BuildUnitFromEvalContext(ctx, dir, resources, &opts)
}

func (r *contractV2Runner) evalStandaloneRootInWorker(
	ctx context.Context,
	dir string,
	res *rootResult,
	occurrences map[string]*model.ResourceOccurrence,
) (*policy.Unit, ast.Object, error) {
	unit, err := r.buildRootUnit(ctx, dir, res.resources, res.instances, res.rootScope, res.scopeIncomplete, newModuleAttributionCache())
	if err != nil {
		return nil, nil, err
	}
	r.indexResourceOccurrences(unit, occurrences)
	if unit == nil || (len(unit.Resources) == 0 && !r.hasNoResources) {
		return nil, nil, nil
	}
	var projectedResources ast.Object
	if len(r.rootRules) > 0 {
		activeRoot := selectMatchingRules([]*policy.Unit{unit}, r.byTypeRoot, r.wildcardRoot)
		if len(activeRoot) > 0 {
			includeByID := r.needRelations || r.needProviders
			inputVal, cachedResources := policy.ProjectUnitsWithResourceCache(
				contractV2PlatformTerraform, []*policy.Unit{unit},
				contractV2ResourceProjectOptions(r.allowedTypes, includeByID),
			)
			projectedResources = cachedResources
			if err := r.evalRuleBatchModeWithInput(ctx, []*policy.Unit{unit}, activeRoot, inputVal, false); err != nil {
				return nil, nil, err
			}
		}
	}
	if len(r.resourceRules) == 0 || len(unit.Resources) == 0 {
		return nil, nil, nil
	}
	if len(selectMatchingRules([]*policy.Unit{unit}, r.byTypeResource, r.wildcardRes)) == 0 {
		return nil, nil, nil
	}
	return unit, projectedResources, nil
}

// runStandalone evaluates all Terraform source roots in parallel (4-worker
// concurrent tfeval pool with ordered commit) when no legacy Terraform rules
// are loaded.
// nolint:gocyclo
func (r *contractV2Runner) runStandalone(ctx context.Context, feedInventory bool) ([]model.Vulnerability, error) {
	// Close the scan-scoped HCL parse cache before tfeval begins so ASTs do not
	// stack with tfeval's own per-root directory cache.
	if cache := hclcache.FromContext(ctx); cache != nil {
		cache.Close()
	}

	evaluator := tfeval.NewWithFS(r.c.fsys)
	evaluator.SetExplicitRootVars(r.c.terraformRootVars)
	evaluator.SetTrackModuleInstances(true)
	evaluator.SetTrackModuleScopes(true)
	if len(r.c.mergeAllow) > 0 {
		evaluator.SetMergeAllow(r.c.mergeAllow)
	}
	resolver := r.c.buildRemoteResolver()
	if resolver != nil {
		evaluator.SetRemoteResolver(resolver)
	}
	defer evaluator.ReleaseCaches()

	roots := r.discoverRoots(ctx, evaluator, resolver)
	var inv *terraformInventory
	if feedInventory && r.c.inventory != nil {
		inv = r.c.newTerraformInventory(r.lookup, r.c.isExternalModulePath, nil)
		inv.files = r.filesByPath
	}

	if err := r.evaluateRootsConcurrently(ctx, evaluator, roots, inv); err != nil {
		return nil, err
	}
	if err := r.evalPlans(ctx); err != nil {
		return nil, err
	}
	return r.finish(ctx)
}

// evaluateRootsConcurrently runs a bounded 4-worker tfeval pool and commits
// each root in deterministic sorted order, immediately releasing root ASTs.
// nolint:gocyclo
func (r *contractV2Runner) evaluateRootsConcurrently(
	ctx context.Context,
	evaluator *tfeval.Evaluator,
	roots []string,
	inv *terraformInventory,
) error {
	if len(roots) == 0 {
		return nil
	}
	workers := min(max(r.c.numWorkers, 1), contractV2MaxRootWorkers, len(roots))
	if workers <= 1 {
		for _, dir := range roots {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			res := evaluateRoot(ctx, evaluator, dir)
			if res.panicked != nil || res.err != nil {
				r.recordRootResult(ctx, dir, &res)
				evaluator.ForgetRootParse(dir)
				if res.panicked != nil && inv != nil {
					inv.fail("terraform_panic")
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			rootOccurrences := inv.addRoot(dir, res.resources, false, nil)
			attrCache := newModuleAttributionCache()
			err := r.onRoot(ctx, dir, res.resources, res.instances, res.rootScope, res.scopeIncomplete, attrCache, rootOccurrences.byAddress)
			evaluator.ForgetRootParse(dir)
			if err != nil {
				contextLogger := logger.FromContext(ctx)
				contextLogger.Warn().Err(err).Str("root", dir).Msg("contract v2: failed to evaluate Terraform root")
				return err
			}
		}
		return ctx.Err()
	}

	type standaloneRootOutcome struct {
		res                rootResult
		unit               *policy.Unit
		projectedResources ast.Object
		err                error
	}

	results := make([]chan standaloneRootOutcome, len(roots))
	for i := range results {
		results[i] = make(chan standaloneRootOutcome, 1)
	}
	windowSize := workers * contractV2RootWindowFactor
	if inv != nil {
		// Keep in-flight resource slices tightly bounded when inventory retains them.
		windowSize = workers
	}
	window := make(chan struct{}, windowSize)
	stop := make(chan struct{})
	var (
		mu       sync.Mutex
		nextRoot int
		wg       sync.WaitGroup
	)
	for range workers {
		worker := evaluator.Fork()
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
				dir := roots[i]
				res := evaluateRoot(ctx, worker, dir)
				var chunkUnit *policy.Unit
				var projectedResources ast.Object
				var evalErr error
				if res.panicked == nil && res.err == nil {
					rootOccurrences := inv.addRoot(dir, res.resources, false, nil)
					if !r.c.isExternalModulePath(dir) && r.rootMatchesRules(res.resources) {
						chunkUnit, projectedResources, evalErr = r.evalStandaloneRootInWorker(ctx, dir, &res, rootOccurrences.byAddress)
					}
				}
				worker.ForgetRootParse(dir)
				if inv == nil {
					res.resources = nil
				}
				res.instances = nil
				res.rootScope = nil
				results[i] <- standaloneRootOutcome{res: res, unit: chunkUnit, projectedResources: projectedResources, err: evalErr}
			}
		})
	}
	defer func() {
		close(stop)
		wg.Wait()
	}()

	for i, dir := range roots {
		var out standaloneRootOutcome
		select {
		case out = <-results[i]:
		case <-ctx.Done():
			return ctx.Err()
		}
		<-window
		r.recordRootResult(ctx, dir, &out.res)
		if out.res.panicked != nil || out.res.err != nil {
			evaluator.ForgetRootParse(dir)
			if out.res.panicked != nil && inv != nil {
				inv.fail("terraform_panic")
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		if !r.c.isExternalModulePath(dir) {
			r.evaluatedRootCnt++
		}
		if out.err != nil && ctx.Err() != nil && isContextError(out.err) {
			// A canceled scan is not a failed root (same as onRoot).
			return ctx.Err()
		}
		if out.err != nil {
			r.countRootFailure()
			contextLogger := logger.FromContext(ctx)
			contextLogger.Warn().Err(out.err).Str("root", dir).Msg("contract v2: failed to evaluate Terraform root")
			r.firstEvalErr = out.err
			return out.err
		}
		if out.unit != nil {
			r.chunk = append(r.chunk, out.unit)
			if out.projectedResources != nil {
				if r.chunkProjectedResources == nil {
					r.chunkProjectedResources = make(map[*policy.Unit]ast.Object)
				}
				r.chunkProjectedResources[out.unit] = out.projectedResources
			}
			r.chunkResCount += len(out.unit.Resources)
			if r.chunkResCount >= contractV2ChunkMaxResources {
				if err := r.flushChunk(ctx); err != nil {
					r.firstEvalErr = err
					return err
				}
			}
		}
	}
	return ctx.Err()
}

// discoverRoots uses the same static module-call graph and root selection as
// legacy Terraform evaluation, so adding or removing legacy rules cannot change
// the roots seen by Contract v2.
func (r *contractV2Runner) discoverRoots(
	ctx context.Context,
	evaluator *tfeval.Evaluator,
	resolver tfeval.RemoteResolver,
) []string {
	_, filesByDir, dirsWithTf := indexTerraformFiles(ctx, r.files, r.c.repoPath)
	if len(dirsWithTf) == 0 {
		return nil
	}

	// Retain the old parallel discovery's cheap byte prefilter, but never use
	// its literal path joins to decide roots. Candidate directories are passed
	// to the shared parser/evaluator, which handles merged roots, placeholders,
	// absolute paths, and fetched modules consistently with legacy evaluation.
	candidateDirs := make(map[string]bool)
	candidateFiles := make(map[string][]*model.FileMetadata)
	for dir, files := range filesByDir {
		for _, file := range files {
			if file == nil || file.OriginalData == "" || mayContainModuleCall(file) {
				candidateDirs[dir] = true
				candidateFiles[dir] = files
				break
			}
		}
	}
	called, _ := discoverStaticCalls(ctx, evaluator, candidateFiles, candidateDirs, r.c.repoPath, resolver, false)
	external := externalModuleFiles(r.c.repoPath, r.c.isExternalModulePath)
	return terraformRootDirs(dirsWithTf, called, external)
}

func mayContainModuleCall(file *model.FileMetadata) bool {
	if tfpath.IsJSONConfig(file.FilePath) {
		return strings.Contains(file.OriginalData, `"module"`)
	}
	return mayDeclareModuleBlockString(file.OriginalData)
}

// mayDeclareModuleBlockString reports whether HCL source text may contain a
// `module "<name>" {` block header, filtering out comments, tags, and
// identifiers like `module_name` without false negatives on valid HCL2.
func mayDeclareModuleBlockString(src string) bool {
	const kw = "module"
	for i := 0; i < len(src); {
		idx := strings.Index(src[i:], kw)
		if idx < 0 {
			return false
		}
		pos := i + idx
		i = pos + len(kw)
		// Must start at a word boundary (not part of `my_module` or `var.module`).
		if pos > 0 && isHCLIdentOrDot(src[pos-1]) {
			continue
		}
		// Skip optional horizontal whitespace and /* */ comments after
		// `module`; it must be followed by `"` or an ident char. An
		// unterminated comment is kept as a candidate for the parser.
		j, ok := skipHCLBlankAndBlockComments(src, i)
		if !ok {
			return true
		}
		if j >= len(src) || (j == i && src[j] != '"') {
			continue
		}
		next := src[j]
		if next != '"' && !isHCLIdentStart(next) {
			continue
		}
		// Reject lines that are pure `#` or `//` comments before `pos`.
		lineStart := strings.LastIndexByte(src[:pos], '\n') + 1
		prefix := strings.TrimLeft(src[lineStart:pos], " \t")
		if strings.HasPrefix(prefix, "#") || strings.HasPrefix(prefix, "//") {
			continue
		}
		return true
	}
	return false
}

// skipHCLBlankAndBlockComments returns the offset of the first byte at or
// after i that is neither a space, a tab, nor part of a /* */ comment. It
// returns false when a comment is not terminated.
func skipHCLBlankAndBlockComments(src string, i int) (int, bool) {
	for i < len(src) {
		switch {
		case src[i] == ' ' || src[i] == '\t':
			i++
		case strings.HasPrefix(src[i:], "/*"):
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return len(src), false
			}
			i += 2 + end + 2
		default:
			return i, true
		}
	}
	return i, true
}

func isHCLIdentStart(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_'
}

func isHCLIdentOrDot(b byte) bool {
	return isHCLIdentStart(b) || (b >= '0' && b <= '9') || b == '-' || b == '.'
}

func (r *contractV2Runner) evalPlans(ctx context.Context) error {
	for _, pf := range r.planFiles {
		if err := ctx.Err(); err != nil {
			return err
		}
		planPath := contractPathKey(pf.FilePath, r.c.repoPath, r.c.fsys)
		planBytes, err := r.c.fsys.ReadFile(planPath)
		if err != nil {
			r.recordPlanFailure(ctx, pf.FilePath, err)
			continue
		}
		unit, err := tfcontract.BuildUnitFromPlan(pf.FilePath, planBytes, &r.baseRootOpts)
		if err != nil {
			r.recordPlanFailure(ctx, pf.FilePath, err)
			continue
		}
		r.evaluatedPlanCnt++
		if err := r.processUnit(ctx, unit); err != nil {
			return err
		}
	}
	return nil
}

func (r *contractV2Runner) processUnit(ctx context.Context, unit *policy.Unit) error {
	if unit == nil || (len(unit.Resources) == 0 && !r.hasNoResources) {
		return nil
	}
	var projectedResources ast.Object
	if len(r.rootRules) > 0 {
		activeRoot := selectMatchingRules([]*policy.Unit{unit}, r.byTypeRoot, r.wildcardRoot)
		if len(activeRoot) > 0 {
			includeByID := r.needRelations || r.needProviders
			inputVal, cachedResources := policy.ProjectUnitsWithResourceCache(
				contractV2PlatformTerraform, []*policy.Unit{unit},
				contractV2ResourceProjectOptions(r.allowedTypes, includeByID),
			)
			projectedResources = cachedResources
			if err := r.evalRuleBatchModeWithInput(ctx, []*policy.Unit{unit}, activeRoot, inputVal, true); err != nil {
				return err
			}
		}
	}
	if len(r.resourceRules) > 0 && len(unit.Resources) > 0 {
		r.chunk = append(r.chunk, unit)
		if projectedResources != nil {
			if r.chunkProjectedResources == nil {
				r.chunkProjectedResources = make(map[*policy.Unit]ast.Object)
			}
			r.chunkProjectedResources[unit] = projectedResources
		}
		r.chunkResCount += len(unit.Resources)
		if r.chunkResCount >= contractV2ChunkMaxResources {
			return r.flushChunk(ctx)
		}
	}
	return nil
}

func (r *contractV2Runner) flushChunk(ctx context.Context) error {
	if len(r.chunk) == 0 {
		return nil
	}
	active := selectMatchingRules(r.chunk, r.byTypeResource, r.wildcardRes)
	var err error
	if len(active) > 0 {
		inputVal := projectContractV2Chunk(r.chunk, r.chunkProjectedResources, r.allowedTypes)
		err = r.evalRuleBatchModeWithInput(ctx, r.chunk, active, inputVal, true)
	}
	r.chunk = nil
	r.chunkProjectedResources = nil
	r.chunkResCount = 0
	return err
}

func contractV2ResourcesFromInput(input ast.Value) ast.Object {
	root, ok := input.(ast.Object)
	if !ok {
		return nil
	}
	resources := root.Get(ast.StringTerm("resources"))
	if resources == nil {
		return nil
	}
	object, _ := resources.Value.(ast.Object)
	return object
}

// contractV2ResourceProjectOptions configures resource projection for v2 rules.
func contractV2ResourceProjectOptions(allowedTypes map[string]bool, includeByID bool) policy.ProjectOptions {
	return policy.ProjectOptions{
		IncludeRelations: true,
		IncludeByID:      includeByID,
		AllowedTypes:     allowedTypes,
	}
}

// projectContractV2Chunk reuses resource terms from the root-scope projection
// when the same Unit later enters the resource-scoped chunk. The terms are
// immutable OPA values; the cache is local to the pending chunk and is cleared
// by flushChunk.
func projectContractV2Chunk(
	units []*policy.Unit,
	cached map[*policy.Unit]ast.Object,
	allowedTypes map[string]bool,
) ast.Value {
	if len(cached) == 0 {
		return policy.ProjectUnits(contractV2PlatformTerraform, units, contractV2ResourceProjectOptions(allowedTypes, false))
	}
	byType := make(map[string][]*ast.Term)
	scopeComplete := appendContractV2ChunkTerms(units, cached, allowedTypes, byType)
	buckets := make([]string, 0, len(byType))
	for bucket := range byType {
		buckets = append(buckets, bucket)
	}
	sort.Strings(buckets)
	resourcePairs := make([][2]*ast.Term, 0, len(buckets))
	for _, bucket := range buckets {
		resourcePairs = append(resourcePairs, [2]*ast.Term{
			ast.StringTerm(bucket), ast.NewTerm(ast.NewArray(byType[bucket]...)),
		})
	}
	return ast.NewObject([][2]*ast.Term{
		{ast.StringTerm("contract_version"), ast.StringTerm(policy.ContractVersionV2)},
		{ast.StringTerm("platform"), ast.StringTerm(contractV2PlatformTerraform)},
		{ast.StringTerm("scope_complete"), ast.BooleanTerm(scopeComplete)},
		{ast.StringTerm("resources"), ast.ObjectTerm(resourcePairs...)},
	}...)
}

func appendContractV2ChunkTerms(
	units []*policy.Unit,
	cached map[*policy.Unit]ast.Object,
	allowedTypes map[string]bool,
	byType map[string][]*ast.Term,
) bool {
	scopeComplete := true
	for i := 0; i < len(units); {
		unit := units[i]
		if unit == nil {
			i++
			continue
		}
		if !unit.ScopeComplete {
			scopeComplete = false
		}
		if resources, ok := cached[unit]; ok {
			appendContractV2Resources(byType, resources)
			i++
			continue
		}
		start := i
		for i < len(units) && units[i] != nil {
			if _, ok := cached[units[i]]; ok {
				break
			}
			if !units[i].ScopeComplete {
				scopeComplete = false
			}
			i++
		}
		projected := policy.ProjectUnits(contractV2PlatformTerraform, units[start:i], contractV2ResourceProjectOptions(allowedTypes, false))
		appendContractV2Resources(byType, contractV2ResourcesFromInput(projected))
	}
	return scopeComplete
}

func appendContractV2Resources(byType map[string][]*ast.Term, resources ast.Object) {
	if resources == nil {
		return
	}
	_ = resources.Iter(func(key, value *ast.Term) error {
		bucket, ok := key.Value.(ast.String)
		if !ok {
			return nil
		}
		array, ok := value.Value.(*ast.Array)
		if !ok {
			return nil
		}
		name := string(bucket)
		for i := range array.Len() {
			byType[name] = append(byType[name], array.Elem(i))
		}
		return nil
	})
}

// nolint:gocyclo
func (r *contractV2Runner) evalRuleBatchModeWithInput(
	ctx context.Context,
	units []*policy.Unit,
	candidateRules []*contractV2Rule,
	inputVal ast.Value,
	parallel bool,
) error {
	if len(units) == 0 || len(candidateRules) == 0 {
		return nil
	}
	resByID := make(map[string]*policy.Resource)
	for _, u := range units {
		for _, res := range u.Resources {
			resByID[res.ID] = res
		}
	}
	var tasks []contractV2EvalTask
	if parallel {
		tasks = r.contractV2EvalTasks(ctx, candidateRules)
	} else {
		tasks = r.contractV2EvalTasksWithWorkers(ctx, candidateRules, 1)
	}
	if !parallel || len(tasks) <= 1 {
		for _, task := range tasks {
			var err error
			if task.prepared != nil {
				err = r.evalContractV2Batch(ctx, task, inputVal, resByID)
			} else {
				err = r.evalContractV2RuleSafely(ctx, task.rules[0], inputVal, resByID)
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
	return utils.ForEach(ctx, tasks, utils.PoolOptions{Workers: r.c.numWorkers, CPUBound: true},
		func(ctx context.Context, task contractV2EvalTask, _ int) error {
			if task.prepared != nil {
				return r.evalContractV2Batch(ctx, task, inputVal, resByID)
			}
			return r.evalContractV2RuleSafely(ctx, task.rules[0], inputVal, resByID)
		})
}

func (r *contractV2Runner) contractV2EvalTasks(ctx context.Context, candidateRules []*contractV2Rule) []contractV2EvalTask {
	return r.contractV2EvalTasksWithWorkers(ctx, candidateRules, max(r.c.numWorkers, 1))
}

func (r *contractV2Runner) contractV2EvalTasksWithWorkers(
	ctx context.Context, candidateRules []*contractV2Rule, workers int,
) []contractV2EvalTask {
	grouped := make(map[*ast.Compiler][]*contractV2Rule)
	var groupOrder []*ast.Compiler
	var singles []*contractV2Rule
	for _, rule := range candidateRules {
		if !r.contractV2RuleCanBatch(ctx, rule) {
			singles = append(singles, rule)
			continue
		}
		compiler := rule.sharedCompiler
		if _, exists := grouped[compiler]; !exists {
			groupOrder = append(groupOrder, compiler)
		}
		grouped[compiler] = append(grouped[compiler], rule)
	}

	tasks := make([]contractV2EvalTask, 0, len(candidateRules))
	workers = max(workers, 1)
	for _, compiler := range groupOrder {
		rules := grouped[compiler]
		batchSize := min(max((len(rules)+workers-1)/workers, 2), contractV2MaxBatchQueries)
		for start := 0; start < len(rules); start += batchSize {
			chunk := rules[start:min(start+batchSize, len(rules))]
			if len(chunk) < 2 {
				singles = append(singles, chunk...)
				continue
			}
			prepared, err := r.prepareContractV2Batch(ctx, chunk)
			if err != nil {
				singles = append(singles, chunk...)
				continue
			}
			tasks = append(tasks, contractV2EvalTask{rules: chunk, prepared: prepared})
		}
	}
	for _, rule := range singles {
		tasks = append(tasks, contractV2EvalTask{rules: []*contractV2Rule{rule}})
	}
	return tasks
}

func (r *contractV2Runner) contractV2RuleCanBatch(ctx context.Context, rule *contractV2Rule) bool {
	return rule != nil && r.c.coverageTracer == nil && rule.partialSetResults &&
		rule.sharedCompiler != nil && rule.sharedStore != nil && rule.sharedPackage != "" &&
		!r.c.hasRuleArguments(ctx, &rule.meta)
}

func (r *contractV2Runner) prepareContractV2Batch(
	ctx context.Context,
	rules []*contractV2Rule,
) (*rego.PreparedEvalQuery, error) {
	if len(rules) < 2 {
		return nil, fmt.Errorf("contract v2 batch requires at least two rules")
	}
	compiler := rules[0].sharedCompiler
	store := rules[0].sharedStore
	packages := make([]string, len(rules))
	var query strings.Builder
	for i, rule := range rules {
		if rule.sharedCompiler != compiler || !sameContractV2Store(rule.sharedStore, store) || rule.sharedPackage == "" {
			return nil, fmt.Errorf("contract v2 batch contains rules from different compiled cohorts")
		}
		packages[i] = rule.sharedPackage
		if i > 0 {
			query.WriteString("; ")
		}
		query.WriteByte('r')
		query.WriteString(strconv.Itoa(i))
		query.WriteString(" = ")
		query.WriteString(rule.sharedPackage)
		query.WriteString(".results")
	}
	key := contractV2BatchCacheKey{compiler: compiler, packages: strings.Join(packages, "\x00")}

	r.batchCacheMu.Lock()
	defer r.batchCacheMu.Unlock()
	if r.batchCache == nil {
		r.batchCache = make(map[contractV2BatchCacheKey]*list.Element)
	}
	if element, ok := r.batchCache[key]; ok {
		r.batchCacheLRU.MoveToFront(element)
		return element.Value.(*contractV2BatchCacheEntry).prepared, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prepared, err := rego.New(
		rego.Query(query.String()),
		rego.SetRegoVersion(ast.RegoV1),
		rego.Compiler(compiler),
		rego.Store(store),
		rego.UnsafeBuiltins(unsafeRegoFunctions),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	entry := &contractV2BatchCacheEntry{key: key, prepared: &prepared}
	element := r.batchCacheLRU.PushFront(entry)
	r.batchCache[key] = element
	for r.batchCacheLRU.Len() > contractV2BatchCacheEntryLimit {
		oldest := r.batchCacheLRU.Back()
		oldEntry := oldest.Value.(*contractV2BatchCacheEntry)
		delete(r.batchCache, oldEntry.key)
		r.batchCacheLRU.Remove(oldest)
	}
	return entry.prepared, nil
}

func (r *contractV2Runner) evalContractV2Batch(
	ctx context.Context,
	task contractV2EvalTask,
	payload ast.Value,
	resByID map[string]*policy.Resource,
) error {
	start := time.Now()
	results, err := evalContractV2BatchSafely(ctx, task.prepared, payload)
	duration := time.Since(start)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if topdown.IsCancel(err) {
			return err
		}
		// Replay independently so one failing rule cannot suppress its siblings.
		for _, rule := range task.rules {
			if err := r.evalContractV2RuleSafely(ctx, rule, payload, resByID); err != nil {
				return err
			}
		}
		return nil
	}
	items, ok := contractV2BatchResultItems(results, len(task.rules))
	if !ok {
		// Partial-set rules should always bind their result, including an empty
		// set. Fall back if the combined query does not preserve that invariant.
		for _, rule := range task.rules {
			if err := r.evalContractV2RuleSafely(ctx, rule, payload, resByID); err != nil {
				return err
			}
		}
		return nil
	}
	perRuleDuration := duration / time.Duration(len(task.rules))
	for i, rule := range task.rules {
		r.decodeContractV2RuleItemsSafely(ctx, rule, items[i], resByID, perRuleDuration)
	}
	return nil
}

func evalContractV2BatchSafely(
	ctx context.Context,
	prepared *rego.PreparedEvalQuery,
	payload ast.Value,
) (results rego.ResultSet, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic during contract v2 batch eval: %v\n%s", recovered, string(debug.Stack()))
		}
	}()
	return prepared.Eval(ctx,
		rego.EvalParsedInput(payload),
		rego.EvalVirtualCache(newIdentityVirtualCache()),
	)
}

func contractV2BatchResultItems(results rego.ResultSet, count int) ([][]interface{}, bool) {
	if len(results) != 1 {
		return nil, false
	}
	items := make([][]interface{}, count)
	for i := range count {
		raw, ok := results[0].Bindings["r"+strconv.Itoa(i)]
		if !ok {
			return nil, false
		}
		set, ok := raw.([]interface{})
		if !ok {
			return nil, false
		}
		items[i] = set
	}
	return items, true
}

func (r *contractV2Runner) evalContractV2RuleSafely(
	ctx context.Context,
	rule *contractV2Rule,
	payload ast.Value,
	resByID map[string]*policy.Resource,
) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = nil
			r.recordContractV2QueryError(rule,
				fmt.Errorf("panic during query '%s' run: %v\n%s", rule.meta.Query, recovered, string(debug.Stack())))
			if ctx.Err() != nil {
				err = ctx.Err()
			}
		}
	}()
	return r.evalContractV2Rule(ctx, rule, payload, resByID)
}

func (r *contractV2Runner) evalContractV2Rule(
	ctx context.Context,
	rule *contractV2Rule,
	payload ast.Value,
	resByID map[string]*policy.Resource,
) error {
	queryID, legacyQueryID, legacyQueryIDs := queryIDsFromMetadata(ctx, &rule.meta)
	if rc, found := lookupRuleConfig(r.c.ruleConfigs, queryID, legacyQueryID, legacyQueryIDs); found {
		if av, ok, err := ruleArgumentsValue(rc); err != nil {
			r.recordContractV2QueryError(rule, err)
			return nil
		} else if ok {
			payload, err = withRuleArguments(payload, av)
			if err != nil {
				r.recordContractV2QueryError(rule, err)
				return nil
			}
		}
	}
	options := []rego.EvalOption{rego.EvalParsedInput(payload), rego.EvalVirtualCache(newIdentityVirtualCache())}
	if r.c.coverageTracer != nil {
		options = append(options, rego.EvalQueryTracer(r.c.coverageTracer))
	}
	start := time.Now()
	rs, err := rule.prepared.Eval(ctx, options...)
	duration := time.Since(start)
	decodeStart := time.Now()
	defer func() {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Debug().
			Str("event", "query_complete").
			Str("queryID", rule.meta.Query).
			Int64("evalNs", duration.Nanoseconds()).
			Int64("decodeNs", time.Since(decodeStart).Nanoseconds()).
			Msg("query completed")
	}()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r.recordContractV2QueryError(rule, err)
		return nil
	}
	items, err := resultItems(rs)
	if err != nil {
		r.recordContractV2QueryError(rule, err)
		return nil
	}
	r.decodeContractV2RuleItems(ctx, rule, items, resByID, duration, false)
	return nil
}

func (r *contractV2Runner) decodeContractV2RuleItems(
	ctx context.Context,
	rule *contractV2Rule,
	items []interface{},
	resByID map[string]*policy.Resource,
	queryDuration time.Duration,
	logTiming bool,
) {
	if logTiming {
		decodeStart := time.Now()
		defer func() {
			contextLogger := logger.FromContext(ctx)
			contextLogger.Debug().
				Str("event", "query_complete").
				Str("queryID", rule.meta.Query).
				Int64("evalNs", queryDuration.Nanoseconds()).
				Int64("decodeNs", time.Since(decodeStart).Nanoseconds()).
				Msg("query completed")
		}()
	}
	if len(items) == 0 {
		return
	}
	var decoded []*model.Vulnerability
	var planLinesByPath contractV2PlanLineCache
	for _, item := range items {
		rawMap, ok := item.(map[string]any)
		if !ok {
			r.recordContractV2QueryError(rule, fmt.Errorf("finding result has type %T, want object", item))
			return
		}
		f, err := policy.DecodeFinding(rawMap)
		if err != nil {
			r.recordContractV2QueryError(rule, err)
			if errors.Is(err, policy.ErrInvalidPath) {
				continue
			}
			return
		}
		res := resByID[f.ResourceID]
		if res == nil {
			r.recordContractV2QueryError(rule, fmt.Errorf("finding references unknown resource ID %q", f.ResourceID))
			return
		}
		rawPlanLines := r.rawPlanLinesForFinding(res, &planLinesByPath)
		v := r.c.decodeContractV2Vulnerability(ctx, r.scanID, rule, res, &f, r.filesByPath, r.callers, rawPlanLines, queryDuration)
		if v != nil {
			if occurrence := r.resourceOccurrence(res.ID); occurrence != nil {
				v.ResourceOccurrences = []*model.ResourceOccurrence{occurrence}
			}
			decoded = append(decoded, v)
		}
	}
	if len(decoded) == 0 {
		return
	}
	r.findingsMu.Lock()
	defer r.findingsMu.Unlock()
	for _, v := range decoded {
		r.findings.addRouted(ctx, r.c, v)
	}
}

func (r *contractV2Runner) rawPlanLinesForFinding(res *policy.Resource, cache *contractV2PlanLineCache) []string {
	if res == nil || res.File == "" {
		return nil
	}
	file := lookupFileByPath(r.filesByPath, res.File, r.c.repoPath, r.c.fsys)
	if file == nil || file.Kind != model.KindTerraformPlan {
		return nil
	}
	planPath := contractPathKey(res.File, r.c.repoPath, r.c.fsys)
	if cache.byPath == nil {
		cache.byPath = make(map[string][]string)
	}
	if lines, ok := cache.byPath[planPath]; ok {
		return lines
	}
	var lines []string
	if planBytes, err := r.c.fsys.ReadFile(planPath); err == nil {
		lines = *utils.SplitLines(string(planBytes))
	}
	cache.byPath[planPath] = lines
	return lines
}

func (r *contractV2Runner) decodeContractV2RuleItemsSafely(
	ctx context.Context,
	rule *contractV2Rule,
	items []interface{},
	resByID map[string]*policy.Resource,
	queryDuration time.Duration,
) {
	defer func() {
		if recovered := recover(); recovered != nil {
			r.recordContractV2QueryError(rule,
				fmt.Errorf("panic decoding query '%s' results: %v\n%s", rule.meta.Query, recovered, string(debug.Stack())))
		}
	}()
	r.decodeContractV2RuleItems(ctx, rule, items, resByID, queryDuration, true)
}

func (r *contractV2Runner) indexResourceOccurrences(
	unit *policy.Unit,
	occurrences map[string]*model.ResourceOccurrence,
) {
	if unit == nil || len(occurrences) == 0 {
		return
	}
	r.occurrencesMu.Lock()
	defer r.occurrencesMu.Unlock()
	if r.occurrencesByResourceID == nil {
		r.occurrencesByResourceID = make(map[string]*model.ResourceOccurrence, len(unit.Resources))
	}
	for _, resource := range unit.Resources {
		if occurrence := occurrences[resource.Address]; occurrence != nil {
			r.occurrencesByResourceID[resource.ID] = occurrence
		}
	}
}

func (r *contractV2Runner) resourceOccurrence(resourceID string) *model.ResourceOccurrence {
	r.occurrencesMu.RLock()
	defer r.occurrencesMu.RUnlock()
	return r.occurrencesByResourceID[resourceID]
}

func (r *contractV2Runner) recordContractV2QueryError(rule *contractV2Rule, err error) {
	if rule == nil || err == nil {
		return
	}
	r.c.recordQueryFailure(&rule.meta, err, QueryFailureEvaluate)
}

func (r *contractV2Runner) finish(ctx context.Context) ([]model.Vulnerability, error) {
	if r.firstEvalErr != nil {
		return nil, r.firstEvalErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := r.flushChunk(ctx); err != nil {
		return nil, err
	}
	for _, rule := range r.rules {
		r.c.tracker.TrackQueryExecution(rule.meta.Aggregation)
	}
	vulns := r.findings.findings()
	contextLogger := logger.FromContext(ctx)
	contextLogger.Info().Msgf("Evaluated %d Contract v2 Terraform rules across %d roots and %d plans",
		len(r.rules), r.evaluatedRootCnt, r.evaluatedPlanCnt)
	return vulns, nil
}

func selectMatchingRules(
	units []*policy.Unit,
	byType map[string][]*contractV2Rule,
	wildcards []*contractV2Rule,
) []*contractV2Rule {
	seen := make(map[*contractV2Rule]bool)
	var out []*contractV2Rule
	for _, r := range wildcards {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for _, u := range units {
		for _, res := range u.Resources {
			for _, r := range byType[res.BucketKey()] {
				if !seen[r] {
					seen[r] = true
					out = append(out, r)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].meta.Query < out[j].meta.Query })
	return out
}

// nolint:gocyclo
func (c *Inspector) decodeContractV2Vulnerability(
	ctx context.Context,
	scanID string,
	rule *contractV2Rule,
	res *policy.Resource,
	f *policy.Finding,
	filesByPath map[string]*model.FileMetadata,
	callers map[string]*model.FileMetadata,
	rawPlanLines []string,
	queryDuration time.Duration,
) *model.Vulnerability {
	span := res.Source.Range(f.Path)
	filePath := span.File
	if filePath == "" {
		filePath = res.File
	}
	file := lookupFileByPath(filesByPath, filePath, c.repoPath, c.fsys)
	var modAttr *model.ModuleAttribution
	var callChain string
	if res.Source != nil {
		modAttr = res.Source.ModuleAttribution
		callChain = res.Source.ModuleCallChain
	}
	// External/remote module files may not be in filesByPath; anchor on the
	// scanned caller file via ModuleAttribution rather than dropping the finding.
	anchoredOnCaller := false
	if file == nil && modAttr != nil {
		if caller := callers[modAttr.CallSite.Filename]; caller != nil {
			file = caller
			anchoredOnCaller = true
		}
	}
	if file == nil {
		return nil
	}
	// Always report the matched FileMetadata.FilePath (not raw HCL span.File,
	// whose path separators can differ on Windows MemFS scans).
	reportedPath := file.FilePath

	vObj := mergeWithMetadata(f.Raw, rule.meta.Metadata)
	contextLogger := logger.FromContext(ctx)
	logWithFields := contextLogger.With().
		Str("scanID", scanID).
		Str("fileName", file.FilePath).
		Str("queryName", rule.meta.Query).
		Logger()

	overrideKey := f.OverrideKey
	queryID := getStringFromMap(ctx, "id", DefaultQueryID, overrideKey, vObj, &logWithFields)
	legacyQueryID := getOptionalStringKey(ctx, "legacyId", DefaultQueryID, overrideKey, vObj, &logWithFields)
	legacyQueryIDs := getOptionalStringSliceKey("legacyIds", vObj)
	platform := getStringFromMap(ctx, "platform", "Terraform", overrideKey, vObj, &logWithFields)

	severity := getResolvedSeverity(ctx, vObj, &logWithFields, overrideKey, c.useOldSeverities)
	if rc, found := lookupRuleConfig(c.ruleConfigs, queryID, legacyQueryID, legacyQueryIDs); found {
		if rc.Severity != nil {
			severity = model.Severity(strings.ToUpper(*rc.Severity))
		}
		if !c.isExternalModulePath(file.FilePath) &&
			rulePathExcluded(file.FilePath, rc.IgnorePaths, rc.OnlyPaths) {
			return nil
		}
	}

	lines := file.Lines()
	if file.Kind == model.KindTerraformPlan && len(rawPlanLines) > 0 {
		lines = rawPlanLines
	}
	line := span.StartLine
	if line < 1 {
		line = 1
	}
	sameFile := !anchoredOnCaller &&
		contractPathKey(filePath, c.repoPath, c.fsys) == contractPathKey(file.FilePath, c.repoPath, c.fsys)
	vulnLoc := span.ToResourceLocation()
	blockLoc := res.Source.BlockSpan.ToResourceLocation()
	if !sameFile || !res.Source.BlockSpan.Valid() ||
		contractPathKey(res.Source.BlockSpan.File, c.repoPath, c.fsys) != contractPathKey(file.FilePath, c.repoPath, c.fsys) {
		blockLoc = vulnLoc
	}
	remLoc := vulnLoc
	if sameFile && res.Source != nil && res.Source.RemediationPoint != nil {
		if rLine, rCol, ok := res.Source.RemediationPoint(line, file); ok {
			remLoc = model.ResourceLocation{
				Start: model.ResourceLine{Line: rLine, Col: rCol},
				End:   model.ResourceLine{Line: rLine, Col: rCol},
			}
		}
	}

	// When anchored on a caller file (external module absent from filesByPath),
	// use the caller's call-site line for adjacent code context and ignore checks
	// rather than applying the external module's line number to the caller file.
	displayLine := line
	if anchoredOnCaller && modAttr != nil && modAttr.CallSite.LineStart > 0 {
		displayLine = modAttr.CallSite.LineStart
	}
	lineText := ""
	if displayLine-1 >= 0 && displayLine-1 < len(lines) {
		lineText = lines[displayLine-1]
	}

	resType := res.Type
	switch res.Kind {
	case address.KindData:
		resType = address.DataPrefix + res.Type
	case address.KindEphemeral:
		resType = address.EphemeralPrefix + res.Type
	}
	// Keep base resource name (without instance_key) for legacy DATADOG_FINGERPRINT
	// continuity and compactFindingsAtDecode deduplication across count/for_each.
	resName := res.Name

	remediation, remediationType := buildReplacementRemediation(res, f)
	if remediation == "" && rule.remediatePrepared != nil {
		if optRem, optType, ok := evalOptionalRemediation(ctx, rule, res, f); ok {
			remediation = optRem
			remediationType = optType
		}
	}
	// Use module-local resource address (without leading module.<name>.) for
	// SearchKey so pkg/inventory/links.go matches module resources identically
	// to legacy rules.
	searchKey := localResourceSearchKey(res, f.Path)

	frameworks := append(
		extractDefaultFrameworks(ctx, rule.meta.Metadata, c.flagEvaluator),
		extractCustomFrameworks(ctx, rule.meta.Metadata, c.flagEvaluator)...,
	)

	v := &model.Vulnerability{
		ScanID:                scanID,
		FileID:                file.ID,
		FileName:              reportedPath,
		QueryName:             getStringFromMap(ctx, "queryName", DefaultQueryName, overrideKey, vObj, &logWithFields),
		QueryID:               queryID,
		LegacyQueryID:         legacyQueryID,
		LegacyQueryIDs:        legacyQueryIDs,
		Experimental:          getBoolFromMap(ctx, "experimental", DefaultExperimental, overrideKey, vObj, &logWithFields),
		QueryURI:              getStringFromMap(ctx, "descriptionUrl", DefaultQueryURI, overrideKey, vObj, &logWithFields),
		Category:              getStringFromMap(ctx, "category", "", overrideKey, vObj, &logWithFields),
		Description:           getStringFromMap(ctx, "descriptionText", "", overrideKey, vObj, &logWithFields),
		DescriptionID:         getStringFromMap(ctx, "descriptionID", DefaultQueryDescriptionID, overrideKey, vObj, &logWithFields),
		Severity:              severity,
		Platform:              platform,
		CWE:                   getStringFromMap(ctx, "cwe", "", overrideKey, vObj, &logWithFields),
		Line:                  line,
		VulnerabilityLocation: vulnLoc,
		RemediationLocation:   remLoc,
		BlockLocation:         blockLoc,
		VulnLines:             detector.GetAdjacentVulnLines(displayLine-1, c.tracker.GetOutputLines(), lines),
		FileSource:            lines,
		ResourceType:          resType,
		ResourceName:          resName,
		SearchKey:             searchKey,
		CloudProvider:         getOptionalStringKey(ctx, "cloudProvider", "", overrideKey, vObj, &logWithFields),
		Remediation:           remediation,
		RemediationType:       remediationType,
		QueryDuration:         queryDuration,
		LineWithVulnerability: lineText,
		ModuleCallChain:       callChain,
		ResourceID:            res.Address,
		RootModule:            res.Source.RootModule,
		Frameworks:            frameworks,
	}
	finalizeFinding(v, rule.meta.Metadata, frameworks, model.TerraformBlock{
		Kind: res.Kind, Type: res.Type, Name: res.Name,
	})
	if res.Source.OverrideInventoryLine > 0 {
		if declaration := lookupFileByPath(filesByPath, res.File, c.repoPath, c.fsys); declaration != nil {
			v.TerraformOverride = &model.TerraformOverrideFinding{
				SourceFileID:     file.ID,
				DeclarationStart: model.ResourceLine{Line: res.Source.BlockSpan.StartLine, Col: res.Source.BlockSpan.StartCol},
			}
			v.FileID = declaration.ID
		}
	}

	if modAttr != nil {
		// Clone & narrow per-finding ArgumentControl, CallSite, and ModuleCodeLocation.
		v.ModuleAttribution = narrowModuleAttribution(modAttr, v)
	}

	if ShouldSkipVulnerability(file.Commands, queryID, legacyQueryID, legacyQueryIDs) {
		markSuppressed(v, model.SuppressionJustificationDisableInFile)
	}
	if sameFile {
		if checkComment(line, file.LinesIgnore) ||
			(res.Source.BlockSpan.Valid() && checkComment(res.Source.BlockSpan.StartLine, file.LinesIgnore)) {
			markSuppressed(v, model.SuppressionJustificationIgnoreComment)
		}
	} else if anchoredOnCaller && v.ModuleAttribution != nil {
		if checkComment(v.ModuleAttribution.CallSite.LineStart, file.LinesIgnore) {
			markSuppressed(v, model.SuppressionJustificationIgnoreComment)
		}
	}
	return v
}

func localResourceSearchKey(res *policy.Resource, path policy.Path) string {
	base := address.Addr(address.Block{Kind: res.Kind, Type: res.Type, Name: res.Name})
	if base == "" {
		base = res.Address
	}
	if pk := policy.PathKey(path); pk != "" {
		return base + "." + pk
	}
	return base
}

func contractPathKey(p, repoPath string, fsys vfs.FS) string {
	if p == "" {
		return ""
	}
	if vfs.IsDisk(fsys) {
		if !filepath.IsAbs(p) && repoPath != "" {
			return filepath.ToSlash(filepath.Clean(filepath.Join(repoPath, p)))
		}
		if abs, err := fsys.Abs(p); err == nil {
			return filepath.ToSlash(filepath.Clean(abs))
		}
	}
	return filepath.ToSlash(filepath.Clean(p))
}

func lookupFileByPath(
	filesByPath map[string]*model.FileMetadata,
	path, repoPath string,
	fsys vfs.FS,
) *model.FileMetadata {
	if path == "" {
		return nil
	}
	if f, ok := filesByPath[contractPathKey(path, repoPath, fsys)]; ok {
		return f
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	if f, ok := filesByPath[clean]; ok {
		return f
	}
	return nil
}
