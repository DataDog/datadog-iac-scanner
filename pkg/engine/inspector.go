/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-iac-scanner/internal/memwatch"
	"github.com/DataDog/datadog-iac-scanner/internal/pathutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector/docker"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector/helm"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector/terraform"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/hclexpr"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/cespare/xxhash/v2"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/cover"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/pkg/errors"
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/sync/singleflight"
)

// Default values for inspector
const (
	UndetectedVulnerabilityLine = -1
	DefaultQueryID              = utils.DefaultQueryID
	DefaultQueryName            = utils.DefaultQueryName
	DefaultExperimental         = utils.DefaultExperimental
	DefaultQueryDescription     = utils.DefaultQueryDescription
	DefaultQueryDescriptionID   = utils.DefaultQueryDescriptionID
	DefaultQueryURI             = utils.DefaultQueryURI
	unresolvedPlaceholder       = utils.UnresolvedPlaceholder

	regoQuery = utils.RegoQuery
)

// slowQueryWarnThreshold is how long a single query (rego eval + result decode)
// may take before it is logged as slow. We surface slow rules so they can be optimized later.
const slowQueryWarnThreshold = 60 * time.Second

// ErrNoResult - error representing when a query didn't return a result
var ErrNoResult = errors.New("query: not result")

// ErrInvalidResult - error representing invalid result
var ErrInvalidResult = errors.New("query: invalid result format")

// QueryLoader is responsible for loading the queries for the inspector
type QueryLoader struct {
	commonLibrary     source.RegoLibraries
	platformLibraries map[string]source.RegoLibraries
	querySum          int
	QueriesMetadata   []model.QueryMetadata
	// parsedCommon is the Common library module parsed once at startup.
	// Passed via rego.ParsedModule() to skip re-parsing 40 KB of Rego text on
	// every PrepareForEval call; each call still compiles its own fresh module
	// set so there is no shared mutable compiler state across goroutines.
	parsedCommon *ast.Module
	// parsedGeneric holds the per-platform Generic library module, also parsed once.
	parsedGeneric map[string]*ast.Module
	// platformKeyBases holds, per platform, a precomputed hash of the common and
	// platform library code + input data. It is the library-dependent part of a
	// compiled-query cache key, hashed once at load time instead of hashing
	// ~82 KB of library text on every LoadQuery call. See preparedCacheKey.
	platformKeyBases map[string]uint64
}

// preparedQueryCache caches compiled *rego.PreparedEvalQuery values across scans
// and across the whole process, keyed by preparedCacheKey. A compiled query is
// safe to share: PrepareForEval/Eval open only read-only transactions on the
// store, the *PreparedEvalQuery is immutable after construction, and Eval is
// safe for concurrent use.
var preparedQueryCache sync.Map // map[uint64]*rego.PreparedEvalQuery

// sharedPreparedQueryCache retains one co-compiled ruleset. A single-entry
// cache is sufficient for the long-lived server's normal workload (the latest
// backend rules and libraries) and bounds retained memory when rules, library
// data, or Terraform module data changes between requests.
var sharedPreparedQueryCache struct {
	sync.Mutex
	key     uint64
	queries map[int]*rego.PreparedEvalQuery
	flight  singleflight.Group
}

type sharedQueryCacheResult struct {
	queries  map[int]*rego.PreparedEvalQuery
	cacheHit bool
}

// ResetCompiledQueryCachesForTest clears process-global compiled-query caches.
func ResetCompiledQueryCachesForTest() {
	sharedPreparedQueryCache.Lock()
	sharedPreparedQueryCache.key = 0
	sharedPreparedQueryCache.queries = nil
	sharedPreparedQueryCache.Unlock()
	preparedQueryCache.Range(func(k, _ any) bool {
		preparedQueryCache.Delete(k)
		return true
	})
}

// hashFields computes a fast, non-cryptographic 64-bit hash of the given strings
// joined by a NUL separator. The NUL separator keeps the field boundaries
// unambiguous (so e.g. ("a","bc") and ("ab","c") hash differently).
func hashFields(fields ...string) uint64 {
	var h xxhash.Digest
	h.Reset()
	for i, f := range fields {
		if i > 0 {
			_, _ = h.WriteString("\x00")
		}
		_, _ = h.WriteString(f)
	}
	return h.Sum64()
}

// preparedCacheKey builds the cache key for a compiled query from everything its
// compiled form depends on: platform, query name, query content, the library
// hash base (library Rego *code*), and the base-store data hash (the merged
// library + module input *data* the store bakes in). Two queries that produce
// the same key compile to an interchangeable *PreparedEvalQuery.
//
// The two precomputed uint64 bases are mixed in as raw 8-byte words rather than
// formatted to strings, so this allocates nothing beyond the digest itself.
func preparedCacheKey(query *model.QueryMetadata, libBase, baseDataHash uint64) uint64 {
	var h xxhash.Digest
	h.Reset()
	_, _ = h.WriteString(query.Platform)
	_, _ = h.WriteString("\x00")
	_, _ = h.WriteString(query.Query)
	_, _ = h.WriteString("\x00")
	_, _ = h.WriteString(query.Content)
	var buf [16]byte
	binary.LittleEndian.PutUint64(buf[0:8], libBase)
	binary.LittleEndian.PutUint64(buf[8:16], baseDataHash)
	_, _ = h.Write(buf[:])
	return h.Sum64()
}

// sharedCacheKey hashes everything the co-compiled prepared queries depend on.
// Query order is significant because the shared compiler rewrites packages to
// data.datadog.q<index>. Library code/input and the merged base store are
// represented by the same precomputed hashes used by the isolated cache.
func sharedCacheKey(queries []model.QueryMetadata, libraryBases, baseDataHashes map[string]uint64) uint64 {
	var h xxhash.Digest
	h.Reset()
	var words [24]byte
	binary.LittleEndian.PutUint64(words[0:8], uint64(len(queries)))
	_, _ = h.Write(words[0:8])
	for i := range queries {
		query := &queries[i]
		_, _ = h.WriteString(query.Platform)
		_, _ = h.WriteString("\x00")
		_, _ = h.WriteString(query.Query)
		_, _ = h.WriteString("\x00")
		_, _ = h.WriteString(query.Content)
		_, _ = h.WriteString("\x00")
		_, _ = h.WriteString(query.InputData)
		binary.LittleEndian.PutUint64(words[0:8], uint64(i))
		binary.LittleEndian.PutUint64(words[8:16], libraryBases[query.Platform])
		binary.LittleEndian.PutUint64(words[16:24], baseDataHashes[query.Platform])
		_, _ = h.Write(words[:])
	}
	return h.Sum64()
}

// hashBaseInputData computes a fast hash of each platform's merged base
// input-data string, identifying the data baked into that platform's shared
// base store for compiled-query cache keying.
func hashBaseInputData(baseInputData map[string]string) map[string]uint64 {
	hashes := make(map[string]uint64, len(baseInputData))
	for platform, data := range baseInputData {
		hashes[platform] = hashFields(data)
	}
	return hashes
}

// VulnerabilityBuilder represents a function that will build a vulnerability
type VulnerabilityBuilder func(ctx context.Context, qCtx *QueryContext, tracker Tracker, v interface{},
	detector *detector.DetectLine, useOldSeverities bool, queryDuration time.Duration) (*model.Vulnerability, error)

// PreparedQuery includes the opaQuery and its metadata
type PreparedQuery struct {
	OpaQuery rego.PreparedEvalQuery
	Metadata model.QueryMetadata
}

// Inspector represents a list of compiled queries, a builder for vulnerabilities, an information tracker
// a flag to enable coverage and the coverage report if it is enabled
type Inspector struct {
	QueryLoader   *QueryLoader
	vb            VulnerabilityBuilder
	tracker       Tracker
	failedQueries map[string]error
	// failedQueriesMu guards failedQueries. Inspect writes it from two places
	// concurrently: the collector goroutine (processResult, on a query error)
	// and every worker goroutine (getVulnerabilitiesFromQuery, on a
	// vulnerability-build error)
	failedQueriesMu sync.Mutex
	ruleConfigs     map[string]config.IacRuleConfig
	detector        *detector.DetectLine

	repoPath             string
	enableCoverageReport bool
	coverageReport       cover.Report
	useOldSeverities     bool
	numWorkers           int
	flagEvaluator        featureflags.FlagEvaluator
	disableRuleIsolation bool
	useRulesCache        bool
	// fsys is the filesystem used for Terraform module resolution. Defaults to
	// the real disk; the HTTP server injects an in-memory FS built from pushed
	// content.
	fsys                   vfs.FS
	remoteModuleDirs       map[string]RemoteModuleDirectory
	remoteModuleProvenance map[string]RemoteModuleProvenance
	externalPathRoots      map[string]bool
}

func (c *Inspector) SetRemoteModuleDirectories(sourceToDir map[string]RemoteModuleDirectory) {
	c.remoteModuleDirs = sourceToDir
}

func (c *Inspector) SetRemoteModuleProvenance(sourceToProvenance map[string]RemoteModuleProvenance) {
	c.remoteModuleProvenance = sourceToProvenance
}

func (c *Inspector) buildModuleProvenanceLookup() moduleProvenanceLookup {
	return func(callerRoot, source, version, moduleName string) (RemoteModuleProvenance, bool) {
		if c.remoteModuleProvenance != nil {
			for _, key := range []string{
				RemoteModuleCallKey(callerRoot, source, version, moduleName),
				RemoteModuleCallKey(callerRoot, source, "", moduleName),
				RemoteModuleKey(callerRoot, source, version),
				RemoteModuleKey(callerRoot, source, ""),
			} {
				if prov, ok := c.remoteModuleProvenance[key]; ok {
					return prov, true
				}
			}
		}
		if c.remoteModuleDirs != nil {
			if directory, ok := lookupRemoteDir(c.remoteModuleDirs, callerRoot, source, version, moduleName); ok {
				sourceType, _ := tfmodules.DetectModuleSourceType(source)
				return RemoteModuleProvenance{
					Source:     source,
					SourceType: sourceType,
					ModuleRoot: directory.Path,
				}, true
			}
		}
		return RemoteModuleProvenance{}, false
	}
}

func (c *Inspector) SetExternalModulePaths(paths []string) {
	if len(paths) == 0 {
		c.externalPathRoots = nil
		return
	}
	roots := make(map[string]bool, len(paths))
	for _, p := range paths {
		roots[filepath.Clean(p)] = true
	}
	c.externalPathRoots = roots
}

// QueryContext contains the context where the query is executed, which scan it belongs, basic information of query,
// the query compiled and its payload
type QueryContext struct {
	Ctx           context.Context
	scanID        string
	Files         map[string]*model.FileMetadata
	Query         *PreparedQuery
	payload       *ast.Value
	FlagEvaluator featureflags.FlagEvaluator
}

var (
	unsafeRegoFunctions = map[string]struct{}{
		"http.send":   {},
		"opa.runtime": {},
	}
)

// safeCapabilities returns the OPA capabilities for this version with the
// unsafeRegoFunctions removed from the allowed-builtins list, so a rule
// referencing one fails to compile (an "undefined function"). This is the
// non-deprecated replacement for Compiler.WithUnsafeBuiltins, which OPA derives
// the same way: the compiler's known-builtins set is built solely from
// capabilities.Builtins. Computed once — capabilities are immutable.
var safeCapabilities = sync.OnceValue(func() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	allowed := caps.Builtins[:0]
	for _, b := range caps.Builtins {
		if _, unsafe := unsafeRegoFunctions[b.Name]; unsafe {
			continue
		}
		allowed = append(allowed, b)
	}
	caps.Builtins = allowed
	return caps
})

// NewInspector initializes a inspector, compiling and loading queries for scan and its tracker
func NewInspector(
	ctx context.Context,
	queriesSource source.QueriesSource,
	vb VulnerabilityBuilder,
	tracker Tracker,
	queryParameters *source.QueryInspectorParameters,
	ruleConfigs map[string]config.IacRuleConfig,
	repoPath string,
	useOldSeverities bool,
	needsLog bool,
	numWorkers int,
	flagEvaluator featureflags.FlagEvaluator,
	fsys vfs.FS,
	disableRuleIsolation bool,
	useRulesCache bool,
) (*Inspector, error) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("engine.NewInspector()")

	if fsys == nil {
		fsys = vfs.DiskFS{}
	}

	queries, err := queriesSource.GetQueries(ctx, queryParameters)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get queries")
	}

	contextLogger.Info().Msgf("Queries loaded: %d", len(queries))

	commonLibrary, err := queriesSource.GetQueryLibrary(ctx, "common")
	if err != nil {
		return nil, errors.Wrap(err, "failed to get library")
	}
	platformLibraries := getPlatformLibraries(ctx, queriesSource, queries)

	queryLoader, err := prepareQueries(queries, commonLibrary, platformLibraries, tracker)
	if err != nil {
		return nil, errors.Wrap(err, "failed to prepare queries")
	}

	failedQueries := make(map[string]error)

	if needsLog {
		contextLogger.Info().
			Msgf("Inspector initialized, number of queries=%d", queryLoader.querySum)
	}

	lineDetector := detector.NewDetectLine(tracker.GetOutputLines()).
		Add(helm.DetectKindLine{}, model.KindHELM).
		Add(docker.DetectKindLine{}, model.KindDOCKER).
		Add(&terraform.DetectKindLine{}, model.KindTerraform)

	return &Inspector{
		QueryLoader:          &queryLoader,
		vb:                   vb,
		tracker:              tracker,
		failedQueries:        failedQueries,
		ruleConfigs:          ruleConfigs,
		detector:             lineDetector,
		repoPath:             repoPath,
		useOldSeverities:     useOldSeverities,
		numWorkers:           utils.AdjustNumWorkers(numWorkers),
		flagEvaluator:        flagEvaluator,
		fsys:                 fsys,
		disableRuleIsolation: disableRuleIsolation,
		useRulesCache:        useRulesCache,
	}, nil
}

func getPlatformLibraries(ctx context.Context, queriesSource source.QueriesSource,
	queries []model.QueryMetadata) map[string]source.RegoLibraries {
	contextLogger := logger.FromContext(ctx)
	supportedPlatforms := make(map[string]string)
	for _, query := range queries {
		supportedPlatforms[query.Platform] = ""
	}
	platformLibraries := make(map[string]source.RegoLibraries)
	for platform := range supportedPlatforms {
		platformLibrary, errLoadingPlatformLib := queriesSource.GetQueryLibrary(ctx, platform)
		if errLoadingPlatformLib != nil {
			contextLogger.Err(errLoadingPlatformLib).Msgf("error loading platform library: %s", errLoadingPlatformLib)
			continue
		}
		platformLibraries[platform] = platformLibrary
	}
	return platformLibraries
}

type QueryResult struct {
	vulnerabilities []model.Vulnerability
	err             error
	queryID         int
}

// evalQuery loads and evaluates a single query, returning its result. Load and
// evaluation failures both carry their error so the serial aggregation records
// them in FailedQueries without terminating the rest of the scan.
func (c *Inspector) evalQuery(ctx context.Context, scanID string, filesMap map[string]*model.FileMetadata,
	payloads platformPayloads, queries []model.QueryMetadata, queryID int,
	modules []tfmodules.ParsedModule, baseStores map[string]storage.Store, baseDataHashes map[string]uint64,
	sharedQueries map[int]*rego.PreparedEvalQuery) QueryResult {
	contextLogger := logger.FromContext(ctx)

	loadStart := time.Now()
	// Prefer the shared-compiler query when one was prepared for this rule (rule
	// isolation disabled); otherwise compile/load it individually, using the
	// process-global compiled-query cache when enabled.
	queryOpa, ok := sharedQueries[queryID]
	var err error
	if !ok {
		queryOpa, err = c.QueryLoader.LoadQuery(ctx, &queries[queryID], modules, baseStores, baseDataHashes, c.useRulesCache)
	}
	loadDur := time.Since(loadStart)
	if err != nil {
		contextLogger.Warn().Err(err).Msgf("failed to load query %s", queries[queryID].Query)
		return QueryResult{err: err, queryID: queryID}
	}

	query := &PreparedQuery{
		OpaQuery: *queryOpa,
		Metadata: queries[queryID],
	}

	// Evaluate each query only against documents of its own platform. The
	// payload is read-only, so sharing the per-platform ast.Value across workers
	// is safe.
	payload := selectPlatformPayload(query.Metadata.Platform, payloads.byPlatform, payloads.full)
	queryContext := &QueryContext{
		Ctx:           ctx,
		scanID:        scanID,
		Files:         filesMap,
		Query:         query,
		payload:       &payload,
		FlagEvaluator: c.flagEvaluator,
	}

	evalStart := time.Now()
	vuls, err := c.doRun(ctx, queryContext)
	evalDur := time.Since(evalStart)
	contextLogger.Debug().Msgf("query timing: load=%s eval=%s query=%s",
		loadDur.Round(time.Millisecond), evalDur.Round(time.Millisecond), queries[queryID].Query)
	if err == nil {
		c.tracker.TrackQueryExecution(query.Metadata.Aggregation)
	}
	return QueryResult{vulnerabilities: vuls, err: err, queryID: queryID}
}

func (c *Inspector) Inspect(
	ctx context.Context,
	scanID string,
	files model.FileMetadatas,
	platforms []string) ([]model.Vulnerability, error) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("engine.Inspect()")

	// Terraform local-module instantiation is gated so it can be disabled remotely.
	queries := c.getQueriesByPlat(platforms)

	var moduleDocs []model.Document
	var moduleExtras map[string][]extraCallerInfo
	var syntheticFiles []*model.FileMetadata
	if shouldInstantiateLocalModules(platforms, files) &&
		c.flagEvaluator != nil &&
		c.flagEvaluator.EvaluateWithOrg(featureflags.IacEnableLocalModuleEval) {
		targets := ruleTargetedResourceTypes(queries, c.terraformRuleLibraries()...)
		moduleDocs, syntheticFiles, moduleExtras = c.instantiateLocalModules(ctx, files, targets)
		memwatch.Sample(ctx, memwatch.PhaseModuleEval)
	}

	// Must run after module mutations (which suppress module bodies in place).
	combinedFiles := files.Combine(ctx, false)

	// Step 1: Parse Terraform modules. A genuine per-file HCL parse failure is
	// non-fatal (logged, scan continues), but a context cancellation must abort
	// the scan rather than proceed with partial module data.
	parsedModules, err := tfmodules.ParseTerraformModules(ctx, c.fsys, files, c.numWorkers)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		contextLogger.Warn().Err(err).Msg("Failed to parse Terraform modules")
	}
	contextLogger.Info().Msgf("Found %d modules", len(parsedModules))

	// Step 2: Enrich modules with parsed variables. As with Step 1, a context
	// cancellation must abort the scan rather than proceed with partial module
	// data; per-module parse failures are non-fatal and handled internally.
	rootDir := c.repoPath
	enrichedModules, err := tfmodules.ParseAllModuleVariables(
		ctx, c.fsys, parsedModules, rootDir, c.buildModuleMetadataResolver())
	if err != nil {
		return nil, err
	}

	// Synthetic files stand in for module instantiations of a file that has
	// already been read; they are only joined once findings need to be
	// attributed back to a call site. Adding them any earlier would have every
	// pass over the scan input, module parsing above in particular, redo that
	// file's work once per instantiation.
	files = append(files, syntheticFiles...)

	// Compute the file map once and share it (read-only) across all workers and
	// payload partitioning.
	filesMap := files.ToMap()

	payloads, err := c.buildPlatformPayloads(ctx, filesMap, combinedFiles.Documents, moduleDocs, queries)
	if err != nil {
		return nil, err
	}

	// Pre-build one inmem.Store per platform so LoadQuery does not re-parse the
	// same payload for every PrepareForEval call. The per-platform data hash is
	// folded into each compiled-query cache key so a compiled query is only
	// reused by a later scan whose base data is byte-identical.
	baseInputData := c.QueryLoader.precomputeBaseInputData(enrichedModules)
	baseStores := precomputeBaseStores(baseInputData)
	baseDataHashes := hashBaseInputData(baseInputData)

	// When rule isolation is disabled, co-compile all rules + libraries once per
	// platform into a shared compiler (rules rewritten to unique packages) so the
	// library AST is retained a single time. Rules missing from the returned map
	// (parse/compile failures) fall back to isolated LoadQuery in the worker, so
	// correctness is preserved even if shared compilation partially fails.
	var sharedQueries map[int]*rego.PreparedEvalQuery
	if c.disableRuleIsolation {
		if c.useRulesCache {
			var cacheHit bool
			sharedQueries, cacheHit, err = c.QueryLoader.loadSharedQueriesCached(
				ctx, queries, baseStores, baseDataHashes)
			if err != nil {
				return nil, err
			}
			contextLogger.Info().Msgf("Shared compiler cache hit: %t", cacheHit)
		} else {
			sharedQueries = c.QueryLoader.loadSharedQueries(ctx, queries, baseStores)
		}
		contextLogger.Info().Msgf("Rule isolation disabled: %d/%d queries served from shared compiler",
			len(sharedQueries), len(queries))
	}

	vulnerabilities, err := c.executeQueries(ctx, scanID, filesMap, payloads, queries,
		enrichedModules, baseStores, baseDataHashes, sharedQueries)
	if err != nil {
		return nil, err
	}
	return expandModuleFindings(vulnerabilities, moduleExtras), nil
}

// executeQueries runs all prepared queries concurrently and collects vulnerabilities.
func (c *Inspector) executeQueries(
	ctx context.Context,
	scanID string,
	filesMap map[string]*model.FileMetadata,
	payloads platformPayloads,
	queries []model.QueryMetadata,
	enrichedModules []tfmodules.ParsedModule,
	baseStores map[string]storage.Store,
	baseDataHashes map[string]uint64,
	sharedQueries map[int]*rego.PreparedEvalQuery,
) ([]model.Vulnerability, error) {
	contextLogger := logger.FromContext(ctx)
	vulnerabilities := make([]model.Vulnerability, 0)

	// Evaluate each query in parallel. Eval is CPU-bound (Rego), so the pool
	// draws from the process-wide CPU budget: when this scan runs as one of N
	// concurrent per-platform services, all their query pools share the same
	// budget and cannot oversubscribe the machine. Results land in an
	// index-aligned slice (no shared mutable state between workers); the actual
	// aggregation happens serially below.
	results := make([]QueryResult, len(queries))
	err := utils.ForEach(ctx, queries, utils.PoolOptions{Workers: c.numWorkers, CPUBound: true},
		func(ctx context.Context, _ model.QueryMetadata, i int) error {
			results[i] = c.evalQuery(ctx, scanID, filesMap, payloads, queries, i, enrichedModules, baseStores, baseDataHashes, sharedQueries)
			return nil
		})
	// The closure never returns a non-nil error itself, so ForEach only reports
	// context cancellation here; surfacing it keeps a canceled scan from being
	// reported as a successful scan with partial/empty results.
	if err != nil {
		return vulnerabilities, err
	}

	// Aggregate serially: processResult mutates shared state.
	moduleVulns := make(map[string]int)
	for i := range results {
		processResult(ctx, &results[i], &vulnerabilities, &moduleVulns, queries, c)
	}
	for vulnerability, number := range moduleVulns {
		contextLogger.Info().Msgf("Found %d of module vulnerability %s", number, vulnerability)
	}

	return vulnerabilities, nil
}

func shouldInstantiateLocalModules(platforms []string, files model.FileMetadatas) bool {
	for _, platform := range platforms {
		if strings.EqualFold(platform, "Terraform") {
			for _, file := range files {
				if file != nil && tfmodules.IsTerraformConfigPath(file.FilePath) {
					return true
				}
			}
		}
	}
	return false
}

// expandModuleFindings clones findings from deduplicated OPA docs back to each
// extra caller, so every call-site gets its own fingerprint/file attribution.
func expandModuleFindings(vulns []model.Vulnerability, extras map[string][]extraCallerInfo) []model.Vulnerability {
	if len(extras) == 0 {
		return vulns
	}
	expanded := make([]model.Vulnerability, 0, len(vulns))
	for i := range vulns {
		expanded = append(expanded, vulns[i])
		for _, ex := range extras[vulns[i].FileID] {
			vCopy := vulns[i]
			vCopy.ModuleCallChain = ex.callChain
			vCopy.FileID = ex.docID
			vCopy.ModuleAttribution = moduleAttributionForResource(
				ex.attributions,
				vCopy.ResourceType,
				vCopy.BlockLocation.Start.Line,
				vCopy.BlockLocation.Start.Col,
			)
			expanded = append(expanded, vCopy)
		}
	}
	return expanded
}

// nolint:gocritic
func processResult(ctx context.Context, result *QueryResult,
	vulnerabilities *[]model.Vulnerability, moduleVulns *map[string]int,
	queries []model.QueryMetadata, c *Inspector) {
	contextLogger := logger.FromContext(ctx)
	if result.err != nil {
		contextLogger.Warn().Err(result.err).Msgf("query failed to execute: %s", queries[result.queryID].Query)
		c.failedQueriesMu.Lock()
		c.failedQueries[queries[result.queryID].Query] = result.err
		c.failedQueriesMu.Unlock()
		return
	}

	// nolint:gocritic
	for _, vulnerability := range result.vulnerabilities {
		if vulnerability.ResourceType == "module" {
			val, ok := (*moduleVulns)[vulnerability.QueryName]
			if ok {
				(*moduleVulns)[vulnerability.QueryName] = val + 1
			} else {
				(*moduleVulns)[vulnerability.QueryName] = 1
				contextLogger.Info().Msgf("Found module vulnerability %s of severity %s", vulnerability.QueryName, vulnerability.Severity)
			}
		}
	}
	*vulnerabilities = append(*vulnerabilities, result.vulnerabilities...)
}

// LenQueriesByPlat returns the number of queries by platforms
func (c *Inspector) LenQueriesByPlat(platforms []string) int {
	count := 0
	for _, query := range c.QueryLoader.QueriesMetadata {
		if contains(platforms, query.Platform) {
			c.tracker.TrackQueryExecuting(query.Aggregation)
			count++
		}
	}
	return count
}

func (c *Inspector) getQueriesByPlat(platforms []string) []model.QueryMetadata {
	queries := make([]model.QueryMetadata, 0)
	for _, query := range c.QueryLoader.QueriesMetadata {
		if contains(platforms, query.Platform) {
			queries = append(queries, query)
		}
	}
	return queries
}

// EnableCoverageReport enables the flag to create a coverage report
func (c *Inspector) EnableCoverageReport() {
	c.enableCoverageReport = true
}

// GetCoverageReport returns the scan coverage report
func (c *Inspector) GetCoverageReport() cover.Report {
	return c.coverageReport
}

// GetFailedQueries returns a map of failed queries and the associated error.
// It returns a copy taken under failedQueriesMu so callers can read the result
// safely even if a scan is still writing to the underlying map.
func (c *Inspector) GetFailedQueries() map[string]error {
	c.failedQueriesMu.Lock()
	defer c.failedQueriesMu.Unlock()
	return maps.Clone(c.failedQueries)
}

func ruleArgumentsValue(rc config.IacRuleConfig) (ast.Value, bool, error) {
	if rc.Arguments == nil {
		return nil, false, nil
	}

	value, err := ast.InterfaceToValue(rc.Arguments)
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

func withRuleArguments(payload, args ast.Value) (ast.Value, error) {
	obj, ok := payload.(ast.Object)
	if !ok {
		return nil, fmt.Errorf("expected OPA input payload object, got %T", payload)
	}

	out := ast.NewObject()
	_ = obj.Iter(func(k, v *ast.Term) error {
		out.Insert(k, v)
		return nil
	})
	out.Insert(ast.StringTerm("arguments"), ast.NewTerm(args))
	return out, nil
}

func queryIDsFromMetadata(ctx context.Context, metadata *model.QueryMetadata) (queryID, legacyQueryID string) {
	queryID = DefaultQueryID
	legacyQueryID = DefaultQueryID
	if id, err := mapKeyToString(ctx, metadata.Metadata, "id", false); err == nil && id != nil {
		queryID = *id
	}
	if legacyID, err := mapKeyToString(ctx, metadata.Metadata, "legacyId", true); err == nil && legacyID != nil {
		legacyQueryID = *legacyID
	}
	return queryID, legacyQueryID
}

func (c *Inspector) doRun(ctx context.Context, qCtx *QueryContext) (vulns []model.Vulnerability, err error) {
	contextLogger := logger.FromContext(ctx)
	defer func() {
		if r := recover(); r != nil {
			errMessage := fmt.Sprintf("Recovered from panic during query '%s' run. ", qCtx.Query.Metadata.Query)
			err = fmt.Errorf("panic: %v\n%s", r, string(debug.Stack()))
			contextLogger.Err(err).Msg(errMessage)
		}
	}()

	payload := *qCtx.payload
	queryID, legacyQueryID := queryIDsFromMetadata(ctx, &qCtx.Query.Metadata)
	if rc, found := lookupRuleConfig(c.ruleConfigs, queryID, legacyQueryID); found {
		if args, ok, err := ruleArgumentsValue(rc); err != nil {
			return nil, errors.Wrap(err, "Failed to prepare rule arguments for query "+queryID)
		} else if ok {
			payload, err = withRuleArguments(payload, args)
			if err != nil {
				return nil, err
			}
		}
	}
	options := []rego.EvalOption{rego.EvalParsedInput(payload)}

	var cov *cover.Cover
	if c.enableCoverageReport {
		cov = cover.New()
		options = append(options, rego.EvalQueryTracer(cov))
	}

	evalStart := time.Now()
	results, err := qCtx.Query.OpaQuery.Eval(qCtx.Ctx, options...)
	evalDuration := time.Since(evalStart)
	qCtx.payload = nil
	if err != nil {
		if topdown.IsCancel(err) {
			return nil, errors.Wrap(err, "query evaluation canceled (scan aborting)")
		}

		return nil, errors.Wrap(err, "failed to evaluate query")
	}
	if c.enableCoverageReport && cov != nil {
		module, parseErr := ast.ParseModuleWithOpts(
			qCtx.Query.Metadata.Query,
			qCtx.Query.Metadata.Content,
			ast.ParserOptions{RegoVersion: ast.RegoV1},
		)
		if parseErr != nil {
			return nil, errors.Wrap(parseErr, "failed to parse coverage module")
		}

		c.coverageReport = cov.Report(map[string]*ast.Module{
			qCtx.Query.Metadata.Query: module,
		})
	}

	decodeStart := time.Now()
	vulns, err = c.DecodeQueryResults(ctx, qCtx, qCtx.Ctx, results, evalDuration)
	decodeDuration := time.Since(decodeStart)

	// Flag slow rules so they can be debugged/optimized later
	if total := evalDuration + decodeDuration; total > slowQueryWarnThreshold {
		contextLogger.Warn().
			Str("event", "slow_rule").
			Str("queryID", qCtx.Query.Metadata.Query).
			Str("platform", qCtx.Query.Metadata.Platform).
			Int64("evalMs", evalDuration.Milliseconds()).
			Int64("decodeMs", decodeDuration.Milliseconds()).
			Int64("totalMs", total.Milliseconds()).
			Int64("thresholdMs", slowQueryWarnThreshold.Milliseconds()).
			Msg("slow rule")
	}
	return vulns, err
}

func (c *Inspector) TransformJsonencodeInPayload(ctx context.Context, value ast.Value) ast.Value {
	switch v := value.(type) {
	case ast.Object:
		newObj := ast.NewObject()
		_ = v.Iter(func(k *ast.Term, val *ast.Term) error {
			newVal := c.TransformJsonencodeInPayload(ctx, val.Value)
			newObj.Insert(k, ast.NewTerm(newVal))
			return nil
		})
		return newObj

	case *ast.Array:
		terms := []*ast.Term{}
		for i := 0; i < v.Len(); i++ {
			elem := v.Elem(i)
			transformed := c.TransformJsonencodeInPayload(ctx, elem.Value)
			terms = append(terms, ast.NewTerm(transformed))
		}
		return ast.NewArray(terms...)

	case ast.String:
		str := string(v)
		if strings.Contains(str, "jsonencode(") {
			// Only try to parse if jsonencode is at the top level (not nested in another function)
			// Check if the string starts with jsonencode or ${jsonencode after trimming
			trimmed := strings.TrimSpace(str)
			if strings.HasPrefix(trimmed, "jsonencode(") || strings.HasPrefix(trimmed, "${jsonencode(") {
				parsed, err := parseJsonencodeHCL(ctx, str)
				if err == nil {
					return parsed
				} else {
					return v
				}
			}
			// If jsonencode is nested in another function (e.g., sha1(jsonencode(...))),
			// skip transformation and return the original value
		}
		return v

	default:
		return v
	}
}

func (c *Inspector) interfaceToPayloadValue(
	ctx context.Context,
	value interface{},
	objects map[uintptr]ast.Value,
) (ast.Value, error) {
	switch v := value.(type) {
	case map[string]interface{}:
		pointer := reflect.ValueOf(v).Pointer()
		if pointer != 0 {
			if converted, ok := objects[pointer]; ok {
				return converted, nil
			}
		}
		object := ast.NewObject()
		if pointer != 0 {
			objects[pointer] = object
		}
		for key, raw := range v {
			converted, err := c.interfaceToPayloadValue(ctx, raw, objects)
			if err != nil {
				return nil, err
			}
			object.Insert(ast.StringTerm(key), ast.NewTerm(converted))
		}
		return object, nil
	case []interface{}:
		terms := make([]*ast.Term, 0, len(v))
		for _, raw := range v {
			converted, err := c.interfaceToPayloadValue(ctx, raw, objects)
			if err != nil {
				return nil, err
			}
			terms = append(terms, ast.NewTerm(converted))
		}
		return ast.NewArray(terms...), nil
	default:
		converted, err := ast.InterfaceToValue(value)
		if err != nil {
			return nil, err
		}
		return c.TransformJsonencodeInPayload(ctx, converted), nil
	}
}

// DecodeQueryResults decodes the results into []model.Vulnerability
func (c *Inspector) DecodeQueryResults(
	ctx context.Context,
	qCtx *QueryContext,
	ctxTimeout context.Context,
	results rego.ResultSet,
	queryDuration time.Duration) ([]model.Vulnerability, error) {
	contextLogger := logger.FromContext(ctx)
	if len(results) == 0 {
		return nil, ErrNoResult
	}

	result := results[0].Bindings

	queryResult, ok := result["result"]
	if !ok {
		return nil, ErrNoResult
	}

	queryResultItems, ok := queryResult.([]interface{})
	if !ok {
		return nil, ErrInvalidResult
	}

	vulnerabilities := make([]model.Vulnerability, 0, len(queryResultItems))
	failedDetectLine := false
	canceled := false
decodeLoop:
	for _, queryResultItem := range queryResultItems {
		select {
		case <-ctxTimeout.Done():
			// Scan canceled (shutdown/error). Stop decoding entirely. The partial
			// result is discarded by the aborting scan. break must exit the loop.
			canceled = true
			break decodeLoop
		default:
			vulnerability, aux := getVulnerabilitiesFromQuery(ctx, qCtx, c, queryResultItem, queryDuration)
			if aux {
				failedDetectLine = aux
			}
			if vulnerability != nil && !aux {
				vulnerabilities = append(vulnerabilities, *vulnerability)
			}
		}
	}

	if canceled {
		contextLogger.Err(ctxTimeout.Err()).Msgf(
			"Scan canceled while processing results of the query: %s %s",
			qCtx.Query.Metadata.Platform,
			qCtx.Query.Metadata.Query)
	}

	if failedDetectLine {
		c.tracker.FailedDetectLine()
	}

	return vulnerabilities, nil
}

func getVulnerabilitiesFromQuery(ctx context.Context, qCtx *QueryContext, c *Inspector,
	queryResultItem interface{}, queryDuration time.Duration) (*model.Vulnerability, bool) {
	contextLogger := logger.FromContext(ctx)
	vulnerability, err := c.vb(ctx, qCtx, c.tracker, queryResultItem, c.detector, c.useOldSeverities, queryDuration)
	if err != nil && err.Error() == ErrNoResult.Error() {
		// Ignoring bad results
		return nil, false
	}
	if err != nil {
		c.failedQueriesMu.Lock()
		if _, ok := c.failedQueries[qCtx.Query.Metadata.Query]; !ok {
			c.failedQueries[qCtx.Query.Metadata.Query] = err
		}
		c.failedQueriesMu.Unlock()

		return nil, false
	}
	file, ok := qCtx.Files[vulnerability.FileID]
	if !ok || file == nil {
		return nil, false
	}

	if rc, found := lookupRuleConfig(c.ruleConfigs, vulnerability.QueryID, vulnerability.LegacyQueryID); found {
		if rc.Severity != nil {
			vulnerability.Severity = model.Severity(strings.ToUpper(*rc.Severity))
		}
		if !c.isExternalModulePath(file.FilePath) && rulePathExcluded(file.FilePath, rc.IgnorePaths, rc.OnlyPaths) {
			contextLogger.Debug().Msgf("Dropping finding in %s for rule %s (rule path filter)",
				file.FilePath, vulnerability.QueryID)
			return nil, false
		}
	}

	if ShouldSkipVulnerability(file.Commands, vulnerability.QueryID, vulnerability.LegacyQueryID) {
		contextLogger.Debug().Msgf("Suppressing vulnerability in file %s for query '%s':%s",
			file.FilePath, vulnerability.QueryName, vulnerability.QueryID)
		markSuppressed(vulnerability, model.SuppressionKindInSource, model.SuppressionJustificationDisableInFile)
	}

	// Detect-line failures should not be reported (or drop the finding) once
	// a suppression decision has already been taken; the SARIF entry is
	// still useful even without an exact line.
	if vulnerability.Line == UndetectedVulnerabilityLine && !vulnerability.IsSuppressed {
		return nil, true
	}

	if checkComment(vulnerability.Line, file.LinesIgnore) {
		contextLogger.Debug().
			Msgf("Suppressing result by Comment at line %d", vulnerability.Line)
		markSuppressed(vulnerability, model.SuppressionKindInSource, model.SuppressionJustificationIgnoreComment)
	}

	return vulnerability, false
}

// lookupRuleConfig returns the first matching rule config for the given queryID or legacyQueryID.
func lookupRuleConfig(ruleConfigs map[string]config.IacRuleConfig, queryID, legacyQueryID string) (config.IacRuleConfig, bool) {
	if len(ruleConfigs) == 0 {
		return config.IacRuleConfig{}, false
	}
	if rc, ok := ruleConfigs[queryID]; ok {
		return rc, true
	}
	if legacyQueryID != "" {
		if rc, ok := ruleConfigs[legacyQueryID]; ok {
			return rc, true
		}
	}
	return config.IacRuleConfig{}, false
}

// rulePathExcluded returns true if the file should be dropped for a given rule
// based on its ignore-paths and only-paths lists.
func rulePathExcluded(filePath string, ignorePaths, onlyPaths []string) bool {
	return pathutil.Excluded(filePath, ignorePaths, onlyPaths)
}

func (c *Inspector) isExternalModulePath(filePath string) bool {
	for root := range c.externalPathRoots {
		rel, err := filepath.Rel(root, filepath.Clean(filePath))
		if err == nil && rel != parentDirectoryPath &&
			!strings.HasPrefix(rel, parentDirectoryPath+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// markSuppressed records the first suppression decision; later gates are
// no-ops so SARIF output stays stable.
func markSuppressed(vulnerability *model.Vulnerability, kind, justification string) {
	if vulnerability.IsSuppressed {
		return
	}
	vulnerability.IsSuppressed = true
	vulnerability.SuppressionKind = kind
	vulnerability.SuppressionJustification = justification
}

// checkComment checks if the vulnerability should be skipped from comment
func checkComment(line int, ignoreLines []int) bool {
	for _, ignoreLine := range ignoreLines {
		if line == ignoreLine {
			return true
		}
	}
	return false
}

// Platform keys used to bucket documents and route queries to per-platform payloads.
const (
	platformCommon         = "common"
	platformK8s            = "k8s"
	platformKubernetes     = "kubernetes"
	platformBicep          = "bicep"
	platformAzureRM        = "azureresourcemanager"
	platformKnative        = "knative"
	platformServerlessFW   = "serverlessfw"
	platformCloudFormation = "cloudformation"
)

// platformPayloads holds per-platform OPA input payloads built once per scan.
type platformPayloads struct {
	byPlatform map[string]ast.Value
	full       ast.Value
}

// partitionDocsByPlatform groups parsed documents by their file's platform
// bucket(s); multi-platform files (Knative, Serverless Framework) land in both
// their own and their parent platform's bucket via platformBucketKeys.
// Documents with an undetermined platform are collected separately and later
// merged into every platform's payload so no rule loses coverage.
func partitionDocsByPlatform(
	filesMap map[string]*model.FileMetadata,
	combinedDocs, moduleDocs []model.Document,
) (byPlatform map[string][]interface{}, unknown, all []interface{}) {
	byPlatform = make(map[string][]interface{})
	all = make([]interface{}, 0, len(combinedDocs)+len(moduleDocs))
	addDoc := func(d model.Document) {
		m := map[string]interface{}(d)
		all = append(all, m)
		id, _ := d["id"].(string)
		var platform string
		if fm := filesMap[id]; fm != nil {
			platform = fm.Platform
		}
		keys := platformBucketKeys(platform)
		if len(keys) == 0 {
			unknown = append(unknown, m)
			return
		}
		for _, key := range keys {
			byPlatform[key] = append(byPlatform[key], m)
		}
	}
	for _, d := range combinedDocs {
		addDoc(d)
	}
	for _, d := range moduleDocs {
		addDoc(d)
	}
	return byPlatform, unknown, all
}

// buildPlatformPayloads partitions documents by platform and builds one OPA
// payload per queried platform. Common-platform queries receive the full
// cross-platform payload.
func (c *Inspector) buildPlatformPayloads(
	ctx context.Context,
	filesMap map[string]*model.FileMetadata,
	combinedDocs, moduleDocs []model.Document,
	queries []model.QueryMetadata,
) (platformPayloads, error) {
	docsByPlatform, unknownDocs, allDocs := partitionDocsByPlatform(filesMap, combinedDocs, moduleDocs)

	makePayload := func(ds []interface{}) (ast.Value, error) {
		return c.interfaceToPayloadValue(
			ctx,
			map[string]interface{}{"document": ds},
			make(map[uintptr]ast.Value),
		)
	}

	needFullPayload := false
	neededPlatforms := make(map[string]bool)
	for i := range queries {
		key := canonicalPlatformKey(queries[i].Platform)
		if key == platformCommon {
			needFullPayload = true
			continue
		}
		neededPlatforms[key] = true
	}

	out := platformPayloads{
		byPlatform: make(map[string]ast.Value, len(neededPlatforms)),
	}
	fullPayloadBuilt := false
	for key := range neededPlatforms {
		ds := docsByPlatform[key]
		if len(unknownDocs) > 0 {
			combined := make([]interface{}, 0, len(ds)+len(unknownDocs))
			combined = append(combined, ds...)
			combined = append(combined, unknownDocs...)
			ds = combined
		}
		pv, err := makePayload(ds)
		if err != nil {
			return platformPayloads{}, err
		}
		out.byPlatform[key] = pv
		if needFullPayload &&
			len(neededPlatforms) == 1 &&
			len(unknownDocs) == 0 &&
			len(ds) == len(allDocs) {
			out.full = pv
			fullPayloadBuilt = true
		}
	}

	if needFullPayload && !fullPayloadBuilt {
		pv, err := makePayload(allDocs)
		if err != nil {
			return platformPayloads{}, err
		}
		out.full = pv
	}

	return out, nil
}

// canonicalPlatformKey maps a query- or file-level platform name to the single
// lowercased key used to bucket documents and select per-platform payloads.
// Kubernetes is keyed "kubernetes" (query metadata uses "k8s"), and Bicep is
// scanned by the Azure Resource Manager rules (Bicep transpiles to ARM).
func canonicalPlatformKey(p string) string {
	p = strings.ToLower(p)
	switch p {
	case platformK8s:
		return platformKubernetes
	case platformBicep:
		return platformAzureRM
	}
	return p
}

// platformBucketKeys returns every payload bucket a document of the given
// platform must belong to. Knative manifests are also scanned by the Kubernetes
// rules and Serverless Framework manifests by the CloudFormation rules; these
// fan-outs mirror multiPlatformTypeCheck in the analyzer (which force-loads the
// parent platform's queries), so those documents are placed in both their own
// bucket and their parent platform's bucket. Every other platform (including
// Crossplane, which is classified consistently by the sink and has its own
// queries) maps to a single bucket. Returns nil for an undetermined platform so
// the caller can treat it as unknown.
func platformBucketKeys(platform string) []string {
	key := canonicalPlatformKey(platform)
	switch key {
	case "":
		return nil
	case platformKnative:
		return []string{platformKnative, platformKubernetes}
	case platformServerlessFW:
		return []string{platformServerlessFW, platformCloudFormation}
	}
	return []string{key}
}

// selectPlatformPayload returns the document payload a query should evaluate
// against: its own platform's payload, or the full payload for common rules
// (and as a defensive fallback when a platform payload was not built).
func selectPlatformPayload(queryPlatform string, byPlatform map[string]ast.Value, full ast.Value) ast.Value {
	if key := canonicalPlatformKey(queryPlatform); key != platformCommon {
		if p, ok := byPlatform[key]; ok {
			return p
		}
	}
	return full
}

// contains is a simple method to check if a slice
// contains an entry
func contains(s []string, e string) bool {
	if canonicalPlatformKey(e) == platformCommon {
		return true
	}
	e = canonicalPlatformKey(e)
	for _, a := range s {
		if strings.EqualFold(a, e) {
			return true
		}
	}
	return false
}

func isDisabled(queries, queryID, legacyQueryID string, output bool) bool {
	for _, query := range strings.Split(queries, ",") {
		if strings.EqualFold(query, queryID) || strings.EqualFold(query, legacyQueryID) {
			return output
		}
	}

	return !output
}

// ShouldSkipVulnerability verifies if the vulnerability in question should be ignored through comment commands
func ShouldSkipVulnerability(command model.CommentsCommands, queryID, legacyQueryID string) bool {
	if queries, ok := command["enable"]; ok {
		return isDisabled(queries, queryID, legacyQueryID, false)
	}
	if queries, ok := command["disable"]; ok {
		return isDisabled(queries, queryID, legacyQueryID, true)
	}
	return false
}

func prepareQueries(queries []model.QueryMetadata, commonLibrary source.RegoLibraries,
	platformLibraries map[string]source.RegoLibraries, tracker Tracker) (QueryLoader, error) {
	// track queries loaded
	sum := 0
	for _, metadata := range queries {
		tracker.TrackQueryLoad(metadata.Aggregation)
		sum += metadata.Aggregation
	}

	// Pre-parse shared Rego libraries once; each LoadQuery passes them via
	// rego.ParsedModule(). Parse failure is fatal (static embedded code).
	parsedCommon, err := ast.ParseModuleWithOpts("Common", commonLibrary.LibraryCode,
		ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return QueryLoader{}, errors.Wrap(err, "failed to parse Common Rego library")
	}

	parsedGeneric := make(map[string]*ast.Module, len(platformLibraries))
	platformKeyBases := make(map[string]uint64, len(platformLibraries))
	for platform, lib := range platformLibraries {
		mod, parseErr := ast.ParseModuleWithOpts("Generic", lib.LibraryCode,
			ast.ParserOptions{RegoVersion: ast.RegoV1})
		if parseErr != nil {
			return QueryLoader{}, errors.Wrapf(parseErr, "failed to parse Generic Rego library for platform %s", platform)
		}
		parsedGeneric[platform] = mod
		platformKeyBases[platform] = hashFields(
			commonLibrary.LibraryCode,
			commonLibrary.LibraryInputData,
			lib.LibraryCode,
			lib.LibraryInputData,
		)
	}

	return QueryLoader{
		commonLibrary:     commonLibrary,
		platformLibraries: platformLibraries,
		querySum:          sum,
		QueriesMetadata:   queries,
		parsedCommon:      parsedCommon,
		parsedGeneric:     parsedGeneric,
		platformKeyBases:  platformKeyBases,
	}, nil
}

// buildMergedInputData merges the platform library, common library and (when
// present) module input data into a single JSON document for a query.
func (q *QueryLoader) buildMergedInputData(query *model.QueryMetadata,
	modules []tfmodules.ParsedModule) (string, error) {
	platformGeneralQuery, ok := q.platformLibraries[query.Platform]
	if !ok {
		return "", errors.New("failed to get platform library")
	}
	mergedInputData, err := source.MergeInputData(platformGeneralQuery.LibraryInputData, query.InputData)
	if err != nil {
		return "", errors.Wrapf(err, "could not merge %s library input data", query.Platform)
	}
	mergedInputData, err = source.MergeInputData(q.commonLibrary.LibraryInputData, mergedInputData)
	if err != nil {
		return "", errors.Wrap(err, "could not merge common library input data")
	}
	if modules != nil {
		mergedInputData, err = source.MergeModulesData(modules, mergedInputData)
		if err != nil {
			return "", errors.Wrap(err, "could not merge modules input data")
		}
	}
	return mergedInputData, nil
}

// precomputeBaseInputData builds, once per platform, the merged input data for
// queries that carry no custom InputData. The common/platform library data and
// the module payload are identical across such queries, so doing this once
// avoids re-serializing the (potentially large) module set for every query.
func (q *QueryLoader) precomputeBaseInputData(modules []tfmodules.ParsedModule) map[string]string {
	base := make(map[string]string, len(q.platformLibraries))
	for platform := range q.platformLibraries {
		data, err := q.buildMergedInputData(&model.QueryMetadata{Platform: platform}, modules)
		if err != nil {
			continue
		}
		base[platform] = data
	}
	return base
}

// precomputeBaseStores builds one inmem.Store per platform from the already-merged
// input data strings. The store is read-only after construction and is safe for
// concurrent use by all query goroutines, avoiding repeated JSON parsing of the
// same large input-data payload for every LoadQuery call.
func precomputeBaseStores(baseInputData map[string]string) map[string]storage.Store {
	stores := make(map[string]storage.Store, len(baseInputData))
	for platform, data := range baseInputData {
		stores[platform] = inmem.NewFromReader(bytes.NewBufferString(data))
	}
	return stores
}

// LoadQuery loads the query into memory so it can be freed when not used anymore.
//
// baseStores holds one shared, read-only inmem store per platform (the merged
// library + module input data for this scan); baseDataHashes holds a hash of
// each store's data. When the query carries no custom InputData it uses the
// shared base store, and its compiled *PreparedEvalQuery is served from / stored
// in the process-global preparedQueryCache — the cache key folds in the base
// data hash, so a compiled query (whose store bakes in this scan's data) is only
// reused by a later scan whose base data is byte-identical. This makes warm
// scans skip the expensive PrepareForEval compile even when Terraform module
// data is present, as long as that data is unchanged.
func (q *QueryLoader) LoadQuery(ctx context.Context, query *model.QueryMetadata,
	modules []tfmodules.ParsedModule,
	baseStores map[string]storage.Store, baseDataHashes map[string]uint64,
	cacheEnabled bool) (*rego.PreparedEvalQuery, error) {
	platformGeneralQuery, ok := q.platformLibraries[query.Platform]
	if !ok {
		return nil, errors.New("failed to get platform library")
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		hasCustomInput := !source.IsEmptyInputData(query.InputData)
		prebuilt, hasBaseStore := baseStores[query.Platform]

		// The compiled query is cacheable only when the caller enabled the cache
		// (server mode via --use-rules-cache) AND it uses the shared per-platform
		// base store (no custom per-query InputData, and a base store exists for
		// the platform). The cache key folds in the base data hash so a cached
		// query is reused only by a scan with identical base data — the store it
		// bakes in.
		useCache := cacheEnabled && hasBaseStore && !hasCustomInput
		var cacheKey uint64
		if useCache {
			cacheKey = preparedCacheKey(query, q.platformKeyBases[query.Platform], baseDataHashes[query.Platform])
			if cached, ok := preparedQueryCache.Load(cacheKey); ok {
				return cached.(*rego.PreparedEvalQuery), nil
			}
		}

		var store storage.Store
		if useCache {
			store = prebuilt
		} else {
			mergedInputData, err := q.buildMergedInputData(query, modules)
			if err != nil {
				return nil, err
			}
			store = inmem.NewFromReader(bytes.NewBufferString(mergedInputData))
		}

		// Build the rego.New() options. When pre-parsed AST modules are
		// available, pass them via rego.ParsedModule() to skip re-tokenizing
		// the ~82 KB of shared library Rego text on every call. Each
		// PrepareForEval still compiles its own fresh module set, so there is
		// no shared mutable compiler state and no concurrency hazard.
		opts := []func(*rego.Rego){
			rego.Query(regoQuery),
			rego.SetRegoVersion(ast.RegoV1),
			rego.Store(store),
			rego.UnsafeBuiltins(unsafeRegoFunctions),
		}
		if q.parsedCommon != nil {
			opts = append(opts, rego.ParsedModule(q.parsedCommon))
		} else {
			opts = append(opts, rego.Module("Common", q.commonLibrary.LibraryCode))
		}
		if parsedGen, ok := q.parsedGeneric[query.Platform]; ok {
			opts = append(opts, rego.ParsedModule(parsedGen))
		} else {
			opts = append(opts, rego.Module("Generic", platformGeneralQuery.LibraryCode))
		}
		opts = append(opts, rego.Module(query.Query, query.Content))

		opaQuery, err := rego.New(opts...).PrepareForEval(ctx)
		if err != nil {
			return nil, err
		}

		if useCache {
			// the duplicate compiled query is discarded.
			actual, _ := preparedQueryCache.LoadOrStore(cacheKey, &opaQuery)
			return actual.(*rego.PreparedEvalQuery), nil
		}

		return &opaQuery, nil
	}
}

// pkgDatadogDecl matches the `package datadog` declaration at the head of every
// rule, so it can be rewritten to a unique per-rule package for shared compilation.
var pkgDatadogDecl = regexp.MustCompile(`(?m)^(\s*)package\s+datadog\b`)

// loadSharedQueries compiles all given queries together with their libraries in
// a SINGLE ast.Compiler per platform, instead of compiling each rule in its own
// isolated compiler. Every rule is rewritten from `package datadog` to a unique
// `package datadog.q<i>` so the rules no longer collide and can co-exist in one
// compiler; the shared common+platform library AST then exists once instead of
// being copied into every compiled query (the dominant retained-heap cost).
//
// It returns a map from the caller's query index to the prepared query. A rule
// that fails to parse or whose platform has no base store is skipped (logged),
// preserving the isolated path's "skip and continue" behavior. Rule identity,
// findings, and SARIF are unaffected: the package rename is internal to
// compilation and never reaches QueryMetadata or the emitted result payload.
func (q *QueryLoader) loadSharedQueries(ctx context.Context, queries []model.QueryMetadata,
	baseStores map[string]storage.Store) map[int]*rego.PreparedEvalQuery {
	contextLogger := logger.FromContext(ctx)

	// Group query indices by platform: one shared compiler is built per platform
	// because libraries and the base store are platform-specific.
	indicesByPlatform := make(map[string][]int)
	for i := range queries {
		indicesByPlatform[queries[i].Platform] = append(indicesByPlatform[queries[i].Platform], i)
	}

	prepared := make(map[int]*rego.PreparedEvalQuery, len(queries))
	for platform, indices := range indicesByPlatform {
		store, ok := baseStores[platform]
		if !ok {
			contextLogger.Warn().Msgf("shared compile: no base store for platform %s, skipping %d rules", platform, len(indices))
			continue
		}
		platformLib, ok := q.platformLibraries[platform]
		if !ok {
			contextLogger.Warn().Msgf("shared compile: no library for platform %s, skipping %d rules", platform, len(indices))
			continue
		}

		// Parse libraries + every rule (renamed) into one module set. A rule that
		// fails to parse is dropped here, individually, BEFORE the shared compile —
		// so one malformed rule cannot fail the whole batch at the parse stage.
		modules := map[string]*ast.Module{
			"Common":  q.parsedCommon,
			"Generic": q.parsedGeneric[platform],
		}
		if modules["Common"] == nil {
			modules["Common"], _ = ast.ParseModuleWithOpts("Common", q.commonLibrary.LibraryCode,
				ast.ParserOptions{RegoVersion: ast.RegoV1})
		}
		if modules["Generic"] == nil {
			modules["Generic"], _ = ast.ParseModuleWithOpts("Generic", platformLib.LibraryCode,
				ast.ParserOptions{RegoVersion: ast.RegoV1})
		}
		// queryPath maps each surviving rule index to its unique query path.
		queryPath := make(map[int]string, len(indices))
		for _, i := range indices {
			// A rule with custom InputData needs a per-query store that merges that
			// data; the shared path can only offer the per-platform base store
			// (built without any rule's InputData). Skip such rules here so the
			// worker falls back to the isolated LoadQuery, which builds the correct
			// store. Without this, a rule whose Rego reads its inputData would run
			// as if that data were absent (wrong findings / false negatives).
			if !source.IsEmptyInputData(queries[i].InputData) {
				continue
			}
			renamed := pkgDatadogDecl.ReplaceAllString(queries[i].Content, fmt.Sprintf("${1}package datadog.q%d", i))
			mod, parseErr := ast.ParseModuleWithOpts(queries[i].Query, renamed,
				ast.ParserOptions{RegoVersion: ast.RegoV1})
			if parseErr != nil {
				contextLogger.Warn().Err(parseErr).Msgf("shared compile: rule %s failed to parse, skipping", queries[i].Query)
				continue
			}
			modules[fmt.Sprintf("rule%d", i)] = mod
			queryPath[i] = fmt.Sprintf("data.datadog.q%d.DatadogPolicy", i)
		}

		compiler := ast.NewCompiler().WithCapabilities(safeCapabilities())
		compiler.Compile(modules)
		if compiler.Failed() {
			// A rule that parsed but failed semantic compilation poisons the whole
			// batch. Fall back to isolated compilation for this platform's rules so
			// correctness is never sacrificed for the memory optimization.
			contextLogger.Warn().Msgf("shared compile failed for platform %s (%v); falling back to isolated compilation",
				platform, compiler.Errors)
			continue
		}

		// Prepare each rule's eval query against the one shared compiler. They all
		// reference the same compiled library AST, so it is retained once.
		for _, i := range indices {
			path, ok := queryPath[i]
			if !ok {
				continue // rule was dropped at parse stage
			}
			pq, prepErr := rego.New(
				rego.Query(fmt.Sprintf("result = %s", path)),
				rego.SetRegoVersion(ast.RegoV1),
				rego.Compiler(compiler),
				rego.Store(store),
				rego.UnsafeBuiltins(unsafeRegoFunctions),
			).PrepareForEval(ctx)
			if prepErr != nil {
				contextLogger.Warn().Err(prepErr).Msgf("shared compile: failed to prepare rule %s, skipping", queries[i].Query)
				continue
			}
			p := pq
			prepared[i] = &p
		}
	}
	return prepared
}

// loadSharedQueriesCached returns the latest matching co-compiled ruleset.
// Identical cold misses are coalesced by key, while different rulesets compile
// concurrently. The mutex protects only the bounded single-entry cache.
func (q *QueryLoader) loadSharedQueriesCached(ctx context.Context, queries []model.QueryMetadata,
	baseStores map[string]storage.Store, baseDataHashes map[string]uint64,
) (preparedQueries map[int]*rego.PreparedEvalQuery, cacheHit bool, err error) {
	key := sharedCacheKey(queries, q.platformKeyBases, baseDataHashes)
	flightKey := strconv.FormatUint(key, 16)
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}

		sharedPreparedQueryCache.Lock()
		if sharedPreparedQueryCache.queries != nil && sharedPreparedQueryCache.key == key {
			cached := sharedPreparedQueryCache.queries
			sharedPreparedQueryCache.Unlock()
			return cached, true, nil
		}
		sharedPreparedQueryCache.Unlock()

		resultCh := sharedPreparedQueryCache.flight.DoChan(flightKey, func() (any, error) {
			// Another caller may have populated the cache between the initial check
			// and this keyed singleflight call.
			sharedPreparedQueryCache.Lock()
			if sharedPreparedQueryCache.queries != nil && sharedPreparedQueryCache.key == key {
				cached := sharedPreparedQueryCache.queries
				sharedPreparedQueryCache.Unlock()
				return sharedQueryCacheResult{queries: cached, cacheHit: true}, nil
			}
			sharedPreparedQueryCache.Unlock()

			prepared := q.loadSharedQueries(ctx, queries, baseStores)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			sharedPreparedQueryCache.Lock()
			sharedPreparedQueryCache.key = key
			sharedPreparedQueryCache.queries = prepared
			sharedPreparedQueryCache.Unlock()
			return sharedQueryCacheResult{queries: prepared}, nil
		})

		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case call := <-resultCh:
			if call.Err != nil {
				if err := ctx.Err(); err != nil {
					return nil, false, err
				}
				// The singleflight leader was canceled while this caller is still
				// active. Retry so an active caller becomes the new leader.
				if errors.Is(call.Err, context.Canceled) || errors.Is(call.Err, context.DeadlineExceeded) {
					continue
				}
				return nil, false, call.Err
			}
			result := call.Val.(sharedQueryCacheResult)
			return result.queries, result.cacheHit || call.Shared, nil
		}
	}
}

func parseJsonencodeHCL(ctx context.Context, input string) (ast.Value, error) {
	contextLogger := logger.FromContext(ctx)
	input = strings.TrimSpace(input)

	// Remove Terraform interpolation
	if strings.HasPrefix(input, "${") && strings.HasSuffix(input, "}") {
		input = strings.TrimPrefix(input, "${")
		input = strings.TrimSuffix(input, "}")
	}

	// Validate jsonencode(...) format
	const prefix = "jsonencode("
	const suffix = ")"

	if !strings.HasPrefix(input, prefix) || !strings.HasSuffix(input, suffix) {
		err := fmt.Errorf("expected jsonencode(...) format, got: %s", input)
		contextLogger.Error().Msg(err.Error())
		return nil, err
	}

	// Extract inner expression
	inner := strings.TrimSuffix(strings.TrimPrefix(input, prefix), suffix)

	expr, diags := hclsyntax.ParseExpression([]byte(inner), "inline_expr.hcl", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		err := fmt.Errorf("HCL parse error: %s", diags.Error())
		contextLogger.Error().Msg(err.Error())
		return nil, err
	}

	val, err := expressionToAST(expr)
	if err != nil {
		err = fmt.Errorf("expression to AST failed: %w", err)
		contextLogger.Error().Msg(err.Error())
		return nil, err
	}

	return val, nil
}

// expressionToAST converts HCL expression to OPA ast.Value
func expressionToAST(expr hclsyntax.Expression) (ast.Value, error) {
	return hclexpr.Dispatch(expr, &inspectorExprVisitor{})
}

// inspectorExprVisitor implements hclexpr.Visitor[ast.Value] for expressionToAST.
type inspectorExprVisitor struct{}

func (v *inspectorExprVisitor) VisitLiteralValue(e *hclsyntax.LiteralValueExpr) (ast.Value, error) {
	return literalToAst(e)
}
func (v *inspectorExprVisitor) VisitTemplateExpr(e *hclsyntax.TemplateExpr) (ast.Value, error) {
	return expressionToASTTemplateExpr(e), nil
}
func (v *inspectorExprVisitor) VisitScopeTraversal(e *hclsyntax.ScopeTraversalExpr) (ast.Value, error) {
	return ast.String(scopeTraversalPath(e.Traversal)), nil
}
func (v *inspectorExprVisitor) VisitIndexExpr(e *hclsyntax.IndexExpr) (ast.Value, error) {
	return expressionToASTIndexExpr(e), nil
}
func (v *inspectorExprVisitor) VisitRelativeTraversal(e *hclsyntax.RelativeTraversalExpr) (ast.Value, error) {
	return expressionToASTRelativeTraversalExpr(e), nil
}
func (v *inspectorExprVisitor) VisitFunctionCall(e *hclsyntax.FunctionCallExpr) (ast.Value, error) {
	return expressionToASTFunctionCallExpr(e), nil
}
func (v *inspectorExprVisitor) VisitConditional(e *hclsyntax.ConditionalExpr) (ast.Value, error) {
	return expressionToASTConditionalExpr(e), nil
}
func (v *inspectorExprVisitor) VisitTupleCons(e *hclsyntax.TupleConsExpr) (ast.Value, error) {
	return expressionToASTTupleConsExpr(e), nil
}
func (v *inspectorExprVisitor) VisitObjectCons(e *hclsyntax.ObjectConsExpr) (ast.Value, error) {
	return expressionToASTObjectConsExpr(e), nil
}
func (v *inspectorExprVisitor) VisitTemplateJoin(e *hclsyntax.TemplateJoinExpr) (ast.Value, error) {
	// A template join wraps the for-loop of a %{for}...%{endfor} template
	// directive; render the underlying for-expression.
	return expressionToAST(e.Tuple)
}
func (v *inspectorExprVisitor) VisitBinaryOp(e *hclsyntax.BinaryOpExpr) (ast.Value, error) {
	return expressionToASTBinaryOpExpr(e), nil
}
func (v *inspectorExprVisitor) VisitUnaryOp(e *hclsyntax.UnaryOpExpr) (ast.Value, error) {
	return expressionToASTUnaryOpExpr(e), nil
}
func (v *inspectorExprVisitor) VisitForExpr(e *hclsyntax.ForExpr) (ast.Value, error) {
	return expressionToASTForExpr(e), nil
}
func (v *inspectorExprVisitor) VisitSplatExpr(e *hclsyntax.SplatExpr) (ast.Value, error) {
	return expressionToASTSplatExpr(e), nil
}
func (v *inspectorExprVisitor) VisitAnonSymbol(_ *hclsyntax.AnonSymbolExpr) (ast.Value, error) {
	// The anonymous splat item renders as an empty string so that a trailing
	// traversal (e.g. .id) composes onto the splat base in VisitSplatExpr.
	return ast.String(""), nil
}
func (v *inspectorExprVisitor) VisitExprSyntaxError(_ *hclsyntax.ExprSyntaxError) (ast.Value, error) {
	return ast.String("__UNSUPPORTED_EXPR__"), nil
}
func (v *inspectorExprVisitor) VisitDefault(e hclsyntax.Expression) (ast.Value, error) {
	return ast.String("__UNSUPPORTED_EXPR__"), nil
}

func expressionToASTTemplateExpr(e *hclsyntax.TemplateExpr) ast.Value {
	result := ""
	for _, part := range e.Parts {
		v, err := expressionToAST(part)
		s := astValueToSimpleString(v)
		if err != nil || v == nil || s == "__UNSUPPORTED_EXPR__" || s == "__UNSUPPORTED_LITERAL__" {
			result += "${...}"
		} else {
			result += s
		}
	}
	return ast.String(result)
}

func expressionToASTTupleConsExpr(e *hclsyntax.TupleConsExpr) ast.Value {
	terms := make([]*ast.Term, 0, len(e.Exprs))
	for _, item := range e.Exprs {
		v, err := expressionToAST(item)
		if err != nil {
			v = ast.String(unresolvedPlaceholder)
		}
		terms = append(terms, ast.NewTerm(v))
	}
	return ast.NewArray(terms...)
}

func expressionToASTObjectConsExpr(e *hclsyntax.ObjectConsExpr) ast.Value {
	obj := ast.NewObject()
	for _, item := range e.Items {
		keyExpr := normalizeKeyExpr(item.KeyExpr)
		keyVal, err := expressionToAST(keyExpr)
		if err != nil {
			continue
		}
		strKey, ok := keyVal.(ast.String)
		if !ok {
			continue
		}
		valVal, err := expressionToAST(item.ValueExpr)
		if err != nil {
			valVal = ast.String(unresolvedPlaceholder)
		}
		obj.Insert(ast.NewTerm(strKey), ast.NewTerm(valVal))
	}
	return obj
}

func expressionToASTIndexExpr(e *hclsyntax.IndexExpr) ast.Value {
	collV, err1 := expressionToAST(e.Collection)
	keyV, err2 := expressionToAST(e.Key)
	if err1 != nil || err2 != nil {
		return ast.String(unresolvedPlaceholder)
	}
	collStr := astValueToSimpleString(collV)
	keyStr := astValueToSimpleString(keyV)
	return ast.String(collStr + "[" + keyStr + "]")
}

func expressionToASTRelativeTraversalExpr(e *hclsyntax.RelativeTraversalExpr) ast.Value {
	sourceVal, err := expressionToAST(e.Source)
	if err != nil {
		return ast.String(unresolvedPlaceholder)
	}
	sourceStr := astValueToSimpleString(sourceVal)
	for _, step := range e.Traversal {
		switch s := step.(type) {
		case hcl.TraverseAttr:
			sourceStr += "." + s.Name
		case hcl.TraverseIndex:
			switch s.Key.Type() {
			case cty.Number:
				sourceStr += "[" + s.Key.AsBigFloat().String() + "]"
			case cty.String:
				sourceStr += "[" + s.Key.AsString() + "]"
			}
		}
	}
	return ast.String(sourceStr)
}

func expressionToASTConditionalExpr(e *hclsyntax.ConditionalExpr) ast.Value {
	condV, _ := expressionToAST(e.Condition)
	trueV, _ := expressionToAST(e.TrueResult)
	falseV, _ := expressionToAST(e.FalseResult)
	return ast.String(astValueToSimpleString(condV) + " ? " + astValueToSimpleString(trueV) + " : " + astValueToSimpleString(falseV))
}

func expressionToASTFunctionCallExpr(e *hclsyntax.FunctionCallExpr) ast.Value {
	args := make([]string, 0, len(e.Args))
	for _, arg := range e.Args {
		v, err := expressionToAST(arg)
		if err != nil {
			args = append(args, unresolvedPlaceholder)
			continue
		}
		args = append(args, astValueToSimpleString(v))
	}
	return ast.String(e.Name + "(" + strings.Join(args, ", ") + ")")
}

func expressionToASTBinaryOpExpr(e *hclsyntax.BinaryOpExpr) ast.Value {
	lhsV, _ := expressionToAST(e.LHS)
	rhsV, _ := expressionToAST(e.RHS)
	return ast.String(astValueToSimpleString(lhsV) + " " + hclexpr.BinaryOpSymbol(e.Op) + " " + astValueToSimpleString(rhsV))
}

func expressionToASTUnaryOpExpr(e *hclsyntax.UnaryOpExpr) ast.Value {
	valV, _ := expressionToAST(e.Val)
	return ast.String(hclexpr.UnaryOpSymbol(e.Op) + astValueToSimpleString(valV))
}

func expressionToASTForExpr(e *hclsyntax.ForExpr) ast.Value {
	collV, _ := expressionToAST(e.CollExpr)
	valV, _ := expressionToAST(e.ValExpr)
	collStr := astValueToSimpleString(collV)
	valStr := astValueToSimpleString(valV)
	var b strings.Builder
	if e.KeyExpr != nil {
		keyV, _ := expressionToAST(e.KeyExpr)
		keyStr := astValueToSimpleString(keyV)
		b.WriteString("{for ")
		b.WriteString(e.KeyVar)
		b.WriteString(", ")
		b.WriteString(e.ValVar)
		b.WriteString(" in ")
		b.WriteString(collStr)
		b.WriteString(" : ")
		b.WriteString(keyStr)
		b.WriteString(" => ")
		b.WriteString(valStr)
		if e.CondExpr != nil {
			condV, _ := expressionToAST(e.CondExpr)
			b.WriteString(" if ")
			b.WriteString(astValueToSimpleString(condV))
		}
		b.WriteString("}")
	} else {
		b.WriteString("[for ")
		if e.KeyVar != "" {
			b.WriteString(e.KeyVar)
			b.WriteString(", ")
		}
		b.WriteString(e.ValVar)
		b.WriteString(" in ")
		b.WriteString(collStr)
		b.WriteString(" : ")
		b.WriteString(valStr)
		if e.CondExpr != nil {
			condV, _ := expressionToAST(e.CondExpr)
			b.WriteString(" if ")
			b.WriteString(astValueToSimpleString(condV))
		}
		b.WriteString("]")
	}
	return ast.String(b.String())
}

func expressionToASTSplatExpr(e *hclsyntax.SplatExpr) ast.Value {
	sourceV, _ := expressionToAST(e.Source)
	base := astValueToSimpleString(sourceV) + "[*]"
	// e.Each is a traversal rooted at the anonymous item symbol (which renders
	// as an empty string), so rendering it yields just the trailing traversal
	// (e.g. ".id" for var.list[*].id, or "" for a bare var.list[*]).
	if e.Each != nil && e.Each != e.Source {
		eachV, err := expressionToAST(e.Each)
		if err == nil {
			return ast.String(base + astValueToSimpleString(eachV))
		}
	}
	return ast.String(base)
}

func scopeTraversalPath(t hcl.Traversal) string {
	items := make([]string, 0, len(t))
	for _, part := range t {
		switch step := part.(type) {
		case hcl.TraverseAttr:
			items = append(items, step.Name)
		case hcl.TraverseRoot:
			items = append(items, step.Name)
		case hcl.TraverseIndex:
			if len(items) == 0 {
				items = append(items, "")
			}
			switch step.Key.Type() {
			case cty.Number:
				items[len(items)-1] += "[" + step.Key.AsBigFloat().String() + "]"
			case cty.String:
				items[len(items)-1] += "[" + step.Key.AsString() + "]"
			}
		}
	}
	return strings.Join(items, ".")
}

func astValueToSimpleString(v ast.Value) string {
	if v == nil {
		return unresolvedPlaceholder
	}
	if s, ok := v.(ast.String); ok {
		return string(s)
	}
	return v.String()
}

// Converts HCL literal values to ast.Value
func literalToAst(expr *hclsyntax.LiteralValueExpr) (ast.Value, error) {
	val := expr.Val
	switch {
	case val.Type().Equals(cty.String):
		return ast.String(val.AsString()), nil

	case val.Type().Equals(cty.Number):
		bf := val.AsBigFloat()
		f64, _ := bf.Float64()
		return ast.NumberTerm(json.Number(fmt.Sprintf("%v", f64))).Value, nil

	case val.Type().Equals(cty.Bool):
		return ast.Boolean(val.True()), nil

	case val.IsNull():
		return ast.Null{}, nil

	default:
		return ast.String("__UNSUPPORTED_LITERAL__"), nil
	}
}

func normalizeKeyExpr(expr hclsyntax.Expression) hclsyntax.Expression {
	expr = hclexpr.Unwrap(expr)

	v := reflect.ValueOf(expr)
	if v.Kind() == reflect.Ptr && !v.IsNil() {
		elem := v.Elem()
		if elem.Kind() == reflect.Struct {
			field := elem.FieldByName("KeyExpr")
			if field.IsValid() && field.CanInterface() {
				if unwrapped, ok := field.Interface().(hclsyntax.Expression); ok {
					return normalizeKeyExpr(unwrapped)
				}
			}
		}
	}

	return expr
}
