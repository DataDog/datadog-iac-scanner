/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime/debug"
	"strings"
	"sync"
	"time"

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
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/open-policy-agent/opa/ast"           // nolint:staticcheck
	"github.com/open-policy-agent/opa/cover"         // nolint:staticcheck
	"github.com/open-policy-agent/opa/rego"          // nolint:staticcheck
	"github.com/open-policy-agent/opa/storage/inmem" // nolint:staticcheck
	"github.com/open-policy-agent/opa/topdown"       // nolint:staticcheck
	"github.com/pkg/errors"
	"github.com/zclconf/go-cty/cty"
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
	DefaultIssueType            = model.IssueTypeIncorrectValue
	unresolvedPlaceholder       = utils.UnresolvedPlaceholder

	regoQuery = utils.RegoQuery
)

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
}

// VulnerabilityBuilder represents a function that will build a vulnerability
type VulnerabilityBuilder func(ctx context.Context, qCtx *QueryContext, tracker Tracker, v interface{},
	detector *detector.DetectLine, useOldSeverities bool, computeNewSimID bool, queryDuration time.Duration) (*model.Vulnerability, error)

// PreparedQuery includes the opaQuery and its metadata
type PreparedQuery struct {
	OpaQuery rego.PreparedEvalQuery
	Metadata model.QueryMetadata
}

// Inspector represents a list of compiled queries, a builder for vulnerabilities, an information tracker
// a flag to enable coverage and the coverage report if it is enabled
type Inspector struct {
	QueryLoader    *QueryLoader
	vb             VulnerabilityBuilder
	tracker        Tracker
	failedQueries  map[string]error
	excludeResults map[string]bool
	ruleConfigs    map[string]config.IacRuleConfig
	detector       *detector.DetectLine

	repoPath             string
	enableCoverageReport bool
	coverageReport       cover.Report
	queryExecTimeout     time.Duration
	useOldSeverities     bool
	numWorkers           int
	computeNewSimID      bool
	flagEvaluator        featureflags.FlagEvaluator
}

// QueryContext contains the context where the query is executed, which scan it belongs, basic information of query,
// the query compiled and its payload
type QueryContext struct {
	Ctx           context.Context
	scanID        string
	Files         map[string]*model.FileMetadata
	Query         *PreparedQuery
	payload       *ast.Value
	BaseScanPaths []string
	FlagEvaluator featureflags.FlagEvaluator
}

var (
	unsafeRegoFunctions = map[string]struct{}{
		"http.send":   {},
		"opa.runtime": {},
	}
)

// NewInspector initializes a inspector, compiling and loading queries for scan and its tracker
func NewInspector(
	ctx context.Context,
	queriesSource source.QueriesSource,
	vb VulnerabilityBuilder,
	tracker Tracker,
	queryParameters *source.QueryInspectorParameters,
	excludeResults map[string]bool,
	ruleConfigs map[string]config.IacRuleConfig,
	repoPath string,
	queryTimeout int,
	useOldSeverities bool,
	needsLog bool,
	numWorkers int,
	computeNewSimID bool,
	flagEvaluator featureflags.FlagEvaluator,
) (*Inspector, error) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("engine.NewInspector()")

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

	queryLoader := prepareQueries(queries, commonLibrary, platformLibraries, tracker)

	failedQueries := make(map[string]error)

	if needsLog {
		contextLogger.Info().
			Msgf("Inspector initialized, number of queries=%d", queryLoader.querySum)
	}

	lineDetector := detector.NewDetectLine(tracker.GetOutputLines()).
		Add(helm.DetectKindLine{}, model.KindHELM).
		Add(docker.DetectKindLine{}, model.KindDOCKER).
		Add(terraform.DetectKindLine{}, model.KindTerraform)

	queryExecTimeout := time.Duration(queryTimeout) * time.Second

	if needsLog {
		contextLogger.Info().Msgf("Query execution timeout=%v", queryExecTimeout)
	}

	return &Inspector{
		QueryLoader:      &queryLoader,
		vb:               vb,
		tracker:          tracker,
		failedQueries:    failedQueries,
		excludeResults:   excludeResults,
		ruleConfigs:      ruleConfigs,
		detector:         lineDetector,
		repoPath:         repoPath,
		queryExecTimeout: queryExecTimeout,
		useOldSeverities: useOldSeverities,
		numWorkers:       utils.AdjustNumWorkers(numWorkers),
		computeNewSimID:  computeNewSimID,
		flagEvaluator:    flagEvaluator,
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

type InspectionJob struct {
	queryID int
}

type QueryResult struct {
	vulnerabilities []model.Vulnerability
	err             error
	queryID         int
}

// This function creates an inspection task and sends it to the jobs channel
func (c *Inspector) createInspectionJobs(jobs chan<- InspectionJob, queries []model.QueryMetadata) {
	defer close(jobs)
	for i := range queries {
		jobs <- InspectionJob{queryID: i}
	}
}

// This function performs an inspection job and sends the result to the results channel
func (c *Inspector) performInspection(ctx context.Context, scanID string, filesMap map[string]*model.FileMetadata,
	astPayload ast.Value, baseScanPaths []string,
	jobs <-chan InspectionJob, results chan<- QueryResult, queries []model.QueryMetadata,
	modules []tfmodules.ParsedModule) {
	for job := range jobs {
		select {
		case <-ctx.Done():
			// Stop accepting job and return on context cancellation
			return
		default:
		}

		queryOpa, err := c.QueryLoader.LoadQuery(ctx, &queries[job.queryID], modules)
		if err != nil {
			continue
		}

		query := &PreparedQuery{
			OpaQuery: *queryOpa,
			Metadata: queries[job.queryID],
		}

		queryContext := &QueryContext{
			Ctx:           ctx,
			scanID:        scanID,
			Files:         filesMap,
			Query:         query,
			payload:       &astPayload,
			BaseScanPaths: baseScanPaths,
			FlagEvaluator: c.flagEvaluator,
		}

		vuls, err := c.doRun(ctx, queryContext)
		if err == nil {
			c.tracker.TrackQueryExecution(query.Metadata.Aggregation)
		}
		results <- QueryResult{vulnerabilities: vuls, err: err, queryID: job.queryID}
	}
}

func (c *Inspector) Inspect(
	ctx context.Context,
	scanID string,
	files model.FileMetadatas,
	baseScanPaths []string,
	platforms []string) ([]model.Vulnerability, error) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("engine.Inspect()")

	// Instantiate local modules into synthetic resource docs; suppress duplicate module bodies.
	moduleDocs := c.instantiateLocalModules(ctx, files)

	// Must run before Combine: instantiateLocalModules clears suppressed file bodies in place.
	combinedFiles := files.Combine(ctx, false)

	vulnerabilities := make([]model.Vulnerability, 0)

	// Step 1: Parse Terraform modules
	parsedModules, err := tfmodules.ParseTerraformModules(ctx, files)
	if err != nil {
		contextLogger.Warn().Err(err).Msg("Failed to parse Terraform modules")
	}
	contextLogger.Info().Msgf("Found %d modules", len(parsedModules))

	// Step 2: Enrich modules with parsed variables
	rootDir := c.repoPath
	enrichedModules := tfmodules.ParseAllModuleVariables(ctx, parsedModules, rootDir)

	// Convert combined documents directly to OPA AST, skipping the
	// json.Marshal -> UnmarshalJSON round-trip to avoid intermediate copies.
	docs := make([]interface{}, 0, len(combinedFiles.Documents))
	for _, d := range combinedFiles.Documents {
		docs = append(docs, map[string]interface{}(d))
	}
	for _, d := range moduleDocs {
		docs = append(docs, map[string]interface{}(d))
	}
	astPayload, err := ast.InterfaceToValue(map[string]interface{}{
		"document": docs,
	})
	if err != nil {
		return vulnerabilities, err
	}

	// Transform jsonencode in payload once before running queries
	// This avoids redundant transformations and prevents race conditions
	astPayload = c.TransformJsonencodeInPayload(ctx, astPayload)

	queries := c.getQueriesByPlat(platforms)

	// Compute the file map once and share it (read-only) across all workers
	filesMap := files.ToMap()

	// Create a channel to collect the results
	results := make(chan QueryResult, len(queries))

	// Create a channel for inspection jobs
	jobs := make(chan InspectionJob, len(queries))

	var wg sync.WaitGroup

	// Start a goroutine for each worker
	for w := 0; w < c.numWorkers; w++ {
		wg.Add(1)

		go func() {
			// Decrement the counter when the goroutine completes
			defer wg.Done()
			c.performInspection(ctx, scanID, filesMap, astPayload, baseScanPaths, jobs, results, queries, enrichedModules)
		}()
	}
	// Start a goroutine to create inspection jobs
	go c.createInspectionJobs(jobs, queries)

	go func() {
		// Wait for all jobs to finish
		wg.Wait()
		// Then close the results channel
		close(results)
	}()

	// Collect all the results
	moduleVulns := make(map[string]int)
loop:
	for {
		select {
		case <-ctx.Done():
			return vulnerabilities, ctx.Err()
		case result, ok := <-results:
			if !ok {
				// Channel closed, we're done
				break loop
			}
			processResult(ctx, &result, &vulnerabilities, &moduleVulns, queries, c)
		}
	}

	for vulnerability, number := range moduleVulns {
		contextLogger.Info().Msgf("Found %d of module vulnerability %s", number, vulnerability)
	}
	return vulnerabilities, nil
}

// nolint:gocritic
func processResult(ctx context.Context, result *QueryResult,
	vulnerabilities *[]model.Vulnerability, moduleVulns *map[string]int,
	queries []model.QueryMetadata, c *Inspector) {
	contextLogger := logger.FromContext(ctx)
	if result.err != nil {
		c.failedQueries[queries[result.queryID].Query] = result.err
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

// GetFailedQueries returns a map of failed queries and the associated error
func (c *Inspector) GetFailedQueries() map[string]error {
	return c.failedQueries
}

func (c *Inspector) doRun(ctx context.Context, qCtx *QueryContext) (vulns []model.Vulnerability, err error) {
	contextLogger := logger.FromContext(ctx)
	queryStart := time.Now()
	timeoutCtx, cancel := context.WithTimeout(qCtx.Ctx, c.queryExecTimeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			errMessage := fmt.Sprintf("Recovered from panic during query '%s' run. ", qCtx.Query.Metadata.Query)
			err = fmt.Errorf("panic: %v\n%s", r, string(debug.Stack()))
			contextLogger.Err(err).Msg(errMessage)
		}
	}()

	options := []rego.EvalOption{rego.EvalParsedInput(*qCtx.payload)}

	var cov *cover.Cover
	if c.enableCoverageReport {
		cov = cover.New()
		options = append(options, rego.EvalQueryTracer(cov))
	}

	results, err := qCtx.Query.OpaQuery.Eval(timeoutCtx, options...)
	qCtx.payload = nil
	if err != nil {
		if topdown.IsCancel(err) {
			return nil, errors.Wrap(err, "query executing timeout exited")
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

	queryDuration := time.Since(queryStart)
	timeoutCtxToDecode, cancelDecode := context.WithTimeout(qCtx.Ctx, c.queryExecTimeout)
	defer cancelDecode()
	return c.DecodeQueryResults(ctx, qCtx, timeoutCtxToDecode, results, queryDuration)
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
	timeOut := false
	for _, queryResultItem := range queryResultItems {
		select {
		case <-ctxTimeout.Done():
			timeOut = true
			// nolint:staticcheck
			break
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

	if timeOut {
		contextLogger.Err(ctxTimeout.Err()).Msgf(
			"Timeout processing the results of the query: %s %s",
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
	vulnerability, err := c.vb(ctx, qCtx, c.tracker, queryResultItem, c.detector, c.useOldSeverities, c.computeNewSimID, queryDuration)
	if err != nil && err.Error() == ErrNoResult.Error() {
		// Ignoring bad results
		return nil, false
	}
	if err != nil {
		if _, ok := c.failedQueries[qCtx.Query.Metadata.Query]; !ok {
			c.failedQueries[qCtx.Query.Metadata.Query] = err
		}

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
		if rulePathExcluded(file.FilePath, rc.IgnorePaths, rc.OnlyPaths) {
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

	if _, ok := c.excludeResults[vulnerability.SimilarityID]; ok {
		contextLogger.Debug().
			Msgf("Suppressing result by SimilarityID: %s", vulnerability.SimilarityID)
		markSuppressed(vulnerability, model.SuppressionKindExternal, model.SuppressionJustificationExcludeResults)
	} else if checkComment(vulnerability.Line, file.LinesIgnore) {
		contextLogger.Debug().
			Msgf("Suppressing result by Comment: %s", vulnerability.SimilarityID)
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
	for _, pattern := range ignorePaths {
		if pathutil.MatchesPath(pattern, filePath) {
			return true
		}
	}
	if len(onlyPaths) == 0 {
		return false
	}
	for _, pattern := range onlyPaths {
		if pathutil.MatchesPath(pattern, filePath) {
			return false
		}
	}
	return true
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

// contains is a simple method to check if a slice
// contains an entry
func contains(s []string, e string) bool {
	if e == "common" {
		return true
	}
	if e == "k8s" {
		e = "kubernetes"
	}
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
	platformLibraries map[string]source.RegoLibraries, tracker Tracker) QueryLoader {
	// track queries loaded
	sum := 0
	for _, metadata := range queries {
		tracker.TrackQueryLoad(metadata.Aggregation)
		sum += metadata.Aggregation
	}
	return QueryLoader{
		commonLibrary:     commonLibrary,
		platformLibraries: platformLibraries,
		querySum:          sum,
		QueriesMetadata:   queries,
	}
}

// LoadQuery loads the query into memory so it can be freed when not used anymore
func (q QueryLoader) LoadQuery(ctx context.Context, query *model.QueryMetadata,
	modules []tfmodules.ParsedModule) (*rego.PreparedEvalQuery, error) {
	contextLogger := logger.FromContext(ctx)
	opaQuery := rego.PreparedEvalQuery{}

	platformGeneralQuery, ok := q.platformLibraries[query.Platform]
	if !ok {
		return nil, errors.New("failed to get platform library")
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		mergedInputData, err := source.MergeInputData(platformGeneralQuery.LibraryInputData, query.InputData)
		if err != nil {
			contextLogger.Debug().Msgf("Could not merge %s library input data", query.Platform)
		}
		mergedInputData, err = source.MergeInputData(q.commonLibrary.LibraryInputData, mergedInputData)
		if err != nil {
			contextLogger.Debug().Msg("Could not merge common library input data")
		}
		if modules != nil {
			mergedInputData, err = source.MergeModulesData(modules, mergedInputData)
			if err != nil {
				contextLogger.Debug().Msg("Could not merge modules input data")
			}
		}
		store := inmem.NewFromReader(bytes.NewBufferString(mergedInputData))
		opaQuery, err = rego.New(
			rego.Query(regoQuery),
			rego.SetRegoVersion(ast.RegoV1),
			rego.Module("Common", q.commonLibrary.LibraryCode),
			rego.Module("Generic", platformGeneralQuery.LibraryCode),
			rego.Module(query.Query, query.Content),
			rego.Store(store),
			rego.UnsafeBuiltins(unsafeRegoFunctions),
		).PrepareForEval(ctx)

		if err != nil {
			return nil, err
		}

		return &opaQuery, nil
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
	return ast.String("__UNSUPPORTED_EXPR__"), nil
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
func (v *inspectorExprVisitor) VisitDefault(e hclsyntax.Expression) (ast.Value, error) {
	return ast.String("__UNSUPPORTED_EXPR__"), nil
}

func expressionToASTTemplateExpr(e *hclsyntax.TemplateExpr) ast.Value {
	result := ""
	for _, part := range e.Parts {
		switch p := part.(type) {
		case *hclsyntax.LiteralValueExpr:
			if p.Val.Type().Equals(cty.String) {
				result += p.Val.AsString()
			}
		default:
			result += "${...}"
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
	if e.Each != nil && e.Each != e.Source {
		eachV, err := expressionToAST(e.Each)
		if err == nil {
			eachStr := astValueToSimpleString(eachV)
			if eachStr == base || strings.HasPrefix(eachStr, base) {
				return ast.String(eachStr)
			}
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
