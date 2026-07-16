/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package source

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	platformreg "github.com/DataDog/datadog-iac-scanner/pkg/platform"
	"github.com/pkg/errors"
)

// FilesystemSource this type defines a struct with a path to a filesystem source of queries
// Source is the path to the queries
// Types are the types given by the flag --type for query selection mechanism
type FilesystemSource struct {
	Source              []string
	Types               []string
	CloudProviders      []string
	Library             string
	ExperimentalQueries bool
}

const (
	// QueryFileName The default query file name
	QueryFileName = "query.rego"
	// MetadataFileName The default metadata file name
	MetadataFileName = "metadata.json"
	// LibrariesDefaultBasePath is the conventional local path for Rego libraries.
	// It is used as the default value for --libraries-path when that flag is provided.
	LibrariesDefaultBasePath = "./assets/libraries"

	emptyInputData = "{}"

	common = "Common"
)

// filesystemSourceWithLibraryOverride wraps a FilesystemSource and delegates GetQueryLibrary to a separate source.
type filesystemSourceWithLibraryOverride struct {
	*FilesystemSource
	libSource QueriesSource
}

func (f *filesystemSourceWithLibraryOverride) GetQueryLibrary(ctx context.Context, platform string) (RegoLibraries, error) {
	return f.libSource.GetQueryLibrary(ctx, platform)
}

// NewFilesystemSourceWithLibraryOverride returns a QueriesSource that loads queries from fs
// but delegates library lookups to libSource (typically a DatadogSource).
func NewFilesystemSourceWithLibraryOverride(fs *FilesystemSource, libSource QueriesSource) QueriesSource {
	return &filesystemSourceWithLibraryOverride{FilesystemSource: fs, libSource: libSource}
}

// NewFilesystemSource initializes a NewFilesystemSource with source to queries and types of queries to load
func NewFilesystemSource(ctx context.Context, source, types, cloudProviders []string,
	libraryPath string, experimentalQueries bool) *FilesystemSource {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("source.NewFilesystemSource()")

	if len(types) == 0 {
		types = []string{""}
	}

	if len(cloudProviders) == 0 {
		cloudProviders = []string{""}
	}

	for s := range source {
		source[s] = filepath.FromSlash(source[s])
	}

	return &FilesystemSource{
		Source:              source,
		Types:               types,
		CloudProviders:      cloudProviders,
		Library:             filepath.FromSlash(libraryPath),
		ExperimentalQueries: experimentalQueries,
	}
}

func getLibraryInDir(ctx context.Context, platform, libraryDirPath string) string {
	contextLogger := logger.FromContext(ctx)
	var libraryFilePath string
	err := filepath.Walk(libraryDirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.EqualFold(filepath.Base(path), platform+".rego") { // try to find the library file <platform>.rego
			libraryFilePath = path
		}
		return nil
	})
	if err != nil {
		contextLogger.Error().Msgf("Failed to analyze path %s: %s", libraryDirPath, err)
	}
	return libraryFilePath
}

// GetPathToCustomLibrary returns the path to the library file for the given platform
// within libraryDirPath, or an empty string if not found.
func GetPathToCustomLibrary(ctx context.Context, platform, libraryDirPath string) string {
	return getLibraryInDir(ctx, platform, libraryDirPath)
}

// GetQueryLibrary returns the library.rego for the platform by reading it from disk.
func (s *FilesystemSource) GetQueryLibrary(ctx context.Context, platform string) (RegoLibraries, error) {
	contextLogger := logger.FromContext(ctx)
	libraryFilePath := getLibraryInDir(ctx, strings.ToLower(platform), s.Library)
	if libraryFilePath == "" {
		return RegoLibraries{}, fmt.Errorf("no library found for platform %q in %q", platform, s.Library)
	}

	libraryCode, err := os.ReadFile(filepath.Clean(libraryFilePath))
	if err != nil {
		return RegoLibraries{}, fmt.Errorf("reading library %q: %w", libraryFilePath, err)
	}

	inputData := emptyInputData
	jsonPath := strings.TrimSuffix(libraryFilePath, ".rego") + ".json"
	if jsonBytes, err := os.ReadFile(filepath.Clean(jsonPath)); err == nil {
		inputData = string(jsonBytes)
	} else {
		contextLogger.Debug().Msgf("No input data file found for %s library", platform)
	}

	return RegoLibraries{
		LibraryCode:      string(libraryCode),
		LibraryInputData: inputData,
	}, nil
}

// CheckType checks if the queries have the type passed as an argument in '--type' flag to be loaded
func (s *FilesystemSource) CheckType(queryPlatform any) bool {
	qp := queryPlatform.(string)
	if platformreg.IsCrossPlatformRule(qp) {
		return true
	}
	if s.Types[0] != "" {
		qKey := platformreg.CompareKey(qp)
		for _, t := range s.Types {
			if platformreg.CompareKey(t) == qKey {
				return true
			}
		}
		return false
	}
	return true
}

// CheckCloudProvider checks if the queries have the cloud provider passed as an argument in '--cloud-provider' flag to be loaded
func (s *FilesystemSource) CheckCloudProvider(cloudProvider any) bool {
	if cloudProvider != nil {
		if strings.EqualFold(cloudProvider.(string), common) {
			return true
		}
		if s.CloudProviders[0] != "" {
			return strings.Contains(strings.ToUpper(strings.Join(s.CloudProviders, ",")), strings.ToUpper(cloudProvider.(string)))
		}
	}

	if s.CloudProviders[0] == "" {
		return true
	}

	return false
}

func checkQueryFilterFieldExclude(ctx context.Context, id any, queries []string) bool {
	if id == nil {
		return false
	}
	contextLogger := logger.FromContext(ctx)
	queryMetadataKey, ok := id.(string)
	if !ok {
		contextLogger.Warn().
			Msgf("Can't cast query metadata key = %v", id)
		return false
	}
	for _, excludedQuery := range queries {
		if strings.EqualFold(queryMetadataKey, excludedQuery) {
			return true
		}
	}
	return false
}

func checkQueryExclude(ctx context.Context, metadata map[string]any, queryParameters *QueryInspectorParameters) bool {
	return checkQueryFilterFieldExclude(ctx, metadata["id"], queryParameters.ExcludeQueries.ByIDs) ||
		checkQueryFilterFieldExclude(ctx, metadata["legacyId"], queryParameters.ExcludeQueries.ByIDs) ||
		checkQueryFilterFieldExclude(ctx, metadata["category"], queryParameters.ExcludeQueries.ByCategories) ||
		checkQueryFilterFieldExclude(ctx, metadata["severity"], queryParameters.ExcludeQueries.BySeverities) ||
		(!queryParameters.BomQueries && metadata["severity"] == model.SeverityTrace) ||
		checkQueryFeatureFlagDisabled(ctx, metadata, queryParameters)
}

func checkQueryFilterFieldInclude(ctx context.Context, id any, queries []string) bool {
	return len(queries) == 0 || checkQueryFilterFieldExclude(ctx, id, queries)
}

func checkQueryInclude(ctx context.Context, metadata map[string]any, queryParameters *QueryInspectorParameters) bool {
	return (checkQueryFilterFieldInclude(ctx, metadata["id"], queryParameters.IncludeQueries.ByIDs) ||
		checkQueryFilterFieldInclude(ctx, metadata["legacyId"], queryParameters.IncludeQueries.ByIDs)) &&
		checkQueryFilterFieldInclude(ctx, metadata["category"], queryParameters.IncludeQueries.ByCategories) &&
		checkQueryFilterFieldInclude(ctx, metadata["severity"], queryParameters.IncludeQueries.BySeverities)
}

func checkQueryFeatureFlagDisabled(ctx context.Context, metadata map[string]any, queryParameters *QueryInspectorParameters) bool {
	if queryParameters.FlagEvaluator == nil {
		return false
	}

	// Extract rule ID from query metadata
	ruleID, exists := metadata["id"]
	if !exists {
		return false
	}

	ruleIDStr, ok := ruleID.(string)
	if !ok {
		return false
	}

	// Extract platform from query metadata
	rulePlatformVal, exists := metadata["platform"]
	if !exists {
		return false
	}

	rulePlatformStr, ok := rulePlatformVal.(string)
	if !ok {
		return false
	}

	// Create custom variables with the rule ID and platform for feature flag evaluation
	customVariables := map[string]any{
		"KICS_RULE_ID":       ruleIDStr,
		"KICS_RULE_PLATFORM": rulePlatformStr,
	}

	contextLogger := logger.FromContext(ctx)
	// Check if the rule is disabled via feature flag

	ruleIdDisabled, err := queryParameters.FlagEvaluator.EvaluateWithOrgAndCustomVariables(featureflags.IacDisableKicsRule, customVariables)
	if err != nil {
		// If feature flag evaluation fails, log and continue (fail open)
		contextLogger.Warn().
			Err(err).Str("rule_id", ruleIDStr).
			Str("feature_flag", featureflags.IacDisableKicsRule).
			Msg("Failed to evaluate feature flag for rule")
	}

	if ruleIdDisabled {
		contextLogger.Info().Str("rule_id", ruleIDStr).Str("feature_flag", featureflags.IacDisableKicsRule).
			Msg("Rule disabled by feature flag")
		return true
	}

	// Check if the rule's platform is enabled via feature flag
	rulePlatformEnabled, err := queryParameters.FlagEvaluator.EvaluateWithOrgAndEnvAndCustomVariables(featureflags.IacEnableKicsPlatform,
		customVariables)
	if err != nil {
		// If feature flag evaluation fails, log and continue (fail open)
		contextLogger.Warn().Err(err).Str("rule_id", ruleIDStr).Str("feature_flag", featureflags.IacEnableKicsPlatform).
			Msg("Failed to evaluate feature flag for rule platform")
	}

	if !rulePlatformEnabled {
		contextLogger.Info().Str("rule_id", ruleIDStr).Str("feature_flag", featureflags.IacEnableKicsPlatform).
			Msg("Rule platform disabled by feature flag")
		return true
	}

	return false
}

// FilterQueries returns the subset of queries whose metadata passes the
// include/exclude filters in queryParameters (use-rules, ignore-rules,
// severity/category filters, TRACE/BoM gating, and feature-flag exclusions),
// plus the experimental gate. It lets query sources that don't read from disk
// (e.g. the server's pushed-rule source) apply the same filtering the
// filesystem source applies via iterateQueryDirs. A nil queryParameters returns
// the queries unchanged.
func FilterQueries(ctx context.Context, queries []model.QueryMetadata,
	queryParameters *QueryInspectorParameters) []model.QueryMetadata {
	if queryParameters == nil {
		return queries
	}
	out := make([]model.QueryMetadata, 0, len(queries))
	for _, query := range queries {
		if query.Experimental && !queryParameters.ExperimentalQueries {
			continue
		}
		if !checkQueryInclude(ctx, query.Metadata, queryParameters) ||
			checkQueryExclude(ctx, query.Metadata, queryParameters) {
			continue
		}
		out = append(out, query)
	}
	return out
}

// GetQueries returns all queries found under the source paths registered in s.Source.
// Rules are no longer embedded in the binary; provide local rule directories via s.Source.
func (s *FilesystemSource) GetQueries(ctx context.Context, queryParameters *QueryInspectorParameters) ([]model.QueryMetadata, error) {
	dirs, err := s.localQueryDirs(ctx)
	if err != nil {
		return nil, err
	}
	queries := s.iterateQueryDirs(ctx, dirs, queryParameters)
	return queries, nil
}

// localQueryDirs recursively collects sub-directories from each path in s.Source.
// It does not collect sub-directories that do not contain a query.rego and metadata.json file.
func (s *FilesystemSource) localQueryDirs(ctx context.Context) ([]string, error) {
	contextLogger := logger.FromContext(ctx)
	var dirs []string
	for _, src := range s.Source {
		evaluated, err := filepath.EvalSymlinks(src)
		if err != nil {
			fmt.Println(err)
			contextLogger.Debug().Msgf("localQueryDirs: error evaluating %s: %v", src, err)
			return nil, errors.New("unable to evaluate path: " + src)
		}
		err = filepath.WalkDir(evaluated, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				contextLogger.Debug().Msgf("localQueryDirs: error walking %s: %v", path, err)
				return err
			}
			if !d.IsDir() {
				return nil
			}
			queryPath := filepath.Join(path, QueryFileName)
			metadataPath := filepath.Join(path, MetadataFileName)
			if fileExists(queryPath) && fileExists(metadataPath) {
				dirs = append(dirs, path)
				return filepath.SkipDir
			}
			return nil
		})
		if err != nil {
			contextLogger.Debug().Msgf("localQueryDirs: error walking %s: %v", src, err)
			return nil, err
		}
	}
	if len(dirs) == 0 {
		return nil, errors.New("no valid query directories found")
	}
	return dirs, nil
}
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// iterateQueryDirs iterates all query directories and reads the respective queries
func (s *FilesystemSource) iterateQueryDirs(ctx context.Context, queryDirs []string,
	queryParameters *QueryInspectorParameters) []model.QueryMetadata {
	queries := make([]model.QueryMetadata, 0, len(queryDirs))

	for _, queryDir := range queryDirs {
		query, errRQ := ReadQueryFile(ctx, queryDir)
		if errRQ != nil {
			continue
		}

		if query.Experimental && !queryParameters.ExperimentalQueries {
			continue
		}

		if !s.CheckType(query.Metadata["platform"]) {
			continue
		}

		if !s.CheckCloudProvider(query.Metadata["cloudProvider"]) {
			continue
		}

		if !checkQueryInclude(ctx, query.Metadata, queryParameters) ||
			checkQueryExclude(ctx, query.Metadata, queryParameters) {
			continue
		}

		queries = append(queries, query)
	}
	return queries
}

// validateMetadata prevents panics when query metadata fields are missing
func validateMetadata(metadata map[string]any) (exist bool, field string) {
	fields := []string{
		"id",
		"platform",
	}
	for _, field = range fields {
		if _, exist = metadata[field]; !exist {
			return
		}
	}
	return
}

// ReadQueryFile reads query files in the local filesystem for a given path and returns a QueryMetadata struct with its
// content
func ReadQueryFile(ctx context.Context, queryDir string) (model.QueryMetadata, error) {
	queryName := filepath.Base(queryDir)
	queryFile, err := os.ReadFile(filepath.Clean(filepath.Join(queryDir, QueryFileName)))
	if err != nil {
		return model.QueryMetadata{}, fmt.Errorf("failed to read query %s: %w", queryName, err)
	}
	metadataFile, err := os.ReadFile(filepath.Clean(filepath.Join(queryDir, MetadataFileName)))
	if err != nil {
		return model.QueryMetadata{}, fmt.Errorf("failed to read query %s: %w", queryName, err)
	}
	return parseQuery(ctx, queryName, queryFile, metadataFile)
}

func parseQuery(ctx context.Context, queryName string, queryContent, metadataContent []byte) (model.QueryMetadata, error) {
	contextLogger := logger.FromContext(ctx)

	var metadata map[string]any
	if err := json.Unmarshal(metadataContent, &metadata); err != nil {
		return model.QueryMetadata{}, fmt.Errorf("failed to read query %s: %w", queryName, err)
	}

	if valid, missingField := validateMetadata(metadata); !valid {
		err := fmt.Errorf("failed to read metadata field from query %s: %s", queryName, missingField)
		contextLogger.Error().Msg(err.Error())
		return model.QueryMetadata{}, err
	}

	platform := platformreg.LibraryIdentityOrUnknown(metadata["platform"].(string))

	aggregation := 1
	if agg, ok := metadata["aggregation"]; ok {
		aggregation = int(agg.(float64))
	}

	experimental := getExperimental(metadata["experimental"])

	return model.QueryMetadata{
		Query:        queryName,
		Content:      string(queryContent),
		Metadata:     metadata,
		Platform:     platform,
		InputData:    "{}",
		Aggregation:  aggregation,
		Experimental: experimental,
	}, nil
}

func getExperimental(experimental any) bool {
	readExperimental, _ := experimental.(string)
	if readExperimental == "true" {
		return true
	} else {
		return false
	}
}
