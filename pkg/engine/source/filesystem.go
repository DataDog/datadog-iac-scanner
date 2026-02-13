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

	"github.com/DataDog/datadog-iac-scanner/assets"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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
	// LibrariesDefaultBasePath the path to rego libraries
	LibrariesDefaultBasePath = "./assets/libraries"

	emptyInputData = "{}"

	common = "Common"

	kicsDefault = "default"
)

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

func isDefaultLibrary(libraryPath string) bool {
	return filepath.FromSlash(libraryPath) == filepath.FromSlash(LibrariesDefaultBasePath)
}

// GetPathToCustomLibrary - returns the libraries path for a given platform
func GetPathToCustomLibrary(ctx context.Context, platform, libraryPathFlag string) string {
	contextLogger := logger.FromContext(ctx)
	libraryFilePath := kicsDefault

	if !isDefaultLibrary(libraryPathFlag) {
		contextLogger.Debug().Msgf("Trying to load custom libraries from %s", libraryPathFlag)

		library := getLibraryInDir(ctx, platform, libraryPathFlag)
		// found a library named according to the platform
		if library != "" {
			libraryFilePath = library
		}
	}

	return libraryFilePath
}

// GetQueryLibrary returns the library.rego for the platform passed in the argument
func (s *FilesystemSource) GetQueryLibrary(ctx context.Context, platform string) (RegoLibraries, error) {
	contextLogger := logger.FromContext(ctx)
	library := GetPathToCustomLibrary(ctx, platform, s.Library)

	if library == "" {
		return RegoLibraries{}, errors.New("unable to get libraries path")
	}

	// getting embedded library
	embeddedLibraryCode, errGettingEmbeddedLibrary := assets.GetEmbeddedLibrary(strings.ToLower(platform))
	if errGettingEmbeddedLibrary != nil {
		return RegoLibraries{}, errGettingEmbeddedLibrary
	}

	embeddedLibraryData, errGettingEmbeddedLibraryCode := assets.GetEmbeddedLibraryData(strings.ToLower(platform))
	if errGettingEmbeddedLibraryCode != nil {
		contextLogger.Debug().Msgf("Could not open embedded library data for %s platform", platform)
		embeddedLibraryData = emptyInputData
	}

	regoLibrary := RegoLibraries{
		LibraryCode:      embeddedLibraryCode,
		LibraryInputData: embeddedLibraryData,
	}
	return regoLibrary, nil
}

// CheckType checks if the queries have the type passed as an argument in '--type' flag to be loaded
func (s *FilesystemSource) CheckType(queryPlatform interface{}) bool {
	if queryPlatform.(string) == common {
		return true
	}
	if s.Types[0] != "" {
		for _, t := range s.Types {
			if strings.EqualFold(t, queryPlatform.(string)) {
				return true
			}
		}
		return false
	}
	return true
}

// CheckCloudProvider checks if the queries have the cloud provider passed as an argument in '--cloud-provider' flag to be loaded
func (s *FilesystemSource) CheckCloudProvider(cloudProvider interface{}) bool {
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

func checkQueryInclude(ctx context.Context, id interface{}, includedQueries []string) bool {
	contextLogger := logger.FromContext(ctx)
	queryMetadataKey, ok := id.(string)
	if !ok {
		contextLogger.Warn().
			Msgf("Can't cast query metadata key = %v", id)
		return false
	}
	for _, includedQuery := range includedQueries {
		if queryMetadataKey == includedQuery {
			return true
		}
	}
	return false
}

func checkQueryExcludeField(ctx context.Context, id interface{}, excludeQueries []string) bool {
	contextLogger := logger.FromContext(ctx)
	queryMetadataKey, ok := id.(string)
	if !ok {
		contextLogger.Warn().
			Msgf("Can't cast query metadata key = %v", id)
		return false
	}
	for _, excludedQuery := range excludeQueries {
		if strings.EqualFold(queryMetadataKey, excludedQuery) {
			return true
		}
	}
	return false
}

func checkQueryExclude(ctx context.Context, metadata map[string]interface{}, queryParameters *QueryInspectorParameters) bool {
	return checkQueryExcludeField(ctx, metadata["id"], queryParameters.ExcludeQueries.ByIDs) ||
		checkQueryExcludeField(ctx, metadata["category"], queryParameters.ExcludeQueries.ByCategories) ||
		checkQueryExcludeField(ctx, metadata["severity"], queryParameters.ExcludeQueries.BySeverities) ||
		(!queryParameters.BomQueries && metadata["severity"] == model.SeverityTrace) ||
		checkQueryFeatureFlagDisabled(ctx, metadata, queryParameters)
}

func checkQueryFeatureFlagDisabled(ctx context.Context, metadata map[string]interface{}, queryParameters *QueryInspectorParameters) bool {
	if queryParameters.FlagEvaluator == nil {
		return false
	}

	// Extract KICS ID from query metadata
	kicsID, exists := metadata["id"]
	if !exists {
		return false
	}

	kicsIDStr, ok := kicsID.(string)
	if !ok {
		return false
	}

	// Extract KICS PLATFORM from query metadata
	kicsPlatform, exists := metadata["platform"]
	if !exists {
		return false
	}

	kicsPlatformStr, ok := kicsPlatform.(string)
	if !ok {
		return false
	}

	// Create custom variables with the KICS ID
	customVariables := map[string]interface{}{
		"KICS_RULE_ID":       kicsIDStr,
		"KICS_RULE_PLATFORM": kicsPlatformStr,
	}

	contextLogger := logger.FromContext(ctx)
	// Check if the rule is disabled via feature flag

	ruleIdDisabled, err := queryParameters.FlagEvaluator.EvaluateWithOrgAndCustomVariables(featureflags.IacDisableKicsRule, customVariables)
	if err != nil {
		// If feature flag evaluation fails, log and continue (fail open)
		contextLogger.Warn().
			Err(err).Str("kics_id", kicsIDStr).
			Str("feature_flag", featureflags.IacDisableKicsRule).
			Msg("Failed to evaluate feature flag for KICS rule")
	}

	if ruleIdDisabled {
		contextLogger.Info().Str("kics_id", kicsIDStr).Str("feature_flag", featureflags.IacDisableKicsRule).
			Msg("KICS rule disabled by feature flag")
		return true
	}

	// Check if the rule is enabled via feature flag
	rulePlatformEnabled, err := queryParameters.FlagEvaluator.EvaluateWithOrgAndCustomVariables(featureflags.IacEnableKicsPlatform,
		customVariables)
	if err != nil {
		// If feature flag evaluation fails, log and continue (fail open)
		contextLogger.Warn().Err(err).Str("kics_id", kicsIDStr).Str("feature_flag", featureflags.IacEnableKicsPlatform).
			Msg("Failed to evaluate feature flag for KICS rule")
	}

	if !rulePlatformEnabled {
		contextLogger.Info().Str("kics_id", kicsIDStr).Str("feature_flag", featureflags.IacEnableKicsPlatform).
			Msg("KICS rule disabled by feature flag")
		return true
	}

	return false
}

// GetQueries walks a given filesource path returns all queries found in an array of
// QueryMetadata struct
func (s *FilesystemSource) GetQueries(ctx context.Context, queryParameters *QueryInspectorParameters) ([]model.QueryMetadata, error) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Info().Msg("iterateEmbeddedQuerySources()")
	dirs, err := s.iterateEmbeddedQuerySources(ctx)
	if err != nil {
		return nil, err
	}

	queries := s.iterateQueryDirs(ctx, dirs, queryParameters)

	return queries, nil
}

// iterate over the embedded query directory and read the respective queries
func (s *FilesystemSource) iterateEmbeddedQuerySources(ctx context.Context) ([]string, error) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Info().Msg("getAllDirs()")

	queryDirs, err := assets.GetEmbeddedQueryDirs(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get query sources")
	}

	return queryDirs, nil
}

// iterateQueryDirs iterates all query directories and reads the respective queries
func (s *FilesystemSource) iterateQueryDirs(ctx context.Context, queryDirs []string,
	queryParameters *QueryInspectorParameters) []model.QueryMetadata {
	queries := make([]model.QueryMetadata, 0, len(queryDirs))

	for _, queryDir := range queryDirs {
		query, errRQ := ReadQuery(ctx, queryDir)
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

		if len(queryParameters.IncludeQueries.ByIDs) > 0 {
			if checkQueryInclude(ctx, query.Metadata["id"], queryParameters.IncludeQueries.ByIDs) {
				queries = append(queries, query)
			}
		} else {
			if checkQueryExclude(ctx, query.Metadata, queryParameters) {
				continue
			}

			queries = append(queries, query)
		}
	}
	return queries
}

// validateMetadata prevents panics when KICS queries metadata fields are missing
func validateMetadata(metadata map[string]interface{}) (exist bool, field string) {
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

// ReadQuery reads query's files for a given path and returns a QueryMetadata struct with it's
// content
func ReadQuery(ctx context.Context, queryDir string) (model.QueryMetadata, error) {
	contextLogger := logger.FromContext(ctx)
	queryContent, err := assets.GetEmbeddedQueryFile(ctx, filepath.Join(queryDir, QueryFileName))
	if err != nil {
		return model.QueryMetadata{}, errors.Wrapf(err, "failed to read query %s", filepath.Base(queryDir))
	}

	metadata, err := ReadMetadata(ctx, queryDir)
	if err != nil {
		return model.QueryMetadata{}, errors.Wrapf(err, "failed to read query %s", filepath.Base(queryDir))
	}

	if valid, missingField := validateMetadata(metadata); !valid {
		err := fmt.Errorf("failed to read metadata field: %s", missingField)
		contextLogger.Error().Msg(err.Error())
		return model.QueryMetadata{}, err
	}

	platform := getPlatform(metadata["platform"].(string))

	aggregation := 1
	if agg, ok := metadata["aggregation"]; ok {
		aggregation = int(agg.(float64))
	}

	experimental := getExperimental(metadata["experimental"])

	return model.QueryMetadata{
		Query:        filepath.Base(filepath.ToSlash(queryDir)),
		Content:      queryContent,
		Metadata:     metadata,
		Platform:     platform,
		InputData:    "{}",
		Aggregation:  aggregation,
		Experimental: experimental,
	}, nil
}

// ReadMetadata read query's metadata file inside the query directory
func ReadMetadata(ctx context.Context, queryDir string) (map[string]interface{}, error) {
	contextLogger := logger.FromContext(ctx)
	f, err := assets.GetEmbeddedQueryFile(ctx, filepath.Clean(filepath.Join(queryDir, MetadataFileName)))
	if err != nil {
		contextLogger.Error().Msgf("Queries provider can't read metadata, query=%s: %v", filepath.Base(queryDir), err)
		return nil, err
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal([]byte(f), &metadata); err != nil {
		return nil, err
	}

	return metadata, nil
}

type supportedPlatforms map[string]string

var supPlatforms = &supportedPlatforms{
	"Ansible":                 "ansible",
	"CloudFormation":          "cloudFormation",
	"Common":                  "common",
	"Crossplane":              "crossplane",
	"Knative":                 "knative",
	"Kubernetes":              "k8s",
	"OpenAPI":                 "openAPI",
	"Terraform":               "terraform",
	"AzureResourceManager":    "azureResourceManager",
	"GRPC":                    "grpc",
	"GoogleDeploymentManager": "googleDeploymentManager",
	"Buildah":                 "buildah",
	"Pulumi":                  "pulumi",
	"ServerlessFW":            "serverlessFW",
	"CICD":                    "cicd",
}

func getPlatform(metadataPlatform string) string {
	if p, ok := (*supPlatforms)[metadataPlatform]; ok {
		return p
	}
	return "unknown"
}

func getExperimental(experimental interface{}) bool {
	readExperimental, _ := experimental.(string)
	if readExperimental == "true" {
		return true
	} else {
		return false
	}
}
