package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// NewDatadogSource creates a DatadogSource with the given options.
func NewDatadogSource(client datadog.Client, options ...DatadogSourceOption) (QueriesSource, error) {
	out := &DatadogSource{
		client:               client,
		wantedPlatforms:      []string{""},
		wantedCloudProviders: []string{""},
	}
	for _, option := range options {
		option(out)
	}
	return out, nil
}

// WithWantedPlatforms specifies a list of platforms to read queries for.
// If unspecified, all platforms will be read.
func WithWantedPlatforms(platforms []string) DatadogSourceOption {
	return func(ds *DatadogSource) {
		ds.wantedPlatforms = slices.Clone(platforms)
	}
}

// WithWantedCloudProviders specifies a list of providers to read queries for.
// If unspecified, all providers will be read.
func WithWantedCloudProviders(providers []string) DatadogSourceOption {
	return func(ds *DatadogSource) {
		ds.wantedCloudProviders = slices.Clone(providers)
	}
}

// WithLibraryOverride sets a QueriesSource to use for libraries when the user supplies --libraries-path.
func WithLibraryOverride(source QueriesSource) DatadogSourceOption {
	return func(ds *DatadogSource) {
		ds.libraryOverride = source
	}
}

// WithLibrarySource specifies the QueriesSource that should be used for libraries.
func WithLibrarySource(source QueriesSource) DatadogSourceOption {
	return func(ds *DatadogSource) {
		ds.librarySource = source
	}
}

type DatadogSourceOption func(source *DatadogSource)

// DatadogSource is a QueriesSource that reads queries and libraries from the Datadog API.
// An optional local override (WithLibraryOverride) is used only when --libraries-path is specified.
type DatadogSource struct {
	client               datadog.Client
	librarySource        QueriesSource
	libraryOverride      QueriesSource
	wantedPlatforms      []string
	wantedCloudProviders []string
	mu                   sync.RWMutex
	libraries            map[string]RegoLibraries // nil until a successful fetch; errors are not cached
}

func (s *DatadogSource) GetQueries(ctx context.Context, querySelection *QueryInspectorParameters) ([]model.QueryMetadata, error) {
	defaultRuleset, err := s.client.GetDefaultRuleset(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving rules from Datadog: %w", err)
	}
	return s.filterRules(defaultRuleset, querySelection)
}

func (s *DatadogSource) loadLibraries(ctx context.Context) (map[string]RegoLibraries, error) {
	s.mu.RLock()
	if s.libraries != nil {
		libs := s.libraries
		s.mu.RUnlock()
		return libs, nil
	}
	s.mu.RUnlock()

	libs, err := s.client.GetLibraries(ctx)
	if err != nil {
		return nil, fmt.Errorf("backend libraries unavailable: %w", err)
	}
	converted := make(map[string]RegoLibraries, len(libs))
	for id, lib := range libs {
		converted[strings.ToLower(id)] = RegoLibraries{
			LibraryCode:      lib.RegoCode,
			LibraryInputData: lib.InputData,
		}
	}
	s.mu.Lock()
	s.libraries = converted
	s.mu.Unlock()
	return converted, nil
}

func (s *DatadogSource) GetQueryLibrary(ctx context.Context, platform string) (RegoLibraries, error) {
	if s.librarySource != nil {
		return s.librarySource.GetQueryLibrary(ctx, platform)
	}
	libs, err := s.loadLibraries(ctx)
	if err != nil {
		if s.libraryOverride != nil {
			return s.libraryOverride.GetQueryLibrary(ctx, platform)
		}
		return RegoLibraries{}, err
	}
	if lib, ok := libs[strings.ToLower(platform)]; ok {
		return lib, nil
	}
	if s.libraryOverride != nil {
		return s.libraryOverride.GetQueryLibrary(ctx, platform)
	}
	return RegoLibraries{}, fmt.Errorf("library %q not found in backend", platform)
}

// filterRules selects the rules from the given ruleset according to the selection criteria.
func (s *DatadogSource) filterRules(ruleset *datadog.Ruleset, selection *QueryInspectorParameters) ([]model.QueryMetadata, error) {
	var out []model.QueryMetadata
	for _, rule := range ruleset.Rules {
		if !rule.IsPublished {
			continue
		}
		if rule.IsTesting && !selection.ExperimentalQueries {
			continue
		}
		if !s.isWantedPlatform(rule.Platform) {
			continue
		}
		if !s.isWantedCloudProvider(rule.Provider) {
			continue
		}
		if !checkIncluded(rule, selection) || checkExcluded(rule, selection) {
			continue
		}
		out = append(out, ConvertRule(rule))
	}
	return out, nil
}

// isWantedPlatform checks if the given platform is in the list of wanted platforms.
func (s *DatadogSource) isWantedPlatform(platform string) bool {
	if strings.EqualFold(platform, "Common") {
		return true
	}
	if s.wantedPlatforms[0] == "" {
		return true
	}
	return isInCaseInsensitiveList(&platform, s.wantedPlatforms)
}

// isWantedCloudProvider checks if the given provider is in the list of wanted providers.
func (s *DatadogSource) isWantedCloudProvider(provider *string) bool {
	if s.wantedCloudProviders[0] == "" {
		return true
	}
	if provider == nil {
		return false
	}
	if strings.EqualFold(*provider, "Common") {
		return true
	}
	return isInCaseInsensitiveList(provider, s.wantedCloudProviders)
}

func checkExcluded(rule *datadog.Rule, selection *QueryInspectorParameters) bool {
	return isInCaseInsensitiveList(rule.LegacyId, selection.ExcludeQueries.ByIDs) ||
		isInCaseInsensitiveList(&rule.ID, selection.ExcludeQueries.ByIDs) ||
		isInCaseInsensitiveList(&rule.Category, selection.ExcludeQueries.ByCategories) ||
		isInCaseInsensitiveList(&rule.Severity, selection.ExcludeQueries.BySeverities) ||
		(!selection.BomQueries && strings.EqualFold(rule.Severity, model.SeverityTrace))
}

func checkIncluded(rule *datadog.Rule, selection *QueryInspectorParameters) bool {
	return (isInCaseInsensitiveNotEmptyList(rule.LegacyId, selection.IncludeQueries.ByIDs) ||
		isInCaseInsensitiveNotEmptyList(&rule.ID, selection.IncludeQueries.ByIDs)) &&
		isInCaseInsensitiveNotEmptyList(&rule.Category, selection.IncludeQueries.ByCategories) &&
		isInCaseInsensitiveNotEmptyList(&rule.Severity, selection.IncludeQueries.BySeverities)
}

// isInCaseInsensitiveList checks if the given item is in the given list, doing a case-insensitive search.
// If the item is nil, the function returns false.
func isInCaseInsensitiveList(id *string, list []string) bool {
	if id == nil {
		return false
	}
	for _, item := range list {
		if strings.EqualFold(*id, item) {
			return true
		}
	}
	return false
}

// isInCaseInsensitiveNotEmptyList checks if the list is empty or the item is in it, doing a case-insensitive search.
func isInCaseInsensitiveNotEmptyList(id *string, list []string) bool {
	return len(list) == 0 || isInCaseInsensitiveList(id, list)
}

// nolint:gocyclo
// ConvertRule converts a Datadog api [Rule] to a [model.QueryMetadata]
func ConvertRule(rule *datadog.Rule) model.QueryMetadata {
	out := model.QueryMetadata{
		InputData: "{}",
		Query:     rule.Name,
		Content:   string(rule.RegoQuery),
		Metadata: map[string]any{
			"id":              rule.ID,
			"queryName":       rule.ShortDescription,
			"descriptionText": rule.Description,
			"platform":        rule.Platform,
			"severity":        rule.Severity,
			"category":        rule.Category,
		},
		Platform:     GetPlatform(rule.Platform),
		Aggregation:  1,
		Experimental: rule.IsTesting,
	}
	setStringPtr(out.Metadata, "legacyId", rule.LegacyId)
	setStringPtr(out.Metadata, "providerUrl", rule.ProviderUrl)
	setStringPtr(out.Metadata, "descriptionID", rule.DescriptionId)
	setStringPtr(out.Metadata, "cloudProvider", rule.Provider)
	if rule.DescriptionId != nil {
		out.Metadata["descriptionID"] = *rule.DescriptionId
	} else {
		sha := sha256.Sum256([]byte(rule.Name))
		out.Metadata["descriptionID"] = hex.EncodeToString(sha[:4])
	}
	if rule.DocumentationUrl != nil {
		out.Metadata["descriptionUrl"] = *rule.DocumentationUrl
	} else if rule.Provider == nil {
		out.Metadata["descriptionUrl"] = fmt.Sprintf(
			"https://docs.datadoghq.com/security/code_security/iac_security/iac_rules/%s/%s/",
			out.Platform, out.Query)
	} else {
		out.Metadata["descriptionUrl"] = fmt.Sprintf(
			"https://docs.datadoghq.com/security/code_security/iac_security/iac_rules/%s/%s/%s/",
			out.Platform, *rule.Provider, out.Query)
	}
	if rule.Cwe != nil {
		out.Metadata["cwe"] = *rule.Cwe
	} else {
		out.Metadata["cwe"] = ""
	}
	if len(rule.Arguments) > 0 {
		out.Metadata["arguments"] = ruleArgumentsToMeta(rule.Arguments)
	}
	if rule.Aggregation != nil {
		out.Metadata["aggregation"] = *rule.Aggregation
		out.Aggregation = *rule.Aggregation
	}
	if len(rule.Overrides) > 0 {
		overrides := map[string]any{}
		for _, ovr := range rule.Overrides {
			override := map[string]any{}
			setStringPtr(override, "id", ovr.ID)
			setStringPtr(override, "queryName", ovr.ShortDescription)
			setStringPtr(override, "descriptionText", ovr.Description)
			setStringPtr(override, "descriptionID", ovr.DescriptionId)
			setStringPtr(override, "descriptionUrl", ovr.DocumentationUrl)
			setStringPtr(override, "providerUrl", ovr.ProviderUrl)
			setStringPtr(override, "platform", ovr.Platform)
			setStringPtr(override, "severity", ovr.Severity)
			setStringPtr(override, "category", ovr.Category)
			setStringPtr(override, "cloudProvider", ovr.Provider)
			setStringPtr(override, "cwe", ovr.Cwe)
			overrides[ovr.Key] = override
		}
		out.Metadata["override"] = overrides
	}
	if len(rule.DefaultFrameworks) > 0 {
		out.Metadata["defaultFrameworks"] = frameworksToMeta(rule.DefaultFrameworks)
	}
	if len(rule.CustomFrameworks) > 0 {
		out.Metadata["customFrameworks"] = frameworksToMeta(rule.CustomFrameworks)
	}
	return out
}

func setStringPtr[T ~string](m map[string]any, key string, v *T) {
	if v != nil {
		m[key] = string(*v)
	}
}

func frameworksToMeta(fs []datadog.Framework) []any {
	result := make([]any, len(fs))
	for i, f := range fs {
		result[i] = map[string]any{
			"framework":         f.Framework,
			"framework_version": f.Version,
			"requirement":       f.Requirement,
			"control":           f.Control,
		}
	}
	return result
}

func ruleArgumentsToMeta(args []datadog.RuleArgument) []any {
	result := make([]any, len(args))
	for i, arg := range args {
		result[i] = map[string]any{
			"name":        arg.Name,
			"description": arg.Description,
		}
	}
	return result
}

var _ QueriesSource = (*DatadogSource)(nil)
