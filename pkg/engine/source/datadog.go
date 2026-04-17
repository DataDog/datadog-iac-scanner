package source

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/jsonapi"
)

// NewDatadogSource creates a DatadogSource with the given options.
func NewDatadogSource(options ...DatadogSourceOption) (QueriesSource, error) {
	out := &DatadogSource{
		httpClient:           http.DefaultClient,
		wantedPlatforms:      []string{""},
		wantedCloudProviders: []string{""},
	}
	for _, option := range options {
		option(out)
	}
	if out.hostname == "" {
		WithSiteFromEnv()(out)
	}
	if out.apiKey == "" {
		WithApiKeyFromEnv()(out)
	}
	if out.appKey == "" {
		WithAppKeyFromEnv()(out)
	}
	if out.librarySource == nil {
		librarySource := NewFilesystemSource(
			context.Background(),
			[]string{""},
			out.wantedPlatforms,
			out.wantedCloudProviders,
			"./assets/libraries",
			true,
		)
		WithLibrarySource(librarySource)(out)
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

// WithLibrarySource lets you specify the QueriesSource instance that library data will be read from.
// If unspecified, a FilesystemSource with equivalent options will be used.
func WithLibrarySource(source QueriesSource) DatadogSourceOption {
	return func(ds *DatadogSource) {
		ds.librarySource = source
	}
}

// WithSite lets you specify a Datadog site to use.
// If unspecified, the Datadog site will be fetched from the environment using WithSiteFromEnv.
func WithSite(site string) DatadogSourceOption {
	return withHostname("api." + site)
}

// WithSiteFromEnv uses the Datadog site specified in the DD_SITE or DATADOG_SITE environment variable.
// If neither variable exists, "datadoghq.com" will be used.
func WithSiteFromEnv() DatadogSourceOption {
	site := getDdEnvvar("SITE")
	if site == "" {
		site = "datadoghq.com"
	}
	return WithSite(site)
}

// WithApiKey lets you specify a Datadog API key.
// If unspecified, the API key will be fetched from the environment using WithApiKeyFromEnv.
func WithApiKey(apiKey string) DatadogSourceOption {
	return func(ds *DatadogSource) {
		ds.apiKey = apiKey
	}
}

// WithAppKey lets you specify a Datadog application key.
// If unspecified, the application key will be fetched from the environment using WithAppKeyFromEnv.
func WithAppKey(appKey string) DatadogSourceOption {
	return func(ds *DatadogSource) {
		ds.appKey = appKey
	}
}

// WithApiKeyFromEnv uses the API key specified in the DD_API_KEY or DATADOG_API_KEY environment variable.
// If neither variable exists, an empty API key will be used.
func WithApiKeyFromEnv() DatadogSourceOption {
	return WithApiKey(getDdEnvvar("API_KEY"))
}

// WithAppKeyFromEnv uses the application key specified in the DD_APP_KEY or DATADOG_APP_KEY environment variable.
// If neither variable exists, an empty application key will be used.
func WithAppKeyFromEnv() DatadogSourceOption {
	return WithAppKey(getDdEnvvar("APP_KEY"))
}

// WithHttpClient lets you specify an http.Client instance to use.
// If unspecified, the [http.DefaultClient] will be used.
func WithHttpClient(client *http.Client) DatadogSourceOption {
	return func(ds *DatadogSource) {
		ds.httpClient = client
	}
}

// withHostname lets you specify the hostname to use for Datadog API requests.
// Used in the implementation and unit tests.
func withHostname(hostname string) DatadogSourceOption {
	return func(ds *DatadogSource) {
		ds.hostname = hostname
	}
}

type DatadogSourceOption func(source *DatadogSource)

// DatadogSource is a QueriesSource that reads queries from the Datadog API.
// Libraries are fetched via another QueriesSource.
type DatadogSource struct {
	hostname             string
	apiKey               string
	appKey               string
	httpClient           *http.Client
	librarySource        QueriesSource
	wantedPlatforms      []string
	wantedCloudProviders []string
}

func (s *DatadogSource) GetQueries(ctx context.Context, querySelection *QueryInspectorParameters) ([]model.QueryMetadata, error) {
	defaultRuleset, err := s.getDefaultRuleset(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving rules from Datadog: %w", err)
	}
	return s.filterRules(defaultRuleset, querySelection)
}

func (s *DatadogSource) GetQueryLibrary(ctx context.Context, platform string) (RegoLibraries, error) {
	return s.librarySource.GetQueryLibrary(ctx, platform)
}

// getDefaultRuleset returns the content of the default ruleset.
func (s *DatadogSource) getDefaultRuleset(ctx context.Context) (*Ruleset, error) {
	path := "rulesets/default-ruleset?include_tests=false&include_testing_rules=true"
	response, err := s.sendRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close() // nolint:errcheck
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the Datadog API returned status %d", response.StatusCode)
	}

	var ruleset *Ruleset
	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if err := jsonapi.Unmarshal(bytes, &ruleset); err != nil {
		return nil, err
	}

	return ruleset, nil
}

// filterRules selects the rules from the given ruleset according to the selection criteria.
func (s *DatadogSource) filterRules(ruleset *Ruleset, selection *QueryInspectorParameters) ([]model.QueryMetadata, error) {
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
		out = append(out, convertRule(rule))
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
	return isInCaseInsensitiveList(platform, s.wantedPlatforms)
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
	return isInCaseInsensitiveList(*provider, s.wantedCloudProviders)
}

func checkExcluded(rule *Rule, selection *QueryInspectorParameters) bool {
	return isInCaseInsensitiveList(rule.ID, selection.ExcludeQueries.ByIDs) ||
		isInCaseInsensitiveList(rule.Category, selection.ExcludeQueries.ByCategories) ||
		isInCaseInsensitiveList(rule.Severity, selection.ExcludeQueries.BySeverities) ||
		(!selection.BomQueries && strings.EqualFold(rule.Severity, model.SeverityTrace))
}

func checkIncluded(rule *Rule, selection *QueryInspectorParameters) bool {
	return isInCaseInsensitiveNotEmptyList(rule.ID, selection.IncludeQueries.ByIDs) &&
		isInCaseInsensitiveNotEmptyList(rule.Category, selection.IncludeQueries.ByCategories) &&
		isInCaseInsensitiveNotEmptyList(rule.Severity, selection.IncludeQueries.BySeverities)
}

// isInCaseInsensitiveList checks if the given item is in the given list, doing a case-insensitive search.
func isInCaseInsensitiveList(id string, list []string) bool {
	for _, item := range list {
		if strings.EqualFold(id, item) {
			return true
		}
	}
	return false
}

// isInCaseInsensitiveNotEmptyList checks if the list is empty or the item is in it, doing a case-insensitive search.
func isInCaseInsensitiveNotEmptyList(id string, list []string) bool {
	return len(list) == 0 || isInCaseInsensitiveList(id, list)
}

// nolint:gocyclo
// convertRule converts a Datadog api [Rule] to a [model.QueryMetadata]
func convertRule(rule *Rule) model.QueryMetadata {
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
		Platform:     getPlatform(rule.Platform),
		Aggregation:  1,
		Experimental: rule.IsTesting,
	}
	setStringPtr(out.Metadata, "descriptionUrl", rule.DocumentationUrl)
	setStringPtr(out.Metadata, "providerUrl", rule.ProviderUrl)
	setStringPtr(out.Metadata, "descriptionID", rule.DescriptionId)
	setStringPtr(out.Metadata, "cloudProvider", rule.Provider)
	if rule.Cwe == nil {
		out.Metadata["cwe"] = ""
	} else {
		out.Metadata["cwe"] = *rule.Cwe
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

func frameworksToMeta(fs []Framework) []any {
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

// sendRequest sends a Datadog API request
func (s *DatadogSource) sendRequest(ctx context.Context, method, path string, requestBody io.Reader) (*http.Response, error) {
	url := fmt.Sprintf("https://%s/api/v2/static-analysis/iac/%s", s.hostname, path)
	req, err := http.NewRequestWithContext(ctx, method, url, requestBody)
	if err != nil {
		return nil, fmt.Errorf("error building %s %s request: %w", method, url, err)
	}
	req.Header.Add("content-type", "application/json")
	if s.apiKey != "" {
		req.Header.Add("dd-api-key", s.apiKey)
	}
	if s.appKey != "" {
		req.Header.Add("dd-application-key", s.appKey)
	}
	return s.httpClient.Do(req)
}

var _ QueriesSource = (*DatadogSource)(nil)

// getDdEnvvar returns the value of the given Datadog environment variable.
// The DD_ prefix is checked first, then the DATADOG_ prefix.
// Returns an empty string if neither environment variable exists.
func getDdEnvvar(name string) string {
	if v, ok := os.LookupEnv("DD_" + name); ok {
		return v
	} else if v, ok = os.LookupEnv("DATADOG_" + name); ok {
		return v
	}
	return ""
}

// Ruleset defines a collection of rules.
type Ruleset struct {
	ID               string  `jsonapi:"primary,iac_ruleset" json:"id"`
	Name             string  `jsonapi:"attribute" json:"name"`
	ShortDescription string  `jsonapi:"attribute" json:"short_description"`
	Description      string  `jsonapi:"attribute" json:"description"`
	Rules            []*Rule `jsonapi:"attribute" json:"rules"`
}

// Rule defines the structure of a rule that's stored in Datadog.
type Rule struct {
	ID                string         `jsonapi:"primary,iac_rule" json:"id"`
	Name              string         `jsonapi:"attribute" json:"name"`
	LegacyId          *string        `jsonapi:"attribute" json:"legacy_id,omitempty"`
	ShortDescription  string         `jsonapi:"attribute" json:"short_description"`
	Description       string         `jsonapi:"attribute" json:"description"`
	DescriptionId     *string        `jsonapi:"attribute" json:"description_id,omitempty"`
	Platform          string         `jsonapi:"attribute" json:"platform"`
	Type              string         `jsonapi:"attribute" json:"type"`
	RegoQuery         []byte         `jsonapi:"attribute" json:"rego_query"`
	Severity          string         `jsonapi:"attribute" json:"severity"`
	Category          string         `jsonapi:"attribute" json:"category"`
	Provider          *string        `jsonapi:"attribute" json:"provider,omitempty"`
	Cwe               *string        `jsonapi:"attribute" json:"cwe,omitempty"`
	DocumentationUrl  *string        `jsonapi:"attribute" json:"documentation_url,omitempty"`
	ProviderUrl       *string        `jsonapi:"attribute" json:"provider_url,omitempty"`
	Aggregation       *int           `jsonapi:"attribute" json:"aggregation,omitempty"`
	Overrides         []RuleOverride `jsonapi:"attribute" json:"overrides,omitempty"`
	DefaultFrameworks []Framework    `jsonapi:"attribute" json:"default_frameworks,omitempty"`
	CustomFrameworks  []Framework    `jsonapi:"attribute" json:"custom_frameworks,omitempty"`
	IsTesting         bool           `jsonapi:"attribute" json:"is_testing"`
	IsPublished       bool           `jsonapi:"attribute" json:"is_published"`
}

type RuleOverride struct {
	Key              string  `jsonapi:"primary,iac_rule_override" json:"key"`
	ID               *string `jsonapi:"attribute" json:"id,omitempty"`
	ShortDescription *string `jsonapi:"attribute" json:"short_description,omitempty"`
	Description      *string `jsonapi:"attribute" json:"description,omitempty"`
	DescriptionId    *string `jsonapi:"attribute" json:"description_id,omitempty"`
	Platform         *string `jsonapi:"attribute" json:"platform,omitempty"`
	Severity         *string `jsonapi:"attribute" json:"severity,omitempty"`
	Category         *string `jsonapi:"attribute" json:"category,omitempty"`
	Provider         *string `jsonapi:"attribute" json:"provider,omitempty"`
	Cwe              *string `jsonapi:"attribute" json:"cwe,omitempty"`
	DocumentationUrl *string `jsonapi:"attribute" json:"documentation_url,omitempty"`
	ProviderUrl      *string `jsonapi:"attribute" json:"provider_url,omitempty"`
}

type Framework struct {
	Framework   string `jsonapi:"attribute" json:"framework"`
	Version     string `jsonapi:"attribute" json:"version"`
	Requirement string `jsonapi:"attribute" json:"requirement"`
	Control     string `jsonapi:"attribute" json:"control"`
}
