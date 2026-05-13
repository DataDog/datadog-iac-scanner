package datadog

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/DataDog/jsonapi"
)

type Client interface {
	// GetDefaultRuleset returns the content of the default ruleset.
	GetDefaultRuleset(ctx context.Context) (*Ruleset, error)
	// GetRemoteConfig applies server-side changes to the local configuration.
	GetRemoteConfig(ctx context.Context, repoUrl string, localConfig []byte) ([]byte, error)
}

// NewDatadogClient creates a DatadogSource with the given options.
func NewDatadogClient(options ...DatadogClientOption) Client {
	out := &datadogClient{
		httpClient: http.DefaultClient,
	}
	for _, option := range options {
		option(out)
	}
	if out.hostname == "" {
		WithHostnameFromEnv()(out)
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
	if out.jwtToken == "" {
		WithJwtTokenFromEnv()(out)
	}
	return out
}

// WithSite lets you specify a Datadog site to use.
// If unspecified, the Datadog site will be fetched from the environment using WithSiteFromEnv.
func WithSite(site string) DatadogClientOption {
	return WithHostname("api." + site)
}

// WithSiteFromEnv uses the Datadog site specified in the DD_SITE or DATADOG_SITE environment variable.
// If neither variable exists, "datadoghq.com" will be used.
func WithSiteFromEnv() DatadogClientOption {
	site := getDdEnvvar("SITE")
	if site == "" {
		site = "datadoghq.com"
	}
	return WithSite(site)
}

// WithApiKey lets you specify a Datadog API key.
// If unspecified, the API key will be fetched from the environment using WithApiKeyFromEnv.
func WithApiKey(apiKey string) DatadogClientOption {
	return func(ds *datadogClient) {
		ds.apiKey = apiKey
	}
}

// WithAppKey lets you specify a Datadog application key.
// If unspecified, the application key will be fetched from the environment using WithAppKeyFromEnv.
func WithAppKey(appKey string) DatadogClientOption {
	return func(ds *datadogClient) {
		ds.appKey = appKey
	}
}

// WithApiKeyFromEnv uses the API key specified in the DD_API_KEY or DATADOG_API_KEY environment variable.
// If neither variable exists, an empty API key will be used.
func WithApiKeyFromEnv() DatadogClientOption {
	return WithApiKey(getDdEnvvar("API_KEY"))
}

// WithAppKeyFromEnv uses the application key specified in the DD_APP_KEY or DATADOG_APP_KEY environment variable.
// If neither variable exists, an empty application key will be used.
func WithAppKeyFromEnv() DatadogClientOption {
	return WithAppKey(getDdEnvvar("APP_KEY"))
}

// WithJwtToken lets you specify a Datadog auth JWT for service-to-service authentication.
// If unspecified, the JWT will be fetched from the environment using WithJwtTokenFromEnv.
func WithJwtToken(jwtToken string) DatadogClientOption {
	return func(ds *datadogClient) {
		ds.jwtToken = jwtToken
	}
}

// WithJwtTokenFromEnv uses the JWT specified in the DD_JWT_TOKEN or DATADOG_JWT_TOKEN environment variable.
// If neither variable exists, an empty JWT will be used. The JWT is sent as the `dd-auth-jwt`
// header and is the auth mechanism used by Datadog code-workload-runner environments.
func WithJwtTokenFromEnv() DatadogClientOption {
	return WithJwtToken(getDdEnvvar("JWT_TOKEN"))
}

// WithHttpClient lets you specify an http.Client instance to use.
// If unspecified, the [http.DefaultClient] will be used.
func WithHttpClient(client *http.Client) DatadogClientOption {
	return func(ds *datadogClient) {
		ds.httpClient = client
	}
}

// WithHostname lets you specify the hostname to use for Datadog API requests.
// The value may include an http:// or https:// scheme; when omitted, https:// is used.
func WithHostname(hostname string) DatadogClientOption {
	return func(ds *datadogClient) {
		ds.hostname = hostname
	}
}

// WithHostnameFromEnv uses the hostname specified in the DD_HOSTNAME or DATADOG_HOSTNAME environment variable.
// When set, it takes precedence over DD_SITE so that internal Datadog runners can point the scanner at a
// private static-analysis-api address (e.g. an internal fabric.dog host). Matches the behavior of
// datadog-static-analyzer's get_datadog_basename.
func WithHostnameFromEnv() DatadogClientOption {
	return WithHostname(getDdEnvvar("HOSTNAME"))
}

type DatadogClientOption func(source *datadogClient)

// DatadogSource is a QueriesSource that reads queries from the Datadog API.
// Libraries are fetched via another QueriesSource.
type datadogClient struct {
	hostname   string
	apiKey     string
	appKey     string
	jwtToken   string
	httpClient *http.Client
}

// GetDefaultRuleset returns the content of the default ruleset.
func (s *datadogClient) GetDefaultRuleset(ctx context.Context) (*Ruleset, error) {
	path := "iac/rulesets/default-ruleset?include_tests=false&include_testing_rules=true"
	response, err := s.sendRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close() // nolint:errcheck
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the Datadog API returned status %d", response.StatusCode)
	}

	var ruleset *Ruleset
	b, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if err := jsonapi.Unmarshal(b, &ruleset); err != nil {
		return nil, err
	}

	return ruleset, nil
}

// GetRemoteConfig applies server-side changes to the local configuration.
func (s *datadogClient) GetRemoteConfig(ctx context.Context, repoUrl string, localConfig []byte) ([]byte, error) {
	if s.apiKey == "" && s.appKey == "" && s.jwtToken == "" {
		// Without credentials, do not send the request; echo the local configuration instead
		return localConfig, nil
	}

	path := "config/client?schema_version=v1"

	request := remoteConfigRequest{
		ID:         "config-request",
		Repository: repoUrl,
		Config:     localConfig,
	}
	body, err := jsonapi.Marshal(request)
	if err != nil {
		return nil, err
	}
	response, err := s.sendRequest(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	defer response.Body.Close() // nolint:errcheck
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the Datadog API returned status %d", response.StatusCode)
	}

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var data remoteConfigResponse
	if err := jsonapi.Unmarshal(b, &data); err != nil {
		return nil, err
	}

	return data.Config, nil
}

// sendRequest sends a Datadog API request
func (s *datadogClient) sendRequest(ctx context.Context, method, path string, requestBody io.Reader) (*http.Response, error) {
	url := fmt.Sprintf("%s/api/v2/static-analysis/%s", s.baseURL(), path)
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
	if s.jwtToken != "" {
		req.Header.Add("dd-auth-jwt", s.jwtToken)
	}
	return s.httpClient.Do(req)
}

// baseURL returns the API base URL, preserving an explicit http:// or https:// scheme
// when present in the hostname and defaulting to https:// otherwise.
func (s *datadogClient) baseURL() string {
	if strings.HasPrefix(s.hostname, "http://") || strings.HasPrefix(s.hostname, "https://") {
		return s.hostname
	}
	return "https://" + s.hostname
}

// getDdEnvvar returns the value of the given Datadog environment variable.
// The DD_ prefix is checked first, then the DATADOG_ prefix. An explicitly empty
// value is treated as absent so that callers fall through to the next candidate,
// matching the behavior of datadog-static-analyzer's get_datadog_variable_value.
// Returns an empty string if neither environment variable provides a value.
func getDdEnvvar(name string) string {
	for _, prefix := range []string{"DD_", "DATADOG_"} {
		if v, ok := os.LookupEnv(prefix + name); ok && v != "" {
			return v
		}
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

// RuleOverride contains a set of keyed changes for the rule configuration
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

// Framework defines a compliance framework
type Framework struct {
	Framework   string `jsonapi:"attribute" json:"framework"`
	Version     string `jsonapi:"attribute" json:"version"`
	Requirement string `jsonapi:"attribute" json:"requirement"`
	Control     string `jsonapi:"attribute" json:"control"`
}

type remoteConfigRequest struct {
	ID         string `jsonapi:"primary,config" json:"id"`
	Repository string `jsonapi:"attribute" json:"repository"`
	Config     []byte `jsonapi:"attribute" json:"config_base64"`
}

type remoteConfigResponse struct {
	ID     string `jsonapi:"primary,config" json:"id"`
	Config []byte `jsonapi:"attribute" json:"config_base64"`
}
