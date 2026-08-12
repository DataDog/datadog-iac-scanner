package datadog

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DataDog/jsonapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCustomRuleset_NotFoundReturnsEmpty(t *testing.T) {
	clearDatadogEnv(t)

	handler := func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v2/static-analysis/iac/rulesets/custom-ruleset", r.URL.Path)
		http.NotFound(w, r)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)

	client := NewDatadogClient(
		WithHostname(server.Listener.Addr().String()),
		WithHttpClient(server.Client()),
		WithJwtToken("my-jwt-token"),
	)
	ruleset, err := client.GetCustomRuleset(t.Context())
	require.NoError(t, err)
	assert.Equal(t, CustomRulesetName, ruleset.ID)
	assert.Empty(t, ruleset.Rules)
}

func TestGetCustomRuleset(t *testing.T) {
	customRules := []*Rule{
		{
			ID:               "custom-dockerfile-untagged-from",
			Name:             "custom-dockerfile-untagged-from",
			ShortDescription: "Untagged FROM image",
			Description:      "Dockerfile uses an untagged base image",
			Platform:         "Dockerfile",
			Type:             "rego",
			RegoQuery:        []byte("package datadog"),
			Severity:         "HIGH",
			Category:         "Best Practices",
			IsPublished:      true,
		},
	}

	client := getDatadogClient(t, nil, customRules, "", nil)
	ruleset, err := client.GetCustomRuleset(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, customRules, ruleset.Rules)
}

func TestMergeRulesets(t *testing.T) {
	defaultRule := &Rule{ID: "default-rule", Name: "default-rule", IsPublished: true}
	customRule := &Rule{ID: "custom-rule", Name: "custom-rule", IsPublished: true}

	merged := MergeRulesets(
		&Ruleset{ID: DefaultRulesetName, Rules: []*Rule{defaultRule}},
		&Ruleset{ID: CustomRulesetName, Rules: []*Rule{customRule}},
	)
	require.Len(t, merged.Rules, 2)
	assert.Equal(t, "default-rule", merged.Rules[0].ID)
	assert.Equal(t, "custom-rule", merged.Rules[1].ID)

	assert.Equal(t,
		&Ruleset{ID: DefaultRulesetName, Rules: []*Rule{defaultRule}},
		MergeRulesets(&Ruleset{ID: DefaultRulesetName, Rules: []*Rule{defaultRule}}, &Ruleset{ID: CustomRulesetName}),
	)
}

func TestGetDefaultRuleset(t *testing.T) {
	rules := []*Rule{
		{
			ID:               "dockerfile-gcp-rule-1",
			Name:             "rule-1",
			LegacyId:         nil,
			ShortDescription: "short 1",
			Description:      "full 1",
			DescriptionId:    ptr("abcdef"),
			Platform:         "Dockerfile",
			Type:             "rego",
			RegoQuery:        []byte("query text 1"),
			Severity:         "HIGH",
			Category:         "Encryption",
			Provider:         ptr("gcp"),
			Cwe:              ptr("123"),
			DocumentationUrl: ptr("http://example.com/doc1"),
			IsTesting:        false,
			IsPublished:      true,
		},
		{
			ID:               "common-rule-2",
			Name:             "rule-2",
			LegacyId:         ptr("rule-2"),
			ShortDescription: "short 2",
			Description:      "full 2",
			Platform:         "Common",
			Type:             "rego",
			RegoQuery:        []byte("query text 2"),
			Severity:         "MEDIUM",
			Category:         "Backup",
			IsTesting:        true,
			IsPublished:      true,
		},
	}

	client := getDatadogClient(t, rules, nil, "", nil)
	ruleset, err := client.GetDefaultRuleset(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, rules, ruleset.Rules)
}

func TestGetRemoteConfig(t *testing.T) {
	repoUrl := "https://example.com/repo"
	remoteConfig := "this is the configuration"
	client := getDatadogClient(t, nil, nil, repoUrl, []byte(remoteConfig))
	actual, err := client.GetRemoteConfig(t.Context(), repoUrl, []byte{})
	assert.NoError(t, err)
	assert.Equal(t, remoteConfig, string(actual))
}

// TestGetRemoteConfig_WithJwtToken verifies that the client authenticates with
// only a JWT (no API or application key) by sending the `dd-auth-jwt` header.
func TestGetRemoteConfig_WithJwtToken(t *testing.T) {
	clearDatadogEnv(t)

	repoUrl := "https://example.com/repo"
	remoteConfig := "remote configuration"

	handler := func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "", r.Header.Get("dd-api-key"))
		assert.Equal(t, "", r.Header.Get("dd-application-key"))
		assert.Equal(t, "my-jwt-token", r.Header.Get("dd-auth-jwt"))

		require.Equal(t, "/api/v2/static-analysis/config/client", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		defer r.Body.Close()
		var request remoteConfigRequest
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, jsonapi.Unmarshal(body, &request))
		assert.Equal(t, repoUrl, request.Repository)

		body, err = jsonapi.Marshal(remoteConfigResponse{ID: "cfg", Config: []byte(remoteConfig)})
		require.NoError(t, err)
		w.Header().Add("content-type", "application/json")
		_, err = w.Write(body)
		require.NoError(t, err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)

	client := NewDatadogClient(
		WithHostname(server.Listener.Addr().String()),
		WithHttpClient(server.Client()),
		WithJwtToken("my-jwt-token"),
	)
	actual, err := client.GetRemoteConfig(t.Context(), repoUrl, []byte{})
	assert.NoError(t, err)
	assert.Equal(t, remoteConfig, string(actual))
}

// TestGetRemoteConfig_EmptyDdJwtTokenFallsBackToDatadogJwtToken verifies that
// an explicitly empty DD_JWT_TOKEN does not shadow a populated DATADOG_JWT_TOKEN.
func TestGetRemoteConfig_EmptyDdJwtTokenFallsBackToDatadogJwtToken(t *testing.T) {
	clearDatadogEnv(t)
	t.Setenv("DD_JWT_TOKEN", "")
	t.Setenv("DATADOG_JWT_TOKEN", "real-jwt-token")

	repoUrl := "https://example.com/repo"
	remoteConfig := "remote configuration"

	handler := func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "real-jwt-token", r.Header.Get("dd-auth-jwt"))
		require.Equal(t, "/api/v2/static-analysis/config/client", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		body, err := jsonapi.Marshal(remoteConfigResponse{ID: "cfg", Config: []byte(remoteConfig)})
		require.NoError(t, err)
		w.Header().Add("content-type", "application/json")
		_, err = w.Write(body)
		require.NoError(t, err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)

	client := NewDatadogClient(
		WithHostname(server.Listener.Addr().String()),
		WithHttpClient(server.Client()),
	)
	actual, err := client.GetRemoteConfig(t.Context(), repoUrl, []byte{})
	assert.NoError(t, err)
	assert.Equal(t, remoteConfig, string(actual))
}

// TestGetRemoteConfig_NoCredentials verifies that, with no API key, no application
// key, and no JWT, the client echoes the local configuration without making any
// HTTP request. The handler fails the test if called.
func TestGetRemoteConfig_NoCredentials(t *testing.T) {
	clearDatadogEnv(t)

	failingHandler := func(w http.ResponseWriter, r *http.Request) {
		assert.Failf(t, "unexpected request", "the client must not contact the API without credentials: %s %s", r.Method, r.URL)
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(failingHandler))
	t.Cleanup(server.Close)

	client := NewDatadogClient(
		WithHostname(server.Listener.Addr().String()),
		WithHttpClient(server.Client()),
	)
	local := []byte("local config")
	actual, err := client.GetRemoteConfig(t.Context(), "https://example.com/repo", local)
	assert.NoError(t, err)
	assert.Equal(t, string(local), string(actual))
}

// clearDatadogEnv prevents DD_* / DATADOG_* credential and endpoint env vars from
// leaking into the constructor's env fallbacks and making the tests depend on the
// developer's local environment.
func clearDatadogEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"DD_API_KEY", "DATADOG_API_KEY",
		"DD_APP_KEY", "DATADOG_APP_KEY",
		"DD_JWT_TOKEN", "DATADOG_JWT_TOKEN",
		"DD_SITE", "DATADOG_SITE",
		"DD_HOSTNAME", "DATADOG_HOSTNAME",
	} {
		t.Setenv(name, "")
	}
}

// TestGetRemoteConfig_DdHostnameTakesPrecedenceOverDdSite verifies that the
// hostname passed via DD_HOSTNAME wins over DD_SITE when both are set.
func TestGetRemoteConfig_DdHostnameTakesPrecedenceOverDdSite(t *testing.T) {
	clearDatadogEnv(t)

	repoUrl := "https://example.com/repo"
	remoteConfig := "remote configuration"

	handler := func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v2/static-analysis/config/client", r.URL.Path)
		body, err := jsonapi.Marshal(remoteConfigResponse{ID: "cfg", Config: []byte(remoteConfig)})
		require.NoError(t, err)
		w.Header().Add("content-type", "application/json")
		_, err = w.Write(body)
		require.NoError(t, err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)

	t.Setenv("DD_HOSTNAME", server.Listener.Addr().String())
	t.Setenv("DD_SITE", "should-be-ignored.invalid")

	client := NewDatadogClient(
		WithHttpClient(server.Client()),
		WithJwtToken("jwt"),
	)
	actual, err := client.GetRemoteConfig(t.Context(), repoUrl, []byte{})
	assert.NoError(t, err)
	assert.Equal(t, remoteConfig, string(actual))
}

// TestGetRemoteConfig_HostnameWithHttpScheme verifies that a hostname that
// already includes an http:// scheme is used as-is, instead of being prefixed
// with https://.
func TestGetRemoteConfig_HostnameWithHttpScheme(t *testing.T) {
	clearDatadogEnv(t)

	repoUrl := "https://example.com/repo"
	remoteConfig := "remote configuration"

	handler := func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v2/static-analysis/config/client", r.URL.Path)
		body, err := jsonapi.Marshal(remoteConfigResponse{ID: "cfg", Config: []byte(remoteConfig)})
		require.NoError(t, err)
		w.Header().Add("content-type", "application/json")
		_, err = w.Write(body)
		require.NoError(t, err)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)

	client := NewDatadogClient(
		WithHostname(server.URL),
		WithJwtToken("jwt"),
	)
	actual, err := client.GetRemoteConfig(t.Context(), repoUrl, []byte{})
	assert.NoError(t, err)
	assert.Equal(t, remoteConfig, string(actual))
}

func getDatadogClient(t *testing.T, defaultRules, customRules []*Rule, repoUrl string, config []byte) Client {
	handler := func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "my-api-key", r.Header.Get("dd-api-key"))
		assert.Equal(t, "my-app-key", r.Header.Get("dd-application-key"))
		switch r.URL.Path {
		case "/api/v2/static-analysis/iac/rulesets/default-ruleset":
			assert.Equal(t, http.MethodGet, r.Method)
			ruleset := Ruleset{
				ID:    DefaultRulesetName,
				Name:  DefaultRulesetName,
				Rules: defaultRules,
			}
			body, err := jsonapi.Marshal(ruleset)
			require.NoError(t, err)
			w.Header().Add("content-type", "application/json")
			_, err = w.Write(body)
			require.NoError(t, err)
		case "/api/v2/static-analysis/iac/rulesets/custom-ruleset":
			assert.Equal(t, http.MethodGet, r.Method)
			ruleset := Ruleset{
				ID:    CustomRulesetName,
				Name:  CustomRulesetName,
				Rules: customRules,
			}
			body, err := jsonapi.Marshal(ruleset)
			require.NoError(t, err)
			w.Header().Add("content-type", "application/json")
			_, err = w.Write(body)
			require.NoError(t, err)
		case "/api/v2/static-analysis/config/client":
			assert.Equal(t, http.MethodPost, r.Method)
			defer r.Body.Close()
			var request remoteConfigRequest
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.NoError(t, jsonapi.Unmarshal(body, &request))
			assert.Equal(t, repoUrl, request.Repository)
			body, err = jsonapi.Marshal(remoteConfigResponse{
				ID:     "cfg",
				Config: config,
			})
			require.NoError(t, err)
			w.Header().Add("content-type", "application/json")
			_, err = w.Write(body)
			require.NoError(t, err)
		default:
			assert.Failf(t, "Unexpected request: %s %s", r.Method, r.URL)
			http.NotFoundHandler().ServeHTTP(w, r)
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)

	source := NewDatadogClient(
		WithHostname(server.Listener.Addr().String()),
		WithHttpClient(server.Client()),
		WithApiKey("my-api-key"),
		WithAppKey("my-app-key"),
	)
	return source
}

func ptr[T any](t T) *T {
	return &t
}
