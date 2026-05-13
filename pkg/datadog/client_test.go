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

	client := getDatadogClient(t, rules, "", nil)
	ruleset, err := client.GetDefaultRuleset(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, rules, ruleset.Rules)
}

func TestGetRemoteConfig(t *testing.T) {
	repoUrl := "https://example.com/repo"
	remoteConfig := "this is the configuration"
	client := getDatadogClient(t, nil, repoUrl, []byte(remoteConfig))
	actual, err := client.GetRemoteConfig(t.Context(), repoUrl, []byte{})
	assert.NoError(t, err)
	assert.Equal(t, remoteConfig, string(actual))
}

// TestGetRemoteConfig_WithJwtToken exercises the JWT auth path used by
// internal Datadog code-workload runners (no API/app keys, only `dd-auth-jwt`).
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

// TestGetRemoteConfig_EmptyDdJwtTokenFallsBackToDatadogJwtToken covers the case
// where DD_JWT_TOKEN is exported but empty (a common shell or runner pattern) and
// the real token is provided via DATADOG_JWT_TOKEN. An explicitly empty DD_ value
// must not shadow a populated DATADOG_ value.
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

// TestGetRemoteConfig_NoCredentials documents that with no API key, no application
// key, and no JWT token, the client echoes the local configuration without making
// any HTTP request. The provided HTTP client would fail the test if called.
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

// clearDatadogEnv ensures that no DD_* / DATADOG_* credential env vars leak into
// the constructor's env fallbacks, which would otherwise make these tests
// dependent on the developer's local environment.
func clearDatadogEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"DD_API_KEY", "DATADOG_API_KEY",
		"DD_APP_KEY", "DATADOG_APP_KEY",
		"DD_JWT_TOKEN", "DATADOG_JWT_TOKEN",
	} {
		t.Setenv(name, "")
	}
}

func getDatadogClient(t *testing.T, rules []*Rule, repoUrl string, config []byte) Client {
	handler := func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "my-api-key", r.Header.Get("dd-api-key"))
		assert.Equal(t, "my-app-key", r.Header.Get("dd-application-key"))
		if r.URL.Path == "/api/v2/static-analysis/iac/rulesets/default-ruleset" {
			assert.Equal(t, http.MethodGet, r.Method)
			ruleset := Ruleset{
				ID:    "default-ruleset",
				Name:  "default-ruleset",
				Rules: rules,
			}
			body, err := jsonapi.Marshal(ruleset)
			require.NoError(t, err)
			w.Header().Add("content-type", "application/json")
			_, err = w.Write(body)
			require.NoError(t, err)
		} else if r.URL.Path == "/api/v2/static-analysis/config/client" {
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
		} else {
			assert.Failf(t, "Unexpected request: %s %s", r.Method, r.URL)
			http.NotFoundHandler().ServeHTTP(w, r)
			return
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
