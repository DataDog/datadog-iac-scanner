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
