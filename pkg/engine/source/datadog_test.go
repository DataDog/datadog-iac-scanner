package source

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/jsonapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuery(t *testing.T) {
	for _, tc := range []struct {
		name     string
		params   QueryInspectorParameters
		expected []model.QueryMetadata
	}{
		{
			name: "All rules",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
			},
			expected: queries,
		},
		{
			name: "No experimental",
			params: QueryInspectorParameters{
				ExperimentalQueries: false,
				BomQueries:          true,
			},
			expected: []model.QueryMetadata{
				queries[0] /* queries[1] is experimental */, queries[2],
			},
		},
		{
			name: "No BOM queries",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          false,
			},
			expected: []model.QueryMetadata{
				queries[0], queries[1], /* queries[2] has severity=TRACE */
			},
		},
		{
			name: "ExcludeQueries ByIDs",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				ExcludeQueries:      QueryFilter{ByIDs: []string{"rule-1"}},
			},
			expected: []model.QueryMetadata{
				/* queries[0] is excluded */ queries[1], queries[2],
			},
		},
		{
			name: "ExcludeQueries BySeverities",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				ExcludeQueries:      QueryFilter{BySeverities: []string{"MEDIUM"}},
			},
			expected: []model.QueryMetadata{
				queries[0] /* queries[1] has severity=MEDIUM */, queries[2],
			},
		},
		{
			name: "ExcludeQueries ByCategories",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				ExcludeQueries:      QueryFilter{ByCategories: []string{"Supply-Chain"}},
			},
			expected: []model.QueryMetadata{
				queries[0], queries[1], /* queries[2] has category=Supply-Chain */
			},
		},
		{
			name: "ExcludeQueries ByMultipleCategories",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				ExcludeQueries:      QueryFilter{ByCategories: []string{"Supply-Chain", "Encryption"}},
			},
			expected: []model.QueryMetadata{
				/* queries[0] has category=Encryption */ queries[1], /* queries[2] has category=Supply-Chain */
			},
		},
		{
			name: "ExcludeQueries ByMultipleCriteria",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				ExcludeQueries: QueryFilter{
					ByIDs:        []string{"rule-2"},
					ByCategories: []string{"Supply-Chain"},
				},
			},
			expected: []model.QueryMetadata{
				queries[0], /* queries[1] has excluded Id */ /* queries[2] has category=Supply-Chain */
			},
		},
		{
			name: "IncludeQueries ByIDs",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				IncludeQueries:      QueryFilter{ByIDs: []string{"rule-2", "rule-3"}},
			},
			expected: []model.QueryMetadata{
				/* queries[0] is not included */ queries[1], queries[2],
			},
		},
		{
			name: "IncludeQueries BySeverities",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				IncludeQueries:      QueryFilter{BySeverities: []string{"HIGH"}},
			},
			expected: []model.QueryMetadata{
				queries[0], /* queries[1] has severity=MEDIUM, queries[2] has severity=TRACE */
			},
		},
		{
			name: "IncludeQueries ByCategories",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				IncludeQueries:      QueryFilter{ByCategories: []string{"Backup"}},
			},
			expected: []model.QueryMetadata{
				/* queries[0] has category=Encryption */ queries[1], /* queries[2] has category=Supply-Chain */
			},
		},
		{
			name: "IncludeQueries BySeverities multiple",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				IncludeQueries:      QueryFilter{BySeverities: []string{"HIGH", "MEDIUM"}},
			},
			expected: []model.QueryMetadata{
				queries[0], queries[1], /* queries[2] has severity=TRACE */
			},
		},
		{
			name: "IncludeQueries BySeverities and ByCategories",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				IncludeQueries: QueryFilter{
					BySeverities: []string{"HIGH"},
					ByCategories: []string{"Encryption", "Backup"},
				},
			},
			expected: []model.QueryMetadata{
				queries[0], /* queries[1]: MEDIUM not in HIGH; queries[2]: TRACE not in HIGH */
			},
		},
		{
			name: "IncludeQueries and ExcludeQueries",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				IncludeQueries:      QueryFilter{BySeverities: []string{"HIGH", "MEDIUM"}},
				ExcludeQueries:      QueryFilter{ByCategories: []string{"Backup"}},
			},
			expected: []model.QueryMetadata{
				queries[0], /* queries[1]: included by severity but excluded by category; queries[2]: not included */
			},
		},
		{
			name: "IncludeQueries and ExcludeQueries by different criteria",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				IncludeQueries:      QueryFilter{ByCategories: []string{"Encryption", "Supply-Chain"}},
				ExcludeQueries:      QueryFilter{BySeverities: []string{"TRACE"}},
			},
			expected: []model.QueryMetadata{
				queries[0], /* queries[1]: not included; queries[2]: included but excluded by severity */
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := getDatadogSource(t, rules)
			actual, err := source.GetQueries(t.Context(), &tc.params)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestSourceWithWantedPlatforms(t *testing.T) {
	for _, tc := range []struct {
		name            string
		wantedPlatforms []string
		expected        []model.QueryMetadata
	}{
		{
			name:            "All rules",
			wantedPlatforms: []string{""},
			expected:        queries,
		},
		{
			name:            "1 platform",
			wantedPlatforms: []string{"GRPC"},
			expected: []model.QueryMetadata{
				queries[1], // Common is always included
				queries[2],
			},
		},
		{
			name:            "2 platforms",
			wantedPlatforms: []string{"Dockerfile", "GRPC"},
			expected: []model.QueryMetadata{
				queries[0],
				queries[1], // Common is always included
				queries[2],
			},
		},
		{
			name:            "Platform not in rules",
			wantedPlatforms: []string{"Kubernetes"},
			expected: []model.QueryMetadata{
				queries[1], // Common is always included
			},
		},
		{
			name:            "Platforms that don't exist",
			wantedPlatforms: []string{"xxxx", "yyyy"},
			expected: []model.QueryMetadata{
				queries[1], // Common is always included
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := getDatadogSource(t, rules, WithWantedPlatforms(tc.wantedPlatforms))
			actual, err := source.GetQueries(t.Context(), &QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
			})
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestSourceWithWantedProviders(t *testing.T) {
	for _, tc := range []struct {
		name            string
		wantedProviders []string
		expected        []model.QueryMetadata
	}{
		{
			name:            "All rules",
			wantedProviders: []string{""},
			expected:        queries,
		},
		{
			name:            "1 provider",
			wantedProviders: []string{"gcp"},
			expected: []model.QueryMetadata{
				queries[0],
				queries[2], // Common is always included
			},
		},
		{
			name:            "2 providers",
			wantedProviders: []string{"gcp", "common"},
			expected: []model.QueryMetadata{
				queries[0],
				queries[2], // Common is always included
			},
		},
		{
			name:            "Providers that don't exist",
			wantedProviders: []string{"xxxx", "yyyy"},
			expected: []model.QueryMetadata{
				queries[2], // Common is always included
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := getDatadogSource(t, rules, WithWantedCloudProviders(tc.wantedProviders))
			actual, err := source.GetQueries(t.Context(), &QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
			})
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

var rules = []*Rule{
	{
		ID:               "rule-1",
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
		ID:               "rule-2",
		Name:             "some-name",
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
	{
		ID:               "rule-3",
		Name:             "rule-3",
		ShortDescription: "short 3",
		Description:      "full 3",
		Platform:         "GRPC",
		Type:             "rego",
		RegoQuery:        []byte("query text 3"),
		Severity:         "TRACE",
		Category:         "Supply-Chain",
		Provider:         ptr("common"),
		Aggregation:      ptr(2),
		Overrides: []RuleOverride{
			{
				Key:              "1.0",
				ID:               ptr("ovr-rule-3"),
				ShortDescription: ptr("ovr short 3"),
				Description:      ptr("ovr full 3"),
				DescriptionId:    ptr("ovr description id"),
				Platform:         ptr("CICD"),
				Severity:         ptr("INFO"),
				Category:         ptr("Best Practices"),
				Provider:         ptr("azure"),
				Cwe:              ptr("456"),
				DocumentationUrl: ptr("http://example.com/doc3"),
			},
		},
		IsPublished: true,
	},
}

var queries = []model.QueryMetadata{
	{
		InputData: "{}",
		Query:     "rule-1",
		Content:   "query text 1",
		Metadata: map[string]any{
			"id":              "rule-1",
			"queryName":       "short 1",
			"descriptionText": "full 1",
			"platform":        "Dockerfile",
			"severity":        "HIGH",
			"category":        "Encryption",
			"descriptionUrl":  "http://example.com/doc1",
			"descriptionId":   "abcdef",
			"cloudProvider":   "gcp",
			"cwe":             "123",
		},
		Platform:    "Dockerfile",
		CWE:         "123",
		Aggregation: 1,
	},
	{
		InputData: "{}",
		Query:     "some-name",
		Content:   "query text 2",
		Metadata: map[string]any{
			"id":              "rule-2",
			"queryName":       "short 2",
			"descriptionText": "full 2",
			"platform":        "Common",
			"severity":        "MEDIUM",
			"category":        "Backup",
		},
		Platform:     "Common",
		Aggregation:  1,
		Experimental: true,
	},
	{
		InputData: "{}",
		Query:     "rule-3",
		Content:   "query text 3",
		Metadata: map[string]any{
			"id":              "rule-3",
			"queryName":       "short 3",
			"descriptionText": "full 3",
			"platform":        "GRPC",
			"severity":        "TRACE",
			"category":        "Supply-Chain",
			"cloudProvider":   "common",
			"aggregation":     2,
			"overrides": map[string]map[string]any{
				"1.0": {
					"id":              "ovr-rule-3",
					"queryName":       "ovr short 3",
					"descriptionText": "ovr full 3",
					"platform":        "CICD",
					"severity":        "INFO",
					"category":        "Best Practices",
					"descriptionUrl":  "http://example.com/doc3",
					"descriptionId":   "ovr description id",
					"cloudProvider":   "azure",
					"cwe":             "456",
				},
			},
		},
		Platform:    "GRPC",
		Aggregation: 2,
	},
}

func getDatadogSource(t *testing.T, rules []*Rule, options ...DatadogSourceOption) QueriesSource {
	handler := func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/api/v2/static-analysis/iac/rulesets/default-ruleset"
		assert.Equal(t, expectedPath, r.URL.Path)
		if r.URL.Path != expectedPath {
			http.NotFoundHandler().ServeHTTP(w, r)
			return
		}
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "my-api-key", r.Header.Get("dd-api-key"))
		assert.Equal(t, "my-app-key", r.Header.Get("dd-application-key"))
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
	}
	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)

	source, err := NewDatadogSource(
		append(options,
			withHostname(server.Listener.Addr().String()),
			WithHttpClient(server.Client()),
			WithApiKey("my-api-key"),
			WithAppKey("my-app-key"),
		)...,
	)
	require.NoError(t, err)
	return source
}

func ptr[T any](t T) *T {
	return &t
}
