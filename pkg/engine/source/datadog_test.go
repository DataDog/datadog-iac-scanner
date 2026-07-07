package source

import (
	"context"
	"errors"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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
				ExcludeQueries:      QueryFilter{ByIDs: []string{"dockerfile-gcp-rule-1"}},
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
				IncludeQueries:      QueryFilter{ByIDs: []string{"rule-2", "grpc-common-rule-3"}},
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
		{
			name: "IncludeQueriesById works with legacy id",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				IncludeQueries:      QueryFilter{ByIDs: []string{"rule-2"}},
			},
			expected: []model.QueryMetadata{
				queries[1],
			},
		},
		{
			name: "IncludeQueriesById works with regular id",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				IncludeQueries:      QueryFilter{ByIDs: []string{"common-rule-2"}},
			},
			expected: []model.QueryMetadata{
				queries[1],
			},
		},
		{
			name: "ExcludeQueriesById works with legacy id",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				ExcludeQueries:      QueryFilter{ByIDs: []string{"rule-2"}},
			},
			expected: []model.QueryMetadata{
				queries[0] /* queries[1] excluded */, queries[2],
			},
		},
		{
			name: "ExcludeQueriesById works with regular id",
			params: QueryInspectorParameters{
				ExperimentalQueries: true,
				BomQueries:          true,
				ExcludeQueries:      QueryFilter{ByIDs: []string{"common-rule-2"}},
			},
			expected: []model.QueryMetadata{
				queries[0] /* queries[1] excluded */, queries[2],
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

func TestConvertRuleIncludesArgumentsInMetadata(t *testing.T) {
	rule := &datadog.Rule{
		ID:               "terraform-aws-required-tags",
		Name:             "required_tags",
		ShortDescription: "Required tags are missing",
		Description:      "Ensure required tags are present",
		DescriptionId:    ptr("required-tags"),
		Platform:         "Terraform",
		Type:             "rego",
		RegoQuery:        []byte("package datadog"),
		Severity:         "HIGH",
		Category:         "Best Practices",
		Provider:         ptr("aws"),
		Arguments: []datadog.RuleArgument{
			{
				Name:        "required_tags",
				Description: "Tags that must exist on the resource",
			},
		},
		IsPublished: true,
	}

	query := ConvertRule(rule)

	assert.Equal(t, []any{
		map[string]any{
			"name":        "required_tags",
			"description": "Tags that must exist on the resource",
		},
	}, query.Metadata["arguments"])
}

var rules = []*datadog.Rule{
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
	{
		ID:               "grpc-common-rule-3",
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
		Overrides: []datadog.RuleOverride{
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
			"id":              "dockerfile-gcp-rule-1",
			"queryName":       "short 1",
			"descriptionText": "full 1",
			"platform":        "Dockerfile",
			"severity":        "HIGH",
			"category":        "Encryption",
			"descriptionUrl":  "http://example.com/doc1",
			"descriptionID":   "abcdef",
			"cloudProvider":   "gcp",
			"cwe":             "123",
		},
		Platform:    "dockerfile",
		Aggregation: 1,
	},
	{
		InputData: "{}",
		Query:     "rule-2",
		Content:   "query text 2",
		Metadata: map[string]any{
			"id":              "common-rule-2",
			"legacyId":        "rule-2",
			"queryName":       "short 2",
			"descriptionText": "full 2",
			"platform":        "Common",
			"severity":        "MEDIUM",
			"category":        "Backup",
			"descriptionUrl":  "https://docs.datadoghq.com/security/code_security/iac_security/iac_rules/common/rule-2/",
			"descriptionID":   "228a1c19",
			"cwe":             "",
		},
		Platform:     "common",
		Aggregation:  1,
		Experimental: true,
	},
	{
		InputData: "{}",
		Query:     "rule-3",
		Content:   "query text 3",
		Metadata: map[string]any{
			"id":              "grpc-common-rule-3",
			"queryName":       "short 3",
			"descriptionText": "full 3",
			"platform":        "GRPC",
			"severity":        "TRACE",
			"category":        "Supply-Chain",
			"cloudProvider":   "common",
			"aggregation":     2,
			"descriptionUrl":  "https://docs.datadoghq.com/security/code_security/iac_security/iac_rules/grpc/common/rule-3/",
			"descriptionID":   "868c4101",
			"cwe":             "",
			"override": map[string]any{
				"1.0": map[string]any{
					"id":              "ovr-rule-3",
					"queryName":       "ovr short 3",
					"descriptionText": "ovr full 3",
					"platform":        "CICD",
					"severity":        "INFO",
					"category":        "Best Practices",
					"descriptionUrl":  "http://example.com/doc3",
					"descriptionID":   "ovr description id",
					"cloudProvider":   "azure",
					"cwe":             "456",
				},
			},
		},
		Platform:    "grpc",
		Aggregation: 2,
	},
}

func getDatadogSource(t *testing.T, rules []*datadog.Rule, options ...DatadogSourceOption) QueriesSource {
	client := &fakeDatadogClient{rules: rules}
	source, err := NewDatadogSource(client, options...)
	require.NoError(t, err)
	return source
}

func TestGetQueryLibraryUsesBackendWithFallback(t *testing.T) {
	source, err := NewDatadogSource(
		&fakeDatadogClient{
			libraries: map[string]datadog.Library{
				"terraform": {
					RegoCode:  "backend code",
					InputData: "backend input",
				},
			},
		},
		WithLibraryOverride(stubLibrarySource{
			libraries: map[string]RegoLibraries{
				"k8s": {
					LibraryCode:      "fallback code",
					LibraryInputData: "fallback input",
				},
			},
		}),
	)
	require.NoError(t, err)

	terraformLib, err := source.GetQueryLibrary(t.Context(), "terraform")
	require.NoError(t, err)
	assert.Equal(t, "backend code", terraformLib.LibraryCode)
	assert.Equal(t, "backend input", terraformLib.LibraryInputData)

	k8sLib, err := source.GetQueryLibrary(t.Context(), "k8s")
	require.NoError(t, err)
	assert.Equal(t, "fallback code", k8sLib.LibraryCode)
	assert.Equal(t, "fallback input", k8sLib.LibraryInputData)
}

func TestGetQueryLibraryUsesExplicitLibrarySource(t *testing.T) {
	source, err := NewDatadogSource(
		&fakeDatadogClient{
			libraries: map[string]datadog.Library{
				"terraform": {
					RegoCode: "backend code",
				},
			},
		},
		WithLibrarySource(stubLibrarySource{
			libraries: map[string]RegoLibraries{
				"terraform": {
					LibraryCode: "explicit source code",
				},
			},
		}),
	)
	require.NoError(t, err)

	lib, err := source.GetQueryLibrary(t.Context(), "terraform")
	require.NoError(t, err)
	assert.Equal(t, "explicit source code", lib.LibraryCode)
}

type stubLibrarySource struct {
	libraries map[string]RegoLibraries
}

func (s stubLibrarySource) GetQueries(_ context.Context, _ *QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return nil, nil
}

func (s stubLibrarySource) GetQueryLibrary(_ context.Context, platform string) (RegoLibraries, error) {
	lib, ok := s.libraries[platform]
	if !ok {
		return RegoLibraries{}, errors.New("missing library")
	}
	return lib, nil
}

type fakeDatadogClient struct {
	rules     []*datadog.Rule
	libraries map[string]datadog.Library
}

func (f fakeDatadogClient) GetDefaultRuleset(ctx context.Context) (*datadog.Ruleset, error) {
	out := &datadog.Ruleset{
		ID:    "default-ruleset",
		Name:  "default-ruleset",
		Rules: f.rules,
	}
	return out, nil
}

func (f fakeDatadogClient) GetDefaultRulesetWithTests(ctx context.Context) (*datadog.Ruleset, error) {
	panic("unimplemented")
}

func (f fakeDatadogClient) GetRemoteConfig(ctx context.Context, repoUrl string, localConfig []byte) ([]byte, error) {
	panic("unimplemented")
}

func (f fakeDatadogClient) GetLibraries(_ context.Context) (map[string]datadog.Library, error) {
	return f.libraries, nil
}

func ptr[T any](t T) *T {
	return &t
}
