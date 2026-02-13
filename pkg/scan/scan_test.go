package scan

import (
	"context"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/stretchr/testify/require"
)

func Test_ExecuteScan(t *testing.T) {
	// Updated test (different from Checkmarx/kics) to use a terraform file example
	tests := []struct {
		name                 string
		scanParams           Parameters
		ctx                  context.Context
		expectedResultsCount int
		expectedSeverity     model.Severity
		expectedLine         int
	}{
		{
			name: "test exec scan",
			scanParams: Parameters{
				Path:                    []string{"./../../test/e2e/fixtures/no-exclusions.tf"},
				QueriesPath:             []string{"assets/queries"},
				LibrariesPath:           "assets/libraries",
				PreviewLines:            3,
				CloudProvider:           []string{"aws"},
				Platform:                []string{"Terraform"},
				ChangedDefaultQueryPath: false,
				MaxFileSizeFlag:         100,
				QueryExecTimeout:        60,
				ScanID:                  "console",
				MaxResolverDepth:        15,
				FlagEvaluator:           featureflags.NewLocalEvaluator(),
			},
			ctx:                  context.Background(),
			expectedResultsCount: 5,
			expectedSeverity:     "MEDIUM",
			expectedLine:         5,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(ctx, &tt.scanParams, &consolePrinter.Printer{})

			if err != nil {
				t.Fatalf(`NewClient failed for path %s with error: %v`, tt.scanParams.Path[0], err)
			}

			r, err := c.executeScan(tt.ctx)

			if err != nil {
				t.Fatalf(`ExecuteScan failed for path %s with error: %v`, tt.scanParams.Path[0], err)
			}

			resultsCount := len(r.Results)
			require.Equal(t, tt.expectedResultsCount, resultsCount)

			// Sort results by severity to ensure deterministic ordering
			// Severity order: HIGH > MEDIUM > LOW > INFO
			severityOrder := map[model.Severity]int{
				model.SeverityHigh:   0,
				model.SeverityMedium: 1,
				model.SeverityLow:    2,
				model.SeverityInfo:   3,
			}
			sort.Slice(r.Results, func(i, j int) bool {
				return severityOrder[r.Results[i].Severity] < severityOrder[r.Results[j].Severity]
			})

			firstResult := &r.Results[0]
			require.Equal(t, tt.expectedSeverity, firstResult.Severity)
		})
	}
}

// func Test_GetSecretsRegexRules(t *testing.T) {
// 	tests := []struct {
// 		name           string
// 		scanParams     Parameters
// 		expectedError  bool
// 		expectedOutput string
// 	}{
// 		{
// 			name: "default value",
// 			scanParams: Parameters{
// 				SecretsRegexesPath: "",
// 			},
// 			expectedOutput: assets.SecretsQueryRegexRulesJSON,
// 			expectedError:  false,
// 		},
// 		{
// 			name: "custom value",
// 			scanParams: Parameters{
// 				SecretsRegexesPath: filepath.Join("..", "..", "assets", "queries", "common", "passwords_and_secrets", "regex_rules.json"),
// 			},
// 			expectedOutput: assets.SecretsQueryRegexRulesJSON,
// 			expectedError:  false,
// 		},
// 		{
// 			name: "invalid path value",
// 			scanParams: Parameters{
// 				SecretsRegexesPath: filepath.Join("invalid", "path"),
// 			},
// 			expectedOutput: "",
// 			expectedError:  true,
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			c := &Client{}
// 			c.ScanParams = &tt.scanParams
// 			v, err := getSecretsRegexRules(c.ScanParams.SecretsRegexesPath)

// 			require.Equal(t, tt.expectedOutput, v)
// 			if tt.expectedError {
// 				require.Error(t, err)
// 			} else {
// 				require.NoError(t, err)
// 			}
// 		})
// 	}
// }

func Test_CreateQueryFilter(t *testing.T) {
	tests := []struct {
		name           string
		scanParams     Parameters
		expectedOutput source.QueryInspectorParameters
	}{
		{
			name: "test empty filter",
			scanParams: Parameters{
				ExcludeQueries:    []string{},
				ExcludeCategories: []string{},
				ExcludeSeverities: []string{},
				IncludeQueries:    []string{},
				InputData:         "",
				BillOfMaterials:   false,
			},
			expectedOutput: source.QueryInspectorParameters{
				ExcludeQueries: source.ExcludeQueries{
					ByIDs:        []string{},
					ByCategories: []string{},
					BySeverities: []string{},
				},
				IncludeQueries: source.IncludeQueries{
					ByIDs: []string{},
				},
				InputDataPath: "",
				BomQueries:    false,
			},
		},
		{
			name: "test query filter with some fields and BoM",
			scanParams: Parameters{
				ExcludeQueries:    []string{"c065b98e-1515-4991-9dca-b602bd6a2fbb"},
				ExcludeCategories: []string{},
				ExcludeSeverities: []string{"info"},
				IncludeQueries:    []string{},
				InputData:         "",
				BillOfMaterials:   true,
			},
			expectedOutput: source.QueryInspectorParameters{
				ExcludeQueries: source.ExcludeQueries{
					ByIDs:        []string{"c065b98e-1515-4991-9dca-b602bd6a2fbb"},
					ByCategories: []string{},
					BySeverities: []string{"info"},
				},
				IncludeQueries: source.IncludeQueries{
					ByIDs: []string{},
				},
				InputDataPath: "",
				BomQueries:    true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{}
			c.ScanParams = &tt.scanParams

			v := c.createQueryFilter()

			require.Equal(t, tt.expectedOutput, *v)
		})
	}
}
