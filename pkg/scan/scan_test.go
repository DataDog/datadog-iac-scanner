package scan

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/stretchr/testify/require"
)

// Test_ExecuteScan smoke-tests the live scan path end-to-end and asserts the
// result is well-shaped. It does NOT pin a specific result count: that count
// is a function of the rule corpus, not of executeScan itself, and a true
// rule-independent rewrite needs a `createQuerySource` injection point that
// `FilesystemSource.GetQueries` does not currently expose.
func Test_ExecuteScan(t *testing.T) {
	scanParams := Parameters{
		Path:                    []string{filepath.Join("test", "sample.tf")},
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
	}

	ctx := context.Background()
	c, err := NewClient(ctx, &scanParams, &consolePrinter.Printer{})
	require.NoError(t, err, "NewClient failed for %s", scanParams.Path[0])

	r, err := c.executeScan(ctx)
	require.NoError(t, err, "executeScan failed for %s", scanParams.Path[0])
	require.NotNil(t, r, "executeScan should return a non-nil result")

	validSeverities := map[model.Severity]struct{}{
		model.SeverityCritical: {},
		model.SeverityHigh:     {},
		model.SeverityMedium:   {},
		model.SeverityLow:      {},
		model.SeverityInfo:     {},
	}
	for i, result := range r.Results {
		_, ok := validSeverities[result.Severity]
		require.Truef(t, ok, "result[%d] has unexpected severity %q", i, result.Severity)
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
				Config:          config.IacConfig{},
				InputData:       "",
				BillOfMaterials: false,
			},
			expectedOutput: source.QueryInspectorParameters{
				ExcludeQueries: source.QueryFilter{},
				IncludeQueries: source.QueryFilter{},
				InputDataPath:  "",
				BomQueries:     false,
			},
		},
		{
			name: "test query filter with some fields and BoM",
			scanParams: Parameters{
				Config: config.IacConfig{
					IgnoreRules:      []string{"c065b98e-1515-4991-9dca-b602bd6a2fbb"},
					IgnoreSeverities: []string{"info"},
					OnlyCategories:   []string{"Accessibility"},
				},
				InputData:       "",
				BillOfMaterials: true,
			},
			expectedOutput: source.QueryInspectorParameters{
				ExcludeQueries: source.QueryFilter{
					ByIDs:        []string{"c065b98e-1515-4991-9dca-b602bd6a2fbb"},
					BySeverities: []string{"info"},
				},
				IncludeQueries: source.QueryFilter{
					ByCategories: []string{"Accessibility"},
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
