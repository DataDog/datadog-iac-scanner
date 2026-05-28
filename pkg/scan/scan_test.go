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

// stubQuerySource serves a fixed query slice and a trivial Rego library.
type stubQuerySource struct {
	queries []model.QueryMetadata
}

func (s *stubQuerySource) GetQueries(_ context.Context, _ *source.QueryInspectorParameters) ([]model.QueryMetadata, error) {
	return s.queries, nil
}

func (s *stubQuerySource) GetQueryLibrary(_ context.Context, platform string) (source.RegoLibraries, error) {
	return source.RegoLibraries{
		LibraryCode:      "package generic." + platform + "\n",
		LibraryInputData: "{}",
	}, nil
}

// Test_ExecuteScan runs the scan pipeline against a synthetic in-memory rule
// so the assertions are decoupled from the rule corpus.
func Test_ExecuteScan(t *testing.T) {
	const ruleID = "test-execute-scan-rule"
	rego := `package Cx

CxPolicy[result] {
	resource := input.document[i].resource.aws_s3_bucket[name]
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_s3_bucket should be encrypted",
		"keyActualValue": "aws_s3_bucket is not encrypted",
	}
}
`
	query := model.QueryMetadata{
		Query:     ruleID,
		Content:   rego,
		InputData: "{}",
		Platform:  "terraform",
		Metadata: map[string]interface{}{
			"id":        ruleID,
			"legacyId":  ruleID,
			"queryName": "Synthetic Execute-Scan Rule",
			"severity":  "HIGH",
			"platform":  "Terraform",
			"category":  "Encryption",
		},
	}

	scanParams := Parameters{
		Path:                    []string{filepath.Join("test", "sample.tf")},
		QueriesPath:             []string{"."},
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
	require.NoError(t, err)
	c.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
		return &stubQuerySource{queries: []model.QueryMetadata{query}}, nil
	}

	r, err := c.executeScan(ctx)
	require.NoError(t, err)
	require.NotNil(t, r)
	require.NotEmpty(t, r.Results, "expected at least one synthetic violation")

	for i, result := range r.Results {
		require.Equalf(t, model.Severity("HIGH"), model.Severity(result.Severity), "result[%d] severity", i)
		require.Equalf(t, ruleID, result.QueryID, "result[%d] query id", i)
	}
}

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
