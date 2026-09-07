package report

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	reportModel "github.com/DataDog/datadog-iac-scanner/pkg/report/model"
	"github.com/DataDog/datadog-iac-scanner/test"
	"github.com/stretchr/testify/require"
)

type reportTestCase struct {
	caseTest       jsonCaseTest
	expectedResult model.Summary
}

type sarifReport struct {
	Schema       string                 `json:"$schema"`
	SarifVersion string                 `json:"version"`
	Runs         []reportModel.SarifRun `json:"runs"`
}

var sarifTests = []reportTestCase{
	{
		caseTest: jsonCaseTest{
			summary:  test.SummaryMock,
			path:     "./testdir",
			filename: "testout",
		},
		expectedResult: test.SummaryMock,
	},
	{
		caseTest: jsonCaseTest{
			summary:  test.SummaryMockCritical,
			path:     "./testdir",
			filename: "testout2",
		},
		expectedResult: test.SummaryMockCritical,
	},
}

// TestPrintSarifReport tests the functions [PrintSarifReport()] and all the methods called by them
func TestPrintSarifReport(t *testing.T) {
	ctx := context.Background()
	for idx, sarifTest := range sarifTests {
		t.Run(fmt.Sprintf("Sarif File test case %d", idx), func(t *testing.T) {
			if err := os.MkdirAll(sarifTest.caseTest.path, os.ModePerm); err != nil {
				t.Fatal(err)
			}
			err := PrintSarifReport(ctx, sarifTest.caseTest.path, sarifTest.caseTest.filename, sarifTest.caseTest.summary, &model.SCIInfo{})
			checkFileExists(t, err, &sarifTest, "sarif")
			jsonResult, err := os.ReadFile(filepath.Join(sarifTest.caseTest.path, sarifTest.caseTest.filename+".sarif"))
			require.NoError(t, err)
			var resultSarif sarifReport
			err = json.Unmarshal(jsonResult, &resultSarif)
			require.NoError(t, err)
			require.Equal(t, "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", resultSarif.Schema)
			require.Equal(t, "2.1.0", resultSarif.SarifVersion)
			require.Len(t, resultSarif.Runs, len(sarifTest.expectedResult.Queries))
			require.NoError(t, os.RemoveAll(sarifTest.caseTest.path))
		})
	}
}

func TestPrintSarifReportPreservesModuleAttribution(t *testing.T) {
	tests := []struct {
		name               string
		attribution        *model.ModuleAttribution
		expectedModulePath int
	}{
		{
			name: "direct local",
			attribution: &model.ModuleAttribution{
				Name:           "network",
				Source:         "modules/network",
				SourceType:     "local",
				DependencyType: "direct",
				CodeLocation: model.SourceLocation{
					Filename: "stack/main.tf", LineStart: 2, LineEnd: 5, ColumnStart: 1, ColumnEnd: 2,
				},
				ModuleCodeLocation: model.SourceLocation{
					Filename: "main.tf", LineStart: 15, LineEnd: 25, ColumnStart: 1, ColumnEnd: 2,
				},
				ModuleCodeOwned: true,
			},
		},
		{
			name: "transitive remote",
			attribution: &model.ModuleAttribution{
				Name:           "network",
				Source:         "registry.example.com/acme/network/aws",
				SourceType:     "registry",
				Version:        "1.2.3",
				DependencyType: "transitive",
				CodeLocation: model.SourceLocation{
					Filename: "stack/main.tf", LineStart: 2, LineEnd: 5, ColumnStart: 1, ColumnEnd: 2,
				},
				ModuleCodeLocation: model.SourceLocation{
					Filename: "main.tf", LineStart: 15, LineEnd: 25, ColumnStart: 1, ColumnEnd: 2,
				},
				ModulePath: []model.ModulePathHop{
					{
						Name: "platform", Source: "modules/platform", SourceType: "local",
						CodeLocation: model.SourceLocation{
							Filename: "stack/main.tf", LineStart: 2, LineEnd: 5, ColumnStart: 1, ColumnEnd: 2,
						},
					},
					{
						Name: "network", Source: "registry.example.com/acme/network/aws",
						SourceType: "registry", Version: "1.2.3",
						CodeLocation: model.SourceLocation{
							Filename: "main.tf", LineStart: 8, LineEnd: 11, ColumnStart: 1, ColumnEnd: 2,
						},
					},
				},
			},
			expectedModulePath: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := model.Summary{Queries: model.QueryResultSlice{{
				QueryName: "Deletion protection disabled",
				QueryID:   "deletion-protection-disabled",
				Severity:  model.SeverityHigh,
				Platform:  "Terraform",
				Files: []model.VulnerableFile{{
					FileName: "cached-module/main.tf",
					Line:     18,
					ResourceLocation: model.ResourceLocation{
						Start: model.ResourceLine{Line: 15, Col: 1},
						End:   model.ResourceLine{Line: 25, Col: 2},
					},
					ResourceType:      "aws_lb",
					ResourceName:      "nlb",
					ModuleAttribution: tt.attribution,
				}},
			}}}

			outputDir := t.TempDir()
			require.NoError(t, PrintSarifReport(
				context.Background(), outputDir, "module", &summary, &model.SCIInfo{},
			))

			raw, err := os.ReadFile(filepath.Join(outputDir, "module.sarif"))
			require.NoError(t, err)
			var output struct {
				Runs []struct {
					Results []struct {
						Locations []struct {
							PhysicalLocation struct {
								ArtifactLocation struct {
									URI string `json:"uri"`
								} `json:"artifactLocation"`
							} `json:"physicalLocation"`
						} `json:"locations"`
						Properties map[string]json.RawMessage `json:"properties"`
					} `json:"results"`
				} `json:"runs"`
			}
			require.NoError(t, json.Unmarshal(raw, &output))
			require.Len(t, output.Runs, 1)
			require.Len(t, output.Runs[0].Results, 1)

			result := output.Runs[0].Results[0]
			require.Equal(t, "stack/main.tf",
				result.Locations[0].PhysicalLocation.ArtifactLocation.URI)

			var modulePayload model.ModuleAttributionSARIF
			require.NoError(t, json.Unmarshal(result.Properties["module"], &modulePayload))
			require.Equal(t, tt.attribution.Name, modulePayload.Name)
			require.Equal(t, tt.attribution.Source, modulePayload.Source)
			require.Equal(t, tt.attribution.SourceType, modulePayload.SourceType)
			require.Equal(t, tt.attribution.Version, modulePayload.Version)
			require.Equal(t, tt.attribution.DependencyType, modulePayload.DependencyType)
			require.Equal(t, tt.attribution.ModuleCodeLocation, modulePayload.ModuleCodeLocation)
			require.Equal(t, tt.attribution.ModulePath, modulePayload.ModulePath)
			require.Len(t, modulePayload.ModulePath, tt.expectedModulePath)
		})
	}
}

func checkFileExists(t *testing.T, err error, tc *reportTestCase, extension string) {
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(tc.caseTest.path, tc.caseTest.filename+fmt.Sprintf(".%s", extension)))
}
