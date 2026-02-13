package model

import (
	"context"
	"os"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

var targetTemplate = sarifDescriptorReference{
	ToolComponent: sarifComponentReference{
		ComponentReferenceGUID:  "58cdcc6f-fe41-4724-bfb3-131a93df4c3f",
		ComponentReferenceName:  "Categories",
		ComponentReferenceIndex: 0,
	},
}

// TestNewSarifReport tests if creates a sarif report correctly
func TestNewSarifReport(t *testing.T) {
	sarif := NewSarifReport().(*sarifReport)
	require.Equal(t, "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", sarif.Schema)
	require.Equal(t, "2.1.0", sarif.SarifVersion)
	require.Equal(t, "Datadog IaC Scanning", sarif.Runs[0].Tool.Driver.ToolName)
	require.Equal(t, constants.URL, sarif.Runs[0].Tool.Driver.ToolURI)
	require.Equal(t, constants.Fullname, sarif.Runs[0].Tool.Driver.ToolFullName)
	require.Equal(t, constants.Version, sarif.Runs[0].Tool.Driver.ToolVersion)
}

type sarifTest struct {
	name string
	vq   []model.QueryResult
	want sarifReport
}

var sarifTests = []sarifTest{
	{
		name: "Should not create any rule",
		vq: []model.QueryResult{
			{
				QueryName:   "test",
				QueryID:     "1",
				Description: "test description",
				QueryURI:    "https://www.test.com",
				Severity:    model.SeverityHigh,
				Files:       []model.VulnerableFile{},
				CWE:         "",
			},
		},
		want: sarifReport{
			Runs: initSarifRun(),
		},
	},
	{
		name: "Should create rule with frameworks in properties",
		vq: []model.QueryResult{
			{
				QueryName:   "test",
				QueryID:     "1",
				Description: "test description",
				QueryURI:    "https://www.test.com",
				Severity:    model.SeverityMedium,
				Frameworks: []model.Framework{
					{
						Framework:        "dcsb-m-v2",
						FrameworkVersion: "0.0.1",
						Control:          "aws.1.10",
						Requirement:      "aws",
					},
					{
						Framework:        "chris-test",
						FrameworkVersion: "0.0.1",
						Control:          "chris.1",
						Requirement:      "chris",
					},
				},
				Files: []model.VulnerableFile{
					{
						KeyActualValue: "test",
						FileName:       "test.tf",
						Line:           1,
						ResourceType:   "aws_ami_launch_permission",
						ResourceName:   "test_resource",
						ResourceLocation: model.ResourceLocation{
							Start: model.ResourceLine{Line: 1, Col: 1},
							End:   model.ResourceLine{Line: 1, Col: 10},
						},
					},
				},
				CWE: "",
			},
		},
		want: sarifReport{
			Runs: []SarifRun{
				{
					Tool: sarifTool{
						Driver: sarifDriver{
							Rules: []sarifRule{
								{
									RuleID:               "test",
									RuleName:             "test",
									RuleShortDescription: sarifMessage{Text: "test"},
									RuleFullDescription:  sarifMessage{Text: "test description\nRule ID: [1]"},
									DefaultConfiguration: sarifConfiguration{
										Level: "note",
									},
									HelpURI: "https://www.test.com",
									RuleProperties: sarifProperties{
										"tags": []string{"DATADOG_RULE_TYPE:IAC_SCANNING", "DATADOG_CATEGORY:", "KICS_QUERY_ID:1"},
										"iac-frameworks": []model.Framework{
											{
												Framework:        "dcsb-m-v2",
												FrameworkVersion: "0.0.1",
												Control:          "aws.1.10",
												Requirement:      "aws",
											},
											{
												Framework:        "chris-test",
												FrameworkVersion: "0.0.1",
												Control:          "chris.1",
												Requirement:      "chris",
											},
										},
									},
								},
							},
						},
					},
					Results: []sarifResult{
						{
							ResultRuleID:    "test",
							ResultRuleIndex: 0,
							ResultKind:      "",
							ResultMessage:   sarifMessage{Text: "test", MessageProperties: nil},
							ResultLocations: []SarifLocation{
								{
									PhysicalLocation: sarifPhysicalLocation{
										ArtifactLocation: sarifArtifactLocation{ArtifactURI: "test.tf"},
										Region:           model.SarifRegion{StartLine: 1, EndLine: 1, StartColumn: 1, EndColumn: 10},
									},
								},
							},
							ResultLevel: "note",
							ResultProperties: sarifProperties{
								"tags": []string{"DATADOG_CATEGORY:", "IAC_RESOURCE_TYPE:aws_ami_launch_permission", "IAC_RESOURCE_NAME:test_resource"},
							},
							PartialFingerprints: SarifPartialFingerprints{
								DatadogFingerprint: GetDatadogFingerprintHash(
									model.SCIInfo{
										RunType: "",
										RepositoryCommitInfo: model.RepositoryCommitInfo{
											RepositoryUrl: "",
											Branch:        "",
											CommitSHA:     "",
										},
									},
									"test.tf",
									"aws_ami_launch_permission",
									"test_resource",
									"1",
								),
							},
						},
					},
				},
			},
		},
	},
	{
		name: "Should create one occurrence with valid startLine",
		vq: []model.QueryResult{
			{
				QueryName:   "test",
				QueryID:     "1",
				Description: "test description",
				QueryURI:    "https://www.test.com",
				Severity:    model.SeverityHigh,
				Files: []model.VulnerableFile{
					{
						KeyActualValue: "test",
						FileName:       "test.json",
						Line:           1,
						ResourceType:   "test_resource_type",
						ResourceName:   "test_resource_name",
						ResourceLocation: model.ResourceLocation{
							Start: model.ResourceLine{Line: 1, Col: 1},
							End:   model.ResourceLine{Line: 1, Col: 2},
						},
					},
				},
				CWE: "",
			},
		},
		want: sarifReport{
			Runs: []SarifRun{
				{
					Tool: sarifTool{
						Driver: sarifDriver{
							Rules: []sarifRule{
								{
									RuleID:               "test",
									RuleName:             "test",
									RuleShortDescription: sarifMessage{Text: "test"},
									RuleFullDescription:  sarifMessage{Text: "test description\nRule ID: [1]"},
									DefaultConfiguration: sarifConfiguration{
										Level: "error",
									},
									HelpURI: "https://www.test.com",
									Relationships: []sarifRelationship{
										{
											Relationship: sarifDescriptorReference{
												ReferenceID:    "CAT000",
												ReferenceIndex: 0,
												ToolComponent: sarifComponentReference{
													ComponentReferenceGUID:  "58cdcc6f-fe41-4724-bfb3-131a93df4c3f",
													ComponentReferenceName:  "Categories",
													ComponentReferenceIndex: targetTemplate.ToolComponent.ComponentReferenceIndex,
												},
											},
										},
									},
								},
							},
						},
					},
					Results: []sarifResult{
						{
							ResultRuleID:    "test",
							ResultRuleIndex: 0,
							ResultKind:      "",
							ResultMessage:   sarifMessage{Text: "test", MessageProperties: nil},
							ResultLocations: []SarifLocation{
								{
									PhysicalLocation: sarifPhysicalLocation{
										ArtifactLocation: sarifArtifactLocation{ArtifactURI: "test.json"},
										Region:           model.SarifRegion{StartLine: 1, EndLine: 1, StartColumn: 1, EndColumn: 2},
									},
								},
							},
							ResultLevel: "warning",
							ResultProperties: sarifProperties{
								"tags": []string{"DATADOG_CATEGORY:", "IAC_RESOURCE_TYPE:test_resource_type", "IAC_RESOURCE_NAME:test_resource_name"},
							},
							PartialFingerprints: SarifPartialFingerprints{
								DatadogFingerprint: GetDatadogFingerprintHash(
									model.SCIInfo{
										RunType: "",
										RepositoryCommitInfo: model.RepositoryCommitInfo{
											RepositoryUrl: "",
											Branch:        "",
											CommitSHA:     "",
										},
									},
									"test.json",
									"test_resource_type",
									"test_resource_name",
									"1",
								),
							},
						},
					},
					Taxonomies: []sarifTaxonomy{
						{
							TaxonomyGUID:             "58cdcc6f-fe41-4724-bfb3-131a93df4c3f",
							TaxonomyName:             "Categories",
							TaxonomyFullDescription:  sarifMessage{Text: "Category is not defined"},
							TaxonomyShortDescription: sarifMessage{Text: "Category is not defined"},
							TaxonomyDefinitions: []taxonomyDefinitions{
								{
									DefinitionGUID:             "",
									DefinitionName:             "Undefined Category",
									DefinitionID:               "CAT000",
									DefinitionShortDescription: cweMessage{Text: "Category is not defined"},
									DefinitionFullDescription:  cweMessage{Text: "Category is not defined"},
									HelpURI:                    "",
								},
							},
						},
						{
							TaxonomyGUID:                              "1489b0c4-d7ce-4d31-af66-6382a01202e3",
							TaxonomyName:                              "CWE",
							TaxonomyFullDescription:                   sarifMessage{Text: "The MITRE Common Weakness Enumeration"},
							TaxonomyShortDescription:                  sarifMessage{Text: "The MITRE Common Weakness Enumeration"},
							TaxonomyDownloadURI:                       "https://cwe.mitre.org/data/published/cwe_v4.13.pdf",
							TaxonomyIsComprehensive:                   true,
							TaxonomyLanguage:                          "en",
							TaxonomyMinRequiredLocDataSemanticVersion: "4.13",
							TaxonomyOrganization:                      "MITRE",
							TaxonomyRealeaseDateUtc:                   "2023-10-26",
							TaxonomyDefinitions: []taxonomyDefinitions{
								{},
							},
						},
					},
				},
			},
		},
	},
	{
		name: "Should create multiple occurrence",
		vq: []model.QueryResult{
			{
				QueryName:   "test",
				QueryID:     "test",
				Description: "test description",
				QueryURI:    "https://www.test.com",
				Category:    "test",
				Severity:    model.SeverityHigh,
				Files: []model.VulnerableFile{
					{
						KeyActualValue: "test",
						FileName:       "",
						Line:           1,
						ResourceType:   "test_resource_type",
						ResourceName:   "test_resource_name",
						ResourceLocation: model.ResourceLocation{
							Start: model.ResourceLine{Line: 1, Col: 1},
							End:   model.ResourceLine{Line: 1, Col: 2},
						},
					},
				},
				CWE: "",
			},
			{
				QueryName:   "test info",
				QueryID:     "test info",
				Description: "test description",
				QueryURI:    "https://www.test.com",
				Category:    "test",
				Severity:    model.SeverityInfo,
				Files: []model.VulnerableFile{
					{
						KeyActualValue: "test",
						FileName:       "",
						Line:           1,
						ResourceType:   "test_resource_type_2",
						ResourceName:   "test_resource_name_2",
						ResourceLocation: model.ResourceLocation{
							Start: model.ResourceLine{Line: 1, Col: 1},
							End:   model.ResourceLine{Line: 1, Col: 2},
						},
					},
				},
				CWE: "22",
			},
		},
		want: sarifReport{
			Runs: []SarifRun{
				{
					Tool: sarifTool{
						Driver: sarifDriver{
							Rules: []sarifRule{
								{
									RuleID:               "test",
									RuleName:             "test",
									RuleShortDescription: sarifMessage{Text: "test"},
									RuleFullDescription:  sarifMessage{Text: "test description\nRule ID: [test]"},
									DefaultConfiguration: sarifConfiguration{
										Level: "error",
									},
									HelpURI: "https://www.test.com",
									Relationships: []sarifRelationship{
										{
											Relationship: sarifDescriptorReference{
												ReferenceID:    "CAT000",
												ReferenceIndex: 0,
												ToolComponent: sarifComponentReference{
													ComponentReferenceGUID:  "58cdcc6f-fe41-4724-bfb3-131a93df4c3f",
													ComponentReferenceName:  "Categories",
													ComponentReferenceIndex: targetTemplate.ToolComponent.ComponentReferenceIndex,
												},
											},
										},
									},
								},
								{
									RuleID:               "test info",
									RuleName:             "test info",
									RuleShortDescription: sarifMessage{Text: "test"},
									RuleFullDescription:  sarifMessage{Text: "test description/nRule ID: [test info]"},
									DefaultConfiguration: sarifConfiguration{
										Level: "none",
									},
									HelpURI: "https://www.test.com",
									Relationships: []sarifRelationship{
										{
											Relationship: sarifDescriptorReference{
												ReferenceID:    "CAT000",
												ReferenceIndex: 0,
												ToolComponent: sarifComponentReference{
													ComponentReferenceGUID:  "58cdcc6f-fe41-4724-bfb3-131a93df4c3f",
													ComponentReferenceName:  "Categories",
													ComponentReferenceIndex: targetTemplate.ToolComponent.ComponentReferenceIndex,
												},
											},
										},
										{
											Relationship: sarifDescriptorReference{
												ReferenceID:   "22",
												ReferenceGUID: "1489b0c4-d7ce-4d31-af66-6382a01202e3",
												ToolComponent: sarifComponentReference{
													ComponentReferenceGUID:  "1489b0c4-d7ce-4d31-af66-6382a01202e3",
													ComponentReferenceName:  "CWE",
													ComponentReferenceIndex: targetTemplate.ToolComponent.ComponentReferenceIndex,
												},
											},
										},
									},
								},
							},
						},
					},

					Results: []sarifResult{
						{
							ResultRuleID:    "test",
							ResultRuleIndex: 0,
							ResultKind:      "",
							ResultMessage: sarifMessage{
								Text:              "test",
								MessageProperties: nil,
							},
							ResultLevel: "warning",
							ResultLocations: []SarifLocation{
								{
									PhysicalLocation: sarifPhysicalLocation{
										ArtifactLocation: sarifArtifactLocation{ArtifactURI: ""},
										Region:           model.SarifRegion{StartLine: 1, EndLine: 1, EndColumn: 2, StartColumn: 1},
									},
								},
							},
							ResultProperties: sarifProperties{
								"tags": []string{"DATADOG_CATEGORY:test", "IAC_RESOURCE_TYPE:test_resource_type", "IAC_RESOURCE_NAME:test_resource_name"},
							},
							PartialFingerprints: SarifPartialFingerprints{
								DatadogFingerprint: GetDatadogFingerprintHash(
									model.SCIInfo{
										RunType: "",
										RepositoryCommitInfo: model.RepositoryCommitInfo{
											RepositoryUrl: "",
											Branch:        "",
											CommitSHA:     "",
										},
									},
									"",
									"test_resource_type",
									"test_resource_name",
									"test",
								),
							},
						},
						{
							ResultRuleID:    "test info",
							ResultRuleIndex: 1,
							ResultKind:      "informational",
							ResultMessage: sarifMessage{
								Text:              "test",
								MessageProperties: sarifProperties{"platform": ""},
							},
							ResultLocations: []SarifLocation{
								{
									PhysicalLocation: sarifPhysicalLocation{
										ArtifactLocation: sarifArtifactLocation{ArtifactURI: ""},
										Region:           model.SarifRegion{StartLine: 1, EndLine: 2},
									},
								},
							},
							ResultProperties: sarifProperties{
								"tags": []string{"DATADOG_CATEGORY:test", "CWE:22", "IAC_RESOURCE_TYPE:test_resource_type_2", "IAC_RESOURCE_NAME:test_resource_name_2"},
							},
							PartialFingerprints: SarifPartialFingerprints{
								DatadogFingerprint: GetDatadogFingerprintHash(
									model.SCIInfo{
										RunType: "",
										RepositoryCommitInfo: model.RepositoryCommitInfo{
											RepositoryUrl: "",
											Branch:        "",
											CommitSHA:     "",
										},
									},
									"",
									"test_resource_type_2",
									"test_resource_name_2",
									"test info",
								),
							},
						},
					},
					Taxonomies: []sarifTaxonomy{
						{
							TaxonomyGUID:             "58cdcc6f-fe41-4724-bfb3-131a93df4c3f",
							TaxonomyName:             "Categories",
							TaxonomyFullDescription:  sarifMessage{Text: "Category is not defined"},
							TaxonomyShortDescription: sarifMessage{Text: "Category is not defined"},
							TaxonomyDefinitions: []taxonomyDefinitions{
								{
									DefinitionGUID:             "",
									DefinitionName:             "Undefined Category",
									DefinitionID:               "CAT000",
									DefinitionShortDescription: cweMessage{Text: "Category is not defined"},
									DefinitionFullDescription:  cweMessage{Text: "Category is not defined"},
									HelpURI:                    "",
								},
							},
						},
						{
							TaxonomyGUID:                              "1489b0c4-d7ce-4d31-af66-6382a01202e3",
							TaxonomyName:                              "CWE",
							TaxonomyFullDescription:                   sarifMessage{Text: "The MITRE Common Weakness Enumeration"},
							TaxonomyShortDescription:                  sarifMessage{Text: "The MITRE Common Weakness Enumeration"},
							TaxonomyDownloadURI:                       "https://cwe.mitre.org/data/published/cwe_v4.13.pdf",
							TaxonomyIsComprehensive:                   true,
							TaxonomyLanguage:                          "en",
							TaxonomyMinRequiredLocDataSemanticVersion: "4.13",
							TaxonomyOrganization:                      "MITRE",
							TaxonomyRealeaseDateUtc:                   "2023-10-26",
							TaxonomyDefinitions: []taxonomyDefinitions{
								{
									DefinitionGUID:             "1489b0c4-d7ce-4d31-af66-6382a01202e3",
									DefinitionID:               "22",
									DefinitionShortDescription: cweMessage{Text: "The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory."},
									DefinitionFullDescription:  cweMessage{Text: "Many file operations are intended to take place within a restricted directory. By using special elements such as .. and / separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system. One of the most common special elements is the ../ sequence, which in most modern operating systems is interpreted as the parent directory of the current location. This is referred to as relative path traversal. Path traversal also covers the use of absolute pathnames such as /usr/local/bin, which may also be useful in accessing unexpected files. This is referred to as absolute path traversal. In many programming languages, the injection of a null byte (the 0 or NUL) may allow an attacker to truncate a generated filename to widen the scope of attack. For example, the product may add .txt to any pathname, thus limiting the attacker to text files, but a null injection may effectively remove this restriction."},
									HelpURI:                    "https://cwe.mitre.org/data/definitions/22.html",
								},
							},
						},
					},
				},
			},
		},
	},
	{
		name: "Should create one occurrence with remediation startLine",
		vq: []model.QueryResult{
			{
				QueryName:   "test",
				QueryID:     "1",
				Description: "test description",
				QueryURI:    "https://www.test.com",
				Severity:    model.SeverityHigh,
				Files: []model.VulnerableFile{
					{
						KeyActualValue: "test",
						FileName:       "test.json",
						Line:           1,
						ResourceType:   "test_resource_type",
						ResourceName:   "test_resource_name",
						ResourceLocation: model.ResourceLocation{
							Start: model.ResourceLine{Line: 1, Col: 1},
							End:   model.ResourceLine{Line: 5, Col: 2},
						},
						RemediationLocation: model.ResourceLocation{
							Start: model.ResourceLine{Line: 2, Col: 1},
							End:   model.ResourceLine{Line: 3, Col: 2},
						},
					},
				},
				CWE: "",
			},
		},
		want: sarifReport{
			Runs: []SarifRun{
				{
					Tool: sarifTool{
						Driver: sarifDriver{
							Rules: []sarifRule{
								{
									RuleID:               "test",
									RuleName:             "test",
									RuleShortDescription: sarifMessage{Text: "test"},
									RuleFullDescription:  sarifMessage{Text: "test description\nRule ID: [1]"},
									DefaultConfiguration: sarifConfiguration{
										Level: "error",
									},
									HelpURI: "https://www.test.com",
									Relationships: []sarifRelationship{
										{
											Relationship: sarifDescriptorReference{
												ReferenceID:    "CAT000",
												ReferenceIndex: 0,
												ToolComponent: sarifComponentReference{
													ComponentReferenceGUID:  "58cdcc6f-fe41-4724-bfb3-131a93df4c3f",
													ComponentReferenceName:  "Categories",
													ComponentReferenceIndex: targetTemplate.ToolComponent.ComponentReferenceIndex,
												},
											},
										},
									},
								},
							},
						},
					},
					Results: []sarifResult{
						{
							ResultRuleID:    "test",
							ResultRuleIndex: 0,
							ResultKind:      "",
							ResultMessage:   sarifMessage{Text: "test", MessageProperties: nil},
							ResultLocations: []SarifLocation{
								{
									PhysicalLocation: sarifPhysicalLocation{
										ArtifactLocation: sarifArtifactLocation{ArtifactURI: "test.json"},
										Region:           model.SarifRegion{StartLine: 2, EndLine: 3, StartColumn: 1, EndColumn: 2},
									},
								},
							},
							ResultLevel: "warning",
							ResultProperties: sarifProperties{
								"tags": []string{"DATADOG_CATEGORY:", "IAC_RESOURCE_TYPE:test_resource_type", "IAC_RESOURCE_NAME:test_resource_name"},
							},
							PartialFingerprints: SarifPartialFingerprints{
								DatadogFingerprint: GetDatadogFingerprintHash(
									model.SCIInfo{
										RunType: "",
										RepositoryCommitInfo: model.RepositoryCommitInfo{
											RepositoryUrl: "",
											Branch:        "",
											CommitSHA:     "",
										},
									},
									"test.json",
									"test_resource_type",
									"test_resource_name",
									"1",
								),
							},
						},
					},
					Taxonomies: []sarifTaxonomy{
						{
							TaxonomyGUID:             "58cdcc6f-fe41-4724-bfb3-131a93df4c3f",
							TaxonomyName:             "Categories",
							TaxonomyFullDescription:  sarifMessage{Text: "Category is not defined"},
							TaxonomyShortDescription: sarifMessage{Text: "Category is not defined"},
							TaxonomyDefinitions: []taxonomyDefinitions{
								{
									DefinitionGUID:             "",
									DefinitionName:             "Undefined Category",
									DefinitionID:               "CAT000",
									DefinitionShortDescription: cweMessage{Text: "Category is not defined"},
									DefinitionFullDescription:  cweMessage{Text: "Category is not defined"},
									HelpURI:                    "",
								},
							},
						},
						{
							TaxonomyGUID:                              "1489b0c4-d7ce-4d31-af66-6382a01202e3",
							TaxonomyName:                              "CWE",
							TaxonomyFullDescription:                   sarifMessage{Text: "The MITRE Common Weakness Enumeration"},
							TaxonomyShortDescription:                  sarifMessage{Text: "The MITRE Common Weakness Enumeration"},
							TaxonomyDownloadURI:                       "https://cwe.mitre.org/data/published/cwe_v4.13.pdf",
							TaxonomyIsComprehensive:                   true,
							TaxonomyLanguage:                          "en",
							TaxonomyMinRequiredLocDataSemanticVersion: "4.13",
							TaxonomyOrganization:                      "MITRE",
							TaxonomyRealeaseDateUtc:                   "2023-10-26",
							TaxonomyDefinitions: []taxonomyDefinitions{
								{},
							},
						},
					},
				},
			},
		},
	},
}

func TestBuildSarifIssue(t *testing.T) {
	ctx := context.Background()
	for _, tt := range sarifTests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewSarifReport().(*sarifReport)
			for _, vq := range tt.vq {
				result.BuildSarifIssue(ctx, &vq, model.SCIInfo{})
			}
			require.Equal(t, len(tt.want.Runs[0].Results), len(result.Runs[0].Results))
			require.Equal(t, len(tt.want.Runs[0].Tool.Driver.Rules), len(result.Runs[0].Tool.Driver.Rules))
			for index, wantResult := range tt.want.Runs[0].Results {
				actualResult := result.Runs[0].Results[index]
				require.Equal(t, wantResult.ResultProperties["tags"], actualResult.ResultProperties["tags"])
				require.Equal(t, wantResult.PartialFingerprints.DatadogFingerprint, actualResult.PartialFingerprints.DatadogFingerprint)
				require.Equal(t, wantResult.ResultMessage.Text, actualResult.ResultMessage.Text)
			}
			if len(tt.want.Runs[0].Tool.Driver.Rules) > 0 {
				if len(result.Runs[0].Tool.Driver.Rules[0].Relationships) > 0 {
					if tt.vq[0].CWE == "" {
						// if CWE is empty, the result should expect one less relationship (only categories present)
						require.Equal(t, len(tt.want.Runs[0].Tool.Driver.Rules[0].Relationships), len(result.Runs[0].Tool.Driver.Rules[0].Relationships))
					} else {
						// if CWE is not empty, the relationships should be the expected number of relationships
						require.Equal(t, tt.want.Runs[0].Tool.Driver.Rules[0].Relationships, result.Runs[0].Tool.Driver.Rules[0].Relationships)
					}
				}
				require.Equal(t, tt.want.Runs[0].Results[0], result.Runs[0].Results[0])
				require.Equal(t, tt.want.Runs[0].Tool.Driver.Rules[0].RuleFullDescription.Text, result.Runs[0].Tool.Driver.Rules[0].RuleFullDescription.Text)
				// Verify iac-frameworks property exists for rules with frameworks
				if len(tt.vq[0].Frameworks) > 0 {
					require.Contains(t, result.Runs[0].Tool.Driver.Rules[0].RuleProperties, "iac-frameworks")
				}

				// for every result in the run we want to check that the location matches the expected location
				require.Equal(t, tt.want.Runs[0].Results[0].ResultLocations[0].PhysicalLocation.ArtifactLocation.ArtifactURI, result.Runs[0].Results[0].ResultLocations[0].PhysicalLocation.ArtifactLocation.ArtifactURI)
			}
		})
	}
}

func TestInitCweCategories(t *testing.T) {
	cweIDs := []string{"22", "41"}
	guids := map[string]string{"22": "1489b0c4-d7ce-4d31-af66-6382a01202e3", "41": "1489b0c4-d7ce-4d31-af66-6382a01202e4"}
	expectedShortDescription22 := "The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory."
	expectedShortDescription41 := "The product is vulnerable to file system contents disclosure through path equivalence. Path equivalence involves the use of special characters in file and directory names. The associated manipulations are intended to generate multiple names for the same object."

	currentDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	defer os.Chdir(currentDir) // Change back to the original working directory when done

	for i := 0; i < 3; i++ {
		if err := os.Chdir(".."); err != nil {
			t.Fatal(err)
		}
	}

	result := initCweCategories(cweIDs, guids)

	require.Len(t, result, 2)
	// Test for CWE-ID 22
	require.Equal(t, "22", result[0].DefinitionID)
	require.Equal(t, "1489b0c4-d7ce-4d31-af66-6382a01202e3", result[0].DefinitionGUID)
	require.Equal(t, expectedShortDescription22, result[0].DefinitionShortDescription.Text)
	require.Equal(t, "https://cwe.mitre.org/data/definitions/22.html", result[0].HelpURI)
	// Test for CWE-ID 41
	require.Equal(t, "41", result[1].DefinitionID)
	require.Equal(t, "1489b0c4-d7ce-4d31-af66-6382a01202e4", result[1].DefinitionGUID)
	require.Equal(t, expectedShortDescription41, result[1].DefinitionShortDescription.Text)
	require.Equal(t, "https://cwe.mitre.org/data/definitions/41.html", result[1].HelpURI)
}

func TestBuildSarifIssueWithFrameworks(t *testing.T) {
	ctx := context.Background()

	queryResult := model.QueryResult{
		QueryName:     "AMI shared with multiple accounts",
		QueryID:       "ba4e0031-3e9d-4d7d-b0d6-bd8f003f8698",
		Description:   "This check ensures that AMIs are not granted launch permissions to multiple accounts",
		QueryURI:      "https://docs.datadoghq.com/security/code_security/iac_security/iac_rules/terraform/aws/ami_shared_with_multiple_accounts",
		Severity:      model.SeverityMedium,
		Category:      "Access Control",
		Platform:      "Terraform",
		CloudProvider: "aws",
		Frameworks: []model.Framework{
			{
				Framework:        "dcsb-m-v2",
				FrameworkVersion: "0.0.1",
				Control:          "aws.1.10",
				Requirement:      "aws",
			},
			{
				Framework:        "chris-test",
				FrameworkVersion: "0.0.1",
				Control:          "chris.1",
				Requirement:      "chris",
			},
		},
		Files: []model.VulnerableFile{
			{
				KeyActualValue: "AMI sharing issue found",
				FileName:       "main.tf",
				Line:           5,
				ResourceType:   "aws_ami_launch_permission",
				ResourceName:   "test_permission",
				ResourceLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 5, Col: 1},
					End:   model.ResourceLine{Line: 8, Col: 2},
				},
			},
		},
		CWE: "284",
	}

	report := NewSarifReport().(*sarifReport)
	cwe := report.BuildSarifIssue(ctx, &queryResult, model.SCIInfo{})

	// Verify CWE was returned
	require.Equal(t, "284", cwe)

	// Verify that rules were created
	require.Len(t, report.Runs[0].Tool.Driver.Rules, 1)
	rule := report.Runs[0].Tool.Driver.Rules[0]

	// Verify iac-frameworks are in rule properties
	require.Contains(t, rule.RuleProperties, "iac-frameworks")
	frameworks, ok := rule.RuleProperties["iac-frameworks"].([]model.Framework)
	require.True(t, ok)
	require.Len(t, frameworks, 2)

	expectedFrameworks := []model.Framework{
		{
			Framework:        "dcsb-m-v2",
			FrameworkVersion: "0.0.1",
			Control:          "aws.1.10",
			Requirement:      "aws",
		},
		{
			Framework:        "chris-test",
			FrameworkVersion: "0.0.1",
			Control:          "chris.1",
			Requirement:      "chris",
		},
	}
	require.Equal(t, expectedFrameworks, frameworks)

	// Verify results were created
	require.Len(t, report.Runs[0].Results, 1)
	result := report.Runs[0].Results[0]

	// Verify other expected properties
	require.Equal(t, "AMI shared with multiple accounts", result.ResultRuleID)
	require.Equal(t, "note", result.ResultLevel) // MEDIUM maps to "note"
	require.Equal(t, "main.tf", result.ResultLocations[0].PhysicalLocation.ArtifactLocation.ArtifactURI)
}
