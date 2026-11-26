/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestBuildSarifIssue_ModuleAttribution(t *testing.T) {
	issue := model.QueryResult{
		QueryName: "acl_rule",
		QueryID:   "acl-rule",
		Severity:  model.SeverityHigh,
		Platform:  "terraform",
		Files: []model.VulnerableFile{{
			FileName: "modules/bucket/main.tf",
			ReportLocation: &model.SourceLocation{
				Filename: "stack/main.tf", LineStart: 2, LineEnd: 2, ColumnStart: 1, ColumnEnd: 43,
			},
			Fingerprint: model.GetDatadogFingerprintHash(
				model.SCIInfo{}, "modules/bucket/main.tf", "terraform",
				"aws_s3_bucket", "this", "acl-rule", "acl = public-read", "stack|module.bucket",
			),
			Line: 3,
			ResourceLocation: model.ResourceLocation{
				Start: model.ResourceLine{Line: 2, Col: 1},
				End:   model.ResourceLine{Line: 4, Col: 1},
			},
			RemediationLocation: model.ResourceLocation{
				Start: model.ResourceLine{Line: 3, Col: 3},
				End:   model.ResourceLine{Line: 3, Col: 22},
			},
			ResourceType:    "aws_s3_bucket",
			ResourceName:    "this",
			Remediation:     "remove insecure ACL",
			RemediationType: "removal",
			ModuleAttribution: &model.ModuleAttribution{
				SourceType:     "local",
				DependencyType: "direct",
				CallSite: model.SourceLocation{
					Filename:    "stack/main.tf",
					LineStart:   2,
					LineEnd:     2,
					ColumnStart: 1,
					ColumnEnd:   43,
				},
				ModuleCodeLocation: model.SourceLocation{
					Filename:    "modules/bucket/main.tf",
					LineStart:   2,
					LineEnd:     4,
					ColumnStart: 1,
					ColumnEnd:   2,
				},
				ModulePath: []model.ModulePathHop{{
					Name:       "bucket",
					Source:     "modules/bucket",
					SourceType: "local",
					CodeLocation: model.SourceLocation{
						Filename: "stack/main.tf", LineStart: 1, LineEnd: 3, ColumnStart: 1, ColumnEnd: 2,
					},
				}},
				ModuleCodeOwned: true,
				ArgumentControl: model.ArgumentControlModule,
			},
		}},
	}

	report := NewSarifReport().(*sarifReport)
	_, err := report.BuildSarifIssue(context.Background(), &issue, model.SCIInfo{})
	require.NoError(t, err)
	require.Len(t, report.Runs[0].Results, 1)

	result := report.Runs[0].Results[0]
	require.Equal(t, "stack/main.tf", result.ResultLocations[0].PhysicalLocation.ArtifactLocation.ArtifactURI)
	require.Equal(t, 2, result.ResultLocations[0].PhysicalLocation.Region.StartLine)
	require.Equal(t, 2, result.ResultLocations[0].PhysicalLocation.Region.EndLine)
	require.Equal(t, 1, result.ResultLocations[0].PhysicalLocation.Region.StartColumn)
	require.Equal(t, 43, result.ResultLocations[0].PhysicalLocation.Region.EndColumn)
	require.Len(t, result.ResultFixes, 1)
	require.Equal(t, "modules/bucket/main.tf", result.ResultFixes[0].ArtifactChanges[0].ArtifactLocation.URI)

	moduleRaw, ok := result.ResultProperties["module"]
	require.True(t, ok)
	payload, err := json.Marshal(moduleRaw)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"source_type": "local",
		"dependency_type": "direct",
		"code_location": {
			"filename": "modules/bucket/main.tf",
			"line_start": 2,
			"line_end": 4,
			"column_start": 1,
			"column_end": 2
		},
		"module_path": [{
			"name": "bucket",
			"source": "modules/bucket",
			"source_type": "local",
			"code_location": {
				"filename": "stack/main.tf",
				"line_start": 1,
				"line_end": 3,
				"column_start": 1,
				"column_end": 2
			}
		}]
	}`, string(payload))
}

func TestBuildSarifIssue_RemoteModuleOmitsFix(t *testing.T) {
	issue := model.QueryResult{
		QueryName: "acl_rule",
		QueryID:   "acl-rule",
		Severity:  model.SeverityHigh,
		Platform:  "terraform",
		Files: []model.VulnerableFile{{
			FileName: "main.tf",
			ReportLocation: &model.SourceLocation{
				Filename: "stack/main.tf", LineStart: 2, LineEnd: 5, ColumnStart: 1, ColumnEnd: 2,
			},
			ResourceType:    "aws_s3_bucket",
			ResourceName:    "this",
			Remediation:     "remove insecure ACL",
			RemediationType: "removal",
			ResourceLocation: model.ResourceLocation{
				Start: model.ResourceLine{Line: 2, Col: 1},
				End:   model.ResourceLine{Line: 4, Col: 1},
			},
			ModuleAttribution: &model.ModuleAttribution{
				DependencyType: "direct",
				CallSite: model.SourceLocation{
					Filename:  "stack/main.tf",
					LineStart: 2,
					LineEnd:   5,
				},
				ModuleCodeLocation: model.SourceLocation{Filename: "main.tf", LineStart: 2, LineEnd: 4},
			},
		}},
	}

	report := NewSarifReport().(*sarifReport)
	_, err := report.BuildSarifIssue(context.Background(), &issue, model.SCIInfo{})
	require.NoError(t, err)
	require.Empty(t, report.Runs[0].Results[0].ResultFixes)
}

func TestBuildSarifIssue_ValueNotSetByModuleOmitsFix(t *testing.T) {
	for name, control := range map[string]model.ArgumentControl{
		"set by a call argument": model.ArgumentControlCaller,
		"not traced":             model.ArgumentControlUnknown,
	} {
		t.Run(name, func(t *testing.T) {
			issue := model.QueryResult{
				QueryName: "acl_rule",
				QueryID:   "acl-rule",
				Severity:  model.SeverityHigh,
				Platform:  "terraform",
				Files: []model.VulnerableFile{{
					FileName: "modules/bucket/main.tf",
					ReportLocation: &model.SourceLocation{
						Filename: "stack/main.tf", LineStart: 4, LineEnd: 4, ColumnStart: 1, ColumnEnd: 2,
					},
					ResourceType:    "aws_s3_bucket",
					ResourceName:    "this",
					Remediation:     "remove insecure ACL",
					RemediationType: "removal",
					ResourceLocation: model.ResourceLocation{
						Start: model.ResourceLine{Line: 2, Col: 1},
						End:   model.ResourceLine{Line: 4, Col: 1},
					},
					ModuleAttribution: &model.ModuleAttribution{
						DependencyType:  "direct",
						CallSite:        model.SourceLocation{Filename: "stack/main.tf", LineStart: 4, LineEnd: 4},
						ModuleCodeOwned: true,
						ArgumentControl: control,
					},
				}},
			}

			report := NewSarifReport().(*sarifReport)
			_, err := report.BuildSarifIssue(context.Background(), &issue, model.SCIInfo{})
			require.NoError(t, err)
			require.Empty(t, report.Runs[0].Results[0].ResultFixes)
		})
	}
}

func TestBuildSarifIssue_NonModuleFindingUnchanged(t *testing.T) {
	issue := model.QueryResult{
		QueryName: "root_rule",
		QueryID:   "root-rule",
		Severity:  model.SeverityHigh,
		Platform:  "terraform",
		Files: []model.VulnerableFile{{
			FileName: "main.tf",
			Fingerprint: model.GetDatadogFingerprintHash(
				model.SCIInfo{}, "main.tf", "terraform",
				"aws_s3_bucket", "root", "root-rule", "acl = private", "",
			),
			Line: 1,
			ResourceLocation: model.ResourceLocation{
				Start: model.ResourceLine{Line: 1, Col: 1},
				End:   model.ResourceLine{Line: 3, Col: 1},
			},
			ResourceType: "aws_s3_bucket",
			ResourceName: "root",
		}},
	}

	report := NewSarifReport().(*sarifReport)
	_, err := report.BuildSarifIssue(context.Background(), &issue, model.SCIInfo{})
	require.NoError(t, err)
	result := report.Runs[0].Results[0]
	require.Equal(t, "main.tf", result.ResultLocations[0].PhysicalLocation.ArtifactLocation.ArtifactURI)
	_, hasModule := result.ResultProperties["module"]
	require.False(t, hasModule)
}

// Even malformed inputs that bypass engine routing cannot fall back to a
// fetched file or publish a path escaping the scanned repository.
func TestBuildSarifIssue_RejectsInvalidModuleReportLocations(t *testing.T) {
	for _, name := range []string{"", "../cache/main.tf", "../../tmp/modules/hash/gcp/main.tf", "/tmp/cache/main.tf",
		`C:\cache\main.tf`, `..\cache\main.tf`, "https://example.com/main.tf"} {
		t.Run(name, func(t *testing.T) {
			file := model.VulnerableFile{
				FileName: "../../tmp/cache/main.tf",
				ResourceLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 1, Col: 1}, End: model.ResourceLine{Line: 2, Col: 2},
				},
				ModuleAttribution: &model.ModuleAttribution{CallSite: model.SourceLocation{Filename: "stack/main.tf"}},
			}
			if name != "" {
				file.ReportLocation = &model.SourceLocation{Filename: name, LineStart: 1, LineEnd: 2}
			}
			issue := model.QueryResult{QueryName: "rule", Severity: model.SeverityHigh, Files: []model.VulnerableFile{file}}
			report := NewSarifReport().(*sarifReport)
			_, err := report.BuildSarifIssue(context.Background(), &issue, model.SCIInfo{})
			require.NoError(t, err)
			require.Empty(t, report.Runs[0].Results)
		})
	}
}

func TestBuildSarifIssue_RepositoryRootRepresentations(t *testing.T) {
	for _, platform := range []string{"Terraform", "Kubernetes"} {
		for _, rootForm := range []string{"absolute", "dot", "relative"} {
			t.Run(platform+"/"+rootForm, func(t *testing.T) {
				base := t.TempDir()
				repo := filepath.Join(base, "repo")
				require.NoError(t, os.MkdirAll(repo, 0o755))
				root := repo
				switch rootForm {
				case "dot":
					t.Chdir(repo)
					root = "."
				case "relative":
					t.Chdir(base)
					root = filepath.Join("repo", "..", "repo")
				}
				filename := "main.tf"
				if platform == "Kubernetes" {
					filename = "deployment.yaml"
				}
				finding := model.Vulnerability{
					QueryID: "root", QueryName: "root", Platform: platform, Severity: model.SeverityHigh,
					FileName: filepath.Join(repo, "infra", filename), Line: 1, LineWithVulnerability: "insecure",
					VulnerabilityLocation: model.ResourceLocation{
						Start: model.ResourceLine{Line: 1, Col: 1}, End: model.ResourceLine{Line: 2, Col: 2},
					},
				}
				ctx := context.Background()
				absolute := model.CreateSummary(ctx, model.Counters{}, []model.Vulnerability{finding}, "test", nil, repo, model.SCIInfo{})
				summary := model.CreateSummary(ctx, model.Counters{}, []model.Vulnerability{finding}, "test", nil, root, model.SCIInfo{})
				require.Equal(t, absolute, summary, "root spelling cannot change paths, fingerprints, or source-file mappings")
				require.Equal(t, filepath.Join("infra", filename), model.ReportPath(finding.FileName, nil, root))
				report := NewSarifReport().(*sarifReport)
				_, err := report.BuildSarifIssue(ctx, &summary.Queries[0], model.SCIInfo{})
				require.NoError(t, err)
				require.Len(t, report.Runs[0].Results, 1)
				require.Equal(t, "infra/"+filename, report.Runs[0].Results[0].ResultLocations[0].PhysicalLocation.ArtifactLocation.ArtifactURI)
			})
		}
	}
}
