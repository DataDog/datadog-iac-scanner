/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"context"
	"encoding/json"
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
			Fingerprint: model.GetDatadogFingerprintHash(
				model.SCIInfo{}, "modules/bucket/main.tf", "terraform",
				"aws_s3_bucket", "this", "acl-rule", "acl = public-read", "stack|module.bucket",
			),
			Line: 3,
			ResourceLocation: model.ResourceLocation{
				Start: model.ResourceLine{Line: 2, Col: 1},
				End:   model.ResourceLine{Line: 4, Col: 1},
			},
			ResourceType:    "aws_s3_bucket",
			ResourceName:    "this",
			Remediation:     "remove insecure ACL",
			RemediationType: "removal",
			ModuleAttribution: &model.ModuleAttribution{
				Name:           "bucket",
				Source:         "modules/bucket",
				SourceType:     "local",
				DependencyType: "direct",
				CodeLocation: model.SourceLocation{
					Filename:    "stack/main.tf",
					LineStart:   2,
					LineEnd:     2,
					ColumnStart: 1,
					ColumnEnd:   43,
				},
				ModuleCodeLocation: model.SourceLocation{
					Filename:    "main.tf",
					LineStart:   2,
					LineEnd:     4,
					ColumnStart: 1,
					ColumnEnd:   2,
				},
				ModuleCodeOwned: true,
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
		"name": "bucket",
		"source": "modules/bucket",
		"source_type": "local",
		"dependency_type": "direct",
		"code_location": {
			"filename": "main.tf",
			"line_start": 2,
			"line_end": 4
		}
	}`, string(payload))
}

func TestBuildSarifIssue_RemoteModuleOmitsFix(t *testing.T) {
	issue := model.QueryResult{
		QueryName: "acl_rule",
		QueryID:   "acl-rule",
		Severity:  model.SeverityHigh,
		Platform:  "terraform",
		Files: []model.VulnerableFile{{
			FileName:        "main.tf",
			ResourceType:    "aws_s3_bucket",
			ResourceName:    "this",
			Remediation:     "remove insecure ACL",
			RemediationType: "removal",
			ResourceLocation: model.ResourceLocation{
				Start: model.ResourceLine{Line: 2, Col: 1},
				End:   model.ResourceLine{Line: 4, Col: 1},
			},
			ModuleAttribution: &model.ModuleAttribution{
				Name:           "bucket",
				Source:         "registry.terraform.io/acme/bucket/aws",
				SourceType:     "registry",
				DependencyType: "direct",
				CodeLocation: model.SourceLocation{
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
