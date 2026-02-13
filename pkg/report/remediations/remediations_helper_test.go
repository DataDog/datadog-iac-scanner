package model

import (
	"context"
	"fmt"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransformToSarifFixE2E(t *testing.T) { //nolint
	testCases := []struct {
		expected      model.SarifFix
		vuln          model.VulnerableFile
		startLocation model.SarifResourceLocation
		endLocation   model.SarifResourceLocation
	}{
		{
			vuln: model.VulnerableFile{
				FileName:        "assets/queries/terraform/aws/s3_bucket_without_versioning/test/positive6.tf",
				SimilarityID:    "3f57a6f32db9ebf0d1da3a73122381ae2b7605a6ba3dc432219fe9fd5a44d7d5",
				OldSimilarityID: "",
				Line:            1,
				ResourceLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 1, Col: 1},
					End:   model.ResourceLine{Line: 9, Col: 2},
				},
				VulnLines:        nil,
				ResourceType:     "n/a",
				ResourceName:     "n/a",
				IssueType:        "MissingAttribute",
				SearchKey:        "module[s3_bucket]",
				SearchLine:       1,
				SearchValue:      "",
				KeyExpectedValue: "'block_public_acls' should equal 'true'",
				KeyActualValue:   "'block_public_acls' is missing",
				Value:            nil,
				Remediation:      "block_public_acls = true",
				RemediationType:  "addition",
				RemediationLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 8, Col: 2},
					End:   model.ResourceLine{Line: 8, Col: 2},
				},
				LineWithVulnerability: "module \"s3_bucket\" {",
				ResourceSource:        "module \"s3_bucket\" {\n  source = \"terraform-aws-modules/s3-bucket/aws\"\n\n  version = \"3.7.0\"\n\n  bucket = \"my-s3-bucket\"\n  acl    = \"private\"\n\n}\n",
				FileSource:            []string{"module \"s3_bucket\" {", "  source = \"terraform-aws-modules/s3-bucket/aws\"", "", "  version = \"3.7.0\"", "", "  bucket = \"my-s3-bucket\"", "  acl    = \"private\"", "", "}", ""},
				BlockLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 1, Col: 1},
					End:   model.ResourceLine{Line: 9, Col: 2},
				},
			},
			startLocation: model.SarifResourceLocation{Line: 8, Col: 2},
			endLocation:   model.SarifResourceLocation{Line: 8, Col: 2},
			expected: model.SarifFix{
				ArtifactChanges: []model.ArtifactChange{
					{
						ArtifactLocation: model.ArtifactLocation{
							URI: "assets/queries/terraform/aws/s3_bucket_without_versioning/test/positive6.tf",
						},
						Replacements: []model.FixReplacement{
							{
								DeletedRegion: model.SarifRegion{
									StartLine:   8,
									EndLine:     8,
									StartColumn: 2,
									EndColumn:   2,
								},
								InsertedContent: model.FixContent{
									Text: "\n  block_public_acls = true\n  ",
								},
							},
						},
					},
				},
				Description: model.FixMessage{
					Text: "Apply remediation: block_public_acls = true",
				},
			},
		},
	}

	ctx := context.Background()
	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("TransformToSarifFix-%d", i), func(t *testing.T) {
			v, err := TransformToSarifFix(ctx, testCase.vuln, testCase.startLocation, testCase.endLocation)
			assert.Nil(t, err)
			require.Equal(t, testCase.expected, v)
		})
	}
}

func TestTransformToSarifFix_Addition(t *testing.T) {
	ctx := context.Background()
	vuln := model.VulnerableFile{
		FileName:        "main.tf",
		RemediationType: "addition",
		Remediation:     `tags = {\n  Environment = "dev"\n}`,
		FileSource: []string{
			"resource \"aws_s3_bucket\" \"bucket\" {",
			"  bucket = \"my-bucket\"",
			"}",
		},
		BlockLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 1}, End: model.ResourceLine{Line: 3}},
	}
	start := model.SarifResourceLocation{Line: 2, Col: 3}
	fix, err := TransformToSarifFix(ctx, vuln, start, start)
	require.NoError(t, err)
	require.Contains(t, fix.ArtifactChanges[0].Replacements[0].InsertedContent.Text, "Environment")
}

func TestTransformToSarifFix_Removal(t *testing.T) {
	ctx := context.Background()
	vuln := model.VulnerableFile{
		FileName:        "main.tf",
		RemediationType: "removal",
		FileSource: []string{
			"resource \"aws_s3_bucket\" \"bucket\" {",
			"  acl = \"public-read\"",
			"}",
		},
	}
	start := model.SarifResourceLocation{Line: 2, Col: 3}
	end := model.SarifResourceLocation{Line: 2, Col: 25}
	fix, err := TransformToSarifFix(ctx, vuln, start, end)
	require.NoError(t, err)
	require.Equal(t, "", fix.ArtifactChanges[0].Replacements[0].InsertedContent.Text)
}

func TestTransformToSarifFix_Replacement(t *testing.T) {
	tests := []struct {
		name     string
		vuln     model.VulnerableFile
		start    model.SarifResourceLocation
		end      model.SarifResourceLocation
		wantErr  bool
		expected string // substring expected in the inserted content
	}{
		{
			name: "simple key-value replacement",
			vuln: model.VulnerableFile{
				FileName:              "main.tf",
				RemediationType:       "replacement",
				Remediation:           `{"before": "acl = \"authenticated-read\"", "after": "private"}`,
				LineWithVulnerability: `  acl = "authenticated-read"`,
				RemediationLocation:   model.ResourceLocation{Start: model.ResourceLine{Line: 3, Col: 3}},
				Line:                  3,
				FileSource:            []string{"resource \"aws_s3_bucket\" \"bucket\" {", "  bucket = \"my-bucket\"", "  acl = \"authenticated-read\"", "}"},
				BlockLocation:         model.ResourceLocation{Start: model.ResourceLine{Line: 1}, End: model.ResourceLine{Line: 4}},
			},
			start:    model.SarifResourceLocation{Line: 3, Col: 3},
			end:      model.SarifResourceLocation{Line: 3, Col: 30},
			wantErr:  false,
			expected: "private",
		},
		{
			name: "list value without quotes",
			vuln: model.VulnerableFile{
				FileName:              "main.tf",
				RemediationType:       "replacement",
				Remediation:           `{"before": "features = [PublicAccess]", "after": "PrivateLink"}`,
				LineWithVulnerability: `  features = [PublicAccess, OtherFeature]`,
				RemediationLocation:   model.ResourceLocation{Start: model.ResourceLine{Line: 4, Col: 3}},
				Line:                  4,
				FileSource: []string{
					"resource \"example\" \"test\" {",
					"  name     = \"example\"",
					"  region   = \"us-east-1\"",
					"  features = [PublicAccess, OtherFeature]",
					"}",
				},
				BlockLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 1}, End: model.ResourceLine{Line: 5}},
			},
			start:    model.SarifResourceLocation{Line: 4, Col: 3},
			end:      model.SarifResourceLocation{Line: 4, Col: 60},
			wantErr:  false,
			expected: "PrivateLink",
		},
		{
			name: "replace multiple matching list items",
			vuln: model.VulnerableFile{
				FileName:              "main.tf",
				RemediationType:       "replacement",
				Remediation:           `{"before": "access = [\"PublicNetworkAccess\"]", "after": "PrivateLink"}`,
				LineWithVulnerability: `  access = ["PublicNetworkAccess", "PublicNetworkAccess"]`,
				RemediationLocation:   model.ResourceLocation{Start: model.ResourceLine{Line: 4, Col: 3}},
				Line:                  4,
				FileSource: []string{
					"resource \"azurerm_example\" \"test\" {",
					"  name = \"multi\"",
					"  location = \"eastus\"",
					"  access = [\"PublicNetworkAccess\", \"PublicNetworkAccess\"]",
					"}",
				},
				BlockLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 1}, End: model.ResourceLine{Line: 5}},
			},
			start:    model.SarifResourceLocation{Line: 4, Col: 3},
			end:      model.SarifResourceLocation{Line: 4, Col: 60},
			wantErr:  false,
			expected: "PrivateLink",
		},
		{
			name: "line with inline comment",
			vuln: model.VulnerableFile{
				FileName:              "main.tf",
				RemediationType:       "replacement",
				Remediation:           `{"before": "acl = \"authenticated-read\"", "after": "private"}`,
				LineWithVulnerability: `  acl = "authenticated-read" # managed by security team`,
				RemediationLocation:   model.ResourceLocation{Start: model.ResourceLine{Line: 3, Col: 3}},
				Line:                  3,
				FileSource: []string{
					"resource \"aws_s3_bucket\" \"bucket\" {",
					"  bucket = \"my-bucket\"",
					"  acl = \"authenticated-read\" # managed by security team",
					"}",
				},
				BlockLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 1}, End: model.ResourceLine{Line: 4}},
			},
			start:    model.SarifResourceLocation{Line: 3, Col: 3},
			end:      model.SarifResourceLocation{Line: 3, Col: 80},
			wantErr:  false,
			expected: "private",
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fix, err := TransformToSarifFix(ctx, tt.vuln, tt.start, tt.end)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Contains(t, fix.ArtifactChanges[0].Replacements[0].InsertedContent.Text, tt.expected)
			}
		})
	}
}

func TestTransformToSarifFix_AddToEmptyBlock(t *testing.T) {
	ctx := context.Background()
	vuln := model.VulnerableFile{
		FileName:        "main.tf",
		RemediationType: "addition",
		Remediation:     `tags = {\n  Environment = "prod"\n}`,
		FileSource: []string{
			"resource \"aws_s3_bucket\" \"example\" {",
			"  tags = {}",
			"}",
		},
		BlockLocation: model.ResourceLocation{Start: model.ResourceLine{Line: 1}, End: model.ResourceLine{Line: 3}},
	}
	start := model.SarifResourceLocation{Line: 2, Col: 10}
	fix, err := TransformToSarifFix(ctx, vuln, start, start)
	require.NoError(t, err)
	require.Contains(t, fix.ArtifactChanges[0].Replacements[0].InsertedContent.Text, "Environment")
}

func TestTransformToSarifFix_Removal_QuotedUnquoted(t *testing.T) {
	tests := []model.VulnerableFile{
		{
			FileName:        "main.tf",
			RemediationType: "removal",
			Line:            2,
			FileSource: []string{
				"resource \"aws_s3_bucket\" \"bucket\" {",
				"  enabled = true",
				"}",
			},
		},
		{
			FileName:        "main.tf",
			RemediationType: "removal",
			Line:            2,
			FileSource: []string{
				"resource \"aws_s3_bucket\" \"bucket\" {",
				"  enabled = \"true\"",
				"}",
			},
		},
	}

	ctx := context.Background()
	for i, vuln := range tests {
		start := model.SarifResourceLocation{Line: 2, Col: 3}
		end := model.SarifResourceLocation{Line: 2, Col: 20}
		t.Run(fmt.Sprintf("removal_case_%d", i), func(t *testing.T) {
			fix, err := TransformToSarifFix(ctx, vuln, start, end)
			require.NoError(t, err)
			require.Equal(t, "", fix.ArtifactChanges[0].Replacements[0].InsertedContent.Text)
		})
	}
}
