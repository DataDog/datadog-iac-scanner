/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector/docker"
	"github.com/DataDog/datadog-iac-scanner/pkg/detector/helm"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

var OriginalData1 = `resource "aws_s3_bucket" "bucket" {
  bucket = "innovationweek-fancy2023-bucket-${random_id.bucket_id.hex}"
  acl    = "authenticated-read"

  versioning {
    enabled = true
  }

  tags = {
    Demo = "true"
  }
}

resource "aws_s3_bucket" "bucket2" {
  bucket = "innovationweek2-2023-bucket-${random_id.bucket_id.hex}"

  tags = {
    Demo = "true"
    Team = "infrastructure-as-code"
  }
}

resource "aws_s3_bucket" "test3" {
  bucket = "iac-remediation-demo-bucket-notags"
  tags = {
    Demo = "true"
  }
}
`

var ArrayTestString = `resource "kubernetes_pod" "positive1" {
  metadata {
    name = "terraform-example"
  }

  spec {
    container = [
     {
      image = "nginx:1.7.9"
      name  = "example22"

      security_context = {
        allow_privilege_escalation = true
      }

      env = {
        name  = "environment"
        value = "test"
      }

      port = {
        container_port = 8080
      }

      liveness_probe = {
        http_get = {
          path = "/nginx_status"
          port = 80

          http_header = {
            name  = "X-Custom-Header"
            value = "Awesome"
          }
        }

        initial_delay_seconds = 3
        period_seconds        = 3
      }
     }
     ,
     {
      image = "nginx:1.7.9"
      name  = "example22222"

      security_context = {
        allow_privilege_escalation = true
      }

      env = {
        name  = "environment"
        value = "test"
      }

      port = {
        container_port = 8080
      }

      liveness_probe = {
        http_get = {
          path = "/nginx_status"
          port = 80

          http_header = {
            name  = "X-Custom-Header"
            value = "Awesome"
          }
        }

        initial_delay_seconds = 3
        period_seconds        = 3
      }
     }
   ]


    dns_config {
      nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
      searches    = ["example.com"]

      option {
        name  = "ndots"
        value = 1
      }

      option {
        name = "use-vc"
      }
    }

    dns_policy = "None"
  }
}



resource "kubernetes_pod" "positive2" {
  metadata {
    name = "terraform-example"
  }

  spec {
    container {
      image = "nginx:1.7.9"
      name  = "example"

      security_context = {
        allow_privilege_escalation = true
      }

      env {
        name  = "environment"
        value = "test"
      }

      port {
        container_port = 8080
      }

      liveness_probe {
        http_get {
          path = "/nginx_status"
          port = 80

          http_header {
            name  = "X-Custom-Header"
            value = "Awesome"
          }
        }

        initial_delay_seconds = 3
        period_seconds        = 3
      }
    }


    dns_config {
      nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
      searches    = ["example.com"]

      option {
        name  = "ndots"
        value = 1
      }

      option {
        name = "use-vc"
      }
    }

    dns_policy = "None"
  }
}`

var ExtendedArrayTestString = `data "google_iam_policy" "admin" {
  binding {
    role = "roles/compute.imageUser"

    members = [
      "serviceAccount:jane@example.com",
    ]
  }
  binding {
    role = "roles/owner"
    members = [
      "serviceAccount:john@example.com",
    ]
  }
}`

// TestDetectTerraformLine tests the functions [DetectTerraformLine()] and all the methods called by them
func TestDetectTerraformLine(t *testing.T) { //nolint
	testCases := []struct {
		expected  model.VulnerabilityLines
		searchKey string
		file      *model.FileMetadata
	}{
		{
			expected: model.VulnerabilityLines{
				Line: 3,
				VulnLines: &[]model.CodeLine{
					{
						Position: 2,
						Line:     "  bucket = \"innovationweek-fancy2023-bucket-${random_id.bucket_id.hex}\"",
					},
					{
						Position: 3,
						Line:     "  acl    = \"authenticated-read\"",
					},
					{
						Position: 4,
						Line:     "",
					},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 1,
						Col:  1,
					},
					End: model.ResourceLine{
						Line: 12,
						Col:  2,
					},
				},
				LineWithVulnerability: "  acl    = \"authenticated-read\"",
				ResolvedFile:          "",
				ResourceSource:        "resource \"aws_s3_bucket\" \"bucket\" {\n  bucket = \"innovationweek-fancy2023-bucket-${random_id.bucket_id.hex}\"\n  acl    = \"authenticated-read\"\n\n  versioning {\n    enabled = true\n  }\n\n  tags = {\n    Demo = \"true\"\n  }\n}\n",
				FileSource:            strings.Split(OriginalData1, "\n"),
				BlockLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 1,
						Col:  1,
					},
					End: model.ResourceLine{
						Line: 12,
						Col:  2,
					},
				},
				RemediationLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 3,
						Col:  3,
					},
					End: model.ResourceLine{
						Line: 3,
						Col:  3,
					},
				},
			},
			searchKey: "aws_s3_bucket[bucket].acl",
			file: &model.FileMetadata{
				ScanID:            "Test2",
				ID:                "Test2",
				Kind:              model.KindTerraform,
				OriginalData:      OriginalData1,
				LinesOriginalData: utils.SplitLines(OriginalData1),
			},
		},
		{
			expected: model.VulnerabilityLines{
				Line: 15,
				VulnLines: &[]model.CodeLine{
					{
						Position: 14,
						Line:     "resource \"aws_s3_bucket\" \"bucket2\" {",
					},
					{
						Position: 15,
						Line:     "  bucket = \"innovationweek2-2023-bucket-${random_id.bucket_id.hex}\"",
					},
					{
						Position: 16,
						Line:     "",
					},
				},
				LineWithVulnerability: "  bucket = \"innovationweek2-2023-bucket-${random_id.bucket_id.hex}\"",
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 14,
						Col:  1,
					},
					End: model.ResourceLine{
						Line: 21,
						Col:  2,
					},
				},
				BlockLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 14,
						Col:  1,
					},
					End: model.ResourceLine{
						Line: 21,
						Col:  2,
					},
				},
				ResourceSource: "resource \"aws_s3_bucket\" \"bucket2\" {\n  bucket = \"innovationweek2-2023-bucket-${random_id.bucket_id.hex}\"\n\n  tags = {\n    Demo = \"true\"\n    Team = \"infrastructure-as-code\"\n  }\n}\n",
				FileSource:     strings.Split(OriginalData1, "\n"),
				RemediationLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 15,
						Col:  3,
					},
					End: model.ResourceLine{
						Line: 15,
						Col:  3,
					},
				},
			},
			searchKey: "aws_s3_bucket[bucket2].bucket",
			file: &model.FileMetadata{
				ScanID:            "Test2",
				ID:                "Test2",
				Kind:              model.KindTerraform,
				OriginalData:      OriginalData1,
				LinesOriginalData: utils.SplitLines(OriginalData1),
			},
		},
		{
			expected: model.VulnerabilityLines{
				Line: 25,
				VulnLines: &[]model.CodeLine{
					{
						Position: 24,
						Line:     "  bucket = \"iac-remediation-demo-bucket-notags\"",
					},
					{
						Position: 25,
						Line:     "  tags = {",
					},
					{
						Position: 26,
						Line:     "    Demo = \"true\"",
					},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 23,
						Col:  1,
					},
					End: model.ResourceLine{
						Line: 28,
						Col:  2,
					},
				},
				LineWithVulnerability: "  tags = {",
				ResolvedFile:          "",
				RemediationLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 26,
						Col:  5,
					},
					End: model.ResourceLine{
						Line: 26,
						Col:  5,
					},
				},
				ResourceSource: "resource \"aws_s3_bucket\" \"test3\" {\n  bucket = \"iac-remediation-demo-bucket-notags\"\n  tags = {\n    Demo = \"true\"\n  }\n}\n",
				FileSource:     strings.Split(OriginalData1, "\n"),
				BlockLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 23,
						Col:  1,
					},
					End: model.ResourceLine{
						Line: 28,
						Col:  2,
					},
				},
			},
			searchKey: "aws_s3_bucket[test3].tags",
			file: &model.FileMetadata{
				ScanID:            "Test3",
				ID:                "Test3",
				Kind:              model.KindTerraform,
				OriginalData:      OriginalData1,
				LinesOriginalData: utils.SplitLines(OriginalData1),
			},
		},
		{
			expected: model.VulnerabilityLines{
				Line: 46,
				VulnLines: &[]model.CodeLine{
					{
						Position: 45,
						Line:     "      security_context = {",
					},
					{
						Position: 46,
						Line:     "        allow_privilege_escalation = true",
					},
					{
						Position: 47,
						Line:     "      }",
					},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 1,
						Col:  1,
					},
					End: model.ResourceLine{
						Line: 92,
						Col:  2,
					},
				},
				LineWithVulnerability: "        allow_privilege_escalation = true",
				ResolvedFile:          "",
				RemediationLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 46,
						Col:  9,
					},
					End: model.ResourceLine{
						Line: 46,
						Col:  9,
					},
				},
				ResourceSource: "resource \"kubernetes_pod\" \"positive1\" {\n  metadata {\n    name = \"terraform-example\"\n  }\n\n  spec {\n    container = [\n     {\n      image = \"nginx:1.7.9\"\n      name  = \"example22\"\n\n      security_context = {\n        allow_privilege_escalation = true\n      }\n\n      env = {\n        name  = \"environment\"\n        value = \"test\"\n      }\n\n      port = {\n        container_port = 8080\n      }\n\n      liveness_probe = {\n        http_get = {\n          path = \"/nginx_status\"\n          port = 80\n\n          http_header = {\n            name  = \"X-Custom-Header\"\n            value = \"Awesome\"\n          }\n        }\n\n        initial_delay_seconds = 3\n        period_seconds        = 3\n      }\n     }\n     ,\n     {\n      image = \"nginx:1.7.9\"\n      name  = \"example22222\"\n\n      security_context = {\n        allow_privilege_escalation = true\n      }\n\n      env = {\n        name  = \"environment\"\n        value = \"test\"\n      }\n\n      port = {\n        container_port = 8080\n      }\n\n      liveness_probe = {\n        http_get = {\n          path = \"/nginx_status\"\n          port = 80\n\n          http_header = {\n            name  = \"X-Custom-Header\"\n            value = \"Awesome\"\n          }\n        }\n\n        initial_delay_seconds = 3\n        period_seconds        = 3\n      }\n     }\n   ]\n\n\n    dns_config {\n      nameservers = [\"1.1.1.1\", \"8.8.8.8\", \"9.9.9.9\"]\n      searches    = [\"example.com\"]\n\n      option {\n        name  = \"ndots\"\n        value = 1\n      }\n\n      option {\n        name = \"use-vc\"\n      }\n    }\n\n    dns_policy = \"None\"\n  }\n}\n",
				FileSource:     strings.Split(ArrayTestString, "\n"),
				BlockLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 1,
						Col:  1,
					},
					End: model.ResourceLine{
						Line: 92,
						Col:  2,
					},
				},
			},
			searchKey: "kubernetes_pod[positive1].spec.container[1].security_context.allow_privilege_escalation",
			file: &model.FileMetadata{
				ScanID:            "Test3",
				ID:                "Test3",
				Kind:              model.KindTerraform,
				OriginalData:      ArrayTestString,
				LinesOriginalData: utils.SplitLines(ArrayTestString),
			},
		},
		{
			expected: model.VulnerabilityLines{
				Line: 10,
				VulnLines: &[]model.CodeLine{
					{
						Position: 9,
						Line:     "  binding {",
					},
					{
						Position: 10,
						Line:     "    role = \"roles/owner\"",
					},
					{
						Position: 11,
						Line:     "    members = [",
					},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 1,
						Col:  1,
					},
					End: model.ResourceLine{
						Line: 15,
						Col:  2,
					},
				},
				LineWithVulnerability: "    role = \"roles/owner\"",
				ResolvedFile:          "",
				RemediationLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 10,
						Col:  5,
					},
					End: model.ResourceLine{
						Line: 10,
						Col:  5,
					},
				},
				ResourceSource: "data \"google_iam_policy\" \"admin\" {\n  binding {\n    role = \"roles/compute.imageUser\"\n\n    members = [\n      \"serviceAccount:jane@example.com\",\n    ]\n  }\n  binding {\n    role = \"roles/owner\"\n    members = [\n      \"serviceAccount:john@example.com\",\n    ]\n  }\n}\n",
				FileSource:     strings.Split(ExtendedArrayTestString, "\n"),
				BlockLocation: model.ResourceLocation{
					Start: model.ResourceLine{
						Line: 1,
						Col:  1,
					},
					End: model.ResourceLine{
						Line: 15,
						Col:  2,
					},
				},
			},
			searchKey: "google_iam_policy[admin].binding[1].role",
			file: &model.FileMetadata{
				ScanID:            "Test4",
				ID:                "Test4",
				Kind:              model.KindTerraform,
				OriginalData:      ExtendedArrayTestString,
				LinesOriginalData: utils.SplitLines(ExtendedArrayTestString),
			},
		},
	}

	ctx := context.Background()
	for i, testCase := range testCases {
		detector := &DetectKindLine{}
		t.Run(fmt.Sprintf("detectTerraformLine-%d", i), func(t *testing.T) {
			v := detector.DetectLine(ctx, testCase.file, testCase.searchKey, 3)
			require.Equal(t, testCase.expected, v)
		})
	}
}

func TestDetectTerraformLineRemediations(t *testing.T) {
	testCases := []struct {
		expected  model.VulnerabilityLines
		searchKey string
		file      *model.FileMetadata
	}{
		{
			expected: model.VulnerabilityLines{
				Line: 24,
				VulnLines: &[]model.CodeLine{
					{Position: 23, Line: "\tversioning {"},
					{Position: 24, Line: "\t  enabled = false"},
					{Position: 25, Line: "\t}"},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 14, Col: 3},
					End:   model.ResourceLine{Line: 26, Col: 4},
				},
				RemediationLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 24, Col: 4},
					End:   model.ResourceLine{Line: 24, Col: 4},
				},
				LineWithVulnerability: "\t  enabled = false",
				ResolvedFile:          "",
				ResourceSource:        "  resource \"aws_s3_bucket\" \"positive1\" {\n\tbucket = \"my-tf-test-bucket\"\n\tacl    = \"private\"\n\n\ttags = {\n\t  Name        = \"My bucket\"\n\t  Environment = \"Dev\"\n\t}\n\n\tversioning {\n\t  enabled = false\n\t}\n  }\n",
				FileSource:            strings.Split(OriginalDataPositive1, "\n"),
				BlockLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 14, Col: 3},
					End:   model.ResourceLine{Line: 26, Col: 4},
				},
			},
			searchKey: "aws_s3_bucket[positive1].versioning.enabled",
			file: &model.FileMetadata{
				ScanID:            "console",
				ID:                "positive1.versioning.enabled",
				Kind:              model.KindTerraform,
				OriginalData:      OriginalDataPositive1,
				LinesOriginalData: utils.SplitLines(OriginalDataPositive1),
			},
		},
		{
			expected: model.VulnerabilityLines{
				Line: 14,
				VulnLines: &[]model.CodeLine{
					{Position: 13, Line: ""},
					{Position: 14, Line: "  resource \"aws_s3_bucket\" \"positive2\" {"},
					{Position: 15, Line: "\tbucket = \"my-tf-test-bucket\""},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 14, Col: 3},
					End:   model.ResourceLine{Line: 22, Col: 4},
				},
				RemediationLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 17, Col: 2},
					End:   model.ResourceLine{Line: 17, Col: 2},
				},
				LineWithVulnerability: "  resource \"aws_s3_bucket\" \"positive2\" {",
				ResolvedFile:          "",
				ResourceSource:        "  resource \"aws_s3_bucket\" \"positive2\" {\n\tbucket = \"my-tf-test-bucket\"\n\tacl    = \"private\"\n\n\ttags = {\n\t  Name        = \"My bucket\"\n\t  Environment = \"Dev\"\n\t}\n  }\n",
				FileSource:            strings.Split(OriginalDataPositive2, "\n"),
				BlockLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 14, Col: 3},
					End:   model.ResourceLine{Line: 22, Col: 4},
				},
			},
			searchKey: "aws_s3_bucket[positive2]",
			file: &model.FileMetadata{
				ScanID:            "console",
				ID:                "positive2.missing_field",
				Kind:              model.KindTerraform,
				OriginalData:      OriginalDataPositive2,
				LinesOriginalData: utils.SplitLines(OriginalDataPositive2),
			},
		},
		{
			expected: model.VulnerabilityLines{
				Line: 23,
				VulnLines: &[]model.CodeLine{
					{Position: 22, Line: ""},
					{Position: 23, Line: "\tversioning {"},
					{Position: 24, Line: "\t  mfa_delete = true"},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 14, Col: 3},
					End:   model.ResourceLine{Line: 26, Col: 4},
				},
				RemediationLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 24, Col: 4},
					End:   model.ResourceLine{Line: 24, Col: 4},
				},
				LineWithVulnerability: "\tversioning {",
				ResolvedFile:          "",
				ResourceSource:        "  resource \"aws_s3_bucket\" \"positive3\" {\n\tbucket = \"my-tf-test-bucket\"\n\tacl    = \"private\"\n\n\ttags = {\n\t  Name        = \"My bucket\"\n\t  Environment = \"Dev\"\n\t}\n\n\tversioning {\n\t  mfa_delete = true\n\t}\n  }\n",
				FileSource:            strings.Split(OriginalDataPositive3, "\n"),
				BlockLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 14, Col: 3},
					End:   model.ResourceLine{Line: 26, Col: 4},
				},
			},
			searchKey: "aws_s3_bucket[positive3].versioning",
			file: &model.FileMetadata{
				ScanID:            "console",
				ID:                "positive3.versioning",
				Kind:              model.KindTerraform,
				OriginalData:      OriginalDataPositive3,
				LinesOriginalData: utils.SplitLines(OriginalDataPositive3),
			},
		},
		{
			expected: model.VulnerabilityLines{
				Line: 27,
				VulnLines: &[]model.CodeLine{
					{Position: 26, Line: "\tversioning_configuration {"},
					{Position: 27, Line: "\t  status = \"Suspended\""},
					{Position: 28, Line: "\t}"},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 23, Col: 3},
					End:   model.ResourceLine{Line: 29, Col: 4},
				},
				RemediationLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 27, Col: 4},
					End:   model.ResourceLine{Line: 27, Col: 4},
				},
				LineWithVulnerability: "\t  status = \"Suspended\"",
				ResolvedFile:          "",
				ResourceSource:        "  resource \"aws_s3_bucket_versioning\" \"example\" {\n\tbucket = aws_s3_bucket.b0.id\n\n\tversioning_configuration {\n\t  status = \"Suspended\"\n\t}\n  }\n",
				FileSource:            strings.Split(OriginalDataPositive7, "\n"),
				BlockLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 23, Col: 3},
					End:   model.ResourceLine{Line: 29, Col: 4},
				},
			},
			searchKey: "aws_s3_bucket_versioning[example].versioning_configuration.status",
			file: &model.FileMetadata{
				ScanID:            "console",
				ID:                "positive7.versioning_configuration.status",
				Kind:              model.KindTerraform,
				OriginalData:      OriginalDataPositive7,
				LinesOriginalData: utils.SplitLines(OriginalDataPositive7),
			},
		},
		{
			expected: model.VulnerabilityLines{
				Line: 1,
				VulnLines: &[]model.CodeLine{
					{Position: 1, Line: "resource \"aws_s3_bucket\" \"no_versioning\" {"},
					{Position: 2, Line: "\tbucket = \"my-tf-test-bucket\""},
					{Position: 3, Line: ""},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 1, Col: 1},
					End:   model.ResourceLine{Line: 7, Col: 4},
				},
				RemediationLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 3, Col: 2},
					End:   model.ResourceLine{Line: 3, Col: 2},
				},
				LineWithVulnerability: "resource \"aws_s3_bucket\" \"no_versioning\" {",
				ResolvedFile:          "",
				ResourceSource:        "resource \"aws_s3_bucket\" \"no_versioning\" {\n\tbucket = \"my-tf-test-bucket\"\n\n\ttags = {\n\t  Name = \"My bucket\"\n\t}\n  }\n",
				FileSource:            strings.Split(OriginalDataMissingVersioning, "\n"),
				BlockLocation: model.ResourceLocation{
					Start: model.ResourceLine{Line: 1, Col: 1},
					End:   model.ResourceLine{Line: 7, Col: 4},
				},
			},
			searchKey: "aws_s3_bucket[no_versioning].versioning.enabled",
			file: &model.FileMetadata{
				ScanID:            "console",
				ID:                "missing.versioning.enabled",
				Kind:              model.KindTerraform,
				OriginalData:      OriginalDataMissingVersioning,
				LinesOriginalData: utils.SplitLines(OriginalDataMissingVersioning),
			},
		},
		{
			expected: model.VulnerabilityLines{
				Line: 4,
				VulnLines: &[]model.CodeLine{
					{Position: 3, Line: "    configuration {"},
					{Position: 4, Line: "      status = \"Enabled\""},
					{Position: 5, Line: "    }"},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{Col: 1, Line: 1},
					End:   model.ResourceLine{Col: 2, Line: 7},
				},
				RemediationLocation: model.ResourceLocation{
					Start: model.ResourceLine{Col: 7, Line: 4},
					End:   model.ResourceLine{Col: 7, Line: 4},
				},
				LineWithVulnerability: "      status = \"Enabled\"",
				ResolvedFile:          "",
				ResourceSource:        "resource \"aws_s3_bucket\" \"example\" {\n  versioning {\n    configuration {\n      status = \"Enabled\"\n    }\n  }\n}\n",
				FileSource:            strings.Split("resource \"aws_s3_bucket\" \"example\" {\n  versioning {\n    configuration {\n      status = \"Enabled\"\n    }\n  }\n}\n", "\n"),
				BlockLocation: model.ResourceLocation{
					Start: model.ResourceLine{Col: 1, Line: 1},
					End:   model.ResourceLine{Col: 2, Line: 7},
				},
			},
			searchKey: "aws_s3_bucket[example].versioning.configuration.status",
			file: &model.FileMetadata{
				ScanID:            "deep",
				ID:                "deep-nested",
				Kind:              model.KindTerraform,
				OriginalData:      "resource \"aws_s3_bucket\" \"example\" {\n  versioning {\n    configuration {\n      status = \"Enabled\"\n    }\n  }\n}\n",
				LinesOriginalData: utils.SplitLines("resource \"aws_s3_bucket\" \"example\" {\n  versioning {\n    configuration {\n      status = \"Enabled\"\n    }\n  }\n}\n"),
			},
		},
		{
			expected: model.VulnerabilityLines{
				Line: 3,
				VulnLines: &[]model.CodeLine{
					{Position: 2, Line: "  statement = [{"},
					{Position: 3, Line: "    actions = [\"s3:GetObject\"]"},
					{Position: 4, Line: "  }]"},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{Col: 1, Line: 1},
					End:   model.ResourceLine{Col: 2, Line: 5},
				},
				RemediationLocation: model.ResourceLocation{
					Start: model.ResourceLine{Col: 5, Line: 3},
					End:   model.ResourceLine{Col: 5, Line: 3},
				},
				LineWithVulnerability: "    actions = [\"s3:GetObject\"]",
				ResolvedFile:          "",
				ResourceSource:        "resource \"aws_iam_policy_document\" \"example\" {\n  statement = [{\n    actions = [\"s3:GetObject\"]\n  }]\n}\n",
				FileSource:            strings.Split("resource \"aws_iam_policy_document\" \"example\" {\n  statement = [{\n    actions = [\"s3:GetObject\"]\n  }]\n}\n", "\n"),
				BlockLocation: model.ResourceLocation{
					Start: model.ResourceLine{Col: 1, Line: 1},
					End:   model.ResourceLine{Col: 2, Line: 5},
				},
			},
			searchKey: "aws_iam_policy_document[example].statement[0].actions[0]",
			file: &model.FileMetadata{
				ScanID:            "indexing",
				ID:                "policy.actions",
				Kind:              model.KindTerraform,
				OriginalData:      "resource \"aws_iam_policy_document\" \"example\" {\n  statement = [{\n    actions = [\"s3:GetObject\"]\n  }]\n}\n",
				LinesOriginalData: utils.SplitLines("resource \"aws_iam_policy_document\" \"example\" {\n  statement = [{\n    actions = [\"s3:GetObject\"]\n  }]\n}\n"),
			},
		},
		{
			expected: model.VulnerabilityLines{
				Line: 1,
				VulnLines: &[]model.CodeLine{
					{Position: 1, Line: "resource \"aws_instance\" \"example\" {"},
					{Position: 2, Line: "  tags = {"},
					{Position: 3, Line: "    Name = \"web-server\""},
				},
				VulnerablilityLocation: model.ResourceLocation{
					Start: model.ResourceLine{Col: 1, Line: 1},
					End:   model.ResourceLine{Col: 2, Line: 5},
				},
				RemediationLocation: model.ResourceLocation{
					Start: model.ResourceLine{Col: 1, Line: 1},
					End:   model.ResourceLine{Col: 1, Line: 1},
				},
				LineWithVulnerability: "resource \"aws_instance\" \"example\" {",
				ResolvedFile:          "",
				ResourceSource:        "resource \"aws_instance\" \"example\" {\n  tags = {\n    Name = \"web-server\"\n  }\n}\n",
				FileSource:            strings.Split("resource \"aws_instance\" \"example\" {\n  tags = {\n    Name = \"web-server\"\n  }\n}\n", "\n"),
				BlockLocation: model.ResourceLocation{
					Start: model.ResourceLine{Col: 1, Line: 1},
					End:   model.ResourceLine{Col: 2, Line: 5},
				},
			},
			searchKey: "aws_instance[example].tags[\"Name\"]",
			file: &model.FileMetadata{
				ScanID:            "mapkey",
				ID:                "tags.name",
				Kind:              model.KindTerraform,
				OriginalData:      "resource \"aws_instance\" \"example\" {\n  tags = {\n    Name = \"web-server\"\n  }\n}\n",
				LinesOriginalData: utils.SplitLines("resource \"aws_instance\" \"example\" {\n  tags = {\n    Name = \"web-server\"\n  }\n}\n"),
			},
		},
	}

	ctx := context.Background()
	for i, testCase := range testCases {
		detector := &DetectKindLine{}
		t.Run(fmt.Sprintf("detectTerraformLine-%d", i), func(t *testing.T) {
			v := detector.DetectLine(ctx, testCase.file, testCase.searchKey, 3)
			require.Equal(t, testCase.expected, v)
		})
	}
}

const OriginalDataPositive1 = `provider "aws" {
	region = "us-east-1"
  }

  terraform {
	required_providers {
	  aws = {
		source  = "hashicorp/aws"
		version = "~> 3.0"
	  }
	}
  }

  resource "aws_s3_bucket" "positive1" {
	bucket = "my-tf-test-bucket"
	acl    = "private"

	tags = {
	  Name        = "My bucket"
	  Environment = "Dev"
	}

	versioning {
	  enabled = false
	}
  }`

const OriginalDataPositive2 = `provider "aws" {
	region = "us-east-1"
  }

  terraform {
	required_providers {
	  aws = {
		source  = "hashicorp/aws"
		version = "~> 3.0"
	  }
	}
  }

  resource "aws_s3_bucket" "positive2" {
	bucket = "my-tf-test-bucket"
	acl    = "private"

	tags = {
	  Name        = "My bucket"
	  Environment = "Dev"
	}
  }`

const OriginalDataPositive3 = `provider "aws" {
	region = "us-east-1"
  }

  terraform {
	required_providers {
	  aws = {
		source  = "hashicorp/aws"
		version = "~> 3.0"
	  }
	}
  }

  resource "aws_s3_bucket" "positive3" {
	bucket = "my-tf-test-bucket"
	acl    = "private"

	tags = {
	  Name        = "My bucket"
	  Environment = "Dev"
	}

	versioning {
	  mfa_delete = true
	}
  }`

const OriginalDataPositive7 = `terraform {
	required_providers {
	  aws = {
		source = "hashicorp/aws"
		version = "4.2.0"
	  }
	}
  }

  provider "aws" {
	# Configuration options
  }

  resource "aws_s3_bucket" "b0" {
	bucket = "my-tf-test-bucket"

	tags = {
	  Name        = "My bucket"
	  Environment = "Dev"
	}
  }

  resource "aws_s3_bucket_versioning" "example" {
	bucket = aws_s3_bucket.b0.id

	versioning_configuration {
	  status = "Suspended"
	}
  }`

const OriginalDataMissingVersioning = `resource "aws_s3_bucket" "no_versioning" {
	bucket = "my-tf-test-bucket"

	tags = {
	  Name = "My bucket"
	}
  }
  `

const policyStatementPrincipalJSONEncode = `resource "aws_s3_bucket_policy" "x" {
  bucket = "b"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "*"
    }]
  })
}
`

const policyStatementPrincipalHeredocJSON = `resource "aws_ecr_repository_policy" "x" {
  repository = "r"

  policy = <<EOF
{
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "*"
    }
  ]
}
EOF
}
`

func TestDetectLinePolicyStatementPrincipalJsonencode(t *testing.T) {
	ctx := context.Background()
	file := &model.FileMetadata{
		ScanID:            "t",
		ID:                "t",
		Kind:              model.KindTerraform,
		OriginalData:      policyStatementPrincipalJSONEncode,
		LinesOriginalData: utils.SplitLines(policyStatementPrincipalJSONEncode),
	}
	got := (&DetectKindLine{}).DetectLine(ctx, file, `aws_s3_bucket_policy[x].policy.Statement[0].Principal`, 3)
	require.Equal(t, 8, got.Line)
	// The remediation/region anchor must stay on the identifying line inside the
	// jsonencode(...) body rather than being pushed past the wrapping `})`,
	// otherwise SARIF would surface the wrong line for rules without an autofix.
	require.Equal(t, 8, got.RemediationLocation.Start.Line)
	require.Equal(t, 8, got.RemediationLocation.End.Line)
}

func TestDetectLinePolicyStatementPrincipalHeredocJSON(t *testing.T) {
	ctx := context.Background()
	file := &model.FileMetadata{
		ScanID:            "t",
		ID:                "t",
		Kind:              model.KindTerraform,
		OriginalData:      policyStatementPrincipalHeredocJSON,
		LinesOriginalData: utils.SplitLines(policyStatementPrincipalHeredocJSON),
	}
	got := (&DetectKindLine{}).DetectLine(ctx, file, `aws_ecr_repository_policy[x].policy.Statement[0].Principal`, 3)
	require.Equal(t, 9, got.Line)
}

const policyFromFileFunction = `resource "aws_iam_role" "DatadogAWSIntegration" {
  name               = "DatadogAWSIntegration"
  assume_role_policy = file("policies/assume/DatadogAWSIntegration.json")
  tags = {
    team = "iac"
  }
}
`

const policyFromFileFunctionInterpolated = `resource "aws_iam_role" "DatadogAWSIntegration" {
  name               = "DatadogAWSIntegration"
  assume_role_policy = file("${path.module}/policies/assume/DatadogAWSIntegration.json")
  tags = {
    team = "iac"
  }
}
`

// A heredoc policy on one line holds every key on that line, so the search
// must not run on into the next block that spells the same key.
func TestDetectLineStaysInsideSearchedBlock(t *testing.T) {
	src := `resource "aws_sqs_queue" "heredoc" {
  name   = "heredoc"
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:*"}]}
POLICY
}

resource "aws_sqs_queue_policy" "other" {
  policy = jsonencode({
    Statement = [{ Principal = "*" }]
  })
}
`
	file := &model.FileMetadata{
		ScanID:            "t",
		ID:                "t",
		Kind:              model.KindTerraform,
		OriginalData:      src,
		LinesOriginalData: utils.SplitLines(src),
	}
	for _, key := range []string{
		`aws_sqs_queue[heredoc].policy.Statement[0].Principal`,
		`aws_sqs_queue[{{heredoc}}].policy.Statement[0].Principal`,
	} {
		got := (&DetectKindLine{}).DetectLine(context.Background(), file, key, 3)
		require.Equal(t, 3, got.Line, key)
		require.Equal(t, 1, got.BlockLocation.Start.Line, key)
	}
}

// A part found only past the named block is skipped; the parts after it still
// search from the last line found within the block.
func TestDetectLineSkipsPartLeavingNamedBlock(t *testing.T) {
	src := `resource "aws_x" "b" {
  bar = [
    "a",
    "b",
  ]
}

resource "aws_x" "c" {
  foo = 1
}
`
	file := &model.FileMetadata{
		ScanID:            "t",
		ID:                "t",
		Kind:              model.KindTerraform,
		OriginalData:      src,
		LinesOriginalData: utils.SplitLines(src),
	}
	got := (&DetectKindLine{}).DetectLine(context.Background(), file, `aws_x[b].foo.bar[1]`, 3)
	require.Equal(t, 4, got.Line)
}

// A key's leading parts may match an earlier block on the way to the one it
// names; only leaving the named block stops the search.
func TestDetectLineReachesNamedBlockPastEarlierOnes(t *testing.T) {
	src := `resource "aws_cloudfront_distribution" "a" {
  ordered_cache_behavior {
    viewer_protocol_policy = "redirect-to-https"
  }
}

resource "aws_cloudfront_distribution" "b" {
  ordered_cache_behavior {
    viewer_protocol_policy = "allow-all"
  }
}
`
	file := &model.FileMetadata{
		ScanID:            "t",
		ID:                "t",
		Kind:              model.KindTerraform,
		OriginalData:      src,
		LinesOriginalData: utils.SplitLines(src),
	}
	key := `resource.aws_cloudfront_distribution[b].ordered_cache_behavior[0].viewer_protocol_policy`
	got := (&DetectKindLine{}).DetectLine(context.Background(), file, key, 3)
	require.Equal(t, 9, got.Line)
	require.Equal(t, 7, got.BlockLocation.Start.Line)
}

func TestDetectLineFileFunctionKeepsAttributeLine(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cases := []struct {
		name string
		src  string
	}{
		{name: "literal_path", src: policyFromFileFunction},
		{name: "interpolated_path", src: policyFromFileFunctionInterpolated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			file := &model.FileMetadata{
				ScanID:            "t",
				ID:                "t",
				Kind:              model.KindTerraform,
				OriginalData:      tc.src,
				LinesOriginalData: utils.SplitLines(tc.src),
			}
			got := (&DetectKindLine{}).DetectLine(ctx, file, `aws_iam_role[DatadogAWSIntegration].assume_role_policy.Statement[0].Principal`, 3)
			require.Equal(t, 3, got.Line)
			require.Equal(t, 3, got.RemediationLocation.Start.Line)
			require.Equal(t, 3, got.RemediationLocation.End.Line)
			require.Contains(t, got.LineWithVulnerability, "assume_role_policy")
		})
	}
}

func TestLocateTerraformBlockUsesNearestBlockForHeaderComments(t *testing.T) {
	source := "# license\n# owner\n\nresource \"aws_s3_bucket\" \"helm\" {\n  bucket = \"x\"\n}\n"
	lines := strings.Split(source, "\n")
	body, err := (&DetectKindLine{}).cachedParseBody(source, "helm_bucket.tf")
	require.NoError(t, err)

	got, err := locateTerraformBlock(context.Background(), body, 2, lines)
	require.NoError(t, err)
	require.Equal(t, 4, got.BlockLocation.Start.Line)
	require.Equal(t, "# owner", got.LineWithVulnerability)
}

func TestCalculateInsertionPointClampsFunctionWrapperAtEndOfFile(t *testing.T) {
	source := "variable \"name\" {\n  default = merge({\n  })\n}"
	lines := strings.Split(source, "\n")[:3]
	body, err := (&DetectKindLine{}).cachedParseBody(source, "variable.tf")
	require.NoError(t, err)
	require.Len(t, body.Blocks, 1)

	line, _ := calculateInsertionPoint(body.Blocks[0], len(lines), lines)

	require.Equal(t, len(lines), line)
}

func TestDetectLineJSONConfig(t *testing.T) {
	src := `{
  "resource": {
    "aws_s3_bucket": {
      "b": {
        "acl": "public-read"
      }
    }
  }
}`
	file := &model.FileMetadata{
		FilePath:          "main.tf.json",
		Kind:              model.KindTerraform,
		OriginalData:      src,
		LinesOriginalData: utils.SplitLines(src),
	}
	got := (&DetectKindLine{}).DetectLine(context.Background(), file, "aws_s3_bucket[b].acl", 3)
	require.Equal(t, 5, got.Line)
	require.Equal(t, "main.tf.json", got.ResolvedFile)
	require.Equal(t, 5, got.VulnerablilityLocation.Start.Line)
	require.Equal(t, 5, got.VulnerablilityLocation.End.Line)
	require.Equal(t, 5, got.RemediationLocation.Start.Line)
	require.Equal(t, 5, got.BlockLocation.Start.Line)
}

func TestDetectLineJSONConfigArrayIndex(t *testing.T) {
	src := `{
  "resource": {
    "aws_security_group": {
      "sg": {
        "ingress": [
          {
            "cidr_blocks": ["0.0.0.0/0"]
          },
          {
            "cidr_blocks": ["10.0.0.0/8"]
          }
        ]
      }
    }
  }
}`
	file := &model.FileMetadata{
		FilePath:          "main.tf.json",
		Kind:              model.KindTerraform,
		OriginalData:      src,
		LinesOriginalData: utils.SplitLines(src),
	}
	got := (&DetectKindLine{}).DetectLine(context.Background(), file, "aws_security_group[sg].ingress[1].cidr_blocks", 3)
	require.Equal(t, 10, got.Line)
}

func TestDetectLineJSONConfigIgnoresQuotedValue(t *testing.T) {
	src := `{
  "resource": {
    "aws_s3_bucket": {
      "prod": {
        "bucket": "acl"
      }
    }
  }
}`
	file := &model.FileMetadata{
		FilePath:          "main.tf.json",
		Kind:              model.KindTerraform,
		OriginalData:      src,
		LinesOriginalData: utils.SplitLines(src),
	}
	got := (&DetectKindLine{}).DetectLine(context.Background(), file, "acl", 3)
	require.Equal(t, -1, got.Line)
}

func TestDetectLineJSONConfigIgnoresUnquotedSubstring(t *testing.T) {
	src := `{
  "resource": {
    "aws_s3_bucket": {
      "prod": {
        "bucket": "mentions-acl-in-value"
      }
    }
  }
}`
	file := &model.FileMetadata{
		FilePath:          "main.tf.json",
		Kind:              model.KindTerraform,
		OriginalData:      src,
		LinesOriginalData: utils.SplitLines(src),
	}
	got := (&DetectKindLine{}).DetectLine(context.Background(), file, "acl", 3)
	require.Equal(t, -1, got.Line)
}

// An indexed repeated block counts the dynamic blocks generating its type, so
// the key lands in the block that holds the flagged element.
func TestDetectLineIndexesDynamicBlocksOfSameType(t *testing.T) {
	src := `resource "google_sql_database_instance" "x" {
  settings {
    dynamic "database_flags" {
      for_each = ["a"]
      content {
        name  = "skip_show_database"
        value = "on"
      }
    }

    dynamic "database_flags" {
      for_each = ["b"]
      content {
        name  = "skip_show_database"
        value = "off"
      }
    }
  }
}
`
	file := &model.FileMetadata{
		ScanID:            "t",
		ID:                "t",
		Kind:              model.KindTerraform,
		OriginalData:      src,
		LinesOriginalData: utils.SplitLines(src),
	}
	got := (&DetectKindLine{}).DetectLine(context.Background(), file,
		`google_sql_database_instance[x].settings.database_flags[1].value`, 3)
	require.Equal(t, 15, got.Line)
}

// A dynamic block takes as many slots as its for_each yields: none when empty or
// unresolved, as the converter then emits no block of the type for it.
func TestDetectLineDynamicBlockSlotsFollowForEach(t *testing.T) {
	build := func(dynamic string) string {
		return "resource \"aws_security_group\" \"sg\" {\n" + dynamic +
			"  ingress {\n    cidr = \"static\"\n  }\n}\n"
	}
	dyn := func(forEach string) string {
		return "  dynamic \"ingress\" {\n    for_each = " + forEach + "\n    content {\n      cidr = ingress.value\n    }\n  }\n"
	}
	tests := []struct {
		name    string
		forEach string
		// wantLines maps the ingress index to the line of its source block.
		wantLines map[int]int
	}{
		{"empty", "[]", map[int]int{0: 9}},
		{"unresolved", "var.rules", map[int]int{0: 9}},
		{"two elements", `["a", "b"]`, map[int]int{0: 5, 1: 5, 2: 9}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := build(dyn(tt.forEach))
			file := &model.FileMetadata{
				ScanID: "t", ID: "t", Kind: model.KindTerraform,
				OriginalData: src, LinesOriginalData: utils.SplitLines(src),
			}
			for idx, want := range tt.wantLines {
				key := fmt.Sprintf("aws_security_group[sg].ingress[%d].cidr", idx)
				got := (&DetectKindLine{}).DetectLine(context.Background(), file, key, 3)
				require.Equal(t, want, got.Line, key)
			}
		})
	}
}

// A for_each only the converter could resolve, with the scan's variables, is
// sized from the document: the dynamic block stands for the blocks it generated.
func TestDetectLineSizesUnresolvableDynamicBlockFromDocument(t *testing.T) {
	src := "resource \"aws_security_group\" \"sg\" {\n" +
		"  dynamic \"ingress\" {\n    for_each = var.rules\n    content {\n      cidr = ingress.value\n    }\n  }\n" +
		"  ingress {\n    cidr = \"static\"\n  }\n}\n"
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	vars := converter.VariableMap{"var": cty.ObjectVal(map[string]cty.Value{
		"rules": cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")}),
	})}
	doc, err := converter.Convert(context.Background(), file, vars, converter.Options{})
	require.NoError(t, err)

	meta := &model.FileMetadata{
		ScanID: "t", ID: "t", Kind: model.KindTerraform, Document: doc,
		OriginalData: src, LinesOriginalData: utils.SplitLines(src),
	}
	for idx, want := range map[int]int{0: 5, 1: 5, 2: 9} {
		key := fmt.Sprintf("aws_security_group[sg].ingress[%d].cidr", idx)
		got := (&DetectKindLine{}).DetectLine(context.Background(), meta, key, 3)
		require.Equal(t, want, got.Line, key)
	}
}

// Several dynamic blocks of one type the detector cannot resolve are told apart
// by the document: each generated block records the dynamic block it came from,
// whichever of them the converter resolved with the scan's variables.
func TestDetectLineSeveralUnresolvableDynamicBlocksFromDocument(t *testing.T) {
	src := "resource \"aws_security_group\" \"sg\" {\n" + // 1
		"  dynamic \"ingress\" {\n    for_each = var.first\n    content {\n      cidr = ingress.value\n    }\n  }\n" + // 2-7
		"  ingress {\n    cidr = \"static\"\n  }\n" + // 8-10
		"  dynamic \"ingress\" {\n    for_each = var.second\n    content {\n      cidr = ingress.value\n    }\n  }\n" + // 11-16
		"  dynamic \"ingress\" {\n    for_each = var.third\n    content {\n      cidr = ingress.value\n    }\n  }\n" + // 17-22
		"}\n"
	strs := func(values ...string) cty.Value {
		elems := make([]cty.Value, 0, len(values))
		for _, v := range values {
			elems = append(elems, cty.StringVal(v))
		}
		return cty.TupleVal(elems)
	}
	tests := []struct {
		name string
		vars map[string]cty.Value
		// wantLines maps the ingress index to the line of its cidr in its source block.
		wantLines []int
	}{
		{
			name: "all resolved by the converter",
			vars: map[string]cty.Value{"first": strs("a", "b"), "second": strs("c"), "third": strs("d", "e")},
			// first x2, static, second x1, third x2
			wantLines: []int{5, 5, 9, 14, 20, 20},
		},
		{
			name: "middle one left as written",
			vars: map[string]cty.Value{"first": strs("a", "b"), "third": strs("d")},
			// first x2, static, third x1
			wantLines: []int{5, 5, 9, 20},
		},
		{
			name: "first one left as written",
			vars: map[string]cty.Value{"second": strs("c"), "third": strs("d", "e", "f")},
			// static, second x1, third x3
			wantLines: []int{9, 14, 20, 20, 20},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
			require.False(t, diags.HasErrors(), diags.Error())
			vars := converter.VariableMap{"var": cty.ObjectVal(tt.vars)}
			doc, err := converter.Convert(context.Background(), file, vars, converter.Options{})
			require.NoError(t, err)

			// As scanned: the line-info document keeps its line tables, while the
			// scan document is either stripped of them or already released.
			scanDocs := map[string]model.Document{
				"scan document released": nil,
				"scan document stripped": stripLineTables(t, doc),
			}
			for shape, scanDoc := range scanDocs {
				meta := &model.FileMetadata{
					ScanID: "t", ID: "t", Kind: model.KindTerraform,
					Document:         scanDoc,
					LineInfoDocument: doc,
					OriginalData:     src, LinesOriginalData: utils.SplitLines(src),
				}
				for idx, want := range tt.wantLines {
					key := fmt.Sprintf("aws_security_group[sg].ingress[%d].cidr", idx)
					got := (&DetectKindLine{}).DetectLine(context.Background(), meta, key, 3)
					require.Equal(t, want, got.Line, shape+": "+key)
				}
			}
		})
	}
}

// stripLineTables returns a deep copy of doc without any _dd_lines, as the scan
// prepares its document.
func stripLineTables(t *testing.T, doc model.Document) model.Document {
	t.Helper()
	var strip func(node interface{}) interface{}
	strip = func(node interface{}) interface{} {
		switch v := node.(type) {
		case model.Document:
			return model.Document(strip(map[string]interface{}(v)).(map[string]interface{}))
		case map[string]interface{}:
			out := make(map[string]interface{}, len(v))
			for key, child := range v {
				if key != "_dd_lines" {
					out[key] = strip(child)
				}
			}
			return out
		case []interface{}:
			out := make([]interface{}, len(v))
			for i, child := range v {
				out[i] = strip(child)
			}
			return out
		}
		return node
	}
	return strip(doc).(model.Document)
}

// Without the line-info document, a scan document that holds no line tables
// cannot tell several unresolved dynamic blocks apart, and the lines it gives
// are the ones from the body alone.
func TestDetectLineStrippedDocumentWithoutLineInfoFallsBack(t *testing.T) {
	src := "resource \"aws_security_group\" \"sg\" {\n" +
		"  ingress {\n    cidr = \"static\"\n  }\n" +
		"}\n"
	file, diags := hclsyntax.ParseConfig([]byte(src), "main.tf", hcl.InitialPos)
	require.False(t, diags.HasErrors(), diags.Error())
	doc, err := converter.Convert(context.Background(), file, converter.VariableMap{}, converter.Options{})
	require.NoError(t, err)
	meta := &model.FileMetadata{
		ScanID: "t", ID: "t", Kind: model.KindTerraform, Document: stripLineTables(t, doc),
		OriginalData: src, LinesOriginalData: utils.SplitLines(src),
	}
	got := (&DetectKindLine{}).DetectLine(context.Background(), meta, "aws_security_group[sg].ingress[0].cidr", 3)
	require.Equal(t, 3, got.Line)
}

// Repeated blocks nested below the resource are located like top-level ones: the
// document gives the source of each block however deep the repeated type sits,
// and the search starts from the nested block enclosing the position it has
// reached rather than the first nested block of the body.
func TestDetectLineNestedDynamicBlocksFromDocument(t *testing.T) {
	strs := func(values ...string) cty.Value {
		elems := make([]cty.Value, 0, len(values))
		for _, v := range values {
			elems = append(elems, cty.StringVal(v))
		}
		return cty.TupleVal(elems)
	}
	tests := []struct {
		name string
		src  string
		vars map[string]cty.Value
		// wantLines maps a search key to the line it must be found at.
		wantLines map[string]int
	}{
		{
			name: "dynamic block between static ones",
			src: "resource \"g\" \"x\" {\n" + // 1
				"  settings {\n" + // 2
				"    database_flags {\n      name = \"static0\"\n    }\n" + // 3-5
				"    dynamic \"database_flags\" {\n      for_each = var.flags\n      content {\n        name = database_flags.value\n      }\n    }\n" + // 6-11
				"    database_flags {\n      name = \"static_last\"\n    }\n" + // 12-14
				"  }\n}\n",
			vars: map[string]cty.Value{"flags": strs("p", "q", "r")},
			wantLines: map[string]int{
				"g[x].settings.database_flags[0].name": 4,
				"g[x].settings.database_flags[1].name": 9,
				"g[x].settings.database_flags[2].name": 9,
				"g[x].settings.database_flags[3].name": 9,
				"g[x].settings.database_flags[4].name": 13,
			},
		},
		{
			name: "several unresolved dynamic blocks in a nested block",
			src: "resource \"g\" \"x\" {\n" + // 1
				"  settings {\n" + // 2
				"    dynamic \"database_flags\" {\n      for_each = var.a\n      content {\n        name = database_flags.value\n      }\n    }\n" + // 3-8
				"    dynamic \"database_flags\" {\n      for_each = var.b\n      content {\n        name = database_flags.value\n      }\n    }\n" + // 9-14
				"  }\n}\n",
			vars: map[string]cty.Value{"a": strs("p", "q"), "b": strs("r")},
			wantLines: map[string]int{
				"g[x].settings.database_flags[0].name": 6,
				"g[x].settings.database_flags[1].name": 6,
				"g[x].settings.database_flags[2].name": 12,
			},
		},
		{
			name: "same repeated type in two nested blocks",
			src: "resource \"g\" \"x\" {\n" + // 1
				"  first {\n" + // 2
				"    flag {\n      name = \"first_only\"\n    }\n" + // 3-5
				"  }\n" + // 6
				"  second {\n" + // 7
				"    flag {\n      name = \"second_0\"\n    }\n" + // 8-10
				"    dynamic \"flag\" {\n      for_each = var.flags\n      content {\n        name = flag.value\n      }\n    }\n" + // 11-16
				"  }\n}\n",
			vars: map[string]cty.Value{"flags": strs("p", "q")},
			wantLines: map[string]int{
				"g[x].first.flag[0].name":  4,
				"g[x].second.flag[0].name": 9,
				"g[x].second.flag[1].name": 14,
				"g[x].second.flag[2].name": 14,
			},
		},
		{
			name: "nested below a nested block",
			src: "resource \"g\" \"x\" {\n" + // 1
				"  outer {\n" + // 2
				"    inner {\n" + // 3
				"      flag {\n        name = \"s\"\n      }\n" + // 4-6
				"      dynamic \"flag\" {\n        for_each = var.flags\n        content {\n          name = flag.value\n        }\n      }\n" + // 7-12
				"    }\n  }\n}\n",
			vars: map[string]cty.Value{"flags": strs("p", "q")},
			wantLines: map[string]int{
				"g[x].outer.inner.flag[0].name": 5,
				"g[x].outer.inner.flag[1].name": 10,
				"g[x].outer.inner.flag[2].name": 10,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, diags := hclsyntax.ParseConfig([]byte(tt.src), "main.tf", hcl.InitialPos)
			require.False(t, diags.HasErrors(), diags.Error())
			vars := converter.VariableMap{"var": cty.ObjectVal(tt.vars)}
			doc, err := converter.Convert(context.Background(), file, vars, converter.Options{})
			require.NoError(t, err)

			scanDocs := map[string]model.Document{
				"scan document released": nil,
				"scan document stripped": stripLineTables(t, doc),
			}
			for shape, scanDoc := range scanDocs {
				meta := &model.FileMetadata{
					ScanID: "t", ID: "t", Kind: model.KindTerraform,
					Document:         scanDoc,
					LineInfoDocument: doc,
					OriginalData:     tt.src, LinesOriginalData: utils.SplitLines(tt.src),
				}
				for key, want := range tt.wantLines {
					got := (&DetectKindLine{}).DetectLine(context.Background(), meta, key, 3)
					require.Equal(t, want, got.Line, shape+": "+key)
				}
			}
		})
	}
}

// Decoding relies on this to know a finding's file before its line is
// detected (see detector.DetectLine.ReportsScannedFile).
func TestDetectLine_AlwaysReportsTheScannedFile(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name, path, src, key string
	}{
		{name: "found", path: "main.tf", src: OriginalData1, key: "aws_s3_bucket[bucket].acl"},
		{name: "not_found", path: "main.tf", src: OriginalData1, key: "aws_s3_bucket[missing].acl"},
		{name: "empty_key", path: "main.tf", src: OriginalData1, key: ""},
		{name: "empty_file", path: "main.tf", src: "", key: "aws_s3_bucket[bucket].acl"},
		{name: "unparsable", path: "main.tf", src: "resource \"aws_s3_bucket\" \"bucket\" {\n  acl = \"x\"\n", key: "aws_s3_bucket[bucket].acl"},
		{name: "referenced_file", path: "iam.tf", src: policyFromFileFunction,
			key: "aws_iam_role[DatadogAWSIntegration].assume_role_policy.Statement[0].Principal"},
		{name: "json_found", path: "main.tf.json", src: "{\n  \"resource\": {\n    \"aws_s3_bucket\": {\n      \"bucket\": {\n        \"acl\": \"x\"\n      }\n    }\n  }\n}\n",
			key: "resource.aws_s3_bucket.bucket.acl"},
		{name: "json_not_found", path: "main.tf.json", src: "{}\n", key: "resource.aws_s3_bucket.bucket.acl"},
		{name: "json_empty", path: "main.tf.json", src: "", key: "resource.aws_s3_bucket.bucket.acl"},
	}
	require.True(t, (&DetectKindLine{}).ReportsScannedFile())

	var unset *detector.DetectLine
	require.False(t, unset.ReportsScannedFile(&model.FileMetadata{Kind: model.KindTerraform}))
	scanDetector := detector.NewDetectLine(3).
		Add(helm.DetectKindLine{}, model.KindHELM).
		Add(docker.DetectKindLine{}, model.KindDOCKER).
		Add(&DetectKindLine{}, model.KindTerraform).
		Add(detector.DockerComposeDetectLine{}, model.KindYAML)
	for kind, want := range map[model.FileKind]bool{
		model.KindTerraform:     true,
		model.KindTerraformPlan: false,
		model.KindJSON:          false,
		model.KindHELM:          false,
		model.KindDOCKER:        false,
		model.KindYAML:          false,
	} {
		require.Equalf(t, want, scanDetector.ReportsScannedFile(&model.FileMetadata{Kind: kind}), "kind %s", kind)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The parse cache is keyed by path, so each case needs its own.
			detector := &DetectKindLine{}
			file := &model.FileMetadata{
				ID:                "t",
				Kind:              model.KindTerraform,
				FilePath:          tc.path,
				OriginalData:      tc.src,
				LinesOriginalData: utils.SplitLines(tc.src),
			}
			got := detector.DetectLine(ctx, file, tc.key, 3)
			require.Equal(t, tc.path, got.ResolvedFile)
		})
	}
}
