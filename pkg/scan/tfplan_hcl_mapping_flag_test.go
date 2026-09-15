/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/stretchr/testify/require"
)

// tfplanHCLMappingRule flags aws_instance resources so a scan of the fixture directory built by
// writeTFPlanHCLMappingFixture (an aws_instance resource, both as HCL and as a tfplan) produces
// findings from both documents.
var tfplanHCLMappingRule = model.QueryMetadata{
	Query:     "test-tfplan-hcl-mapping-rule",
	Content:   "package datadog\n\nDatadogPolicy contains result if {\n\tinput.document[i].resource.aws_instance[name]\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceType\": \"aws_instance\",\n\t\t\"resourceName\": name,\n\t\t\"searchKey\": sprintf(\"aws_instance[%s]\", [name]),\n\t}\n}\n",
	InputData: "{}",
	Platform:  "terraform",
	Metadata: map[string]interface{}{
		"id":        "test-tfplan-hcl-mapping-rule",
		"legacyId":  "test-tfplan-hcl-mapping-rule",
		"queryName": "Synthetic TFPlan HCL Mapping Rule",
		"severity":  "HIGH",
		"platform":  "Terraform",
		"category":  "Encryption",
	},
}

// tfplanJSONFixture is a minimal but complete Terraform plan JSON: the analyzer's platform
// classifier (pkg/analyzer/analyzer.go's classifyByContent) requires configuration,
// planned_values, resource_changes, AND terraform_version to all be present before it will
// classify a .json file as "terraform" at all - a plan missing any of these is silently dropped
// before scanning, never reaching the TFPlan detector.
const tfplanJSONFixture = `{
  "format_version": "1.0",
  "terraform_version": "1.5.0",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_instance.web",
          "mode": "managed",
          "type": "aws_instance",
          "name": "web",
          "provider_name": "registry.terraform.io/hashicorp/aws",
          "schema_version": 1,
          "values": {
            "ami": "ami-123456",
            "instance_type": "t2.micro"
          }
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_instance.web",
      "mode": "managed",
      "type": "aws_instance",
      "name": "web",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "ami": "ami-123456",
          "instance_type": "t2.micro"
        },
        "after_unknown": {}
      }
    }
  ],
  "configuration": {
    "root_module": {
      "resources": [
        {
          "address": "aws_instance.web",
          "mode": "managed",
          "type": "aws_instance",
          "name": "web",
          "expressions": {
            "ami": { "constant_value": "ami-123456" },
            "instance_type": { "constant_value": "t2.micro" }
          }
        }
      ]
    }
  }
}
`

const tfplanHCLMappingMainTF = `resource "aws_instance" "web" {
  ami           = "ami-123456"
  instance_type = "t2.micro"
}
`

// writeTFPlanHCLMappingFixture writes main.tf and plan.tfplan.json (the same aws_instance.web
// resource, once as HCL and once as a plan) into a fresh temp directory and returns its path.
func writeTFPlanHCLMappingFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(tfplanHCLMappingMainTF), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "plan.tfplan.json"), []byte(tfplanJSONFixture), 0o600))
	return dir
}

// runTFPlanHCLMappingScan scans the fixture directory (which holds both main.tf and
// plan.tfplan.json for the same resource) with ShouldScanTfPlans always on and
// ShouldMapTfPlanToHCL set per mapToHCL, returning the tfplan-sourced finding.
func runTFPlanHCLMappingScan(t *testing.T, mapToHCL bool) []model.Vulnerability {
	t.Helper()

	scanParams := Parameters{
		Path:                    []string{writeTFPlanHCLMappingFixture(t)},
		QueriesPath:             []string{"."},
		LibrariesPath:           "assets/libraries",
		PreviewLines:            3,
		CloudProvider:           []string{"aws"},
		Platform:                []string{"Terraform"},
		ChangedDefaultQueryPath: false,
		MaxFileSizeFlag:         100,
		ScanID:                  "console",
		MaxResolverDepth:        15,
		FlagEvaluator:           featureflags.NewLocalEvaluator(),
		ShouldScanTfPlans:       true,
		ShouldMapTfPlanToHCL:    mapToHCL,
	}

	ctx := context.Background()
	c, err := NewClient(ctx, &scanParams, &consolePrinter.Printer{})
	require.NoError(t, err)
	c.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
		return &stubQuerySource{queries: []model.QueryMetadata{tfplanHCLMappingRule}}, nil
	}

	r, err := c.executeScan(ctx)
	require.NoError(t, err)
	require.NotNil(t, r)
	return r.Results
}

func findTFPlanFinding(t *testing.T, results []model.Vulnerability) model.Vulnerability {
	t.Helper()
	for i := range results {
		if results[i].IsFromTFPlan {
			return results[i]
		}
	}
	t.Fatalf("expected a finding sourced from the tfplan JSON file; got %d results total", len(results))
	return model.Vulnerability{}
}

// TestShouldMapTfPlanToHCL_MapsToHCLFileWhenEnabled verifies that with ShouldMapTfPlanToHCL on,
// the HCL-sourced and TFPlan-sourced findings for the same resource merge into a single result
// (internal/storage's getUniqueVulnerabilities) rather than being reported twice, that the
// surviving finding is the TFPlan-sourced one (tagged IsFromTFPlan), and that it's reported
// against the resolved HCL file/line rather than the plan JSON itself.
func TestShouldMapTfPlanToHCL_MapsToHCLFileWhenEnabled(t *testing.T) {
	results := runTFPlanHCLMappingScan(t, true)

	require.Len(t, results, 1,
		"expected the HCL-sourced and TFPlan-sourced findings to merge into one when ShouldMapTfPlanToHCL is true")
	finding := findTFPlanFinding(t, results)
	require.Equal(t, "main.tf", filepath.Base(finding.FileName),
		"expected the surviving finding to be resolved to the HCL file")
}

// TestShouldMapTfPlanToHCL_ReportsAgainstPlanFileWhenDisabled verifies that with
// ShouldMapTfPlanToHCL off (the default), the HCL-sourced and TFPlan-sourced findings remain
// distinct (different FileName, so they don't share a fingerprint) - the pre-mapping behavior -
// even though ShouldScanTfPlans is on, and the tfplan one is still reported against the plan
// JSON file itself.
func TestShouldMapTfPlanToHCL_ReportsAgainstPlanFileWhenDisabled(t *testing.T) {
	results := runTFPlanHCLMappingScan(t, false)

	require.Len(t, results, 2,
		"expected the HCL-sourced and TFPlan-sourced findings to remain distinct when ShouldMapTfPlanToHCL is false")
	finding := findTFPlanFinding(t, results)
	require.Equal(t, "plan.tfplan.json", filepath.Base(finding.FileName),
		"expected the tfplan finding to remain against the plan JSON when ShouldMapTfPlanToHCL is false")
}
