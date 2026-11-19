/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/stretchr/testify/require"
)

// syntheticQuery is a rule raising one finding per match of a Rego body that
// binds i (the document), typ, name and key (the search key).
func syntheticQuery(id, platform, metadataPlatform, body string) model.QueryMetadata {
	return model.QueryMetadata{
		Query: id,
		Content: `package datadog

DatadogPolicy contains result if {
` + body + `
	result := {
		"documentId": input.document[i].id,
		"resourceType": typ,
		"resourceName": name,
		"searchKey": key,
	}
}
`,
		InputData: "{}",
		Platform:  platform,
		Metadata: map[string]interface{}{
			"id": id, "legacyId": id, "queryName": id, "severity": "HIGH",
			"platform": metadataPlatform, "category": "Encryption",
		},
	}
}

// scanLinks scans with queries and returns the inventory and the SARIF
// fingerprint of each finding.
func scanLinks(t *testing.T, params *Parameters, queries ...model.QueryMetadata) (*inventory.Inventory, []string) {
	t.Helper()
	params.OutputPath = t.TempDir()
	params.OutputName = "result"
	params.ReportFormats = []string{"sarif"}
	params.InventoryPath = filepath.Join(t.TempDir(), "inventory.json")
	ctx := context.Background()
	c, err := NewClient(ctx, params, &consolePrinter.Printer{})
	require.NoError(t, err)
	c.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
		return &stubQuerySource{queries: queries}, nil
	}
	_, err = c.PerformScan(ctx)
	require.NoError(t, err)

	data, err := os.ReadFile(params.InventoryPath)
	require.NoError(t, err)
	var inv inventory.Inventory
	require.NoError(t, json.Unmarshal(data, &inv))

	var sarif struct {
		Runs []struct {
			Results []struct {
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	data, err = os.ReadFile(filepath.Join(params.OutputPath, "result.sarif"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &sarif))
	var fingerprints []string
	for _, r := range sarif.Runs[0].Results {
		fingerprints = append(fingerprints, r.PartialFingerprints["DATADOG_FINGERPRINT"])
	}
	return &inv, fingerprints
}

// linkedRefs maps each fingerprint to the rows it links to.
func linkedRefs(inv *inventory.Inventory) map[string][]string {
	refs := make(map[string][]string)
	for _, l := range inv.FindingLinks {
		refs[l.FindingFingerprint] = append(refs[l.FindingFingerprint], l.ResourceRef)
	}
	return refs
}

func TestInventoryLinksTerraformFindings(t *testing.T) {
	rootTF := inventoryRootTF + "\nresource \"aws_s3_bucket\" \"pair\" {\n  count  = 2\n  bucket = \"pair-${count.index}\"\n}\n"
	root := writeRepo(t, map[string]string{
		"infra/main.tf":                 rootTF,
		"infra/modules/logging/main.tf": inventoryModuleTF,
	})
	inv, fingerprints := scanLinks(t, terraformParams(root), inventoryTestQuery)
	require.NotEmpty(t, fingerprints)
	require.Zero(t, inv.Stats.FindingsUnlinked, "every bucket finding belongs to a row")

	refs := linkedRefs(inv)
	for _, fp := range fingerprints {
		require.NotEmpty(t, refs[fp], "fingerprint %s is linked", fp)
	}
	var linked [][]string
	for _, fp := range fingerprints {
		linked = append(linked, refs[fp])
	}
	require.ElementsMatch(t, [][]string{
		{"infra|aws_s3_bucket.extra"},
		{"infra|aws_s3_bucket.pair[0]", "infra|aws_s3_bucket.pair[1]"},
		{`infra|module.logging["prod"].aws_s3_bucket.this`},
		{`infra|module.logging["staging"].aws_s3_bucket.this`},
		{"infra|module.dyn.aws_s3_bucket.this"},
	}, linked, "a count block's instances share their finding; module instances each have theirs")
}

func TestInventoryLinksDocumentFindings(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"k8s/web.yaml": inventoryK8sYAML,
		"cfn/stack.yaml": "AWSTemplateFormatVersion: \"2010-09-09\"\nResources:\n  LogsBucket:\n    Type: AWS::S3::Bucket\n" +
			"\n  Queue:\n    Type: AWS::SQS::Queue\n",
	})
	service := syntheticQuery("test-k8s-service", "k8s", "Kubernetes", `	input.document[i].kind == "Service"
	typ := "Service"
	name := input.document[i].metadata.name
	key := sprintf("metadata.name={{%s}}.spec", [name])`)
	queue := syntheticQuery("test-cfn-queue", "cloudFormation", "CloudFormation", `	resource := input.document[i].Resources[logical]
	resource.Type == "AWS::SQS::Queue"
	typ := resource.Type
	name := logical
	key := sprintf("Resources.%s.Type", [logical])`)
	params := documentParams(root)
	params.Platform = []string{"Kubernetes", "CloudFormation"}

	inv, fingerprints := scanLinks(t, params, service, queue)
	require.Len(t, fingerprints, 2)
	require.Zero(t, inv.Stats.FindingsUnlinked)
	refs := linkedRefs(inv)
	var linked []string
	for _, fp := range fingerprints {
		require.Len(t, refs[fp], 1)
		linked = append(linked, refs[fp][0])
	}
	require.ElementsMatch(t, []string{"k8s/web.yaml|v1/Service/shop/web", "cfn/stack.yaml|Queue"}, linked,
		"a finding links to its document's row, or to the entry holding its line")
}

func TestInventoryCountsUnlinkedFindings(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"main.tf": "variable \"env\" {}\n\nresource \"aws_s3_bucket\" \"b\" {}\n",
	})
	variables := syntheticQuery("test-variable", "terraform", "Terraform", `	input.document[i].variable[name]
	typ := "variable"
	key := sprintf("variable.%s", [name])`)
	inv, fingerprints := scanLinks(t, terraformParams(root), variables)
	require.Len(t, fingerprints, 1)
	require.Empty(t, inv.FindingLinks, "a variable is not a resource")
	require.Equal(t, 1, inv.Stats.FindingsUnlinked)
}
