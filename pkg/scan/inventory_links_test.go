/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	reportmodel "github.com/DataDog/datadog-iac-scanner/pkg/report/model"
	"github.com/rs/zerolog"
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
	return scanLinksWithContext(t, context.Background(), params, queries...)
}

func scanLinksWithContext(t *testing.T, ctx context.Context, params *Parameters, queries ...model.QueryMetadata) (*inventory.Inventory, []string) {
	t.Helper()
	params.OutputPath = t.TempDir()
	params.OutputName = "result"
	params.ReportFormats = []string{"sarif"}
	params.InventoryPath = filepath.Join(t.TempDir(), "inventory.json")
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

	var fingerprints []string
	for _, r := range readSARIFRun(t, params).Results {
		fingerprints = append(fingerprints, r.PartialFingerprints.DatadogFingerprint)
	}
	return &inv, fingerprints
}

func readSARIFRun(t *testing.T, params *Parameters) reportmodel.SarifRun {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(params.OutputPath, "result.sarif"))
	require.NoError(t, err)
	var sarif struct{ Runs []reportmodel.SarifRun }
	require.NoError(t, json.Unmarshal(data, &sarif))
	require.Len(t, sarif.Runs, 1)
	return sarif.Runs[0]
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
	t.Run("override", func(t *testing.T) {
		root := writeRepo(t, map[string]string{
			"infra/main.tf": `resource "aws_s3_bucket" "example" {
  bucket = "example"
  acl = "private"
}
`,
			"infra/override.tf": `resource "aws_s3_bucket" "example" {
  acl = "public-read"
}
`,
		})
		inv, fingerprints := scanLinks(t, terraformParams(root), terraformPublicACLRule)
		require.Len(t, inv.Resources, 1)
		require.Equal(t, "infra/main.tf", inv.Resources[0].File)
		require.Equal(t, 1, inv.Resources[0].LineStart)
		require.Zero(t, inv.Stats.FindingsUnlinked)
		require.Len(t, fingerprints, 1)
		require.Equal(t, []string{"infra|aws_s3_bucket.example"}, linkedRefs(inv)[fingerprints[0]])
	})
}

var terraformPublicACLRule = syntheticQuery("test-public-acl", "terraform", "Terraform", `	input.document[i].resource.aws_s3_bucket[name].acl == "public-read"
	typ := "aws_s3_bucket"
	key := sprintf("aws_s3_bucket.%s.acl", [name])`)

func TestTerraformOverrideFindings(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"main.tf": `resource "aws_s3_bucket" "example" {
  bucket = "example"
  acl = "private"
}
resource "aws_s3_bucket" "sibling" {
  bucket = "sibling"
}
resource "aws_s3_bucket" "absent" {
  count = 2
  bucket = "absent"
}
resource "aws_s3_bucket" "disabled_each" {
  for_each = { example = "example" }
  bucket = each.value
}
`,
		"override.tf": `resource "aws_s3_bucket" "example" {
  acl = "public-read"
}
resource "aws_s3_bucket" "absent" {
  count = 0
}
resource "aws_s3_bucket" "disabled_each" {
  for_each = {}
}
`,
	})
	privateOrMissing := syntheticQuery("test-partial", "terraform", "Terraform", `	bucket := input.document[i].resource.aws_s3_bucket[name]
	name == "example"
	bucket.acl != "public-read"
	typ := "aws_s3_bucket"
	key := sprintf("aws_s3_bucket[%s].acl", [name])`)
	missing := syntheticQuery("test-missing-bucket", "terraform", "Terraform", `	bucket := input.document[i].resource.aws_s3_bucket[name]
	not bucket.bucket
	typ := "aws_s3_bucket"
	key := sprintf("aws_s3_bucket[%s].bucket", [name])`)
	siblings := syntheticQuery("test-same-file", "terraform", "Terraform", `	doc := input.document[i]
	name := "example"
	doc.resource.aws_s3_bucket[name].bucket == "example"
	doc.resource.aws_s3_bucket[name].acl == "public-read"
	doc.resource.aws_s3_bucket.sibling.bucket == "sibling"
	typ := "aws_s3_bucket"
	key := sprintf("aws_s3_bucket[%s].bucket", [name])`)
	absent := syntheticQuery("test-absent", "terraform", "Terraform", `	name := {"absent", "disabled_each"}[_]
	input.document[i].resource.aws_s3_bucket[name]
	typ := "aws_s3_bucket"
	key := sprintf("aws_s3_bucket[%s]", [name])`)
	params := terraformParams(root)
	inv, _ := scanLinks(t, params, terraformPublicACLRule, privateOrMissing, missing, siblings, absent)
	require.Len(t, inv.Resources, 2)
	require.Contains(t, rowsByPath(inv), "aws_s3_bucket.example")
	require.Contains(t, rowsByPath(inv), "aws_s3_bucket.sibling")
	results := readSARIFRun(t, params).Results
	require.Len(t, results, 2)
	for _, result := range results {
		require.NotEmpty(t, result.ResultLocations)
		loc := result.ResultLocations[0].PhysicalLocation
		switch result.ResultRuleID {
		case "test-public-acl":
			require.Equal(t, "override.tf", loc.ArtifactLocation.ArtifactURI)
			require.Equal(t, 2, loc.Region.StartLine)
			require.Equal(t, model.GetDatadogFingerprintHash(model.SCIInfo{}, "override.tf", "Terraform",
				"aws_s3_bucket", "example", "test-public-acl", "", ""), result.PartialFingerprints.DatadogFingerprint)
		case "test-same-file":
			require.Equal(t, "main.tf", loc.ArtifactLocation.ArtifactURI)
			require.Equal(t, 2, loc.Region.StartLine)
		default:
			t.Fatalf("unexpected finding %s", result.ResultRuleID)
		}
	}
}

func TestTerraformOverrideUsesSelectedRootVariables(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"main.tf": `variable "acl" { default = "private" }
variable "replicas" { default = 1 }
resource "aws_s3_bucket" "example" {
  count  = var.replicas
  bucket = "example"
  acl    = var.acl
}
`,
		"override.tf": `resource "aws_s3_bucket" "example" { force_destroy = true }`,
		"terraform.tfvars": `acl = "private"
replicas = 1
`,
		"selected.tfvars": `acl = "public-read"
replicas = 2
`,
	})
	rule := syntheticQuery("test-public-acl-with-override", "terraform", "Terraform", `	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.acl == "public-read"
	bucket.force_destroy == true
	typ := "aws_s3_bucket"
	key := sprintf("aws_s3_bucket.%s.acl", [name])`)
	params := terraformParams(root)
	params.TerraformVarsPath = filepath.Join(root, "selected.tfvars")
	inv, fingerprints := scanLinks(t, params, rule)
	require.Len(t, fingerprints, 1)
	require.ElementsMatch(t, []string{
		".|aws_s3_bucket.example[0]", ".|aws_s3_bucket.example[1]",
	}, linkedRefs(inv)[fingerprints[0]])
	loc := readSARIFRun(t, params).Results[0].ResultLocations[0].PhysicalLocation
	require.Equal(t, "main.tf", loc.ArtifactLocation.ArtifactURI)
	require.Equal(t, 6, loc.Region.StartLine)
}

func TestTerraformStandaloneOverrideUsesModuleScope(t *testing.T) {
	rule := syntheticQuery("test-standalone-override", "terraform", "Terraform", `	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.acl == "public-read"
	bucket.tags.fixture == "test"
	typ := "aws_s3_bucket"
	key := sprintf("aws_s3_bucket.%s.acl", [name])`)
	for _, tc := range []struct {
		name, declaration, acl string
	}{
		{"variable default", `variable "acl" { default = "public-read" }`, "var.acl"},
		{"local and function", `locals { acl = "PUBLIC-READ" }`, "lower(local.acl)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeRepo(t, map[string]string{
				"main.tf": `module "child" {
  source = "./child"
  count  = 0
}
`,
				"child/main.tf": tc.declaration + "\n" + `resource "aws_s3_bucket" "example" {
  bucket = "example"
  acl = ` + tc.acl + "\n}\n",
				"child/override.tf": `resource "aws_s3_bucket" "example" { tags = { fixture = "test" } }`,
			})
			params := terraformParams(root)
			inv, fingerprints := scanLinks(t, params, rule)
			require.Empty(t, inv.Resources)
			require.Empty(t, inv.FindingLinks)
			const file = "child/main.tf"
			fingerprint := model.GetDatadogFingerprintHash(model.SCIInfo{}, filepath.FromSlash(file), "Terraform",
				"aws_s3_bucket", "example", rule.Query, "", "")
			require.Equal(t, []string{fingerprint}, fingerprints)
			loc := readSARIFRun(t, params).Results[0].ResultLocations[0].PhysicalLocation
			require.Equal(t, file, loc.ArtifactLocation.ArtifactURI)
			require.Equal(t, 4, loc.Region.StartLine)
		})
	}
}

func TestTerraformOverridePreservesCertificateMetadata(t *testing.T) {
	pem, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "test_certificate", "certificate.pem"))
	require.NoError(t, err)
	rule := syntheticQuery("test-certificate-metadata", "terraform", "Terraform", `	cert := input.document[i].resource.aws_acm_certificate[name]
	cert.tags.fixture == "test"
	is_array(cert.certificate_body.expiration_date)
	cert.certificate_body.rsa_key_bytes == 512
	typ := "aws_acm_certificate"
	key := sprintf("aws_acm_certificate.%s.certificate_body", [name])`)
	for _, tc := range []struct {
		name, prefix, overrideBody, wantFile string
		wantLine, wantRows                   int
	}{
		{"root inherits", "", "", "main.tf", 2, 1},
		{"root replaces", "", "  certificate_body = \"replacement.pem\"\n", "override.tf", 3, 1},
		{"standalone inherits", "child/", "", "child/main.tf", 2, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				tc.prefix + "main.tf": `resource "aws_acm_certificate" "example" {
  certificate_body = "certificate.pem"
}
`,
				tc.prefix + "override.tf":     "resource \"aws_acm_certificate\" \"example\" {\n  tags = { fixture = \"test\" }\n" + tc.overrideBody + "}\n",
				tc.prefix + "certificate.pem": string(pem),
				tc.prefix + "replacement.pem": string(pem),
			}
			if tc.prefix != "" {
				files["main.tf"] = `module "child" {
  source = "./child"
  count  = 0
}
`
			}
			params := terraformParams(writeRepo(t, files))
			inv, fingerprints := scanLinks(t, params, rule)
			require.Len(t, inv.Resources, tc.wantRows)
			require.Len(t, fingerprints, 1)
			loc := readSARIFRun(t, params).Results[0].ResultLocations[0].PhysicalLocation
			require.Equal(t, tc.wantFile, loc.ArtifactLocation.ArtifactURI)
			require.Equal(t, tc.wantLine, loc.Region.StartLine)
		})
	}
}

func TestTerraformJSONOverrideFinding(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"main.tf": `resource "aws_s3_bucket" "example" {
  bucket = "example"
  acl = "private"
}
`,
		"override.tf.json": `{
  "resource": {
    "aws_s3_bucket": {
      "example": {
        "acl": "public-read"
      }
    }
  }
}
`,
	})
	rule := terraformPublicACLRule
	rule.Content = `package datadog

DatadogPolicy contains {
	"_dd_id": doc.id,
	"path": ["resource", "aws_s3_bucket", name, "acl"],
	"resourceType": "aws_s3_bucket",
	"resourceName": name,
} if {
	doc := input.document[_]
	doc.resource.aws_s3_bucket[name].acl == "public-read"
}
`
	inv, fingerprints := scanLinks(t, terraformParams(root), rule)
	require.Len(t, fingerprints, 1)
	require.Equal(t, model.GetDatadogFingerprintHash(model.SCIInfo{}, "override.tf.json", "Terraform",
		"aws_s3_bucket", "example", "test-public-acl", "", ""), fingerprints[0])
	require.Equal(t, []string{".|aws_s3_bucket.example"}, linkedRefs(inv)[fingerprints[0]])
	require.Zero(t, inv.Stats.FindingsUnlinked)
	sarif := sarifResults(t, terraformParams(root), rule)
	var report struct{ Runs []reportmodel.SarifRun }
	require.NoError(t, json.Unmarshal([]byte(sarif), &report))
	require.Len(t, report.Runs, 1)
	require.Len(t, report.Runs[0].Results, 1)
	loc := report.Runs[0].Results[0].ResultLocations[0].PhysicalLocation
	require.Equal(t, "override.tf.json", loc.ArtifactLocation.ArtifactURI)
	require.Equal(t, 5, loc.Region.StartLine)
}

func TestTerraformOrphanOverrideFindings(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"main.tf":     `resource "aws_s3_bucket" "base" { bucket = "base" }`,
		"sub/main.tf": `resource "aws_s3_bucket" "other" { bucket = "other" }`,
		"sub/override.tf": `resource "aws_s3_bucket" "base" {
  acl = "public-read"
}
resource "aws_s3_bucket" "other" {
  acl = "public-read"
}
`,
		"sub/z_override.tf": `resource "aws_s3_bucket" "orphan" {
  bucket = "orphan"
  acl    = "public-read"
}
`,
	})
	logging := syntheticQuery("test-bucket-logging", "terraform", "Terraform", `	bucket := input.document[i].resource.aws_s3_bucket[name]
	not bucket.logging
	typ := "aws_s3_bucket"
	key := sprintf("aws_s3_bucket[%s].logging", [name])`)
	versioning := syntheticQuery("test-bucket-versioning", "terraform", "Terraform", `	bucket := input.document[i].resource.aws_s3_bucket[name]
	not bucket.versioning
	typ := "aws_s3_bucket"
	key := sprintf("aws_s3_bucket[%s].versioning", [name])`)
	params := terraformParams(root)
	var logs bytes.Buffer
	log := zerolog.New(zerolog.SyncWriter(&logs)).Level(zerolog.WarnLevel)
	inv, _ := scanLinksWithContext(t, log.WithContext(context.Background()), params, terraformPublicACLRule, logging, versioning)
	warnings := standaloneOverrideWarnings(t, &logs, root)
	require.Contains(t, warnings, "sub/override.tf")
	require.Contains(t, warnings, "sub/z_override.tf")
	rows := make(map[string]string)
	for _, row := range inv.Resources {
		rows[row.ResourceRef] = row.File
	}
	require.Equal(t, map[string]string{
		".|aws_s3_bucket.base":     "main.tf",
		"sub|aws_s3_bucket.base":   "sub/override.tf",
		"sub|aws_s3_bucket.other":  "sub/main.tf",
		"sub|aws_s3_bucket.orphan": "sub/z_override.tf",
	}, rows)

	const file = "sub/z_override.tf"
	const ref = "sub|aws_s3_bucket.orphan"
	require.Equal(t, inventory.Resource{
		ResourceRef: ref, ResourcePath: "aws_s3_bucket.orphan", Platform: "terraform",
		ResourceType: "aws_s3_bucket", ResourceName: "orphan", Provider: "aws",
		File: file, LineStart: 1, LineEnd: 4, ColumnStart: 1, ColumnEnd: 2,
		Completeness: inventory.CompletenessComplete,
	}, rowsByPath(inv)["aws_s3_bucket.orphan"])
	links := linkedRefs(inv)
	var rules []string
	for _, result := range readSARIFRun(t, params).Results {
		if result.ResultLocations[0].PhysicalLocation.ArtifactLocation.ArtifactURI == file {
			rules = append(rules, result.ResultRuleID)
			fingerprint := model.GetDatadogFingerprintHash(model.SCIInfo{}, filepath.FromSlash(file), "Terraform",
				"aws_s3_bucket", "orphan", result.ResultRuleID, "", "")
			require.Equal(t, fingerprint, result.PartialFingerprints.DatadogFingerprint)
			require.Equal(t, []string{ref}, links[fingerprint])
		}
	}
	require.ElementsMatch(t, []string{"test-public-acl", "test-bucket-logging", "test-bucket-versioning"}, rules)
}

func standaloneOverrideWarnings(t *testing.T, logs *bytes.Buffer, root string) []string {
	t.Helper()
	var files []string
	for _, entry := range logLines(t, logs) {
		if entry["message"] == "tfeval: keeping override as a standalone block because it has no unique base declaration" {
			require.Equal(t, "warn", entry["level"])
			file, ok := entry["file"].(string)
			require.True(t, ok)
			rel, err := filepath.Rel(root, file)
			require.NoError(t, err)
			files = append(files, filepath.ToSlash(rel))
		}
	}
	return files
}

func TestTerraformOverrideWithAmbiguousBase(t *testing.T) {
	const bucket = `resource "aws_s3_bucket" "example" {
  acl = "public-read"
}
`
	root := writeRepo(t, map[string]string{"a.tf": bucket, "b.tf": bucket, "override.tf": bucket})
	params := terraformParams(root)
	var logs bytes.Buffer
	log := zerolog.New(zerolog.SyncWriter(&logs)).Level(zerolog.WarnLevel)
	inv, _ := scanLinksWithContext(t, log.WithContext(context.Background()), params, terraformPublicACLRule)
	require.Contains(t, standaloneOverrideWarnings(t, &logs, root), "override.tf")

	var files []string
	for _, result := range readSARIFRun(t, params).Results {
		files = append(files, result.ResultLocations[0].PhysicalLocation.ArtifactLocation.ArtifactURI)
	}
	require.ElementsMatch(t, []string{"a.tf", "b.tf", "override.tf"}, files)
	require.Len(t, inv.Resources, 1)
	require.Equal(t, "a.tf", inv.Resources[0].File)
	fingerprint := model.GetDatadogFingerprintHash(model.SCIInfo{}, "a.tf", "Terraform",
		"aws_s3_bucket", "example", "test-public-acl", "", "")
	require.Equal(t, []inventory.FindingLink{{FindingFingerprint: fingerprint, ResourceRef: ".|aws_s3_bucket.example"}}, inv.FindingLinks)
}

func TestTerraformHCLOverridesOfJSONBase(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"main.tf.json": `{
  "resource": {
    "aws_s3_bucket": {
      "example": {
        "bucket": "example",
        "acl": "private"
      }
    }
  }
}
`,
		"a_override.tf": `resource "aws_s3_bucket" "example" {
  acl = "private"
  force_destroy = true
}
`,
		"override.tf": `resource "aws_s3_bucket" "example" {
  acl = "public-read"
}
`,
	})
	rule := syntheticQuery("test-effective-bucket", "terraform", "Terraform", `	bucket := input.document[i].resource.aws_s3_bucket[name]
	bucket.bucket == "example"
	bucket.force_destroy == true
	bucket.acl == "public-read"
	typ := "aws_s3_bucket"
	key := sprintf("aws_s3_bucket.%s.acl", [name])`)

	params := terraformParams(root)
	inv, fingerprints := scanLinks(t, params, rule)
	require.Len(t, inv.Resources, 1)
	require.Equal(t, "main.tf.json", inv.Resources[0].File)
	require.Equal(t, 4, inv.Resources[0].LineStart)
	require.Len(t, fingerprints, 1)
	require.Equal(t, []string{".|aws_s3_bucket.example"}, linkedRefs(inv)[fingerprints[0]])
	results := readSARIFRun(t, params).Results
	require.Len(t, results, 1)
	loc := results[0].ResultLocations[0].PhysicalLocation
	require.Equal(t, "override.tf", loc.ArtifactLocation.ArtifactURI)
	require.Equal(t, 2, loc.Region.StartLine)
}

func TestTerraformDataOverrideFinding(t *testing.T) {
	const declaration = `data "aws_iam_policy_document" "example" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
`
	rule := syntheticQuery("test-iam-statement", "terraform", "Terraform", `	policy := input.document[i].data.aws_iam_policy_document[name]
	walk(policy.statement, [path, actions])
	path[count(path)-1] == "actions"
	actions[_] == "*"
	typ := "aws_iam_policy_document"
	key := sprintf("aws_iam_policy_document[%s].statement[0]", [name])`)

	for _, tc := range []struct {
		file, content string
		line          int
	}{
		{"override.tf", `data "aws_iam_policy_document" "example" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}
`, 3},
		{"override.tf.json", `{
  "data": {
    "aws_iam_policy_document": {
      "example": {
        "statement": [{
          "actions": ["*"], "resources": ["*"]
        }]
      }
    }
  }
}
`, 5},
	} {
		t.Run(tc.file, func(t *testing.T) {
			root := writeRepo(t, map[string]string{"main.tf": declaration, tc.file: tc.content})
			params := terraformParams(root)
			inv, fingerprints := scanLinks(t, params, rule)
			require.Len(t, inv.Resources, 1)
			require.Equal(t, "main.tf", inv.Resources[0].File)
			require.Len(t, fingerprints, 1)
			require.Equal(t, model.GetDatadogFingerprintHash(model.SCIInfo{}, tc.file, "Terraform",
				"aws_iam_policy_document", "example", "test-iam-statement", "", ""), fingerprints[0])
			require.Equal(t, []string{".|data.aws_iam_policy_document.example"}, linkedRefs(inv)[fingerprints[0]])

			loc := readSARIFRun(t, params).Results[0].ResultLocations[0].PhysicalLocation
			require.Equal(t, tc.file, loc.ArtifactLocation.ArtifactURI)
			require.Equal(t, tc.line, loc.Region.StartLine)
		})
	}
}

func TestTerraformOverrideFindingInCalledModule(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"main.tf": `module "child" {
  source        = "./child"
  base_name     = "example"
  effective_acl = "public-read"
}
`,
		"child/main.tf": `resource "aws_s3_bucket" "example" {
  bucket = var.base_name
  acl    = "private"
}
variable "base_name" {}
variable "effective_acl" {}
`,
		"child/override.tf": `resource "aws_s3_bucket" "example" {
  acl = var.effective_acl
}
`,
	})
	inv, fingerprints := scanLinks(t, terraformParams(root), terraformPublicACLRule)
	require.Len(t, inv.Resources, 1)
	require.Len(t, fingerprints, 1)
	require.Equal(t, "child/main.tf", inv.Resources[0].File)
	require.Equal(t, []string{".|module.child.aws_s3_bucket.example"}, linkedRefs(inv)[fingerprints[0]])

	sarif := sarifResults(t, terraformParams(root), terraformPublicACLRule)
	var report struct{ Runs []reportmodel.SarifRun }
	require.NoError(t, json.Unmarshal([]byte(sarif), &report))
	require.Len(t, report.Runs, 1)
	require.Len(t, report.Runs[0].Results, 1)
	result := report.Runs[0].Results[0]
	primary := result.ResultLocations[0].PhysicalLocation
	require.Equal(t, "main.tf", primary.ArtifactLocation.ArtifactURI)
	require.Equal(t, 4, primary.Region.StartLine, "the caller argument controls the override")
	module, err := json.Marshal(result.ResultProperties["module"])
	require.NoError(t, err)
	var attribution model.ModuleAttributionSARIF
	require.NoError(t, json.Unmarshal(module, &attribution))
	require.Equal(t, "child/override.tf", attribution.ModuleCodeLocation.Filename)
	require.Equal(t, 2, attribution.ModuleCodeLocation.LineStart)
}

func TestTerraformCountedOverrideFindingInCalledModule(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"main.tf": `module "child" {
  source    = "./child"
  base_name = "example"
}
`,
		"child/main.tf": `resource "aws_s3_bucket" "example" {
  count  = 1
  bucket = "${var.base_name}-${count.index}"
}
variable "base_name" {}
`,
		"child/override.tf": `resource "aws_s3_bucket" "example" {
  count = 2
  acl   = "public-read"
}
`,
	})
	rule := syntheticQuery("test-counted-override", "terraform", "Terraform", `	bucket := input.document[i].resource.aws_s3_bucket[name]
	startswith(bucket.bucket, "example-")
	bucket.acl == "public-read"
	typ := "aws_s3_bucket"
	key := sprintf("aws_s3_bucket.%s.acl", [name])`)

	params := terraformParams(root)
	inv, fingerprints := scanLinks(t, params, rule)
	const overrideFile = "child/override.tf"
	fingerprint := model.GetDatadogFingerprintHash(model.SCIInfo{}, filepath.FromSlash(overrideFile), "Terraform",
		"aws_s3_bucket", "example", rule.Query, "", "main.tf|module.child")
	require.Equal(t, []string{fingerprint}, fingerprints)
	require.ElementsMatch(t, []string{
		".|module.child.aws_s3_bucket.example[0]",
		".|module.child.aws_s3_bucket.example[1]",
	}, linkedRefs(inv)[fingerprint])
	require.Len(t, inv.Resources, 2)
	for _, row := range inv.Resources {
		require.Equal(t, "child/main.tf", row.File)
	}

	result := readSARIFRun(t, params).Results[0]
	primary := result.ResultLocations[0].PhysicalLocation
	require.Equal(t, "main.tf", primary.ArtifactLocation.ArtifactURI)
	require.Equal(t, 2, primary.Region.StartLine, "the literal ACL is controlled by the module")
	module, err := json.Marshal(result.ResultProperties["module"])
	require.NoError(t, err)
	var attribution model.ModuleAttributionSARIF
	require.NoError(t, json.Unmarshal(module, &attribution))
	require.Equal(t, overrideFile, attribution.ModuleCodeLocation.Filename)
	require.Equal(t, 3, attribution.ModuleCodeLocation.LineStart)
	require.Len(t, attribution.ModulePath, 1)
	require.Equal(t, "child", attribution.ModulePath[0].Name)
	require.Equal(t, "local", attribution.ModulePath[0].SourceType)
}

func TestTerraformZeroInstancesWithoutOverrides(t *testing.T) {
	for _, tc := range []struct {
		name, expansion string
		wantFindings    int
	}{
		{"literal count", "count = 0", 0},
		{"empty for_each", "for_each = {}", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeRepo(t, map[string]string{
				"main.tf": "resource \"aws_s3_bucket\" \"example\" {\n  " + tc.expansion + "\n  bucket = \"example\"\n}\n",
			})
			inv, fingerprints := scanLinks(t, terraformParams(root), inventoryTestQuery)
			require.Empty(t, inv.Resources)
			require.Len(t, fingerprints, tc.wantFindings)
			require.EqualValues(t, tc.wantFindings, inv.Stats.FindingsUnlinked)
		})
	}
}

func TestInventoryLinksDocumentFindings(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"k8s/web.yaml": inventoryK8sYAML,
		"cfn/stack.yaml": "AWSTemplateFormatVersion: \"2010-09-09\"\nResources:\n  LogsBucket:\n    Type: AWS::S3::Bucket\n" +
			"\n  Queue:\n    Type: AWS::SQS::Queue\nParameters:\n  Env:\n    Type: String\n    Default: prod\n",
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
	parameter := syntheticQuery("test-cfn-parameter", "cloudFormation", "CloudFormation", `	input.document[i].Parameters[p]
	typ := "parameter"
	name := p
	key := sprintf("Parameters.%s.Default", [p])`)
	params := documentParams(root)
	params.Platform = []string{"Kubernetes", "CloudFormation"}

	inv, fingerprints := scanLinks(t, params, service, queue, parameter)
	require.Len(t, fingerprints, 3)
	require.Equal(t, 1, inv.Stats.FindingsUnlinked, "the parameter belongs to no resource")
	refs := linkedRefs(inv)
	var linked []string
	for _, fp := range fingerprints {
		linked = append(linked, refs[fp]...)
	}
	require.ElementsMatch(t, []string{"k8s/web.yaml|v1/Service/shop/web", "cfn/stack.yaml|Queue"}, linked,
		"a finding links to its document's row, or to the entry its key names; the parameter after the last entry links to none")
	for _, r := range inv.Resources {
		if r.ResourceRef == "cfn/stack.yaml|Queue" {
			require.Equal(t, 7, r.LineEnd, "the last entry ends with its collection")
		}
	}
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

func TestInventoryDuplicateDocumentsGetTheirOwnRows(t *testing.T) {
	dup := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\ndata:\n  a: \"1\"\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\ndata:\n  b: \"2\"\n"
	root := writeRepo(t, map[string]string{"k8s/dup.yaml": dup})
	configMap := syntheticQuery("test-k8s-configmap", "k8s", "Kubernetes", `	input.document[i].kind == "ConfigMap"
	typ := "ConfigMap"
	some field
	input.document[i].data[field]
	name := sprintf("%s-%s", [input.document[i].metadata.name, field])
	key := sprintf("metadata.name={{%s}}.data.%s", [input.document[i].metadata.name, field])`)
	// Raised on both documents, kept once by the scan.
	both := syntheticQuery("test-k8s-configmap-name", "k8s", "Kubernetes", `	input.document[i].kind == "ConfigMap"
	typ := "ConfigMap"
	name := input.document[i].metadata.name
	key := sprintf("metadata.name={{%s}}", [name])`)
	params := documentParams(root)
	params.Platform = []string{"Kubernetes"}

	inv, fingerprints := scanLinks(t, params, configMap, both)
	require.Len(t, fingerprints, 3)
	require.Len(t, inv.Resources, 2)
	require.Equal(t, "k8s/dup.yaml|v1/ConfigMap//cm", inv.Resources[0].ResourceRef)
	require.Equal(t, 1, inv.Resources[0].LineStart)
	require.Equal(t, "k8s/dup.yaml|v1/ConfigMap//cm#2", inv.Resources[1].ResourceRef)
	require.Equal(t, lineOf(t, dup, "---")+1, inv.Resources[1].LineStart)
	require.Equal(t, "v1/ConfigMap//cm", inv.Resources[1].ResourcePath, "the path stays as the document names it")

	refs := linkedRefs(inv)
	var linked [][]string
	for _, fp := range fingerprints {
		sort.Strings(refs[fp])
		linked = append(linked, refs[fp])
	}
	require.ElementsMatch(t, [][]string{
		{"k8s/dup.yaml|v1/ConfigMap//cm"},
		{"k8s/dup.yaml|v1/ConfigMap//cm#2"},
		{"k8s/dup.yaml|v1/ConfigMap//cm", "k8s/dup.yaml|v1/ConfigMap//cm#2"},
	}, linked, "each document's finding links to its own row, and the finding the scan raised on both and kept once to both")
}

func TestInventoryLinksTerraformJSONFindings(t *testing.T) {
	tfjson := `{
  "resource": {
    "aws_s3_bucket": {
      "logs": {
        "bucket": "logs"
      },
      "pair": {
        "count": 2,
        "bucket": "pair",
        "tags": {
          "team": "data"
        }
      }
    }
  }
}
`
	// Compact JSON puts every block on one line; only the bad bucket is public.
	compact := `{"resource":{"aws_s3_bucket":{"bad":{"bucket":"bad","acl":"public-read"},"good":{"bucket":"good"}}}}` + "\n"
	root := writeRepo(t, map[string]string{"infra/main.tf.json": tfjson, "infra/compact.tf.json": compact})
	bucket := syntheticQuery("test-tf-bucket", "terraform", "Terraform", `	input.document[i].resource.aws_s3_bucket[name].bucket
	typ := "aws_s3_bucket"
	key := sprintf("aws_s3_bucket[%s].bucket", [name])`)
	public := syntheticQuery("test-tf-public", "terraform", "Terraform", `	input.document[i].resource.aws_s3_bucket[name].acl == "public-read"
	typ := "aws_s3_bucket"
	key := sprintf("aws_s3_bucket[%s].acl", [name])`)
	inv, fingerprints := scanLinks(t, terraformParams(root), inventoryTestQuery, bucket, public)
	require.NotEmpty(t, fingerprints)
	require.Zero(t, inv.Stats.FindingsUnlinked, "every bucket finding belongs to a row")

	// Every block of a type shares the type's key in JSON: each row spans its
	// own object instead.
	lines := make(map[string][2]int)
	for _, r := range inv.Resources {
		lines[r.ResourceRef] = [2]int{r.LineStart, r.LineEnd}
	}
	require.Equal(t, map[string][2]int{
		"infra|aws_s3_bucket.logs":    {lineOf(t, tfjson, `"logs"`), lineOf(t, tfjson, `"bucket": "logs"`)},
		"infra|aws_s3_bucket.pair[0]": {lineOf(t, tfjson, `"pair"`), lineOf(t, tfjson, `"team"`) + 1},
		"infra|aws_s3_bucket.pair[1]": {lineOf(t, tfjson, `"pair"`), lineOf(t, tfjson, `"team"`) + 1},
		"infra|aws_s3_bucket.bad":     {1, 1},
		"infra|aws_s3_bucket.good":    {1, 1},
	}, lines)

	refs := linkedRefs(inv)
	perRow := make(map[string]int)
	for _, fp := range fingerprints {
		require.Contains(t, [][]string{
			{"infra|aws_s3_bucket.logs"},
			{"infra|aws_s3_bucket.pair[0]", "infra|aws_s3_bucket.pair[1]"},
			{"infra|aws_s3_bucket.bad"},
			{"infra|aws_s3_bucket.good"},
		}, refs[fp], "fingerprint %s links to its block only", fp)
		for _, ref := range refs[fp] {
			perRow[ref]++
		}
	}
	require.Equal(t, 3, perRow["infra|aws_s3_bucket.bad"], "the bad bucket has its three findings")
	require.Equal(t, 2, perRow["infra|aws_s3_bucket.good"], "the clean sibling on the same line gets no public-bucket finding")

	// A finding on a variable belongs to no resource, even one on its line.
	shared := `{"variable":{"env":{"default":"prod"}},"resource":{"aws_s3_bucket":{"one":{"bucket":"one"}}}}` + "\n"
	root = writeRepo(t, map[string]string{"infra/main.tf.json": shared})
	variable := syntheticQuery("test-tf-variable", "terraform", "Terraform", `	input.document[i].variable[name]
	typ := "variable"
	key := sprintf("variable[%s]", [name])`)
	inv, fingerprints = scanLinks(t, terraformParams(root), variable)
	require.Len(t, fingerprints, 1)
	require.Empty(t, inv.FindingLinks, "the bucket on the variable's line is not its resource")
	require.Equal(t, 1, inv.Stats.FindingsUnlinked)
}

func TestInventoryLinksAnsibleFindings(t *testing.T) {
	play := syntheticQuery("test-ansible-become", "ansible", "Ansible", `	play := input.document[i].playbooks[_]
	play.become == true
	typ := "play"
	name := play.name
	key := sprintf("name={{%s}}.become", [play.name])`)
	task := "    - name: Install nginx\n      ansible.builtin.apt:\n        name: nginx\n"
	for _, tasks := range []string{task, task + "    - name: Start nginx\n      ansible.builtin.service:\n        name: nginx\n"} {
		root := writeRepo(t, map[string]string{
			"site.yml": "- name: Web\n  hosts: all\n  become: true\n  tasks:\n" + tasks,
		})
		params := documentParams(root)
		params.Platform = []string{"Ansible"}

		inv, fingerprints := scanLinks(t, params, play)
		require.Len(t, fingerprints, 1)
		require.NotEmpty(t, inv.Resources)
		require.Empty(t, inv.FindingLinks, "a play-level finding belongs to no task, however many the play has")
		require.Equal(t, 1, inv.Stats.FindingsUnlinked)
	}

	// Two tasks the scan reports as one finding, each named by its place in
	// the document: the finding belongs to both.
	shell := syntheticQuery("test-ansible-shell", "ansible", "Ansible", `	some j
	task := input.document[i].playbooks[j]
	task.shell
	typ := "shell"
	name := task.name
	key := sprintf("playbooks.%d.shell", [j])`)
	root := writeRepo(t, map[string]string{
		"roles/web/tasks/main.yml": "- name: Run\n  shell: echo one\n- name: Run\n  shell: echo two\n",
	})
	params := documentParams(root)
	params.Platform = []string{"Ansible"}
	inv, fingerprints := scanLinks(t, params, shell)
	require.Len(t, fingerprints, 1, "the scan keeps one finding for the two tasks")
	require.ElementsMatch(t, []string{"roles/web/tasks/main.yml|tasks[0]", "roles/web/tasks/main.yml|tasks[1]"},
		linkedRefs(inv)[fingerprints[0]], "each task its search key names")
	require.Zero(t, inv.Stats.FindingsUnlinked)
}

func TestInventoryDeduplicatedFindingsKeepEveryResource(t *testing.T) {
	// The rule names a bucket by its BucketName, which both share: the scan
	// reports one finding for the two.
	versioning := syntheticQuery("test-cfn-versioning", "cloudFormation", "CloudFormation", `	resource := input.document[i].Resources[logical]
	resource.Type == "AWS::S3::Bucket"
	typ := resource.Type
	name := resource.Properties.BucketName
	key := sprintf("Resources.%s.Properties", [logical])`)
	stack := "Resources:\n  Logs:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: shared\n" +
		"  Backup:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: shared\n" +
		"  Queue:\n    Type: AWS::SQS::Queue\n"
	root := writeRepo(t, map[string]string{"cfn/stack.yaml": stack})
	params := documentParams(root)
	params.Platform = []string{"CloudFormation"}

	inv, fingerprints := scanLinks(t, params, versioning)
	require.Len(t, fingerprints, 1, "the scan reports one finding for both buckets")
	require.ElementsMatch(t, []string{"cfn/stack.yaml|Logs", "cfn/stack.yaml|Backup"}, linkedRefs(inv)[fingerprints[0]],
		"the finding links to every bucket it stands for, and not to the queue")
	require.Zero(t, inv.Stats.FindingsUnlinked)

	// Without an inventory the scan is the same.
	params.InventoryPath = ""
	withoutInventory, withInventory := sarifResults(t, params, versioning), sarifResults(t, documentParamsWithInventory(t, root), versioning)
	require.Equal(t, withoutInventory, withInventory)
}

// sarifResults scans and returns the SARIF results, less the execution time.
func sarifResults(t *testing.T, params *Parameters, queries ...model.QueryMetadata) string {
	t.Helper()
	params.OutputPath = t.TempDir()
	params.OutputName = "result"
	params.ReportFormats = []string{"sarif"}
	ctx := context.Background()
	c, err := NewClient(ctx, params, &consolePrinter.Printer{})
	require.NoError(t, err)
	c.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
		return &stubQuerySource{queries: queries}, nil
	}
	_, err = c.PerformScan(ctx)
	require.NoError(t, err)
	data, err := os.ReadFile(filepath.Join(params.OutputPath, "result.sarif"))
	require.NoError(t, err)
	return string(executionTime.ReplaceAll(data, []byte("DATADOG_EXECUTION_TIME_SECS:")))
}

func documentParamsWithInventory(t *testing.T, root string) *Parameters {
	params := documentParams(root)
	params.Platform = []string{"CloudFormation"}
	params.InventoryPath = filepath.Join(t.TempDir(), "inventory.json")
	return params
}
