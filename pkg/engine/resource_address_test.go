/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

const addressRule = `package datadog
DatadogPolicy contains result if {
 some i, typ, name
 _ := input.document[i].resource[typ][name].input
 result := {"documentId": input.document[i].id, "resourceType": typ, "resourceName": "provider-name",
 "searchKey": sprintf("resource.%s.%s.input", [typ, name])}
}
DatadogPolicy contains result if {
 some i, typ, name
 _ := input.document[i].data[typ][name].inputs
 result := {"documentId": input.document[i].id, "resourceType": sprintf("data.%s", [typ]), "resourceName": "provider-name",
 "searchKey": sprintf("data.%s.%s.inputs", [typ, name])}
}`

func addressFindings(t *testing.T, root string, files model.FileMetadatas) []model.Vulnerability {
	t.Helper()
	ins := newTestInspector(t, inspectorOpts{
		queries: []model.QueryMetadata{{
			Query: "addresses", Content: addressRule, InputData: "{}", Platform: "terraform",
			Metadata: map[string]interface{}{"id": "address-rule"}, Aggregation: 1,
		}}, repoPath: root, vb: DefaultVulnerabilityBuilder, flagEvaluator: featureflags.NewLocalEvaluator(),
	})
	// Runner preparation canonicalizes document maps and slices before Inspect.
	// Keep original line trees, as the real lazy line-info loader does.
	for _, file := range files {
		raw, err := json.Marshal(file.Document)
		require.NoError(t, err)
		var canonical model.Document
		require.NoError(t, json.Unmarshal(raw, &canonical))
		file.Document = canonical
	}
	ins.SetReleaseDocumentsAfterPayload(true)
	findings, err := ins.Inspect(context.Background(), "test", files, []string{"terraform"})
	require.NoError(t, err)
	require.Empty(t, ins.GetFailedQueries())
	return findings
}

func writeAddressConfig(t *testing.T, root, name, source string) model.FileMetadatas {
	t.Helper()
	path := filepath.Join(root, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(source), 0o644))
	return parseTerraform(t, path)
}

func TestAddressedInstancesSurviveStorageAndContextCopies(t *testing.T) {
	for _, name := range []string{"main.tf", "main.tf.json"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			source := `resource "terraform_data" "same" {
 count = 3
 input = "same"
}
resource "terraform_data" "different" {
 count = 2
 input = count.index
}
data "null_data_source" "keyed" {
 for_each = { "" = 1, "a.b" = 1, "a\"b" = 1, "a\\b" = 1 }
 inputs = { value = "same" }
}`
			if strings.HasSuffix(name, ".json") {
				source = `{"resource":{"terraform_data":{"same":{"count":3,"input":"same"},"different":{"count":2,"input":"${count.index}"}}},
 "data":{"null_data_source":{"keyed":{"for_each":{"":1,"a.b":1,"a\"b":1,"a\\b":1},"inputs":{"value":"same"}}}}}`
			}
			findings := addressFindings(t, root, writeAddressConfig(t, root, name, source))
			want := []string{"terraform_data.same[0]", "terraform_data.same[1]", "terraform_data.same[2]",
				"terraform_data.different[0]", "terraform_data.different[1]", `data.null_data_source.keyed[""]`,
				`data.null_data_source.keyed["a.b"]`, `data.null_data_source.keyed["a\"b"]`, `data.null_data_source.keyed["a\\b"]`}
			var got []string
			for _, v := range findings {
				got = append(got, v.ResourceAddress)
				require.Empty(t, v.ResourceAddressFallback)
				require.Equal(t, ".", v.RootModuleDir)
				require.Positive(t, v.Line)
				if name == "main.tf" && strings.HasPrefix(v.ResourceAddress, "terraform_data.same") {
					require.Equal(t, 3, v.Line)
					require.Equal(t, 1, v.BlockLocation.Start.Line)
				}
			}
			require.ElementsMatch(t, want, got) // Equality, including multiplicity.
			store := storage.NewMemoryStorage()
			require.NoError(t, store.SaveVulnerabilities(context.Background(), findings))
			unique, err := store.GetVulnerabilities(context.Background(), "test")
			require.NoError(t, err)
			require.Len(t, unique, len(want))
		})
	}
}

func TestAddressedNestedModulesAndMultipleRoots(t *testing.T) {
	root := t.TempDir()
	var files model.FileMetadatas
	for _, stack := range []string{"stack-a", "stack-b"} {
		files = append(files, writeAddressConfig(t, root, stack+"/main.tf", `module "a" {
 source = "../modules/a"
 for_each = toset(["x", "q\"\\.z"])
}`)...)
	}
	files = append(files, writeAddressConfig(t, root, "modules/a/main.tf", `module "b" {
 source = "../b"
 count = 2
}`)...)
	files = append(files, writeAddressConfig(t, root, "modules/b/main.tf", `resource "terraform_data" "example" {
 for_each = { key = "same", "" = "same" }
 input = each.value
}
data "null_data_source" "example" {
 count = 2
 inputs = { value = "same" }
}`)...)
	findings := addressFindings(t, root, files)
	var got, want []string
	for _, stack := range []string{"stack-a", "stack-b"} {
		for _, key := range []string{"x", `q"\.z`} {
			for i := 0; i < 2; i++ {
				for _, suffix := range []string{`terraform_data.example[""]`, `terraform_data.example["key"]`, "data.null_data_source.example[0]", "data.null_data_source.example[1]"} {
					want = append(want, fmt.Sprintf("%s|module.a[%q].module.b[%d].%s", stack, key, i, suffix))
				}
			}
		}
	}
	for _, v := range findings {
		require.Empty(t, v.ResourceAddressFallback)
		require.NotNil(t, v.ModuleAttribution)
		got = append(got, v.RootModuleDir+"|"+v.ResourceAddress)
		require.Equal(t, filepath.Join(root, "modules/b/main.tf"), v.FileName)
		if strings.Contains(v.ResourceAddress, "data.null") {
			require.Equal(t, 7, v.Line)
		} else {
			require.Equal(t, 3, v.Line)
		}
	}
	require.ElementsMatch(t, want, got)
}

func TestUnresolvedAddressIsExplicit(t *testing.T) {
	root := t.TempDir()
	findings := addressFindings(t, root, writeAddressConfig(t, root, "main.tf", `variable "unknown" { type = number }
resource "terraform_data" "unknown" {
 count = var.unknown
 input = "same"
}`))
	require.Len(t, findings, 1)
	require.Empty(t, findings[0].ResourceAddress)
	require.Equal(t, "resource_address_unresolved", findings[0].ResourceAddressFallback)
}

// Identical attributes do not imply identical addresses. Across roots the
// same module call can expand a different set of resource keys, while extra
// callers of the same keys can still share OPA documents.
func TestModuleDeduplicationRetainsDifferentResourceKeys(t *testing.T) {
	root := t.TempDir()
	var files model.FileMetadatas
	for _, stack := range []string{"a", "b", "c"} {
		key := stack
		if key == "c" {
			key = "a"
		}
		files = append(files, writeAddressConfig(t, root, stack+"/calls.tf", fmt.Sprintf(`module "shared" {
 source = "../shared"
 keys = toset([%q])
}`, key))...)
	}
	files = append(files, writeAddressConfig(t, root, "shared/resource.tf", `variable "keys" { type = set(string) }
resource "terraform_data" "same" {
 for_each = var.keys
 input = "same"
}`)...)
	var got []string
	for _, finding := range addressFindings(t, root, files) {
		got = append(got, finding.RootModuleDir+"|"+finding.ResourceAddress)
	}
	require.ElementsMatch(t, []string{
		`a|module.shared.terraform_data.same["a"]`,
		`b|module.shared.terraform_data.same["b"]`,
		`c|module.shared.terraform_data.same["a"]`,
	}, got)
}

func TestAddressLookupPreservesLiteralTemplateMarkers(t *testing.T) {
	for _, name := range []string{`module.m["{{literal}}"].r[""]`, `r["a\"\\.b"]`} {
		file := &model.FileMetadata{ResourceAddresses: map[string][]string{
			layerBlockKey("terraform_data", name): {"authoritative"},
		}}
		for _, search := range []string{"resource.terraform_data." + name + ".input", "terraform_data[" + name + "].input"} {
			require.Equal(t, []string{"authoritative"}, findingAddresses(file, &model.Vulnerability{SearchKey: search}))
		}
	}
}

func TestUnknownModuleInstanceDoesNotClaimSingletonAddress(t *testing.T) {
	root := t.TempDir()
	files := writeAddressConfig(t, root, "main.tf", `variable "unknown" { type = number }
module "unknown" {
 source = "./child"
 count = var.unknown
}`)
	files = append(files, writeAddressConfig(t, root, "child/main.tf", `resource "terraform_data" "example" {
 input = "same"
}`)...)
	findings := addressFindings(t, root, files)
	require.Len(t, findings, 1)
	require.Empty(t, findings[0].ResourceAddress)
	require.Equal(t, "resource_address_unresolved", findings[0].ResourceAddressFallback)
	require.Equal(t, ".", findings[0].RootModuleDir)
}

func TestTruncatedAddressExpansionKeepsExplicitFallback(t *testing.T) {
	root := t.TempDir()
	findings := addressFindings(t, root, writeAddressConfig(t, root, "main.tf", `resource "terraform_data" "capped" {
 count = 51
 input = "same"
}`))
	var addressed, unresolved int
	for _, finding := range findings {
		if finding.ResourceAddress == "" {
			unresolved++
			require.Equal(t, "resource_address_unresolved", finding.ResourceAddressFallback)
		} else {
			addressed++
			require.Empty(t, finding.ResourceAddressFallback)
		}
	}
	require.Equal(t, 50, addressed)
	require.Equal(t, 1, unresolved)
}
