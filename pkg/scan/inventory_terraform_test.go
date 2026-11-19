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
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/stretchr/testify/require"
)

const inventoryRootTF = `variable "extra_buckets" {
  type = set(string)
}

resource "aws_instance" "web" {
  count         = 2
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
}

data "aws_ami" "ubuntu" {
  most_recent = true
}

module "logging" {
  source   = "./modules/logging"
  for_each = toset(["prod", "staging"])
  env      = each.key
}

module "dyn" {
  source   = "./modules/logging"
  for_each = var.extra_buckets
  env      = each.key
}

resource "aws_s3_bucket" "extra" {
  for_each = var.extra_buckets
  bucket   = "extra-${each.key}"
}

resource "google_storage_bucket" "beta" {
  provider = google-beta
  name     = "beta"
}
`

const inventoryModuleTF = `variable "env" {
  type = string
}

resource "aws_s3_bucket" "this" {
  bucket = "logs-${var.env}"
}
`

// lineOf returns the 1-based line of the first line of content holding text.
func lineOf(t *testing.T, content, text string) int {
	t.Helper()
	for i, line := range strings.Split(content, "\n") {
		if strings.Contains(line, text) {
			return i + 1
		}
	}
	t.Fatalf("%q not found", text)
	return 0
}

// scanInventory scans root with the synthetic rule and returns its inventory.
func scanInventory(t *testing.T, params *Parameters) *inventory.Inventory {
	t.Helper()
	params.InventoryPath = filepath.Join(t.TempDir(), "inventory.json")
	ctx := context.Background()
	c, err := NewClient(ctx, params, &consolePrinter.Printer{})
	require.NoError(t, err)
	c.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
		return &stubQuerySource{queries: []model.QueryMetadata{inventoryTestQuery}}, nil
	}
	metadata, err := c.PerformScan(ctx)
	require.NoError(t, err)
	require.Equal(t, InventoryWritten, metadata.Inventory.Status, metadata.Inventory.Error)
	data, err := os.ReadFile(params.InventoryPath)
	require.NoError(t, err)
	var inv inventory.Inventory
	require.NoError(t, json.Unmarshal(data, &inv))
	return &inv
}

func terraformParams(root string) *Parameters {
	params := remoteModuleScanParams(root)
	params.QueriesPath = []string{"."}
	params.ChangedDefaultQueryPath = false
	return params
}

func rowsByPath(inv *inventory.Inventory) map[string]inventory.Resource {
	rows := make(map[string]inventory.Resource, len(inv.Resources))
	for _, r := range inv.Resources {
		rows[r.ResourcePath] = r
	}
	return rows
}

func TestInventoryTerraformRows(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"infra/main.tf":                 inventoryRootTF,
		"infra/modules/logging/main.tf": inventoryModuleTF,
		// An override restates a block; it stays one row.
		"infra/override.tf": "resource \"aws_s3_bucket\" \"extra\" {\n  bucket = \"overridden\"\n}\n",
	})
	inv := scanInventory(t, terraformParams(root))
	rows := rowsByPath(inv)

	paths := make([]string, 0, len(rows))
	for p := range rows {
		paths = append(paths, p)
	}
	require.ElementsMatch(t, []string{
		"aws_instance.web[0]",
		"aws_instance.web[1]",
		"data.aws_ami.ubuntu",
		`module.logging["prod"].aws_s3_bucket.this`,
		`module.logging["staging"].aws_s3_bucket.this`,
		"module.dyn.aws_s3_bucket.this",
		"aws_s3_bucket.extra",
		"google_storage_bucket.beta",
	}, paths, "every type is listed, not only the ones a rule targets")
	require.Len(t, inv.Resources, len(rows), "one row per address")

	web := rows["aws_instance.web[0]"]
	require.Equal(t, inventory.Resource{
		ResourceRef:  "infra|aws_instance.web[0]",
		ResourcePath: "aws_instance.web[0]",
		Platform:     "terraform",
		ResourceType: "aws_instance",
		ResourceName: "web",
		Provider:     "aws",
		File:         "infra/main.tf",
		LineStart:    lineOf(t, inventoryRootTF, `resource "aws_instance" "web"`),
		LineEnd:      lineOf(t, inventoryRootTF, `instance_type`) + 1,
		ColumnStart:  1,
		ColumnEnd:    2,
		Completeness: inventory.CompletenessComplete,
	}, web)

	data := rows["data.aws_ami.ubuntu"]
	require.Equal(t, "aws_ami", data.ResourceType)
	require.Equal(t, "ubuntu", data.ResourceName)

	require.Equal(t, "google-beta", rows["google_storage_bucket.beta"].Provider)

	extra := rows["aws_s3_bucket.extra"]
	require.Equal(t, inventory.CompletenessInstanceUnresolved, extra.Completeness)
	require.Equal(t, "infra/main.tf", extra.File, "the block as written, not the override")

	prod := rows[`module.logging["prod"].aws_s3_bucket.this`]
	require.Equal(t, `infra|module.logging["prod"].aws_s3_bucket.this`, prod.ResourceRef)
	require.Equal(t, "infra/modules/logging/main.tf", prod.File)
	require.Equal(t, lineOf(t, inventoryModuleTF, `resource "aws_s3_bucket" "this"`), prod.LineStart)
	require.Equal(t, `module.logging["prod"]`, prod.ModuleCall)
	require.Equal(t, "infra/modules/logging", prod.ModuleSource)
	require.Equal(t, "local", prod.ModuleSourceType)
	require.Equal(t, "direct", prod.ModuleDependencyType)
	require.Empty(t, prod.ModuleVersion)
	require.Equal(t, "infra/main.tf", prod.CallSiteFile)
	require.Equal(t, lineOf(t, inventoryRootTF, `module "logging"`), prod.CallSiteLineStart)
	require.Equal(t, lineOf(t, inventoryRootTF, `module "dyn"`)-2, prod.CallSiteLineEnd)
	require.Equal(t, inventory.CompletenessComplete, prod.Completeness)
	var hops []model.ModulePathHop
	require.NoError(t, json.Unmarshal([]byte(prod.ModulePath), &hops))
	require.Len(t, hops, 1)
	require.Equal(t, "logging", hops[0].Name)

	dyn := rows["module.dyn.aws_s3_bucket.this"]
	require.Equal(t, "module.dyn", dyn.ModuleCall)
	require.Equal(t, inventory.CompletenessInstanceUnresolved, dyn.Completeness,
		"the module's for_each is unknown, so its instance key is left out")
}

func TestInventoryTerraformRemoteModule(t *testing.T) {
	root := t.TempDir()
	_, manifestPath := writeRemoteModuleFixture(t, root)
	params := terraformParams(root)
	params.TerraformModules = TerraformModulesOn
	params.RemoteModulesManifestPath = manifestPath

	inv := scanInventory(t, params)
	rows := rowsByPath(inv)
	vpc, ok := rows["module.vpc.aws_vpc.this"]
	require.True(t, ok, "rows: %v", rows)
	require.Equal(t, ".|module.vpc.aws_vpc.this", vpc.ResourceRef, "the repository root is the root module")
	require.Equal(t, "registry.terraform.io/terraform-aws-modules/vpc/aws@5.0.0/main.tf", vpc.File,
		"a fetched module's file is named after where it came from, as in the reports")
	require.Equal(t, "module.vpc", vpc.ModuleCall)
	require.Equal(t, "registry", vpc.ModuleSourceType)
	require.Equal(t, "5.0.0", vpc.ModuleVersion)
	require.Contains(t, vpc.ModuleSource, "terraform-aws-modules/vpc/aws")
	require.Equal(t, "main.tf", vpc.CallSiteFile)

	for _, f := range inv.Files {
		require.NotContains(t, f.Path, "downloaded-vpc", "a fetched module is not a file of the repository")
	}
}

// scanSARIF scans with params into a new directory and returns the SARIF
// report without its execution time.
func scanSARIF(t *testing.T, params Parameters) string {
	t.Helper()
	params.OutputPath = t.TempDir()
	params.OutputName = "result"
	params.ReportFormats = []string{"sarif"}
	ctx := context.Background()
	c, err := NewClient(ctx, &params, &consolePrinter.Printer{})
	require.NoError(t, err)
	c.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
		return &stubQuerySource{queries: []model.QueryMetadata{inventoryTestQuery}}, nil
	}
	_, err = c.PerformScan(ctx)
	require.NoError(t, err)
	sarif, err := os.ReadFile(filepath.Join(params.OutputPath, "result.sarif"))
	require.NoError(t, err)
	return string(executionTime.ReplaceAll(sarif, []byte("DATADOG_EXECUTION_TIME_SECS:")))
}

func TestInventoryDoesNotChangeTerraformFindings(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"infra/main.tf":                 inventoryRootTF,
		"infra/modules/logging/main.tf": inventoryModuleTF,
	})
	without := scanSARIF(t, *terraformParams(root))
	require.Contains(t, without, `"module_path"`, "the module instances have findings")

	with := *terraformParams(root)
	with.InventoryPath = filepath.Join(t.TempDir(), "inventory.json")
	require.Equal(t, without, scanSARIF(t, with))
}

func TestInventoryTerraformRootsNoRuleTargets(t *testing.T) {
	// No rule can match these types, so the scan does not evaluate the
	// modules; the inventory still lists their resources.
	root := writeRepo(t, map[string]string{
		"main.tf":           "resource \"random_id\" \"suffix\" {\n  byte_length = 4\n}\n\nmodule \"m\" {\n  source = \"./modules/m\"\n}\n",
		"modules/m/main.tf": "resource \"null_resource\" \"n\" {}\n",
	})
	inv := scanInventory(t, terraformParams(root))
	rows := rowsByPath(inv)
	require.Contains(t, rows, "random_id.suffix")
	require.Contains(t, rows, "module.m.null_resource.n")
	require.Equal(t, "modules/m", rows["module.m.null_resource.n"].ModuleSource)

	without := scanSARIF(t, *terraformParams(root))
	with := *terraformParams(root)
	with.InventoryPath = filepath.Join(t.TempDir(), "inventory.json")
	require.Equal(t, without, scanSARIF(t, with))
}

func TestInventoryTerraformRootsSkippedForExternalCalls(t *testing.T) {
	// The scan evaluates only the roots that reach a fetched module, since no
	// rule matches what the repository declares; the inventory evaluates the
	// other root too.
	root := t.TempDir()
	_, manifestPath := writeRemoteModuleFixture(t, root)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "other"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "other", "main.tf"),
		[]byte("resource \"random_id\" \"other\" {\n  byte_length = 4\n}\n"), 0o600))
	params := terraformParams(root)
	params.TerraformModules = TerraformModulesOn
	params.RemoteModulesManifestPath = manifestPath

	rows := rowsByPath(scanInventory(t, params))
	require.Contains(t, rows, "module.vpc.aws_vpc.this")
	require.Equal(t, "other|random_id.other", rows["random_id.other"].ResourceRef)
}

func TestInventoryTerraformUnresolvedModule(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"main.tf": "module \"missing\" {\n  source  = \"terraform-aws-modules/missing/aws\"\n  version = \"1.0.0\"\n}\n\nresource \"aws_s3_bucket\" \"b\" {}\n",
	})
	params := terraformParams(root)
	params.TerraformModules = TerraformModulesOn
	params.NetworkIsolation = true

	inv := scanInventory(t, params)
	require.Equal(t, inventory.StatusPartial, inv.Status)
	require.Len(t, inv.UnresolvedSources, 1)
	got := inv.UnresolvedSources[0]
	require.Equal(t, inventory.PlatformTerraform, got.Platform)
	require.Equal(t, "terraform-aws-modules/missing/aws@1.0.0", got.Source)
	require.NotEmpty(t, got.Reason)
	t.Logf("reason: %s", got.Reason)
}

func TestInventoryFailsWhenResourcesMayBeMissing(t *testing.T) {
	inventoryPath := filepath.Join(t.TempDir(), "inventory.json")
	c := &Client{ScanParams: &Parameters{InventoryPath: inventoryPath}}
	c.startInventory(context.Background())
	c.inventory.collector.Fail(inventory.FailureTerraformPanic)

	status := c.finishInventory(context.Background(), nil)
	require.Equal(t, InventoryFailed, status.Status)
	require.Equal(t, inventory.FailureTerraformPanic, status.Reason)
	_, err := os.Stat(inventoryPath)
	require.True(t, os.IsNotExist(err))
}
