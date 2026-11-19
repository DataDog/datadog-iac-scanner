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
	"regexp"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
)

// inventoryTestQuery is a synthetic rule, so the scan has findings without
// the rule corpus.
var inventoryTestQuery = model.QueryMetadata{
	Query: "test-inventory-rule",
	Content: `package datadog

DatadogPolicy contains result if {
	input.document[i].resource.aws_s3_bucket[name]
	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_s3_bucket",
		"resourceName": name,
		"searchKey": sprintf("aws_s3_bucket[%s]", [name]),
	}
}
`,
	InputData: "{}",
	Platform:  "terraform",
	Metadata: map[string]interface{}{
		"id":        "test-inventory-rule",
		"legacyId":  "test-inventory-rule",
		"queryName": "Synthetic Inventory Rule",
		"severity":  "HIGH",
		"platform":  "Terraform",
		"category":  "Encryption",
	},
}

// executionTime is the one SARIF value that differs between two runs.
var executionTime = regexp.MustCompile(`DATADOG_EXECUTION_TIME_SECS:[^"]*`)

// performInventoryScan scans the sample file into outDir and returns the SARIF
// report and the metadata.
func performInventoryScan(t *testing.T, outDir, inventoryPath string) ([]byte, ScanMetadata) {
	t.Helper()
	params := Parameters{
		Path:             []string{filepath.Join("test", "sample.tf")},
		QueriesPath:      []string{"."},
		LibrariesPath:    "assets/libraries",
		OutputPath:       outDir,
		OutputName:       "result",
		ReportFormats:    []string{"sarif"},
		PreviewLines:     3,
		CloudProvider:    []string{"aws"},
		Platform:         []string{"Terraform"},
		MaxFileSizeFlag:  100,
		ScanID:           "console",
		MaxResolverDepth: 15,
		FlagEvaluator:    featureflags.NewLocalEvaluator(),
		InventoryPath:    inventoryPath,
	}
	ctx := context.Background()
	c, err := NewClient(ctx, &params, &consolePrinter.Printer{})
	require.NoError(t, err)
	c.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
		return &stubQuerySource{queries: []model.QueryMetadata{inventoryTestQuery}}, nil
	}

	metadata, err := c.PerformScan(ctx)
	require.NoError(t, err)
	sarif, err := os.ReadFile(filepath.Join(outDir, "result.sarif"))
	require.NoError(t, err)
	require.Contains(t, string(sarif), "test-inventory-rule", "the scan must have findings")
	return executionTime.ReplaceAll(sarif, []byte("DATADOG_EXECUTION_TIME_SECS:")), metadata
}

func TestInventoryDoesNotChangeTheScan(t *testing.T) {
	withoutSARIF, withoutMetadata := performInventoryScan(t, t.TempDir(), "")
	require.Nil(t, withoutMetadata.Inventory)
	doc, err := json.Marshal(withoutMetadata)
	require.NoError(t, err)
	require.NotContains(t, string(doc), `"Inventory":`, "the metadata is unchanged without the option")

	inventoryPath := filepath.Join(t.TempDir(), "inventory.json")
	withSARIF, withMetadata := performInventoryScan(t, t.TempDir(), inventoryPath)

	require.Equal(t, string(withoutSARIF), string(withSARIF), "the inventory must not change the SARIF")
	withoutMetadata.Stats.Duration, withMetadata.Stats.Duration = 0, 0
	require.Equal(t, withoutMetadata.Stats, withMetadata.Stats)

	require.NotNil(t, withMetadata.Inventory)
	require.Equal(t, InventoryWritten, withMetadata.Inventory.Status)

	data, err := os.ReadFile(inventoryPath)
	require.NoError(t, err)
	result, err := gojsonschema.Validate(gojsonschema.NewBytesLoader(inventory.Schema), gojsonschema.NewBytesLoader(data))
	require.NoError(t, err)
	require.Truef(t, result.Valid(), "schema errors: %v", result.Errors())

	var inv inventory.Inventory
	require.NoError(t, json.Unmarshal(data, &inv))
	require.Equal(t, []string{"terraform"}, inv.PlatformsScanned)
	require.NotEmpty(t, inv.ScanID)
}

func TestInventoryRedactsRepositoryCredentials(t *testing.T) {
	inventoryPath := filepath.Join(t.TempDir(), "inventory.json")
	c := &Client{ScanParams: &Parameters{
		InventoryPath: inventoryPath,
		SCIInfo: model.SCIInfo{RepositoryCommitInfo: model.RepositoryCommitInfo{
			RepositoryUrl: "https://x-access-token:secret@example.invalid/acme/infra.git",
			CommitSHA:     "abc",
			Branch:        "main",
		}},
	}}
	c.startInventory(context.Background())
	require.Equal(t, InventoryWritten, c.finishInventory(context.Background()).Status)

	data, err := os.ReadFile(inventoryPath)
	require.NoError(t, err)
	require.NotContains(t, string(data), "secret")
	var inv inventory.Inventory
	require.NoError(t, json.Unmarshal(data, &inv))
	require.Equal(t, "abc", inv.Repository.CommitSHA)
	require.Equal(t, "main", inv.Repository.Branch)
}

func TestInventoryReplacesTheFileOfAnEarlierScan(t *testing.T) {
	inventoryPath := filepath.Join(t.TempDir(), "inventory.json")
	require.NoError(t, os.WriteFile(inventoryPath, []byte(`{"stale":true}`), 0o600))

	c := &Client{ScanParams: &Parameters{InventoryPath: inventoryPath}}
	c.startInventory(context.Background())
	_, err := os.Stat(inventoryPath)
	require.True(t, os.IsNotExist(err), "the earlier inventory is removed before the scan")
}

func TestInventoryFailuresDoNotFailTheScan(t *testing.T) {
	t.Run("the earlier file cannot be removed", func(t *testing.T) {
		inventoryPath := filepath.Join(t.TempDir(), "inventory.json")
		require.NoError(t, os.MkdirAll(filepath.Join(inventoryPath, "child"), 0o755))

		_, metadata := performInventoryScan(t, t.TempDir(), inventoryPath)
		require.Equal(t, InventoryFailed, metadata.Inventory.Status)
		require.Equal(t, InventoryReasonStaleFile, metadata.Inventory.Reason)
	})

	t.Run("the file cannot be written", func(t *testing.T) {
		inventoryPath := filepath.Join(t.TempDir(), "missing", "inventory.json")

		_, metadata := performInventoryScan(t, t.TempDir(), inventoryPath)
		require.Equal(t, InventoryFailed, metadata.Inventory.Status)
		require.Equal(t, InventoryReasonWriteError, metadata.Inventory.Reason)
		_, err := os.Stat(inventoryPath)
		require.True(t, os.IsNotExist(err))
	})

	t.Run("building the inventory panics", func(t *testing.T) {
		inventoryPath := filepath.Join(t.TempDir(), "inventory.json")
		c := &Client{ScanParams: &Parameters{InventoryPath: inventoryPath}}
		// A run without a collector panics when it builds.
		c.inventory = &inventoryRun{}

		status := c.finishInventory(context.Background())
		require.Equal(t, InventoryFailed, status.Status)
		require.Equal(t, InventoryReasonPanic, status.Reason)
		_, err := os.Stat(inventoryPath)
		require.True(t, os.IsNotExist(err))
	})
}
