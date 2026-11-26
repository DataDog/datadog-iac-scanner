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
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/tracker"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/rs/zerolog"
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

func TestScanMarksUnexpectedDocumentIDCollisionIncomplete(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"first/main.tf":  `resource "aws_s3_bucket" "first" {}`,
		"second/main.tf": `resource "aws_s3_bucket" "second" {}`,
	})
	params := terraformParams(root)
	params.Path = append(params.Path, filepath.Join(root, "second", "main.tf"))
	params.InventoryPath = filepath.Join(t.TempDir(), "inventory.json")
	var logs bytes.Buffer
	log := zerolog.New(zerolog.SyncWriter(&logs)).Level(zerolog.WarnLevel)
	ctx := log.WithContext(t.Context())

	client, err := NewClient(ctx, params, &consolePrinter.Printer{})
	require.NoError(t, err)
	client.querySourceFactory = func(_ context.Context, _ []string) (source.QueriesSource, error) {
		return &stubQuerySource{queries: []model.QueryMetadata{inventoryTestQuery}}, nil
	}
	key := model.DocumentKey{
		Path: model.DocumentPath(filepath.Join(root, "first", "main.tf"), root, nil),
		Kind: model.KindTerraform, Platform: "terraform",
	}
	require.NoError(t, client.Storage.SaveFile(ctx, &model.FileMetadata{
		ID: key.ID(), FilePath: "other.tf",
	}))

	metadata, err := client.PerformScan(ctx)
	require.NoError(t, err)
	require.True(t, metadata.Incomplete)
	require.Equal(t, 1, metadata.Stats.DuplicateDocumentIDs, "the overlapping path should be coalesced")
	require.Equal(t, 1, metadata.Stats.Violations, "the unaffected document should still be evaluated")
	raw, err := os.ReadFile(params.InventoryPath)
	require.NoError(t, err)
	var inv inventory.Inventory
	require.NoError(t, json.Unmarshal(raw, &inv))
	require.Equal(t, inventory.StatusPartial, inv.Status)
	require.Contains(t, logLines(t, &logs), map[string]any{
		"level": "warn", "duplicate_document_ids": float64(1),
		"message": "Scan incomplete: rejected documents with duplicate IDs",
	})
}

// writeRepo creates the files of a test repository.
func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	return root
}

func TestInventoryManifest(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"infra/main.tf":      "resource \"aws_s3_bucket\" \"logs\" {\n  bucket = \"logs\"\n}\n",
		"infra/variables.tf": "variable \"env\" {\n  type = string\n}\n",
		"infra/broken.tf":    "resource \"aws_s3_bucket\" \"oops\" {\n  bucket = \n",
		"k8s/web.yaml":       "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\n",
		"k8s/broken.yaml":    "apiVersion: v1\nkind: Service\nmetadata:\n  name: \"web\n",
		"k8s/empty.yaml":     "# apiVersion: v1\n# kind: Service\n",
		"docs/notes.md":      "not IaC\n",
	})
	// One megabyte is the smallest limit: a larger Terraform file is skipped.
	big := strings.Repeat("# padding to exceed the size limit\n", 40000)
	require.NoError(t, os.WriteFile(filepath.Join(root, "infra", "generated.tf"), []byte(big), 0o600))

	inventoryPath := filepath.Join(t.TempDir(), "inventory.json")
	params := Parameters{
		Path:             []string{root},
		RepoPath:         root,
		QueriesPath:      []string{"."},
		LibrariesPath:    "assets/libraries",
		PreviewLines:     3,
		CloudProvider:    []string{"aws"},
		Platform:         []string{"Terraform", "Kubernetes"},
		MaxFileSizeFlag:  1,
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
	require.Equal(t, InventoryWritten, metadata.Inventory.Status)

	data, err := os.ReadFile(inventoryPath)
	require.NoError(t, err)
	var inv inventory.Inventory
	require.NoError(t, json.Unmarshal(data, &inv))

	require.Equal(t, []inventory.File{
		{Path: "infra/broken.tf", Platform: "terraform", Status: inventory.FileFailed, Reason: inventory.ReasonParseError},
		{Path: "infra/generated.tf", Platform: "terraform", Status: inventory.FileFailed, Reason: inventory.ReasonTooLarge},
		{Path: "infra/main.tf", Platform: "terraform", Status: inventory.FileScanned},
		{Path: "infra/variables.tf", Platform: "terraform", Status: inventory.FileScanned},
		{Path: "k8s/broken.yaml", Platform: "kubernetes", Status: inventory.FileFailed, Reason: inventory.ReasonParseError},
		{Path: "k8s/empty.yaml", Platform: "kubernetes", Status: inventory.FileScanned},
		{Path: "k8s/web.yaml", Platform: "kubernetes", Status: inventory.FileScanned},
	}, inv.Files)
	require.Equal(t, inventory.StatusPartial, inv.Status)
	require.Equal(t, 3, inv.Stats.FilesFailed)
	require.Equal(t, 7, metadata.Inventory.Files)
	require.Equal(t, 3, metadata.Inventory.FilesFailed)
}

func TestInventoryManifestLeavesOutExternalFiles(t *testing.T) {
	root := t.TempDir()
	run := &inventoryRun{collector: inventory.NewCollector(root)}
	run.noteFiles(nil, []string{filepath.Join(root, ".terraform", "modules", "vpc")})
	c := &Client{Tracker: &tracker.CITracker{
		BagOfFilesFound: map[string]int{
			filepath.Join(root, "main.tf"):                                   1,
			filepath.Join(root, ".terraform", "modules", "vpc", "main.tf"):   1,
			filepath.Join(filepath.Dir(root), "elsewhere", "module", "x.tf"): 1,
			filepath.Join(root, "charts", "api", "templates", "empty.yaml"):  1,
			filepath.Join(root, "odd.yaml"):                                  1,
		},
		BagOfFilesParse: map[string]int{filepath.Join(root, "main.tf"): 1},
		EmptyFiles:      map[string]bool{filepath.Join(root, "charts", "api", "templates", "empty.yaml"): true},
	}}

	c.recordManifest(run, nil)
	inv := run.collector.Build(&inventory.Metadata{})
	require.Equal(t, []inventory.File{
		{Path: "charts/api/templates/empty.yaml", Status: inventory.FileScanned},
		{Path: "main.tf", Status: inventory.FileScanned},
		{Path: "odd.yaml", Status: inventory.FileFailed, Reason: inventory.ReasonUnknown},
	}, inv.Files)
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
	require.Equal(t, InventoryWritten, c.finishInventory(context.Background(), nil, nil).Status)

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
	performInventoryScan(t, t.TempDir(), inventoryPath)
	require.FileExists(t, inventoryPath)

	c := &Client{ScanParams: &Parameters{InventoryPath: inventoryPath}}
	c.startInventory(context.Background())
	_, err := os.Stat(inventoryPath)
	require.True(t, os.IsNotExist(err), "the earlier inventory is removed before the scan")
	require.Nil(t, c.inventory.failure)
}

func TestInventoryNeverReplacesAnotherFile(t *testing.T) {
	t.Run("a report of the scan", func(t *testing.T) {
		withoutSARIF, _ := performInventoryScan(t, t.TempDir(), "")
		outDir := t.TempDir()
		sarifPath := filepath.Join(outDir, "result.sarif")

		withSARIF, metadata := performInventoryScan(t, outDir, sarifPath)
		require.Equal(t, string(withoutSARIF), string(withSARIF), "the report stays as the scan wrote it")
		require.Equal(t, InventoryFailed, metadata.Inventory.Status)
		require.Equal(t, InventoryReasonPathConflict, metadata.Inventory.Reason)

		// An earlier report at the path is not removed either.
		withSARIF, metadata = performInventoryScan(t, outDir, sarifPath)
		require.Equal(t, string(withoutSARIF), string(withSARIF))
		require.Equal(t, InventoryReasonPathConflict, metadata.Inventory.Reason)
	})

	for _, tt := range []struct {
		name   string
		params func(path string) Parameters
	}{
		{"the metadata path", func(path string) Parameters { return Parameters{InventoryPath: path, MetadataPath: path} }},
		{"under the metadata path", func(path string) Parameters {
			return Parameters{InventoryPath: filepath.Join(path, "inventory.json"), MetadataPath: path}
		}},
		{"under the payload path", func(path string) Parameters {
			return Parameters{InventoryPath: filepath.Join(path, "inventory.json"), PayloadPath: path}
		}},
		{"the payload path", func(path string) Parameters { return Parameters{InventoryPath: path, PayloadPath: path} }},
		{"a scanned file", func(path string) Parameters { return Parameters{InventoryPath: path, Path: []string{path}} }},
		{"a file the scanner did not write", func(path string) Parameters { return Parameters{InventoryPath: path} }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "main.tf")
			require.NoError(t, os.WriteFile(path, []byte("resource \"aws_s3_bucket\" \"b\" {}\n"), 0o600))
			params := tt.params(path)
			c := &Client{ScanParams: &params}
			c.startInventory(context.Background())

			require.NotNil(t, c.inventory.failure)
			require.Equal(t, InventoryReasonPathConflict, c.inventory.failure.Reason)
			require.Nil(t, c.inventory.sink(), "nothing is evaluated or listed for an inventory that is not written")
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, "resource \"aws_s3_bucket\" \"b\" {}\n", string(data), "the file is not removed")
			status := c.finishInventory(context.Background(), nil, nil)
			require.Equal(t, InventoryFailed, status.Status)
			data, err = os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, "resource \"aws_s3_bucket\" \"b\" {}\n", string(data), "nor replaced")
		})
	}

	t.Run("a scanned file stays scanned", func(t *testing.T) {
		withoutSARIF, _ := performInventoryScan(t, t.TempDir(), "")
		source, err := filepath.Abs(filepath.Join("test", "sample.tf"))
		require.NoError(t, err)
		original, err := os.ReadFile(source)
		require.NoError(t, err)

		withSARIF, metadata := performInventoryScan(t, t.TempDir(), source)
		require.Equal(t, string(withoutSARIF), string(withSARIF), "the refused path is still scanned")
		require.Equal(t, InventoryReasonPathConflict, metadata.Inventory.Reason)
		data, err := os.ReadFile(source)
		require.NoError(t, err)
		require.Equal(t, string(original), string(data))
	})

	t.Run("under the metadata path through a symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlinks need privileges on Windows")
		}
		out := t.TempDir()
		alias := filepath.Join(t.TempDir(), "alias")
		require.NoError(t, os.Symlink(out, alias))
		metadataPath := filepath.Join(out, "meta.json")
		for _, inventoryPath := range []string{
			filepath.Join(alias, "meta.json", "inventory.json"),
			filepath.Join(alias, "meta.json"),
		} {
			c := &Client{ScanParams: &Parameters{InventoryPath: inventoryPath, MetadataPath: metadataPath}}
			c.startInventory(context.Background())
			require.NotNil(t, c.inventory.failure, inventoryPath)
			require.Equal(t, InventoryReasonPathConflict, c.inventory.failure.Reason, inventoryPath)
			require.Equal(t, InventoryFailed, c.finishInventory(context.Background(), nil, nil).Status)
			require.NoDirExists(t, metadataPath)
		}
	})

	t.Run("the metadata path before it is written", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out", "..", "metadata.json")
		c := &Client{ScanParams: &Parameters{InventoryPath: filepath.Clean(path), MetadataPath: path}}
		c.startInventory(context.Background())
		require.NotNil(t, c.inventory.failure)
		require.Equal(t, InventoryReasonPathConflict, c.inventory.failure.Reason)
		// Nor may the inventory be written where the metadata needs a
		// directory, or the reverse.
		for _, paths := range [][2]string{
			{filepath.Join(filepath.Dir(path), "result.json"), filepath.Join(filepath.Dir(path), "result.json", "metadata.json")},
			{filepath.Join(filepath.Dir(path), "payload.json"), ""},
		} {
			params := Parameters{InventoryPath: paths[0], MetadataPath: paths[1]}
			if paths[1] == "" {
				params.PayloadPath = filepath.Join(paths[0], "payload", "payload.json")
			}
			c = &Client{ScanParams: &params}
			c.startInventory(context.Background())
			require.NotNil(t, c.inventory.failure, paths[0])
			require.Equal(t, InventoryReasonPathConflict, c.inventory.failure.Reason, paths[0])
			require.Equal(t, InventoryFailed, c.finishInventory(context.Background(), nil, nil).Status)
			require.NoFileExists(t, paths[0])
		}
		// Nor may the inventory make a directory where the metadata goes.
		under := filepath.Join(path, "inventory.json")
		c = &Client{ScanParams: &Parameters{InventoryPath: under, MetadataPath: path}}
		c.startInventory(context.Background())
		require.NotNil(t, c.inventory.failure)
		require.Equal(t, InventoryReasonPathConflict, c.inventory.failure.Reason)
		require.Equal(t, InventoryFailed, c.finishInventory(context.Background(), nil, nil).Status, "no inventory is written")
		require.NoDirExists(t, filepath.Clean(path))
	})
}

func TestInventoryWindowsRootedPathConflict(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows rooted paths")
	}
	out := t.TempDir()
	t.Chdir(out)
	parent := filepath.Join(out, "result.json")
	metadata := filepath.Join(parent, "metadata.json")
	inv := filepath.Join(parent, "inventory.json")
	volume := filepath.VolumeName(out)
	for _, tt := range []struct{ name, metadata, inventory, relation string }{
		{"under rooted metadata", parent[len(volume):], inv, "under"},
		{"rooted inventory under metadata", parent, inv[len(volume):], "under"},
		{"above rooted metadata", metadata[len(volume):], parent, "above"},
		{"rooted inventory above metadata", metadata, parent[len(volume):], "above"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{ScanParams: &Parameters{InventoryPath: tt.inventory, MetadataPath: tt.metadata}}
			c.startInventory(t.Context())
			status := c.finishInventory(t.Context(), nil, nil)
			require.NotNil(t, status)
			require.Equal(t, InventoryFailed, status.Status)
			require.Equal(t, InventoryReasonPathConflict, status.Reason)
			require.Equal(t, "the inventory path is also "+tt.relation+" the metadata path", status.Error)
			require.NoDirExists(t, parent)
			require.NoFileExists(t, parent)
		})
	}
}

func TestInventoryFailuresDoNotFailTheScan(t *testing.T) {
	t.Run("a directory is at the path", func(t *testing.T) {
		inventoryPath := filepath.Join(t.TempDir(), "inventory.json")
		require.NoError(t, os.MkdirAll(filepath.Join(inventoryPath, "child"), 0o755))

		_, metadata := performInventoryScan(t, t.TempDir(), inventoryPath)
		require.Equal(t, InventoryFailed, metadata.Inventory.Status)
		require.Equal(t, InventoryReasonPathConflict, metadata.Inventory.Reason)
		require.DirExists(t, filepath.Join(inventoryPath, "child"))
	})

	t.Run("the file cannot be written", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("needs file permissions that stop the directory from being created")
		}
		readOnly := t.TempDir()
		require.NoError(t, os.Chmod(readOnly, 0o500))
		t.Cleanup(func() { _ = os.Chmod(readOnly, 0o700) })
		inventoryPath := filepath.Join(readOnly, "missing", "inventory.json")

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

		status := c.finishInventory(context.Background(), nil, nil)
		require.Equal(t, InventoryFailed, status.Status)
		require.Equal(t, InventoryReasonPanic, status.Reason)
		_, err := os.Stat(inventoryPath)
		require.True(t, os.IsNotExist(err))
	})
}
