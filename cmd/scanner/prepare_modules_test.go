package main

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/moduleprepare"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/stretchr/testify/require"
	cli "github.com/urfave/cli/v3"
)

func TestPrepareModulesConvergesFromRequestToStagedArchive(t *testing.T) {
	repositoryRoot := t.TempDir()
	source := "terraform-aws-modules/vpc/aws//modules/vpc"
	require.NoError(t, os.WriteFile(filepath.Join(repositoryRoot, "main.tf"), []byte(`
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws//modules/vpc"
  version = "5.4.0"
}
`), 0o600))
	moduleRoot := t.TempDir()
	firstResponsePath := filepath.Join(moduleRoot, "first-response.json")
	manifestPath := filepath.Join(moduleRoot, "manifest.json")

	require.NoError(t, runPrepareModulesCommand(t.Context(), []string{
		"prepare-modules",
		"--path", repositoryRoot,
		"--module-root", moduleRoot,
		"--output-response", firstResponsePath,
		"--output-manifest", manifestPath,
	}))
	first := readPrepareResponse(t, firstResponsePath)
	require.Equal(t, moduleprepare.StatusRequiresStaging, first.Status)
	require.Len(t, first.Requests, 1)
	require.NoFileExists(t, manifestPath)

	archivePath := filepath.Join(moduleRoot, "incoming", "vpc.zip")
	writeModuleZip(t, archivePath, "vpc-commit/modules/vpc/main.tf", `resource "test" "vpc" {}`)
	staged := moduleprepare.StagedModules{
		SchemaVersion: moduleprepare.ResponseSchemaVersion,
		Modules: []moduleprepare.StagedModule{{
			RequestID:        first.Requests[0].RequestID,
			Source:           source,
			RequestedVersion: "5.4.0",
			ResolvedVersion:  "5.4.0",
			Kind:             moduleprepare.StagedKindArchive,
			ArtifactPath:     "incoming/vpc.zip",
			ArchiveFormat:    "zip",
			TransportDigest:  moduleFileDigest(t, archivePath),
			Declarations:     first.Requests[0].Declarations,
		}},
	}
	stagedData, err := json.Marshal(staged)
	require.NoError(t, err)
	stagedPath := filepath.Join(moduleRoot, "staged.json")
	require.NoError(t, os.WriteFile(stagedPath, stagedData, 0o600))
	secondResponsePath := filepath.Join(moduleRoot, "second-response.json")

	require.NoError(t, runPrepareModulesCommand(t.Context(), []string{
		"prepare-modules",
		"--path", repositoryRoot,
		"--module-root", moduleRoot,
		"--output-response", secondResponsePath,
		"--output-manifest", manifestPath,
		"--staged-modules", stagedPath,
	}))
	second := readPrepareResponse(t, secondResponsePath)
	require.Equal(t, moduleprepare.StatusComplete, second.Status)
	require.Empty(t, second.Requests)
	require.Equal(t, filepath.ToSlash(manifestPath), second.ManifestPath)
	manifest, err := resolver.LoadManifest(t.Context(), manifestPath)
	require.NoError(t, err)
	require.Len(t, manifest.Entries, 1)
}

func runPrepareModulesCommand(ctx context.Context, args []string) error {
	command := &cli.Command{
		Name:   prepareModulesAction.Name,
		Flags:  prepareModulesAction.Flags,
		Action: prepareModules,
	}
	return command.Run(ctx, args)
}

func readPrepareResponse(t *testing.T, path string) moduleprepare.Response {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var response moduleprepare.Response
	require.NoError(t, json.Unmarshal(data, &response))
	return response
}

func writeModuleZip(t *testing.T, path, name, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	file, err := os.Create(path)
	require.NoError(t, err)
	writer := zip.NewWriter(file)
	entry, err := writer.Create(name)
	require.NoError(t, err)
	_, err = entry.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	require.NoError(t, file.Close())
}

func moduleFileDigest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
