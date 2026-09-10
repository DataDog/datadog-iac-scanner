/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/modulegraph"
	"github.com/stretchr/testify/require"
)

func TestEnrichModuleBlock_LocalDeclaration(t *testing.T) {
	repo := t.TempDir()
	mainTF := filepath.Join(repo, "stack", "main.tf")
	moduleTF := filepath.Join(repo, "modules", "bucket", "main.tf")
	writeInventoryFixture(t, mainTF, `
module "bucket" {
  source = "../modules/bucket"
}
`)
	writeInventoryFixture(t, moduleTF, `
resource "aws_s3_bucket" "this" {
  bucket = "logs"
}
`)

	files := model.FileMetadatas{
		parseTFAt(t, mainTF, repo),
		parseTFAt(t, moduleTF, repo),
	}
	opts := &WalkOptions{RepoPath: repo}
	resources := WalkFiles(files, []string{"terraform"}, opts)

	mod, ok := findResource(resources, BlockModule, "bucket")
	require.True(t, ok)
	require.NotNil(t, mod.Module)
	require.Equal(t, "bucket", mod.Module.Name)
	require.Equal(t, "local", mod.Module.SourceType)
	require.Equal(t, "direct", mod.Module.DependencyType)
	require.Equal(t, "stack/main.tf", mod.Module.ModuleCodeLocation.Filename)

	bucket, ok := findResource(resources, BlockResource, "this")
	require.True(t, ok)
	require.NotNil(t, bucket.Module)
	require.Equal(t, "bucket", bucket.Module.Name)
	require.Equal(t, "direct", bucket.Module.DependencyType)
	require.Equal(t, "stack/main.tf", bucket.File)
	require.Equal(t, "main.tf", bucket.Module.ModuleCodeLocation.Filename)
	require.Equal(t, 2, bucket.Module.ModuleCodeLocation.LineStart)
}

func TestEnrichModuleResource_ResolvedRemoteModule(t *testing.T) {
	repo := t.TempDir()
	caller := filepath.Join(repo, "stack", "main.tf")
	moduleBody := filepath.Join(repo, "cache", "bucket", "main.tf")
	writeInventoryFixture(t, caller, `
module "bucket" {
  source  = "registry.terraform.io/acme/bucket/aws"
  version = "9.3.2"
}
`)
	writeInventoryFixture(t, moduleBody, `
resource "aws_s3_bucket" "this" {
  bucket = "logs"
}
`)

	files := model.FileMetadatas{
		parseTFAt(t, caller, repo),
		parseTFAt(t, moduleBody, repo),
	}
	opts := &WalkOptions{
		RepoPath: repo,
		ResolvedModules: []modulegraph.ResolvedModule{{
			CallerRoot: filepath.Join(repo, "stack"),
			CallerFile: caller,
			CallerLine: 2,
			CallerEndLine: 5,
			Name:       "bucket",
			Source:          "registry.terraform.io/acme/bucket/aws",
			Version:         "9.3.2",
			ResolvedVersion: "9.3.2",
			LocalPath:       filepath.Join(repo, "cache", "bucket"),
			CanonicalSource: "registry.terraform.io/acme/bucket/aws",
			Depth:           1,
		}},
	}
	resources := WalkFiles(files, []string{"terraform"}, opts)

	bucket, ok := findResource(resources, BlockResource, "this")
	require.True(t, ok)
	require.NotNil(t, bucket.Module)
	require.Equal(t, "bucket", bucket.Module.Name)
	require.Equal(t, "registry", bucket.Module.SourceType)
	require.Equal(t, "9.3.2", bucket.Module.Version)
	require.Equal(t, "direct", bucket.Module.DependencyType)
	require.Equal(t, "stack/main.tf", bucket.File)
	require.Equal(t, 2, bucket.StartLine)
	require.Equal(t, "main.tf", bucket.Module.ModuleCodeLocation.Filename)
}

func writeInventoryFixture(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, writeFile(path, content))
}

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func parseTFAt(t *testing.T, path, repo string) *model.FileMetadata {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	rel, err := filepath.Rel(repo, path)
	require.NoError(t, err)
	return parseTF(t, filepath.ToSlash(rel), string(content))
}
