/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfmodules

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

func TestIsTerraformConfigPath(t *testing.T) {
	require.True(t, IsTerraformConfigPath("main.tf"))
	require.True(t, IsTerraformConfigPath("stack/main.tf.json"))
	require.False(t, IsTerraformConfigPath("terraform.tfvars"))
	require.False(t, IsTerraformConfigPath("prod.auto.tfvars"))
	require.False(t, IsTerraformConfigPath("README.md"))
}

func TestParseTerraformModules_TFJSON(t *testing.T) {
	files := model.FileMetadatas{{
		FilePath: "main.tf.json",
		OriginalData: `{
  "module": {
    "bucket": {
      "source": "registry.example.com/acme/bucket/aws",
      "version": "1.2.3"
    }
  }
}`,
	}}
	modules, err := ParseTerraformModules(context.Background(), vfs.DiskFS{}, files, 0)
	require.NoError(t, err)
	require.Len(t, modules, 1)
	var module ParsedModule
	for key := range modules {
		module = modules[key]
		break
	}
	require.Equal(t, "bucket", module.Name)
	require.Equal(t, "registry.example.com/acme/bucket/aws", module.Source)
	require.Equal(t, "1.2.3", module.Version)
	require.Equal(t, "registry", module.SourceType)
}

func TestParseTerraformModules_TFJSONResolvesVariableInterpolation(t *testing.T) {
	files := model.FileMetadatas{{
		FilePath: "main.tf.json",
		OriginalData: `{
  "variable": {
    "module_source": {
      "default": "registry.example.com/acme/bucket/aws"
    }
  },
  "module": {
    "bucket": {
      "source": "${var.module_source}",
      "version": "1.2.3"
    }
  }
}`,
	}}
	modules, err := ParseTerraformModules(context.Background(), vfs.DiskFS{}, files, 0)
	require.NoError(t, err)
	require.Len(t, modules, 1)
	var module ParsedModule
	for key := range modules {
		module = modules[key]
		break
	}
	require.Equal(t, "registry.example.com/acme/bucket/aws", module.Source)
}

func TestLoadTFFilesFromDir_IncludesTFJSON(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "main.tf.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"module":{"bucket":{"source":"x"}}}`), 0o600))
	files, err := LoadTFFilesFromDir(root, "")
	require.NoError(t, err)
	require.Len(t, files, 1)
	require.Equal(t, filepath.Clean(path), files[0].FilePath)
}

func TestParseTerraformModulesFromFiles_TFJSONOnDisk(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "main.tf.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
  "module": {
    "bucket": {
      "source": "registry.example.com/acme/bucket/aws",
      "version": "1.2.3"
    }
  }
}`), 0o600))
	files, err := LoadTFFilesFromDir(root, "")
	require.NoError(t, err)
	allowed := map[string]bool{files[0].FilePath: true}
	modules, err := ParseTerraformModulesFromFiles(context.Background(), nil, files, allowed)
	require.NoError(t, err)
	require.Len(t, modules, 1)
}
