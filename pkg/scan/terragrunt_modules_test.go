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

	"github.com/stretchr/testify/require"
)

// Only units with a remote source become module discovery calls, declared by
// the unit file so the engine finds the module from the unit.
func TestTerragruntModuleCalls(t *testing.T) {
	root := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	files := map[string]string{
		"root.hcl": `terraform {
  source = "git::https://example.com/modules.git//${path_relative_to_include()}?ref=v2.0.0"
}`,
		"live/vpc/terragrunt.hcl": `terraform {
  source = "tfr:///acme/vpc/aws?version=1.2.3"
}`,
		"live/db/terragrunt.hcl": `include "root" {
  path = find_in_parent_folders("root.hcl")
}`,
		"live/local/terragrunt.hcl": `terraform {
  source = "../../modules/bucket"
}`,
		"live/skipped/terragrunt.hcl": `terraform {
  source = "tfr:///acme/skipped/aws?version=1.0.0"
}
skip = true`,
	}
	var paths []string
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		if filepath.Base(name) == "terragrunt.hcl" {
			paths = append(paths, path)
		}
	}

	calls := terragruntModuleCalls(context.Background(), paths, root, nil)

	bySource := map[string]string{}
	for _, call := range calls {
		require.Equal(t, "terragrunt", call.Name)
		require.False(t, call.IsLocal)
		bySource[call.Source] = call.Version + " " + call.FileName + " " + call.SourceType
	}
	require.Equal(t, map[string]string{
		"acme/vpc/aws": "1.2.3 " + filepath.Join(root, "live/vpc/terragrunt.hcl") + " registry",
		"git::https://example.com/modules.git//live/db?ref=v2.0.0": " " +
			filepath.Join(root, "live/db/terragrunt.hcl") + " git",
	}, bySource)
}

// A stack unit's remote module is fetched for the stack file declaring it;
// the unit configuration it is generated from is not a unit of its own.
func TestTerragruntModuleCalls_Stack(t *testing.T) {
	root := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	files := map[string]string{
		"units/vpc/terragrunt.hcl": `terraform {
  source = "tfr:///acme/vpc/aws?version=${values.version}"
}`,
		"live/terragrunt.stack.hcl": `unit "network" {
  source = "../units/vpc"
  path   = "network"
  values = { version = "3.0.0" }
}`,
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}

	calls := terragruntModuleCalls(context.Background(), []string{
		filepath.Join(root, "live/terragrunt.stack.hcl"),
		filepath.Join(root, "units/vpc/terragrunt.hcl"),
	}, root, nil)

	require.Len(t, calls, 1)
	require.Equal(t, "network", calls[0].Name)
	require.Equal(t, "acme/vpc/aws", calls[0].Source)
	require.Equal(t, "3.0.0", calls[0].Version)
	require.Equal(t, filepath.Join(root, "live/terragrunt.stack.hcl"), calls[0].FileName)
}
