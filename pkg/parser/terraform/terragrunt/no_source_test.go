/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package terragrunt

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func evaluateUnit(t *testing.T, root, unit string) Unit {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(unit), "terragrunt.hcl")
	src, err := os.ReadFile(path)
	require.NoError(t, err)
	u, err := Evaluate(context.Background(), vfs.DiskFS{}, root, path, src, nil)
	require.NoError(t, err)
	return u
}

func TestEvaluateUnitReturnsInputs(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": `locals {
  region = "eu"
}
inputs = {
  acl    = "public-read"
  region = local.region
  tags   = { team = get_env("TEAM"), env = "prod" }
  secret = get_env("SECRET")
}
`})
	u := evaluateUnit(t, root, "u")
	assert.Nil(t, u.Translation)
	require.Len(t, u.Inputs, 4)
	assert.Equal(t, "public-read", u.Inputs["acl"].AsString())
	assert.Equal(t, "eu", u.Inputs["region"].AsString())
	assert.False(t, u.Inputs["secret"].IsKnown(), "a wholly unknown input is present and unknown")
	tags := u.Inputs["tags"]
	require.True(t, tags.IsKnown())
	assert.False(t, tags.IsWhollyKnown(), "the unknown part stays a cty unknown, not the placeholder")
	assert.Equal(t, "prod", tags.GetAttr("env").AsString())
	assert.False(t, tags.GetAttr("team").IsKnown())
}

func TestEvaluateUnitAppliesInclude(t *testing.T) {
	root := repo(t, map[string]string{
		"root.hcl":         "inputs = { shared = \"a\", acl = \"private\" }",
		"u/terragrunt.hcl": "include \"r\" {\n  path = \"../root.hcl\"\n}\ninputs = {\n  acl = \"public-read\"\n}\n",
	})
	u := evaluateUnit(t, root, "u")
	assert.Equal(t, "a", u.Inputs["shared"].AsString())
	assert.Equal(t, "public-read", u.Inputs["acl"].AsString())
}

func TestEvaluateUnitSkipCases(t *testing.T) {
	tests := map[string]string{
		"skip":           "skip = true\ninputs = { a = 1 }",
		"unknown inputs": "inputs = { (get_env(\"K\")) = 1 }",
		"bad include":    "include {\n  path = \"../nope.hcl\"\n}\ninputs = { a = 1 }",
		"no inputs":      "locals { a = 1 }",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			root := repo(t, map[string]string{"u/terragrunt.hcl": content})
			u := evaluateUnit(t, root, "u")
			assert.Nil(t, u.Translation)
			assert.Empty(t, u.Inputs)
		})
	}
}

func TestEvaluateWithSourceAlsoReturnsInputs(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": "terraform { source = \"./m\" }\ninputs = { a = 1 }"})
	u := evaluateUnit(t, root, "u")
	require.NotNil(t, u.Translation)
	require.Len(t, u.Inputs, 1, "kept for the unit's files when the module cannot be resolved")
}
