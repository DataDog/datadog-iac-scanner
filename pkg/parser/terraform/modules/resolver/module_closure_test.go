/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func mapConfigReader(files map[string]string, reads *[][]string) ModuleConfigReader {
	return func(_ context.Context, dirs []string) (map[string]map[string][]byte, error) {
		if reads != nil {
			*reads = append(*reads, append([]string(nil), dirs...))
		}
		wanted := make(map[string]bool, len(dirs))
		for _, dir := range dirs {
			wanted[dir] = true
		}
		out := make(map[string]map[string][]byte)
		for name, content := range files {
			dir := path.Dir(name)
			if !wanted[dir] {
				continue
			}
			if out[dir] == nil {
				out[dir] = make(map[string][]byte)
			}
			out[dir][path.Base(name)] = []byte(content)
		}
		return out, nil
	}
}

func TestLocalModuleClosureFollowsLocalSourcesTransitively(t *testing.T) {
	files := map[string]string{
		"modules/app/main.tf": `
module "shared" { source = "../shared" }
module "nested" { source = "./nested" }
module "remote" { source = "git::https://example.com/org/repo.git" }
module "escape" { source = "../../../outside" }
module "root" { source = "../.." }
`,
		"modules/app/README.md":     `module "ignored" { source = "../ignored" }`,
		"modules/app/nested/x.tf":   `module "back" { source = "../../shared" }`,
		"modules/shared/main.tf":    `module "common" { source = "../common" }`,
		"modules/common/main.tf":    `resource "null_resource" "x" {}`,
		"modules/unrelated/main.tf": `module "other" { source = "../other" }`,
	}
	var reads [][]string
	closure, err := LocalModuleClosure(t.Context(), "modules/app/", mapConfigReader(files, &reads))
	require.NoError(t, err)
	require.Equal(t, []string{"modules/app", "modules/shared", "modules/app/nested", "modules/common"}, closure)
	require.Equal(t, [][]string{
		{"modules/app"},
		{"modules/shared", "modules/app/nested"},
		{"modules/common"},
	}, reads, "each closure level is read in one batch")
}

func TestLocalModuleClosureFollowsJSONConfiguration(t *testing.T) {
	closure, err := LocalModuleClosure(t.Context(), "modules/app", mapConfigReader(map[string]string{
		"modules/app/main.tf.json": `{"module": {
			"shared": {"source": "../shared"},
			"templated": {"source": "${var.prefix}/x"},
			"remote": {"source": "git::https://example.com/org/repo.git"}
		}}`,
		"modules/shared/main.tf": `resource "null_resource" "x" {}`,
	}, nil))
	require.NoError(t, err)
	require.Equal(t, []string{"modules/app", "modules/shared"}, closure)
}

func TestLocalModuleClosureAcceptsPackageRoot(t *testing.T) {
	closure, err := LocalModuleClosure(context.Background(), "", mapConfigReader(map[string]string{
		"main.tf": `module "vpc" { source = "./modules/vpc" }`,
	}, nil))
	require.NoError(t, err)
	require.Equal(t, []string{".", "modules/vpc"}, closure)
}

func TestLocalModuleClosureRejectsEscapingSubdir(t *testing.T) {
	_, err := LocalModuleClosure(context.Background(), "../outside", mapConfigReader(nil, nil))
	require.Error(t, err)
}
