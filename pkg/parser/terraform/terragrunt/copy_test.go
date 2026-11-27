/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package terragrunt

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func moduleFileNames(t *testing.T, hcl string) []string {
	t.Helper()
	root := repo(t, map[string]string{
		"u/terragrunt.hcl":   hcl,
		"u/main.tf":          "",
		"u/extra.tf.json":    "{}",
		"u/legacy.tofu":      "",
		"u/.hidden.tf":       "",
		"u/skip.tf":          "",
		"u/notes.txt":        "",
		"u/terraform.tfvars": "",
		"m/main.tf":          "",
	})
	var names []string
	for _, p := range translate(t, root, "u").ModuleFiles {
		assert.Equal(t, filepath.Join(root, "u"), filepath.Dir(p))
		names = append(names, filepath.Base(p))
	}
	return names
}

func TestModuleFilesDefaults(t *testing.T) {
	got := moduleFileNames(t, "terraform { source = \"../m\" }\ninputs = {}")
	assert.ElementsMatch(t, []string{"main.tf", "extra.tf.json", "legacy.tofu", "skip.tf"}, got, "hidden files are not copied")
}

func TestModuleFilesCopyFilters(t *testing.T) {
	got := moduleFileNames(t, `terraform {
  source            = "../m"
  include_in_copy   = [".hidden.tf", "*.txt"]
  exclude_from_copy = ["skip.tf", "*.tofu"]
}
inputs = {}`)
	assert.ElementsMatch(t, []string{"main.tf", "extra.tf.json", ".hidden.tf"}, got)

	got = moduleFileNames(t, `terraform {
  source            = "../m"
  include_in_copy   = ["skip.tf"]
  exclude_from_copy = ["skip.tf"]
}
inputs = {}`)
	assert.NotContains(t, got, "skip.tf", "exclude_from_copy wins over include_in_copy")
}

func TestModuleFilesFiltersFromInclude(t *testing.T) {
	root := repo(t, map[string]string{
		"root.hcl":         "terraform {\n  exclude_from_copy = [\"skip.tf\"]\n}\n",
		"u/terragrunt.hcl": "include \"r\" {\n  path = \"../root.hcl\"\n}\nterraform { source = \"../m\" }\ninputs = {}",
		"u/main.tf":        "",
		"u/skip.tf":        "",
		"m/main.tf":        "",
	})
	var names []string
	for _, p := range translate(t, root, "u").ModuleFiles {
		names = append(names, filepath.Base(p))
	}
	assert.Equal(t, []string{"main.tf"}, names)
}

func TestNoModuleFilesWithoutTranslation(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": "inputs = { a = 1 }", "u/main.tf": ""})
	assert.Nil(t, translate(t, root, "u"))
}

func TestCopyFilterNestedPaths(t *testing.T) {
	f := CopyFilter{Include: []string{".keep"}, Exclude: []string{"build", "*.bak"}}
	assert.True(t, f.Copies("templates/a.tpl"))
	assert.False(t, f.Copies("build/out.txt"), "a file under an excluded directory")
	assert.False(t, f.Copies("a.bak"))
	assert.True(t, f.Copies("templates/a.bak"), "a glob is relative to the unit directory, * stops at a slash")
	assert.False(t, f.Copies(".git/config"), "hidden directory")
	assert.True(t, f.Copies(".keep"), "hidden but included")
}

func TestCopyFilterTraversesParentsOfIncludedPaths(t *testing.T) {
	f := CopyFilter{Include: []string{".assets/acl.txt", ".deep/*/x.txt", ".all/**"}}
	assert.True(t, f.Copies(".assets/acl.txt"))
	assert.False(t, f.Copies(".assets/other.txt"), "only the included path of a hidden directory")
	assert.True(t, f.Traverses(".assets"), "the parent of an included file")
	assert.True(t, f.Traverses(".deep"))
	assert.True(t, f.Traverses(".deep/sub"))
	assert.False(t, f.Traverses(".deep/sub/z/y"), "beyond the pattern")
	assert.True(t, f.Traverses(".all/a/b"), "under a ** pattern")
	assert.False(t, f.Traverses(".other"), "a hidden directory nothing includes")
	assert.True(t, f.Traverses("visible"))
	assert.False(t, CopyFilter{Include: []string{".assets/acl.txt"}, Exclude: []string{".assets"}}.Traverses(".assets"), "an excluded directory")
}
