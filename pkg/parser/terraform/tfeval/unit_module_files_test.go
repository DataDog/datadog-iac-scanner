/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

// unitFixture writes a module, a unit calling it as module.terragrunt with the
// given extra files, and another root calling the same module.
func unitFixture(t *testing.T, module, unitFiles map[string]string) (e *Evaluator, unit, other string) {
	t.Helper()
	root := t.TempDir()
	writeModule(t, root, "mod", module)
	call := map[string]string{"terragrunt.generated.tf": `module "terragrunt" { source = "../mod" }`}
	unit = writeModule(t, root, "unit", call)
	other = writeModule(t, root, "other", map[string]string{"main.tf": `module "m" { source = "../mod" }`})
	var paths []string
	for name, content := range unitFiles {
		writeModule(t, root, "unit", map[string]string{name: content})
		paths = append(paths, filepath.Join(unit, name))
	}
	e = New()
	e.SetUnitModuleFiles(map[string]UnitModule{unit: {Files: paths}})
	return e, unit, other
}

func resourceNamed(t *testing.T, e *Evaluator, dir, name string) *ResolvedResource {
	t.Helper()
	resources, _, _, err := e.EvaluateModule(t.Context(), dir, nil)
	require.NoError(t, err)
	var found *ResolvedResource
	for i := range resources {
		if resources[i].Name == name {
			require.Nil(t, found, "%s resolved twice", name)
			found = &resources[i]
		}
	}
	return found
}

func TestUnitModuleFilesSeeTheModule(t *testing.T) {
	e, unit, _ := unitFixture(t, map[string]string{
		"main.tf": `
variable "acl" { default = "public-read" }
locals { prefix = "p" }
resource "aws_s3_bucket" "main" { bucket = "m" }`,
	}, map[string]string{
		"extra.tf": `
resource "aws_s3_bucket" "extra" {
  acl    = var.acl
  bucket = "${local.prefix}-${aws_s3_bucket.main.bucket}"
}`,
	})
	r := resourceNamed(t, e, unit, "extra")
	require.NotNil(t, r)
	require.Equal(t, "public-read", r.Attributes["acl"].AsString())
	require.Equal(t, "p-m", r.Attributes["bucket"].AsString())
	require.Equal(t, filepath.Join(unit, "extra.tf"), r.DefinedIn)
	require.Equal(t, "module.terragrunt", r.ModuleAddress)
	require.NotNil(t, resourceNamed(t, e, unit, "main"))
}

func TestUnitModuleFilesAreNotTheUnitRoot(t *testing.T) {
	e, unit, _ := unitFixture(t, map[string]string{"main.tf": `variable "acl" { default = "x" }`},
		map[string]string{"extra.tf": `resource "aws_s3_bucket" "extra" { acl = var.acl }`})
	resources, _, _, err := e.EvaluateModule(t.Context(), unit, nil)
	require.NoError(t, err)
	for _, r := range resources {
		require.NotEmpty(t, r.ModuleAddress, "%s must only be evaluated in the module", r.Name)
	}
}

func TestUnitFileShadowsModuleFile(t *testing.T) {
	e, unit, _ := unitFixture(t, map[string]string{
		"main.tf": `resource "aws_s3_bucket" "old" { acl = "private" }`,
	}, map[string]string{
		"main.tf": `resource "aws_s3_bucket" "new" { acl = "public-read" }`,
	})
	require.Nil(t, resourceNamed(t, e, unit, "old"))
	require.NotNil(t, resourceNamed(t, e, unit, "new"))
}

func TestUnitOverrideFileMergesIntoModuleBlock(t *testing.T) {
	e, unit, _ := unitFixture(t, map[string]string{
		"main.tf": `resource "aws_s3_bucket" "main" {
  acl    = "private"
  bucket = "m"
}`,
	}, map[string]string{
		"main_override.tf": `resource "aws_s3_bucket" "main" { acl = "public-read" }`,
	})
	r := resourceNamed(t, e, unit, "main")
	require.NotNil(t, r)
	require.Equal(t, "public-read", r.Attributes["acl"].AsString())
	require.Equal(t, "m", r.Attributes["bucket"].AsString())
	require.Equal(t, filepath.Join(unit, "main_override.tf"), r.Body.Attributes["acl"].SrcRange.Filename)
}

func TestUnitModuleFilesDoNotLeakToOtherCallers(t *testing.T) {
	e, unit, other := unitFixture(t, map[string]string{
		"main.tf": `
variable "acl" { default = "private" }
resource "aws_s3_bucket" "main" { acl = var.acl }`,
	}, map[string]string{
		"main_override.tf": `resource "aws_s3_bucket" "main" { acl = "public-read" }`,
		"extra.tf":         `resource "aws_s3_bucket" "extra" { acl = var.acl }`,
	})
	// The same evaluator serves both roots, as in a scan.
	require.NotNil(t, resourceNamed(t, e, unit, "extra"))
	for range 2 {
		r := resourceNamed(t, e, other, "main")
		require.NotNil(t, r)
		require.True(t, r.Attributes["acl"].RawEquals(cty.StringVal("private")))
		require.Nil(t, resourceNamed(t, e, other, "extra"))
	}
	r := resourceNamed(t, e, unit, "main")
	require.Equal(t, "public-read", r.Attributes["acl"].AsString())
}

// assetFixture writes a module and a unit like unitFixture, with assets in both.
func assetFixture(t *testing.T, unitAssets map[string]string, unitModule UnitModule) (*Evaluator, string) {
	t.Helper()
	root := t.TempDir()
	writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "main" {
  acl    = file("acl.txt")
  bucket = join(",", sort(fileset(path.module, "**/*.txt")))
}`,
		"acl.txt":    "private",
		"module.txt": "m",
	})
	unit := writeModule(t, root, "unit", map[string]string{
		"terragrunt.generated.tf": `module "terragrunt" { source = "../mod" }`,
		"extra.tf":                `resource "aws_s3_bucket" "extra" { acl = file("acl.txt") }`,
	})
	for name, content := range unitAssets {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(unit, name)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(unit, name), []byte(content), 0o644))
	}
	unitModule.Files = []string{filepath.Join(unit, "extra.tf")}
	e := New()
	e.SetUnitModuleFiles(map[string]UnitModule{unit: unitModule})
	return e, unit
}

func TestUnitAssetsShadowModuleAssets(t *testing.T) {
	e, unit := assetFixture(t, map[string]string{"acl.txt": "public-read", "unit.txt": "u"}, UnitModule{})
	for _, name := range []string{"main", "extra"} {
		r := resourceNamed(t, e, unit, name)
		require.NotNil(t, r, name)
		require.Equal(t, "public-read", r.Attributes["acl"].AsString(), "%s reads the unit's copy", name)
	}
	require.Equal(t, "acl.txt,module.txt,unit.txt", resourceNamed(t, e, unit, "main").Attributes["bucket"].AsString())
}

func TestUnitAssetsHonorCopyFilters(t *testing.T) {
	e, unit := assetFixture(t, map[string]string{"acl.txt": "public-read", ".hidden.txt": "h", "skip.txt": "s"},
		UnitModule{ExcludeFromCopy: []string{"acl.txt", "skip.txt"}})
	main := resourceNamed(t, e, unit, "main")
	require.Equal(t, "private", main.Attributes["acl"].AsString(), "an excluded asset is not copied")
	require.Equal(t, "acl.txt,module.txt", main.Attributes["bucket"].AsString(), "hidden and excluded files are not seen")

	e, unit = assetFixture(t, map[string]string{".hidden.txt": "h"}, UnitModule{IncludeInCopy: []string{".hidden.txt"}})
	require.Contains(t, resourceNamed(t, e, unit, "main").Attributes["bucket"].AsString(), ".hidden.txt")
}

func TestUnitAssetsDoNotLeakToOtherCallers(t *testing.T) {
	e, unit := assetFixture(t, map[string]string{"acl.txt": "public-read"}, UnitModule{})
	root := filepath.Dir(unit)
	other := writeModule(t, root, "other", map[string]string{"main.tf": `module "m" { source = "../mod" }`})
	require.NotNil(t, resourceNamed(t, e, unit, "main"))
	r := resourceNamed(t, e, other, "main")
	require.Equal(t, "private", r.Attributes["acl"].AsString())
}

func TestUnitAssetsWithoutUnitTerraformFiles(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "mod", map[string]string{
		"main.tf": `resource "aws_s3_bucket" "main" { acl = file("${path.module}/acl.txt") }`,
		"acl.txt": "private",
	})
	unit := writeModule(t, root, "unit", map[string]string{
		"terragrunt.generated.tf": `module "terragrunt" { source = "../mod" }`,
		"acl.txt":                 "public-read",
	})
	e := New()
	e.SetUnitModuleFiles(map[string]UnitModule{unit: {}})
	require.Equal(t, "public-read", resourceNamed(t, e, unit, "main").Attributes["acl"].AsString())
}

func TestUnitIncludedHiddenDirectoryIsListed(t *testing.T) {
	e, unit := assetFixture(t, map[string]string{".assets/acl.txt": "public-read", ".assets/other.txt": "o"},
		UnitModule{IncludeInCopy: []string{".assets/acl.txt"}})
	r := resourceNamed(t, e, unit, "main")
	require.NotNil(t, r)
	require.Equal(t, ".assets/acl.txt,acl.txt,module.txt", r.Attributes["bucket"].AsString())
}
