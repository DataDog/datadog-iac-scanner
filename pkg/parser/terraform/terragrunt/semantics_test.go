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
	"regexp"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const unknownRef = `"${__dd_unknown__}"`

// rootHCL is the common layout: a root file computing the module source from
// the unit's path and providing shared inputs.
const rootHCL = `locals {
  region = "eu-west-1"
}
terraform {
  source = "${get_parent_terragrunt_dir()}/modules//bucket"
}
inputs = {
  region = local.region
  tags   = { owner = "platform", env = "unknown" }
  unit   = path_relative_to_include()
}
`

func squash(s string) string { return regexp.MustCompile(` +`).ReplaceAllString(s, " ") }

// has checks that text contains want, ignoring runs of spaces (alignment).
func has(t *testing.T, text, want string, msg ...any) {
	t.Helper()
	assert.Contains(t, squash(text), squash(want), msg...)
}

func hasNot(t *testing.T, text, want string, msg ...any) {
	t.Helper()
	assert.NotContains(t, squash(text), squash(want), msg...)
}

const includeRoot = `include "root" {
  path = find_in_parent_folders("root.hcl")
}
`

// find_in_parent_folders matches directories too, e.g. a source tree root.
func TestFindInParentFoldersMatchesDirectories(t *testing.T) {
	root := repo(t, map[string]string{
		"src/modules/bucket/main.tf": ``,
		"live/app/terragrunt.hcl":    "terraform {\n  source = \"${find_in_parent_folders(\"src\")}//modules/bucket\"\n}\n",
	})
	tr := translate(t, root, "live/app")
	require.NotNil(t, tr)
	has(t, tr.Text, `source = "../../src/modules/bucket"`)
}

func TestIncludeShallowMerge(t *testing.T) {
	root := repo(t, map[string]string{
		"root.hcl":                   rootHCL,
		"modules/bucket/main.tf":     ``,
		"prod/bucket/terragrunt.hcl": includeRoot + "inputs = {\n  tags = { env = \"prod\" }\n  own = 1\n}\n",
	})
	tr := translate(t, root, "prod/bucket")
	require.NotNil(t, tr)
	has(t, tr.Text, `source = "../../modules/bucket"`, "absolute source with // becomes relative")
	has(t, tr.Text, `region = "eu-west-1"`)
	has(t, tr.Text, `unit   = "prod/bucket"`, "path functions describe the unit")
	has(t, tr.Text, `env = "prod"`)
	hasNot(t, tr.Text, "owner", "shallow: the child's tags replace the parent's")
	has(t, tr.Text, "own = 1")
}

func TestIncludeDeepMerge(t *testing.T) {
	root := repo(t, map[string]string{
		"root.hcl": `inputs = {
  tags  = { owner = "platform", env = "unknown" }
  cidrs = ["10.0.0.0/16"]
  name  = "root"
}`,
		"prod/terragrunt.hcl": `include {
  path           = find_in_parent_folders("root.hcl")
  merge_strategy = "deep"
}
terraform { source = "../m" }
inputs = {
  tags  = { env = "prod" }
  cidrs = ["192.168.0.0/16"]
  name  = "unit"
}`,
	})
	tr := translate(t, root, "prod")
	require.NotNil(t, tr)
	has(t, tr.Text, `owner = "platform"`)
	has(t, tr.Text, `env   = "prod"`)
	has(t, tr.Text, `"10.0.0.0/16"`)
	has(t, tr.Text, `"192.168.0.0/16"`)
	has(t, tr.Text, `name = "unit"`)
}

func TestIncludeNoMerge(t *testing.T) {
	root := repo(t, map[string]string{
		"root.hcl": `inputs = { a = 1, b = 2 }
terraform { source = "../root-module" }`,
		"u/terragrunt.hcl": `include "root" {
  path           = find_in_parent_folders("root.hcl")
  merge_strategy = "no_merge"
}
terraform { source = "../m" }
inputs = { c = 3 }`,
	})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `source = "../m"`)
	has(t, tr.Text, "c = 3")
	hasNot(t, tr.Text, "a = 1")
	hasNot(t, tr.Text, "b = 2")
}

func TestIncludeExpose(t *testing.T) {
	root := repo(t, map[string]string{
		"root.hcl": `locals { env = "prod" }
terraform { source = "../m" }
inputs = { base = "x" }
`,
		"u/terragrunt.hcl": `include "root" {
  path   = find_in_parent_folders("root.hcl")
  expose = true
}
include "hidden" {
  path           = find_in_parent_folders("root.hcl")
  merge_strategy = "no_merge"
}
inputs = {
  env    = include.root.locals.env
  base   = include.root.inputs.base
  source = include.root.terraform.source
  nope   = include.hidden.locals.env
}`,
	})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `env  = "prod"`)
	has(t, tr.Text, `base = "x"`)
	has(t, tr.Text, `nope = `+unknownRef, "a file included without expose is not readable")
}

func TestIncludeUnlabeledExpose(t *testing.T) {
	root := repo(t, map[string]string{
		"root.hcl": "locals { env = \"prod\" }\nterraform { source = \"../m\" }",
		"u/terragrunt.hcl": `include {
  path   = find_in_parent_folders("root.hcl")
  expose = true
}
inputs = { env = include.locals.env }`,
	})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `env = "prod"`)
}

func TestIncludedFilePathFunctionsDescribeTheUnit(t *testing.T) {
	root := repo(t, map[string]string{
		"root.hcl": `terraform { source = "../m" }
inputs = {
  terragrunt_dir = get_terragrunt_dir()
  parent_dir     = get_parent_terragrunt_dir()
  original_dir   = get_original_terragrunt_dir()
  repo_root      = get_repo_root()
  from_root      = get_path_from_repo_root()
  to_root        = get_path_to_repo_root()
  rel_to         = path_relative_to_include("root")
  rel_from       = path_relative_from_include("root")
}`,
		"live/prod/terragrunt.hcl": `include "root" {
  path = find_in_parent_folders("root.hcl")
}`,
	})
	tr := translate(t, root, "live/prod")
	require.NotNil(t, tr)
	for _, want := range []string{
		`terragrunt_dir = "` + filepath.Join(root, "live/prod") + `"`,
		`parent_dir     = "` + root + `"`,
		`original_dir   = "` + filepath.Join(root, "live/prod") + `"`,
		`repo_root      = "` + root + `"`,
		`from_root      = "live/prod"`,
		`to_root        = "../.."`,
		`rel_to         = "live/prod"`,
		`rel_from       = "../.."`,
	} {
		has(t, tr.Text, want)
	}
}

func TestIncludedFilesOwnIncludesAreIgnored(t *testing.T) {
	root := repo(t, map[string]string{
		"root.hcl": `include "other" {
  path = "other.hcl"
}
terraform { source = "../m" }
inputs = { a = 1 }`,
		"other.hcl":        `inputs = { leaked = 1 }`,
		"u/terragrunt.hcl": includeRoot,
	})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, "a = 1")
	hasNot(t, tr.Text, "leaked")
}

func TestIncludeFailureSkipsTheUnit(t *testing.T) {
	outside := repo(t, map[string]string{"root.hcl": `terraform { source = "../m" }`})
	tests := map[string]string{
		"missing file":    "include {\n  path = \"../nope.hcl\"\n}\nterraform { source = \"../m\" }",
		"unknown path":    "include {\n  path = local.x\n}\nterraform { source = \"../m\" }",
		"outside repo":    "include {\n  path = \"" + filepath.Join(outside, "root.hcl") + "\"\n}\nterraform { source = \"../m\" }",
		"bad strategy":    "include {\n  path = \"../root.hcl\"\n  merge_strategy = \"x\"\n}\nterraform { source = \"../m\" }",
		"syntax in other": "include {\n  path = \"../bad.hcl\"\n}\nterraform { source = \"../m\" }",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			root := repo(t, map[string]string{
				"root.hcl": `inputs = { a = 1 }`, "bad.hcl": "inputs = {",
				"u/terragrunt.hcl": content,
			})
			assert.Nil(t, translate(t, root, "u"))
		})
	}
}

func TestIncludeMultipleLaterWins(t *testing.T) {
	root := repo(t, map[string]string{
		"a.hcl": "inputs = { x = \"a\", only_a = 1 }\nterraform { source = \"../m\" }",
		"b.hcl": "inputs = { x = \"b\" }",
		"u/terragrunt.hcl": `include "a" {
  path = "../a.hcl"
}
include "b" {
  path = "../b.hcl"
}`,
	})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `x      = "b"`)
	has(t, tr.Text, "only_a = 1")
}

func TestFindInParentFolders(t *testing.T) {
	root := repo(t, map[string]string{
		"terragrunt.hcl": `terraform { source = "../nope" }`,
		"a/env.hcl":      `locals { env = "a" }`,
		"a/b/c/terragrunt.hcl": `terraform { source = "../m" }
locals {
  env      = read_terragrunt_config(find_in_parent_folders("env.hcl")).locals.env
  fallback = find_in_parent_folders("missing.hcl", "fb")
  default  = find_in_parent_folders()
  missing  = find_in_parent_folders("missing.hcl")
}
inputs = {
  env      = local.env
  fallback = local.fallback
  default  = local.default
  missing  = local.missing
}`,
	})
	tr := translate(t, root, "a/b/c")
	require.NotNil(t, tr)
	has(t, tr.Text, `env      = "a"`)
	has(t, tr.Text, `fallback = "fb"`)
	has(t, tr.Text, `default  = "`+filepath.Join(root, "terragrunt.hcl")+`"`)
	has(t, tr.Text, `missing  = `+unknownRef)
}

func TestFindInParentFoldersStopsAtRepositoryRoot(t *testing.T) {
	parent := repo(t, map[string]string{
		"outside.hcl": `x = 1`,
		"repo/u/terragrunt.hcl": `terraform { source = "../m" }
inputs = { found = find_in_parent_folders("outside.hcl", "none") }`,
	})
	root := filepath.Join(parent, "repo")
	path := filepath.Join(root, "u", "terragrunt.hcl")
	src, err := os.ReadFile(path)
	require.NoError(t, err)
	tr, err := Translate(context.Background(), vfs.DiskFS{}, root, path, src, nil)
	require.NoError(t, err)
	require.NotNil(t, tr)
	has(t, tr.Text, `found = "none"`)
}

func TestFindInParentFoldersIgnoresSymlinkLeavingRepository(t *testing.T) {
	parent := repo(t, map[string]string{
		"outside/env.hcl": `locals { env = "outside" }`,
		"repo/u/terragrunt.hcl": `terraform { source = "../m" }
inputs = { found = find_in_parent_folders("env.hcl", "none") }`,
	})
	root := filepath.Join(parent, "repo")
	require.NoError(t, os.Symlink(filepath.Join(parent, "outside", "env.hcl"), filepath.Join(root, "env.hcl")))
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `found = "none"`)
}

func TestReadTerragruntConfig(t *testing.T) {
	root := repo(t, map[string]string{
		"common.hcl": `locals {
  name = "common"
  dir  = get_terragrunt_dir()
  orig = get_original_terragrunt_dir()
}
inputs = { shared = "yes" }`,
		"u/terragrunt.hcl": `locals {
  c = read_terragrunt_config("../common.hcl")
  d = read_terragrunt_config("../absent.hcl", { locals = { name = "dflt" } })
}
terraform { source = "../m" }
inputs = {
  name   = local.c.locals.name
  dir    = local.c.locals.dir
  orig   = local.c.locals.orig
  shared = local.c.inputs.shared
  dflt   = local.d.locals.name
}`,
	})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `name   = "common"`)
	has(t, tr.Text, `dir    = "`+root+`"`, "the read file is its own unit")
	has(t, tr.Text, `orig   = "`+filepath.Join(root, "u")+`"`, "the original dir is the unit")
	has(t, tr.Text, `shared = "yes"`)
	has(t, tr.Text, `dflt   = "dflt"`)
}

func TestReadTerragruntConfigCycleAndDepth(t *testing.T) {
	root := repo(t, map[string]string{
		"a.hcl": `locals { b = read_terragrunt_config("b.hcl") }
inputs = { v = local.b.locals.back.inputs.v }`,
		"b.hcl": `locals { back = read_terragrunt_config("a.hcl", { inputs = { v = "cycle" } }) }`,
		"u/terragrunt.hcl": `locals { a = read_terragrunt_config("../a.hcl") }
terraform { source = "../m" }
inputs = {
  ok    = "fine"
  cycle = local.a.inputs.v
  self  = read_terragrunt_config("terragrunt.hcl", "self")
}`,
	})
	tr := translate(t, root, "u")
	require.NotNil(t, tr, "a cycle does not fail the unit")
	has(t, tr.Text, `ok    = "fine"`)
	has(t, tr.Text, `cycle = "cycle"`)
	has(t, tr.Text, `self  = "self"`, "the unit cannot read itself")
}

func TestReadTerragruntConfigIsConfined(t *testing.T) {
	outside := repo(t, map[string]string{"x.hcl": `locals { v = "outside" }`})
	root := repo(t, map[string]string{"u/terragrunt.hcl": `terraform { source = "../m" }
inputs = { v = read_terragrunt_config("` + filepath.Join(outside, "x.hcl") + `", "none") }`})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `v = "none"`)
}

func TestReadTfvarsFile(t *testing.T) {
	root := repo(t, map[string]string{
		"vars.tfvars":      "region = \"eu\"\nzones = [\"a\", \"b\"]\n",
		"vars.tfvars.json": `{"n": 2}`,
		"u/terragrunt.hcl": `terraform { source = "../m" }
inputs = {
  raw    = read_tfvars_file("../vars.tfvars")
  region = jsondecode(read_tfvars_file("../vars.tfvars")).region
  n      = jsondecode(read_tfvars_file("../vars.tfvars.json")).n
}`,
	})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `region = "eu"`)
	has(t, tr.Text, `n      = 2`)
	has(t, tr.Text, `{\"region\":\"eu\",\"zones\":[\"a\",\"b\"]}`, "the result is JSON text")
}

func TestLocalsReadThroughIndex(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": `locals {
  b = "${local["a"]}-b"
  a = "a"
}
terraform { source = "../m" }
inputs = {
  b = local["b"]
}`})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `b = "a-b"`)
}

func TestLocalSourceWithGetterPrefixIsKept(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": `terraform { source = "file://../m" }`})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `source = "file://../m"`)
}

func TestLocalsDependencyOrderAndCycle(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": `locals {
  c = "${local.b}-c"
  b = "${local.a}-b"
  a = "a"
  x = local.y
  y = local.x
  z = "${local.x}-z"
  fine = "fine"
}
terraform { source = "../m" }
inputs = {
  c    = local.c
  x    = local.x
  z    = local.z
  fine = local.fine
  miss = local.nothing
}`})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `c    = "a-b-c"`)
	has(t, tr.Text, `fine = "fine"`)
	for _, name := range []string{"x   ", "z   ", "miss"} {
		has(t, tr.Text, name+" = "+unknownRef)
	}
}

func TestFeatureDefault(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": `feature "flag" {
  default = true
}
terraform { source = "../m" }
inputs = {
  enabled = feature.flag.value
  other   = feature.nope.value
}`})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `enabled = true`)
	has(t, tr.Text, `other   = `+unknownRef)
}

func TestGetEnvNeverReadsTheEnvironment(t *testing.T) {
	t.Setenv("DD_TEST_TERRAGRUNT_ENV", "from-env")
	root := repo(t, map[string]string{"u/terragrunt.hcl": `terraform { source = "../m" }
inputs = {
  with_default = get_env("DD_TEST_TERRAGRUNT_ENV", "default")
  no_default   = get_env("DD_TEST_TERRAGRUNT_ENV")
  home         = get_env("HOME")
}`})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `with_default = "default"`)
	has(t, tr.Text, `no_default   = `+unknownRef)
	has(t, tr.Text, `home         = `+unknownRef)
	hasNot(t, tr.Text, "from-env")
}

func TestRunTimeFunctionsAndDependenciesAreUnknown(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": `terraform { source = "../m" }
inputs = {
  a = run_cmd("echo", "x")
  b = sops_decrypt_file("x.yaml")
  c = get_aws_account_id()
  d = get_aws_account_alias()
  e = get_aws_caller_identity_arn()
  f = get_aws_caller_identity_user_id()
  g = get_platform()
  h = get_working_dir()
  i = dependency.vpc.outputs.id
  j = values.name
  k = "prefix-${run_cmd("x")}"
  ok = "ok"
}`})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"} {
		has(t, tr.Text, "  "+name+"  = "+unknownRef)
	}
	has(t, tr.Text, `ok = "ok"`)
}

func TestCommandFunctions(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": `terraform { source = "../m" }
inputs = {
  cmd     = get_terraform_command()
  args    = get_terraform_cli_args()
  vars    = get_terraform_commands_that_need_vars()
  lock    = get_terraform_commands_that_need_locking()
  input   = get_terraform_commands_that_need_input()
  par     = get_terraform_commands_that_need_parallelism()
  retry   = get_default_retryable_errors()
  marked  = mark_as_read("f.txt")
  globbed = mark_glob_as_read("*.txt")
}`})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `cmd     = "plan"`)
	has(t, tr.Text, `args    = []`)
	has(t, tr.Text, `"apply", "console", "destroy"`)
	has(t, tr.Text, `marked  = "f.txt"`)
	has(t, tr.Text, `globbed = "*.txt"`)
	hasNot(t, tr.Text, "retry   = "+unknownRef)
}

func TestFileFunctionsAreConfined(t *testing.T) {
	outside := repo(t, map[string]string{"secret.txt": "s3cret"})
	root := repo(t, map[string]string{
		"data.txt": "inside",
		"u/terragrunt.hcl": `terraform { source = "../m" }
inputs = {
  inside  = file("../data.txt")
  outside = file("` + filepath.Join(outside, "secret.txt") + `")
}`,
	})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `inside  = "inside"`)
	has(t, tr.Text, `outside = `+unknownRef)
}

func TestSkipAndExclude(t *testing.T) {
	tests := map[string]struct {
		content string
		skipped bool
	}{
		"skip true":            {"skip = true", true},
		"skip false":           {"skip = false", false},
		"skip unknown":         {"skip = get_env(\"X\")", false},
		"skip from local":      {"locals { s = true }\nskip = local.s", true},
		"exclude plan":         {"exclude {\n  if = true\n  actions = [\"plan\"]\n}", true},
		"exclude all":          {"exclude {\n  if = true\n  actions = [\"all\"]\n}", true},
		"exclude apply":        {"exclude {\n  if = true\n  actions = [\"apply\"]\n}", true},
		"exclude if false":     {"exclude {\n  if = false\n  actions = [\"all\"]\n}", false},
		"exclude if unknown":   {"exclude {\n  if = get_env(\"X\")\n  actions = [\"all\"]\n}", false},
		"exclude destroy only": {"exclude {\n  if = true\n  actions = [\"destroy\"]\n}", false},
		"exclude unknown acts": {"exclude {\n  if = true\n  actions = local.nothing\n}", false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			root := repo(t, map[string]string{"u/terragrunt.hcl": "terraform { source = \"../m\" }\n" + tc.content})
			assert.Equal(t, tc.skipped, translate(t, root, "u") == nil)
		})
	}
}

// skip is not inherited (a root terragrunt.hcl commonly sets it to skip itself),
// while an exclude block of an included file applies to the unit.
func TestSkipIsNotInheritedButExcludeIs(t *testing.T) {
	root := repo(t, map[string]string{
		"skip/root.hcl":         "skip = true\nterraform { source = \"../m\" }",
		"skip/u/terragrunt.hcl": includeRoot,
		"skip/s/terragrunt.hcl": includeRoot + "\nskip = true",
		"excl/root.hcl":         "exclude {\n  if = true\n  actions = [\"all\"]\n}\nterraform { source = \"../m\" }",
		"excl/u/terragrunt.hcl": includeRoot,
	})
	assert.NotNil(t, translate(t, root, "skip/u"), "an included skip does not skip the unit")
	assert.Nil(t, translate(t, root, "skip/s"), "the unit's own skip does")
	assert.Nil(t, translate(t, root, "excl/u"), "an included exclude applies")
}

func TestFailingItemsDoNotHideOthers(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": `locals {
  obj  = { good = "g", bad = local.nothing, list = ["a", run_cmd("x"), "c"] }
  tup  = ["x", dependency.d.outputs.o]
  both = merge({ a = 1 }, { b = local.nothing, c = 3 })
}
terraform { source = "../m" }
inputs = {
  obj  = local.obj
  tup  = local.tup
  both = local.both
}`})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `good = "g"`)
	has(t, tr.Text, `bad  = `+unknownRef)
	has(t, tr.Text, `["a", `+unknownRef+`, "c"]`)
	has(t, tr.Text, `["x", `+unknownRef+`]`)
	has(t, tr.Text, `a = 1`)
	has(t, tr.Text, `c = 3`)
}

func TestSourceFromIncludedFileIsNormalized(t *testing.T) {
	root := repo(t, map[string]string{
		"root.hcl": `terraform {
  source = "${get_repo_root()}/modules//app"
}`,
		"live/u/terragrunt.hcl": includeRoot,
	})
	tr := translate(t, root, "live/u")
	require.NotNil(t, tr)
	has(t, tr.Text, `source = "../../modules/app"`)
}

func TestLineTableInIncludedFile(t *testing.T) {
	root := repo(t, map[string]string{
		"root.hcl": `locals {
  common = { shared = "c" }
}
terraform {
  source = "../m"
}
inputs = merge(
  local.common,
  {
    region = "eu"
    name   = "root"
  },
  { name = "root2" },
)
`,
		"u/terragrunt.hcl": includeRoot + `inputs = {
  own = 1
}
`,
	})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	rootFile := filepath.Join(root, "root.hcl")
	unit := filepath.Join(root, "u", "terragrunt.hcl")

	anchor, ok := tr.Lines.Anchor()
	require.True(t, ok)
	assert.Equal(t, rootFile, anchor.Real.Filename, "terraform.source set by the included file")
	assert.Equal(t, 5, anchor.Real.LineStart)

	region, ok := tr.Lines.Argument("region")
	require.True(t, ok)
	assert.Equal(t, rootFile, region.Real.Filename)
	assert.Equal(t, 10, region.Real.LineStart)

	name, ok := tr.Lines.Argument("name")
	require.True(t, ok)
	assert.Equal(t, 13, name.Real.LineStart, "the last literal setting wins")

	shared, ok := tr.Lines.Argument("shared")
	require.True(t, ok)
	assert.Equal(t, rootFile, shared.Real.Filename)
	assert.Equal(t, 7, shared.Real.LineStart, "a computed key maps to the inputs attribute")

	own, ok := tr.Lines.Argument("own")
	require.True(t, ok)
	assert.Equal(t, unit, own.Real.Filename)
	assert.Equal(t, 5, own.Real.LineStart)
}

func TestLineTableComputedKeyInUnit(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": `locals {
  common = { shared = "c" }
}
terraform { source = "../m" }
inputs = merge(local.common, { own = 1 })
`})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	unit := filepath.Join(root, "u", "terragrunt.hcl")
	shared, ok := tr.Lines.Argument("shared")
	require.True(t, ok)
	assert.Equal(t, unit, shared.Real.Filename)
	assert.Equal(t, 5, shared.Real.LineStart)
	own, ok := tr.Lines.Argument("own")
	require.True(t, ok)
	assert.Equal(t, 5, own.Real.LineStart)
	assert.Greater(t, own.Real.ColumnStart, shared.Real.ColumnStart)
}

func TestTfvarsStillOverrideIncludedInputs(t *testing.T) {
	root := repo(t, map[string]string{
		"root.hcl":           "terraform { source = \"../m\" }\ninputs = { acl = \"public-read\" }",
		"u/terragrunt.hcl":   includeRoot,
		"u/terraform.tfvars": `acl = "private"`,
		"m/main.tf":          ``,
	})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	has(t, tr.Text, `acl = "private"`)
	acl, _ := tr.Lines.Argument("acl")
	assert.Equal(t, filepath.Join(root, "u", "terraform.tfvars"), acl.Real.Filename)
}

func TestUnknownWholeInputsFromIncludeSkipsUnit(t *testing.T) {
	root := repo(t, map[string]string{
		"root.hcl":         "terraform { source = \"../m\" }\ninputs = local.nothing",
		"u/terragrunt.hcl": includeRoot + "inputs = { a = 1 }",
	})
	assert.Nil(t, translate(t, root, "u"))
}
