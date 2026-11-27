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
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An unknown input reaches the module as an unknown value, never as a known
// string: the placeholder is a reference the evaluator cannot resolve.
func TestTranslatePlaceholderEvaluatesToUnknown(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": `terraform {
  source = "./m"
}
inputs = {
  acl  = get_env("X")
  tags = { team = local.team, env = "prod" }
}
`})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	file, diags := hclsyntax.ParseConfig([]byte(tr.Text), "t.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors(), diags.Error())
	attrs := file.Body.(*hclsyntax.Body).Blocks[0].Body.Attributes
	ctx := &hcl.EvalContext{}
	assert.False(t, partial.WithUnknownRefs(attrs["acl"].Expr, ctx).IsKnown(), "acl must be unknown")
	assert.False(t, partial.WithUnknownRefs(attrs["tags"].Expr, ctx).IsWhollyKnown(), "tags.team must be unknown")
}

// repo writes files (relative paths) under a temporary repository root.
func repo(t *testing.T, files map[string]string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
	}
	return root
}

func translate(t *testing.T, root, unit string) *model.TerragruntTranslation {
	t.Helper()
	return evaluateUnit(t, root, unit).Translation
}

func TestTranslateLiterals(t *testing.T) {
	root := repo(t, map[string]string{"live/terragrunt.hcl": `
terraform {
  source = "../modules/bucket"
}

inputs = {
  acl     = "public-read"
  count_n = 3
  enabled = true
  tags    = { env = "prod", team = upper("infra") }
  cidrs   = ["10.0.0.0/8", "172.16.0.0/12"]
}
`})
	tr := translate(t, root, "live")
	require.NotNil(t, tr)
	assert.Equal(t, VirtualFileName, tr.FileName)
	text := tr.Text
	assert.True(t, strings.HasPrefix(text, "module \"terragrunt\" {\n  source"), text)
	assert.Contains(t, text, `"public-read"`)
	assert.Contains(t, text, `["10.0.0.0/8", "172.16.0.0/12"]`)
	assert.Contains(t, text, "= 3\n")
	assert.Contains(t, text, "= true\n")
	assert.Contains(t, text, `"INFRA"`)
	assert.True(t, strings.HasSuffix(text, "}\n"))
}

func TestTranslatePlaceholders(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": `
terraform { source = "../m" }
inputs = {
  from_local = local.x
  dep        = dependency.vpc.outputs.id
  nested = {
    known   = "a"
    unknown = local.y
    list    = ["ok", local.z]
  }
  partial = "prefix-${local.x}"
  broken  = file("../../outside.txt")
}
`})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	placeholder := `"${__dd_unknown__}"`
	for _, want := range []string{
		"from_local = " + placeholder,
		"dep = " + placeholder,
		`known   = "a"`,
		"unknown = " + placeholder,
		`list    = ["ok", ` + placeholder + `]`,
		"partial = " + placeholder,
		"broken = " + placeholder,
	} {
		assert.Contains(t, tr.Text, want)
	}
}

func TestTranslateSkipCases(t *testing.T) {
	tests := map[string]string{
		"no terraform block":    `inputs = { a = 1 }`,
		"no source":             "terraform {}\ninputs = { a = 1 }",
		"unknown source":        "terraform { source = local.s }\ninputs = { a = 1 }",
		"non-string source":     "terraform { source = 3 }",
		"unknown whole inputs":  "terraform { source = \"../m\" }\ninputs = local.all",
		"inputs not an object":  "terraform { source = \"../m\" }\ninputs = \"x\"",
		"inputs function fails": "terraform { source = \"../m\" }\ninputs = merge(local.a, { b = 1 })",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			root := repo(t, map[string]string{"u/terragrunt.hcl": content})
			assert.Nil(t, translate(t, root, "u"))
		})
	}
}

func TestTranslateSyntaxError(t *testing.T) {
	root := repo(t, nil)
	path := filepath.Join(root, "terragrunt.hcl")
	tr, err := Translate(context.Background(), vfs.DiskFS{}, root, path, []byte("terraform {"), nil)
	assert.Nil(t, tr)
	assert.Error(t, err)
}

func TestTranslateWithoutInputsKeepsModuleDefaults(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": `terraform { source = "../m" }`})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	assert.Equal(t, "module \"terragrunt\" {\n  source = \"../m\"\n}\n", tr.Text)
}

func TestTranslateDropsInvalidNames(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": `
terraform { source = "../m" }
inputs = {
  "not valid" = 1
  count       = 2
  ok          = 3
}
`})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	assert.Equal(t, "module \"terragrunt\" {\n  source = \"../m\"\n  ok = 3\n}\n", tr.Text)
}

func TestTranslateTfvarsOverrideInputs(t *testing.T) {
	root := repo(t, map[string]string{
		"live/terragrunt.hcl": `
terraform { source = "../modules/bucket" }
inputs = {
  acl    = "public-read"
  region = "eu"
  keepme = "from inputs"
}`,
		"live/terraform.tfvars":        `acl = "private"`,
		"live/zz.auto.tfvars":          `region = "us"`,
		"live/aa.auto.tfvars":          `region = "ap"`,
		"live/ignored.tfvars":          `keepme = "never loaded"`,
		"modules/bucket/main.tf":       ``,
		"modules/bucket/b.auto.tfvars": `extra = "from module"`,
	})
	tr := translate(t, root, "live")
	require.NotNil(t, tr)
	text := tr.Text
	assert.Contains(t, text, `acl = "private"`)
	assert.Contains(t, text, `region = "us"`, "the last auto file wins")
	assert.Contains(t, text, `keepme = "from inputs"`)
	assert.Contains(t, text, `extra = "from module"`)

	acl, ok := tr.Lines.Argument("acl")
	require.True(t, ok)
	assert.Equal(t, filepath.Join(root, "live", "terraform.tfvars"), acl.Real.Filename)
	keep, ok := tr.Lines.Argument("keepme")
	require.True(t, ok)
	assert.Equal(t, filepath.Join(root, "live", "terragrunt.hcl"), keep.Real.Filename)
	extra, ok := tr.Lines.Argument("extra")
	require.True(t, ok)
	assert.Equal(t, filepath.Join(root, "modules", "bucket", "b.auto.tfvars"), extra.Real.Filename)
}

func TestTranslateUnitFileReplacesModuleFileOfSameName(t *testing.T) {
	root := repo(t, map[string]string{
		"live/terragrunt.hcl":             `terraform { source = "../modules/bucket" }`,
		"live/terraform.tfvars":           `own = "unit"`,
		"modules/bucket/terraform.tfvars": "own = \"module\"\nother = \"module\"",
	})
	tr := translate(t, root, "live")
	require.NotNil(t, tr)
	assert.Contains(t, tr.Text, `own = "unit"`)
	assert.NotContains(t, tr.Text, "other")
}

func TestTranslateRemoteModuleIgnoresModuleTfvars(t *testing.T) {
	root := repo(t, map[string]string{
		"live/terragrunt.hcl":   `terraform { source = "git::https://example.invalid/m.git//x?ref=v1" }`,
		"live/auto.auto.tfvars": `a = 1`,
	})
	tr := translate(t, root, "live")
	require.NotNil(t, tr)
	assert.Contains(t, tr.Text, `"git::https://example.invalid/m.git//x?ref=v1"`)
	assert.Contains(t, tr.Text, "a = 1")
}

func TestTranslateConfinesModuleTfvarsToRepository(t *testing.T) {
	outside := repo(t, map[string]string{"mod/terraform.tfvars": `leak = "outside"`})
	root := repo(t, map[string]string{"live/terragrunt.hcl": `terraform { source = "` + outside + `/mod" }`})
	tr := translate(t, root, "live")
	require.NotNil(t, tr)
	assert.NotContains(t, tr.Text, "leak")
}

func TestTranslateJSONTfvars(t *testing.T) {
	root := repo(t, map[string]string{
		"u/terragrunt.hcl":        `terraform { source = "../m" }`,
		"u/terraform.tfvars.json": `{"names": ["a", "b"], "n": 2}`,
	})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	assert.Contains(t, tr.Text, `names = ["a", "b"]`)
	assert.Contains(t, tr.Text, `n = 2`)
}

func TestTranslateLineTable(t *testing.T) {
	root := repo(t, map[string]string{"u/terragrunt.hcl": `terraform {
  source = "../m"
}

inputs = {
  a = "x"
  obj = {
    k = 1
  }
}
`})
	tr := translate(t, root, "u")
	require.NotNil(t, tr)
	unit := filepath.Join(root, "u", "terragrunt.hcl")

	lines := strings.Split(strings.TrimSuffix(tr.Text, "\n"), "\n")
	assert.Equal(t, len(lines), tr.Lines[len(tr.Lines)-1].ToLine, "the table covers every virtual line")
	prev := 0
	for _, m := range tr.Lines {
		assert.Equal(t, prev+1, m.FromLine, "mappings are contiguous")
		prev = m.ToLine
	}

	anchor, ok := tr.Lines.Anchor()
	require.True(t, ok)
	assert.Equal(t, model.SourceLocation{Filename: unit, LineStart: 2, ColumnStart: 3, LineEnd: 2, ColumnEnd: 18}, anchor.Real)
	assert.Equal(t, 1, anchor.FromLine)

	src, ok := tr.Lines.Argument("source")
	require.True(t, ok)
	assert.Equal(t, anchor.Real, src.Real)

	a, ok := tr.Lines.Argument("a")
	require.True(t, ok)
	assert.Equal(t, model.SourceLocation{Filename: unit, LineStart: 6, ColumnStart: 3, LineEnd: 6, ColumnEnd: 10}, a.Real)

	obj, ok := tr.Lines.Argument("obj")
	require.True(t, ok)
	assert.Equal(t, 7, obj.Real.LineStart)
	assert.Equal(t, 9, obj.Real.LineEnd)
	assert.Greater(t, obj.ToLine, obj.FromLine, "a nested value spans several virtual lines")
	for l := obj.FromLine; l <= obj.ToLine; l++ {
		m, ok := tr.Lines.Lookup(l)
		require.True(t, ok)
		assert.Equal(t, "obj", m.Argument)
	}
	_, ok = tr.Lines.Lookup(len(lines) + 1)
	assert.False(t, ok)
}

func TestTranslateMemFS(t *testing.T) {
	fsys := vfs.NewMemFS(map[string][]byte{
		"/repo/live/terraform.tfvars": []byte(`acl = "private"`),
	})
	src := []byte(`
terraform { source = "../m" }
inputs = { acl = "public-read" }
`)
	tr, err := Translate(context.Background(), fsys, "/repo", "/repo/live/terragrunt.hcl", src, nil)
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.Contains(t, tr.Text, `acl = "private"`)
}

func TestTranslateReadsTfvarsFromEngineResolvedModuleDir(t *testing.T) {
	root := repo(t, map[string]string{
		".git/HEAD":                       "ref: refs/heads/main",
		"live/terragrunt.hcl":             `terraform { source = "file:///build/app/modules/bucket" }`,
		"modules/bucket/terraform.tfvars": `from_module = "yes"`,
	})
	// /build/app/modules/bucket does not exist: the engine falls back to the repository suffix.
	tr := translate(t, root, "live")
	require.NotNil(t, tr)
	assert.Contains(t, tr.Text, `from_module = "yes"`)
}

func TestTranslateAbsoluteAndDotSources(t *testing.T) {
	root := repo(t, map[string]string{
		"abs/terragrunt.hcl":    "",
		"mod/terraform.tfvars":  `m = 1`,
		"dot/terragrunt.hcl":    `terraform { source = "." }`,
		"dot/terraform.tfvars":  `d = 1`,
		"dot/other.auto.tfvars": `o = 1`,
	})
	require.NoError(t, os.WriteFile(filepath.Join(root, "abs", "terragrunt.hcl"),
		[]byte(`terraform { source = "`+filepath.ToSlash(filepath.Join(root, "mod"))+`" }`), 0o600))
	tr := translate(t, root, "abs")
	require.NotNil(t, tr)
	assert.Contains(t, tr.Text, "m = 1")

	tr = translate(t, root, "dot")
	require.NotNil(t, tr)
	assert.Contains(t, tr.Text, "d = 1")
	assert.Contains(t, tr.Text, "o = 1")
}

func TestTranslateRegistrySources(t *testing.T) {
	cases := []struct {
		name, source, wantSource, wantVersion string
	}{
		{"public", "tfr:///terraform-aws-modules/s3-bucket/aws?version=4.1.2", "terraform-aws-modules/s3-bucket/aws", "4.1.2"},
		{"submodule", "tfr:///ns/name/aws//modules/sub?version=1.0.0", "ns/name/aws//modules/sub", "1.0.0"},
		{"host", "tfr://registry.example.invalid/ns/name/aws//sub?version=2.0.0", "registry.example.invalid/ns/name/aws//sub", "2.0.0"},
		{"no version", "tfr:///ns/name/aws", "ns/name/aws", ""},
		{"git unchanged", "git::https://example.invalid/m.git?ref=v1", "git::https://example.invalid/m.git?ref=v1", ""},
		{"https unchanged", "https://example.invalid/m.zip", "https://example.invalid/m.zip", ""},
		{"registry address unchanged", "ns/name/aws", "ns/name/aws", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := repo(t, map[string]string{"u/terragrunt.hcl": "terraform {\n  source = \"" + tc.source + "\"\n}\ninputs = { a = 1 }\n"})
			tr := translate(t, root, "u")
			require.NotNil(t, tr)
			assert.Contains(t, tr.Text, `source = "`+tc.wantSource+`"`)
			if tc.wantVersion == "" {
				assert.NotContains(t, tr.Text, "version")
				return
			}
			assert.Contains(t, tr.Text, `version = "`+tc.wantVersion+`"`)
			m, ok := tr.Lines.Argument("version")
			require.True(t, ok)
			src, _ := tr.Lines.Argument("source")
			assert.Equal(t, src.Real, m.Real)
			assert.Equal(t, 2, m.Real.LineStart)
		})
	}
}

const remoteUnit = "terraform {\n  source = \"git::https://example.invalid/m.git\"\n}\ninputs = {\n  acl = \"private\"\n  own = \"input\"\n}\n"

func translateWithFetched(t *testing.T, root string, dirs ModuleDirs) *model.TerragruntTranslation {
	t.Helper()
	path := filepath.Join(root, "live", "terragrunt.hcl")
	tr, err := Translate(context.Background(), vfs.DiskFS{}, root, path, []byte(remoteUnit), dirs)
	require.NoError(t, err)
	require.NotNil(t, tr)
	return tr
}

func TestTranslateFetchedModuleTfvars(t *testing.T) {
	root := repo(t, map[string]string{"live/terragrunt.hcl": remoteUnit})
	fetched, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(fetched, "terraform.tfvars"), []byte(`acl = "public-read"`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(fetched, "b.auto.tfvars"), []byte(`extra = "from module"`), 0o600))
	// A symlink leaving the fetched module is not followed.
	secret := filepath.Join(t.TempDir(), "secret.tfvars")
	require.NoError(t, os.WriteFile(secret, []byte(`leak = "x"`), 0o600))
	require.NoError(t, os.Symlink(secret, filepath.Join(fetched, "c.auto.tfvars")))

	var got [3]string
	tr := translateWithFetched(t, root, func(callerRoot, source, version string) string {
		got = [3]string{callerRoot, source, version}
		return fetched
	})
	assert.Equal(t, [3]string{filepath.Join(root, "live"), "git::https://example.invalid/m.git", ""}, got)
	assert.Contains(t, tr.Text, `acl = "public-read"`, "the fetched tfvars override the input")
	assert.Contains(t, tr.Text, `extra = "from module"`)
	assert.Contains(t, tr.Text, `own = "input"`)
	assert.NotContains(t, tr.Text, "leak")

	unit := filepath.Join(root, "live", "terragrunt.hcl")
	source, ok := tr.Lines.Argument("source")
	require.True(t, ok)
	for _, name := range []string{"acl", "extra"} {
		m, ok := tr.Lines.Argument(name)
		require.True(t, ok)
		assert.Equal(t, unit, m.Real.Filename, "mapped into the repository")
		assert.Equal(t, source.Real, m.Real, "at the source attribute")
	}
}

func TestTranslateRemoteWithoutFetchedModuleIsUnchanged(t *testing.T) {
	root := repo(t, map[string]string{"live/terragrunt.hcl": remoteUnit})
	for name, dirs := range map[string]ModuleDirs{
		"nil lookup":   nil,
		"not fetched":  func(string, string, string) string { return "" },
		"empty module": func(string, string, string) string { return t.TempDir() },
	} {
		t.Run(name, func(t *testing.T) {
			tr := translateWithFetched(t, root, dirs)
			assert.Contains(t, tr.Text, `acl = "private"`)
			assert.NotContains(t, tr.Text, "extra")
		})
	}
}
