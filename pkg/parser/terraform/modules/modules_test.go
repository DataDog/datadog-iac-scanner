package tfmodules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/require"
)

func TestParseTerraformModules_LocalModuleOnDisk(t *testing.T) {
	tmpDir := t.TempDir()

	// Create local module directory and .tf file
	localModDir := filepath.Join(tmpDir, "local-mod")
	err := os.MkdirAll(localModDir, 0o755)
	if err != nil {
		t.Fatalf("failed to create local module dir: %v", err)
	}

	err = os.WriteFile(filepath.Join(localModDir, "main.tf"), []byte(`
variable "bucket_name" {
  type        = string
  description = "The name of the bucket"
}
`), 0o644)
	if err != nil {
		t.Fatalf("failed to write module main.tf: %v", err)
	}

	// Create root module with reference to local module
	mainTF := `
module "local_bucket" {
  source = "./local-mod"
}
`

	ctx := context.Background()
	files := model.FileMetadatas{
		&model.FileMetadata{
			FilePath:     filepath.Join(tmpDir, "main.tf"),
			OriginalData: mainTF,
			LinesOriginalData: &[]string{
				mainTF,
			},
		},
	}

	gotMap, err := ParseTerraformModules(ctx, nil, files, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expect only one parsed module
	if len(gotMap) != 1 {
		t.Fatalf("expected 1 module, got %d", len(gotMap))
	}

	var mod ParsedModule
	for _, m := range gotMap {
		mod = m
		break
	}

	expectedAbs := filepath.Clean(filepath.Join(tmpDir, "local-mod"))
	if mod.AbsSource != expectedAbs {
		t.Errorf("expected absolute source path %q, got %q", expectedAbs, mod.AbsSource)
	}
	if mod.Source != "./local-mod" {
		t.Errorf("expected original source to be \"./local-mod\", got %q", mod.Source)
	}
	if !mod.IsLocal {
		t.Errorf("expected IsLocal=true, got false")
	}
	if mod.SourceType != "local" {
		t.Errorf("expected SourceType=local, got %q", mod.SourceType)
	}
}

func TestParseTerraformModules_AbsoluteLocalModule(t *testing.T) {
	rootDir := t.TempDir()
	moduleDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(moduleDir, "main.tf"), []byte(`resource "test" "example" {}`), 0o600))
	mainTF := `module "local" { source = "` + filepath.ToSlash(moduleDir) + `" }`
	files := model.FileMetadatas{
		&model.FileMetadata{
			FilePath:          filepath.Join(rootDir, "main.tf"),
			OriginalData:      mainTF,
			LinesOriginalData: &[]string{mainTF},
		},
	}

	modules, err := ParseTerraformModules(context.Background(), nil, files, 0)

	require.NoError(t, err)
	require.Len(t, modules, 1)
	for _, module := range modules {
		require.Equal(t, filepath.Clean(moduleDir), module.AbsSource)
	}
}

// TestParseTerraformModules_CanceledContext guards the cancellation contract:
// a canceled scan must surface ctx.Err() rather than silently return partial
// module data. HCL parse workers skip individual failures, so without an
// explicit propagation a canceled parse would return (partial, nil).
func TestParseTerraformModules_CanceledContext(t *testing.T) {
	files := model.FileMetadatas{
		&model.FileMetadata{
			FilePath:     filepath.Join(t.TempDir(), "main.tf"),
			OriginalData: `module "m" { source = "./x" }`,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled scan

	_, err := ParseTerraformModules(ctx, nil, files, 0)
	require.ErrorIs(t, err, context.Canceled)
}

// TestParseDirModules_CanceledContext guards per-directory extraction: once the
// scan is canceled, parseDirModules must stop before parsing the rest of the
// files in that directory rather than finishing the whole directory first.
func TestParseDirModules_CanceledContext(t *testing.T) {
	dir := t.TempDir()
	const fileBody = `locals { x = "y" }`
	files := make([]*model.FileMetadata, 32)
	for i := range files {
		files[i] = &model.FileMetadata{
			FilePath:     filepath.Join(dir, fmt.Sprintf("file_%02d.tf", i)),
			OriginalData: fileBody,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := parseDirModules(ctx, nil, &sync.Map{}, dirFiles{dir: dir, files: files}, nil)
	require.ErrorIs(t, err, context.Canceled)
}

// TestParseAllModuleVariables_CanceledContext guards the cancellation contract:
// a canceled context should return an empty slice without blocking.
func TestParseAllModuleVariables_CanceledContext(t *testing.T) {
	modules := map[string]ParsedModule{
		"a": {Name: "a", IsLocal: true, AbsSource: t.TempDir()},
		"b": {Name: "b", IsLocal: true, AbsSource: t.TempDir()},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled scan

	got, err := ParseAllModuleVariables(ctx, nil, modules, t.TempDir(), nil)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, got)
}

// TestParseTerraformModules_IdenticalContentResolvedPerDirectory guards the
// content-keyed extract cache: two directories can hold byte-identical .tf
// files, so the cached extract is shared between them, but each module argument
// must still resolve against the locals of its own directory.
func TestParseTerraformModules_IdenticalContentResolvedPerDirectory(t *testing.T) {
	root := t.TempDir()
	// Byte-identical in both directories, so both hit the same cache entry.
	const mainTF = `module "m" {
  source = local.mod_path
}`
	files := model.FileMetadatas{}
	for dirName, modName := range map[string]string{"stack-a": "mod-a", "stack-b": "mod-b"} {
		dir := filepath.Join(root, dirName)
		require.NoError(t, os.MkdirAll(filepath.Join(dir, modName), 0o755))
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, modName, "main.tf"), []byte(`resource "test" "r" {}`), 0o600))
		localsTF := `locals {
  mod_path = "./` + modName + `"
}`
		require.NoError(t, os.WriteFile(filepath.Join(dir, "locals.tf"), []byte(localsTF), 0o600))
		files = append(files,
			&model.FileMetadata{FilePath: filepath.Join(dir, "main.tf"), OriginalData: mainTF},
			&model.FileMetadata{FilePath: filepath.Join(dir, "locals.tf"), OriginalData: localsTF},
		)
	}

	modules, err := ParseTerraformModules(context.Background(), nil, files, 0)
	require.NoError(t, err)
	require.Len(t, modules, 2)

	sourceByDir := make(map[string]string)
	absByDir := make(map[string]string)
	for _, mod := range modules {
		dir := filepath.Base(filepath.Dir(mod.FileName))
		sourceByDir[dir] = mod.Source
		absByDir[dir] = mod.AbsSource
	}
	require.Equal(t, "./mod-a", sourceByDir["stack-a"])
	require.Equal(t, "./mod-b", sourceByDir["stack-b"])
	require.Equal(t, filepath.Join(root, "stack-a", "mod-a"), absByDir["stack-a"])
	require.Equal(t, filepath.Join(root, "stack-b", "mod-b"), absByDir["stack-b"])
}

// TestParseTerraformModules_MissingSourceLeavesSourceTypeUnset locks in the
// distinction between an absent source argument and one that resolves to an
// empty string: only the latter is classified (as "unknown").
func TestParseTerraformModules_MissingSourceLeavesSourceTypeUnset(t *testing.T) {
	dir := t.TempDir()
	const mainTF = `module "m" {
  version = "1.2.3"
}`
	files := model.FileMetadatas{
		&model.FileMetadata{FilePath: filepath.Join(dir, "main.tf"), OriginalData: mainTF},
	}

	modules, err := ParseTerraformModules(context.Background(), nil, files, 0)
	require.NoError(t, err)
	require.Len(t, modules, 1)
	for _, mod := range modules {
		require.Equal(t, "1.2.3", mod.Version)
		require.Empty(t, mod.Source)
		require.Empty(t, mod.SourceType, "an absent source must not be classified")
		require.False(t, mod.IsLocal)
	}
}

func TestParseTerraformModules(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []ParsedModule
	}{
		{
			name: "simple_literal_source",
			content: `
module "basic" {
  source  = "git::https://example.com/modules/basic.git"
  version = "1.0.0"
}
`,
			expected: []ParsedModule{
				{
					Name:          "basic",
					Source:        "git::https://example.com/modules/basic.git",
					Version:       "1.0.0",
					IsLocal:       false,
					SourceType:    "git",
					RegistryScope: "",
				},
			},
		},
		{
			name: "source_from_local",
			content: `
locals {
  mod_src = "git::https://example.com/modules/with-locals.git"
}

module "with_locals" {
  source = local.mod_src
}
`,
			expected: []ParsedModule{
				{
					Name:          "with_locals",
					Source:        "git::https://example.com/modules/with-locals.git",
					Version:       "",
					IsLocal:       false,
					SourceType:    "git",
					RegistryScope: "",
				},
			},
		},
		{
			name: "source_from_var_with_default",
			content: `
variable "bucket_mod" {
  default = "git::https://example.com/modules/s3.git"
}

module "bucket" {
  source = var.bucket_mod
}
`,
			expected: []ParsedModule{
				{
					Name:          "bucket",
					Source:        "git::https://example.com/modules/s3.git",
					Version:       "",
					IsLocal:       false,
					SourceType:    "git",
					RegistryScope: "",
				},
			},
		},
		{
			name: "source_using_format_function",
			content: `
locals {
  env = "prod"
}
module "dynamic" {
  source = format("git::https://example.com/modules/app-%s.git", local.env)
}
`,
			expected: []ParsedModule{
				{
					Name:          "dynamic",
					Source:        "git::https://example.com/modules/app-prod.git",
					Version:       "",
					IsLocal:       false,
					SourceType:    "git",
					RegistryScope: "",
				},
			},
		},
		{
			name: "source_using_join_function",
			content: `
module "joined" {
  source = join("/", ["git::https://example.com", "modules", "joined"])
}
`,
			expected: []ParsedModule{
				{
					Name:          "joined",
					Source:        "git::https://example.com/modules/joined",
					Version:       "",
					IsLocal:       false,
					SourceType:    "git",
					RegistryScope: "",
				},
			},
		},
		{
			name: "invalid_traversal_fallback",
			content: `
module "invalid" {
  source = var.nonexistent
}
`,
			expected: []ParsedModule{
				{
					Name:          "invalid",
					Source:        "__UNKNOWN_REF__",
					Version:       "",
					IsLocal:       false,
					SourceType:    "unknown",
					RegistryScope: "",
				},
			},
		},
		{
			name: "public_registry_format",
			content: `
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
}
`,
			expected: []ParsedModule{
				{
					Name:          "vpc",
					Source:        "terraform-aws-modules/vpc/aws",
					Version:       "",
					IsLocal:       false,
					SourceType:    "registry",
					RegistryScope: "public",
				},
			},
		},
		{
			name: "private_registry_host",
			content: `
module "core" {
  source = "registry.privatecorp.io/infra/core/aws"
}
`,
			expected: []ParsedModule{
				{
					Name:          "core",
					Source:        "registry.privatecorp.io/infra/core/aws",
					Version:       "",
					IsLocal:       false,
					SourceType:    "registry",
					RegistryScope: "private",
				},
			},
		},
		{
			name: "data_reference_source",
			content: `
module "external" {
  source = data.aws_s3_bucket.logs.bucket_domain_name
}
`,
			expected: []ParsedModule{
				{
					Name:          "external",
					Source:        "data_ref:aws_s3_bucket.logs.bucket_domain_name",
					Version:       "",
					IsLocal:       false,
					SourceType:    "data_ref",
					RegistryScope: "",
				},
			},
		},
		{
			name: "multiple_modules",
			content: `
module "one" {
  source = "git::https://github.com/org/repo.git//modules/mod1"
}

module "two" {
  source = "terraform-aws-modules/vpc/aws"
  version = "3.0.0"
}

module "three" {
  source = "./local-mod"
}
`,
			expected: []ParsedModule{
				{
					Name:          "one",
					Source:        "git::https://github.com/org/repo.git//modules/mod1",
					Version:       "",
					IsLocal:       false,
					SourceType:    "git",
					RegistryScope: "",
				},
				{
					Name:          "two",
					Source:        "terraform-aws-modules/vpc/aws",
					Version:       "3.0.0",
					IsLocal:       false,
					SourceType:    "registry",
					RegistryScope: "public",
				},
				{
					Name:          "three",
					Source:        "./local-mod",
					Version:       "",
					IsLocal:       true,
					SourceType:    "local",
					RegistryScope: "",
				},
			},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate a single file input using the test case content
			files := model.FileMetadatas{
				&model.FileMetadata{
					FilePath:     "/test/path/main.tf", // Used for baseDir resolution
					OriginalData: tt.content,
					LinesOriginalData: &[]string{
						tt.content,
					}},
			}

			gotMap, err := ParseTerraformModules(ctx, nil, files, 0)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Flatten map to slice for comparison
			got := make([]ParsedModule, 0, len(gotMap))
			for _, mod := range gotMap {
				got = append(got, mod)
			}

			// Normalize expected absolute paths for IsLocal modules
			for i := range tt.expected {
				if tt.expected[i].IsLocal {
					expectedAbs, err := filepath.Abs(filepath.Join("/test/path", tt.expected[i].Source))
					if err != nil {
						t.Fatalf("failed to normalize expected path: %v", err)
					}
					tt.expected[i].AbsSource = expectedAbs
				}
			}
			// Strip location fields — these tests verify source/type detection, not source positions.
			for i := range got {
				got[i].FileName = ""
				got[i].DefLine = 0
				got[i].DefEndLine = 0
			}
			sort.Slice(got, func(i, j int) bool {
				return got[i].Name < got[j].Name
			})
			sort.Slice(tt.expected, func(i, j int) bool {
				return tt.expected[i].Name < tt.expected[j].Name
			})
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("unexpected result:\nGot:  %#v\nWant: %#v", got, tt.expected)
			}
		})
	}
}

func TestLooksLikeLocalModuleSource(t *testing.T) {
	isWindows := runtime.GOOS == "windows"
	cases := map[string]bool{
		"./foo":                         true,
		"../bar":                        true,
		"/abs/unix":                     !isWindows,
		`c:\abs\windows`:                isWindows,
		"file:///some/mod":              true,
		"git::https://...":              false,
		"registry.terraform.io/foo/bar": false,
		"${path.module}/mod":            false,
		"git::./modules/example":        true,
		"../modules/%s":                 true,
	}

	for input, expected := range cases {
		if got := LooksLikeLocalModuleSource(input); got != expected {
			t.Errorf("LooksLikeLocalModuleSource(%q) = %v, want %v", input, got, expected)
		}
	}
}

func TestDetectModuleSourceTypeWithScope(t *testing.T) {
	tests := []struct {
		source    string
		wantType  string
		wantScope string
	}{
		{"./module", "local", ""},
		{"git::./mod", "git", ""},
		{"registry.terraform.io/org/vpc/aws", "registry", "public"},
		{"terraform-aws-modules/vpc/aws", "registry", "public"},
		{"terraform-aws-modules/eks/aws//modules/karpenter", "registry", "public"},
		{"company.internal.io/infra/mod/aws", "registry", "private"},
		{"company.internal.io/infra/mod/aws//child", "registry", "private"},
		{"registry.example.com:8443/ns/name/aws", "registry", "private"},
		{"registry.terraform.io:443/org/vpc/aws", "registry", "public"},
		{"https://github.com/org/repo", "unknown", ""},
		{"data_ref:aws_s3.bucket.id", "data_ref", ""},
		{"", "unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			gotType, gotScope := DetectModuleSourceType(tt.source)
			if gotType != tt.wantType || gotScope != tt.wantScope {
				t.Errorf("DetectModuleSourceType(%q) = (%q, %q), want (%q, %q)",
					tt.source, gotType, gotScope, tt.wantType, tt.wantScope)
			}
		})
	}
}

func TestResolveExpr_BinaryOpExpr(t *testing.T) {
	t.Run("arithmetic_concatenates_resolved_sides", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`1 + 2`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.BinaryOpExpr); !ok {
			t.Fatalf("expected *hclsyntax.BinaryOpExpr, got %T", expr)
		}
		result := resolveExpr(expr, map[string]string{}, map[string]string{})
		// Number literals resolve to __NON_STRING_LITERAL__ so we get op between them
		want := "__NON_STRING_LITERAL__ + __NON_STRING_LITERAL__"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})
	t.Run("comparison_with_vars", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`var.a == var.b`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		result := resolveExpr(expr, map[string]string{}, map[string]string{"a": "x", "b": "y"})
		want := "x == y"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})
}

func TestResolveExpr_SplatExpr(t *testing.T) {
	t.Run("splat_resolved_or_placeholder", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`var.list[*]`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.SplatExpr); !ok {
			t.Fatalf("expected *hclsyntax.SplatExpr, got %T", expr)
		}
		result := resolveExpr(expr, map[string]string{}, map[string]string{"list": "a,b"})
		if result != "a,b[*]" && result != "__UNRESOLVED__" {
			t.Errorf("resolveExpr = %q", result)
		}
	})
	t.Run("splat_with_traversal_unresolved", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`var.list[*].id`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		result := resolveExpr(expr, map[string]string{}, map[string]string{})
		// var.list unresolved => __UNKNOWN_REF__[*].id; resolveRelativeTraversal then short-circuits to __UNRESOLVED__
		if result != "__UNRESOLVED__" {
			t.Errorf("resolveExpr = %q, want __UNRESOLVED__", result)
		}
	})
}

func TestResolveExpr_ForExpr(t *testing.T) {
	t.Run("for_expr_uses_default", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`[for x in var.list : x]`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.ForExpr); !ok {
			t.Fatalf("expected *hclsyntax.ForExpr, got %T", expr)
		}
		result := resolveExpr(expr, map[string]string{}, map[string]string{})
		if result != "__UNRESOLVED__" {
			t.Errorf("resolveExpr = %q, want __UNRESOLVED__", result)
		}
	})
}

func TestResolveExpr_UnaryOpExpr(t *testing.T) {
	t.Run("negate", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`-1`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.UnaryOpExpr); !ok {
			t.Fatalf("expected *hclsyntax.UnaryOpExpr, got %T", expr)
		}
		result := resolveExpr(expr, map[string]string{}, map[string]string{})
		want := "-__NON_STRING_LITERAL__"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})
	t.Run("logical_not_with_var", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`!var.flag`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		result := resolveExpr(expr, map[string]string{}, map[string]string{"flag": "true"})
		want := "!true"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})
}

func TestResolveExpr_RelativeTraversalExpr(t *testing.T) {
	t.Run("function_call_source_with_traversal", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression(
			[]byte(`format("%s", "value").suffix`),
			"test.hcl", hcl.Pos{Line: 1, Column: 1},
		)
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.RelativeTraversalExpr); !ok {
			t.Fatalf("expected *hclsyntax.RelativeTraversalExpr, got %T", expr)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{})
		want := "value.suffix"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})

	t.Run("unresolved_source_short_circuits", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression(
			[]byte("tostring(var.x).attr"),
			"test.hcl", hcl.Pos{Line: 1, Column: 1},
		)
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.RelativeTraversalExpr); !ok {
			t.Fatalf("expected *hclsyntax.RelativeTraversalExpr, got %T", expr)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{})
		if result != "__UNRESOLVED__" {
			t.Errorf("resolveExpr = %q, want %q", result, "__UNRESOLVED__")
		}
	})

	t.Run("in_template_expression", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression(
			[]byte(`"prefix-${format("%s", "val").suffix}"`),
			"test.hcl", hcl.Pos{Line: 1, Column: 1},
		)
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{})
		want := "prefix-val.suffix"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})

	t.Run("multi_step_traversal", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression(
			[]byte(`format("%s", "base").a.b`),
			"test.hcl", hcl.Pos{Line: 1, Column: 1},
		)
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.RelativeTraversalExpr); !ok {
			t.Fatalf("expected *hclsyntax.RelativeTraversalExpr, got %T", expr)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{})
		want := "base.a.b"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})

	t.Run("traversal_with_index_step", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression(
			[]byte(`format("%s", "base")[0].name`),
			"test.hcl", hcl.Pos{Line: 1, Column: 1},
		)
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.RelativeTraversalExpr); !ok {
			t.Fatalf("expected *hclsyntax.RelativeTraversalExpr, got %T", expr)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{})
		want := "base[0].name"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})
}

func TestResolveExpr_ParenthesesExpr(t *testing.T) {
	t.Run("main_switch_unwraps_and_resolves", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("(var.source)"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.ParenthesesExpr); !ok {
			t.Fatalf("expected *hclsyntax.ParenthesesExpr, got %T", expr)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{"source": "./modules/vpc"})
		want := "./modules/vpc"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})

	t.Run("in_template_expression", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`"prefix-${(var.x)}-suffix"`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{"x": "value"})
		want := "prefix-value-suffix"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})
}

func TestResolveExpr_TemplateWrapExpr(t *testing.T) {
	t.Run("main_switch_unwraps_and_resolves", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`"${var.source}"`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.TemplateWrapExpr); !ok {
			t.Fatalf("expected TemplateWrapExpr, got %T", expr)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{"source": "./local/module"})
		want := "./local/module"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})

	t.Run("in_template_expression", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`"prefix-${var.x}-suffix"`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{"x": "value"})
		want := "prefix-value-suffix"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})
}

func TestResolveExpr_TupleConsExpr(t *testing.T) {
	t.Run("main_switch_resolves_elements", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`[var.a, var.b]`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.TupleConsExpr); !ok {
			t.Fatalf("expected *hclsyntax.TupleConsExpr, got %T", expr)
		}

		vars := map[string]string{"a": "x", "b": "y"}
		result := resolveExpr(expr, map[string]string{}, vars)
		want := "[x, y]"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})
}

func TestResolveExpr_ObjectConsExpr(t *testing.T) {
	t.Run("main_switch_resolves_keys_and_values", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`{k = var.v}`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.ObjectConsExpr); !ok {
			t.Fatalf("expected *hclsyntax.ObjectConsExpr, got %T", expr)
		}

		vars := map[string]string{"v": "resolved"}
		result := resolveExpr(expr, map[string]string{}, vars)
		want := "{k: resolved}"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})
}

func TestResolveExpr_IndexExpr(t *testing.T) {
	t.Run("main_switch_resolves_collection_and_key", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte("var.list[var.i]"), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.IndexExpr); !ok {
			t.Fatalf("expected *hclsyntax.IndexExpr, got %T", expr)
		}

		vars := map[string]string{"list": "items", "i": "0"}
		result := resolveExpr(expr, map[string]string{}, vars)
		want := "items[0]"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})

	t.Run("in_template_expression", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`"${var.map[var.k]}"`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{"map": "m", "k": "key"})
		want := "m[key]"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})
}

func TestResolveExpr_ConditionalExpr(t *testing.T) {
	t.Run("main_switch_resolves_condition_true_false", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`var.enabled ? var.yes : var.no`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.ConditionalExpr); !ok {
			t.Fatalf("expected *hclsyntax.ConditionalExpr, got %T", expr)
		}

		vars := map[string]string{"enabled": "true", "yes": "./module-a", "no": "./module-b"}
		result := resolveExpr(expr, map[string]string{}, vars)
		want := "true ? ./module-a : ./module-b"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})

	t.Run("in_template_expression", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression([]byte(`"${var.flag ? var.a : var.b}"`), "test.hcl", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{"flag": "x", "a": "first", "b": "second"})
		want := "x ? first : second"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})
}

func TestResolveExpr_FunctionCallExpr(t *testing.T) {
	t.Run("format_function_resolves", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression(
			[]byte(`format("%s/%s", var.base, var.path)`),
			"test.hcl", hcl.Pos{Line: 1, Column: 1},
		)
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.FunctionCallExpr); !ok {
			t.Fatalf("expected *hclsyntax.FunctionCallExpr, got %T", expr)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{
			"base": "./modules",
			"path": "vpc",
		})
		want := "./modules/vpc"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})

	t.Run("join_function_resolves", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression(
			[]byte(`join("-", ["a", "b", "c"])`),
			"test.hcl", hcl.Pos{Line: 1, Column: 1},
		)
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.FunctionCallExpr); !ok {
			t.Fatalf("expected *hclsyntax.FunctionCallExpr, got %T", expr)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{})
		want := "a-b-c"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})

	t.Run("unsupported_function_returns_sentinel", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression(
			[]byte(`tostring(var.x)`),
			"test.hcl", hcl.Pos{Line: 1, Column: 1},
		)
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}
		if _, ok := expr.(*hclsyntax.FunctionCallExpr); !ok {
			t.Fatalf("expected *hclsyntax.FunctionCallExpr, got %T", expr)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{})
		want := "__UNSUPPORTED_FUNC_tostring__"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})

	t.Run("function_call_in_template_expression", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression(
			[]byte(`"prefix-${format("%s", "value")}"`),
			"test.hcl", hcl.Pos{Line: 1, Column: 1},
		)
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{})
		want := "prefix-value"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})

	t.Run("unsupported_function_in_template_returns_sentinel", func(t *testing.T) {
		expr, diags := hclsyntax.ParseExpression(
			[]byte(`"prefix-${tostring(var.x)}"`),
			"test.hcl", hcl.Pos{Line: 1, Column: 1},
		)
		if diags.HasErrors() {
			t.Fatalf("parse failed: %v", diags)
		}

		result := resolveExpr(expr, map[string]string{}, map[string]string{})
		want := "prefix-__UNSUPPORTED_FUNC_tostring__"
		if result != want {
			t.Errorf("resolveExpr = %q, want %q", result, want)
		}
	})
}

func TestGetProviderFromResourceType(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  string
		expectErr bool
	}{
		{
			name:     "Valid AWS resource",
			input:    "aws_s3_bucket",
			expected: "aws",
		},
		{
			name:     "Valid Azure resource",
			input:    "azurerm_network_interface",
			expected: "azurerm",
		},
		{
			name:     "Valid GCP resource",
			input:    "google_compute_instance",
			expected: "google",
		},
		{
			name:      "Invalid empty input",
			input:     "",
			expectErr: true,
		},
		{
			name:      "Invalid no underscore",
			input:     "aws",
			expectErr: true,
		},
		{
			name:     "Custom provider",
			input:    "customprovider_widget",
			expected: "customprovider",
		},
		{
			name:     "Short input with underscore",
			input:    "a_b",
			expected: "a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := GetProviderFromResourceType(tt.input)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, provider)
			}
		})
	}
}
