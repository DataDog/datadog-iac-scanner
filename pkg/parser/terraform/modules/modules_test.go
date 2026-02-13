package tfmodules

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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
		{
			FilePath: filepath.Join(tmpDir, "main.tf"),
			Content:  mainTF,
			LinesOriginalData: &[]string{
				mainTF,
			},
		},
	}

	gotMap, err := ParseTerraformModules(ctx, files)
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
				model.FileMetadata{
					FilePath: "/test/path/main.tf", // Used for baseDir resolution
					Content:  tt.content,
					LinesOriginalData: &[]string{
						tt.content,
					}},
			}

			gotMap, err := ParseTerraformModules(ctx, files)
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
		{"company.internal.io/infra/mod/aws", "registry", "private"},
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
