/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package registry

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// TestHCLToRegistryIntegration tests the full flow from HCL parsing to registry population
func TestHCLToRegistryIntegration(t *testing.T) {
	// Create new registry instance for test
	reg := New()

	// Create test HCL content
	hclContent := `
# Root resources
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}

# Module declarations
module "security" {
  source = "./modules/security"
  vpc_id = aws_vpc.main.id
}

module "compute" {
  source = "./modules/compute"

  subnet_id = aws_subnet.public.id
  security_group_id = module.security.sg_id
}

# Resource with count
resource "aws_instance" "web" {
  count = 3

  ami           = "ami-123456"
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.public.id
}

# Resource with for_each
resource "aws_s3_bucket" "data" {
  for_each = var.bucket_names

  bucket = each.value
}
`

	// Create temp file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "main.tf")
	err := os.WriteFile(testFile, []byte(hclContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Parse the HCL file
	file, diags := hclsyntax.ParseConfig([]byte(hclContent), testFile, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		t.Fatalf("Failed to parse HCL: %v", diags)
	}

	// Extract and register addresses (simulating what the terraform parser does)
	ctx := context.Background()
	extractAndRegisterAddresses(ctx, file, testFile, reg)

	// Verify registrations
	tests := []struct {
		address      string
		shouldExist  bool
		expectedLine int
	}{
		{
			address:      "aws_vpc.main",
			shouldExist:  true,
			expectedLine: 3,
		},
		{
			address:      "aws_subnet.public",
			shouldExist:  true,
			expectedLine: 7,
		},
		{
			address:      "module.security",
			shouldExist:  true,
			expectedLine: 13,
		},
		{
			address:      "module.compute",
			shouldExist:  true,
			expectedLine: 18,
		},
		{
			address:      "aws_instance.web",
			shouldExist:  true,
			expectedLine: 26,
		},
		{
			address:      "aws_s3_bucket.data",
			shouldExist:  true,
			expectedLine: 35,
		},
		{
			address:      "aws_instance.nonexistent",
			shouldExist:  false,
			expectedLine: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			location, found := reg.Lookup(tt.address)
			if found != tt.shouldExist {
				t.Errorf("Lookup(%q) found=%v, want %v", tt.address, found, tt.shouldExist)
			}
			if found && tt.expectedLine > 0 && location.Line != tt.expectedLine {
				t.Errorf("Lookup(%q) line=%d, want %d", tt.address, location.Line, tt.expectedLine)
			}
			if found && location.FilePath != testFile {
				t.Errorf("Lookup(%q) file=%s, want %s", tt.address, location.FilePath, testFile)
			}
		})
	}

	// Test lookups with indices (should normalize and find the base resource)
	indexedTests := []struct {
		address      string
		expectedBase string
		shouldExist  bool
	}{
		{
			address:      "aws_instance.web[0]",
			expectedBase: "aws_instance.web",
			shouldExist:  true,
		},
		{
			address:      "aws_instance.web[2]",
			expectedBase: "aws_instance.web",
			shouldExist:  true,
		},
		{
			address:      `aws_s3_bucket.data["logs"]`,
			expectedBase: "aws_s3_bucket.data",
			shouldExist:  true,
		},
		{
			address:      `module.security[0]`,
			expectedBase: "module.security",
			shouldExist:  true,
		},
		{
			address:      `module.compute["prod"]`,
			expectedBase: "module.compute",
			shouldExist:  true,
		},
	}

	for _, tt := range indexedTests {
		t.Run("indexed_"+tt.address, func(t *testing.T) {
			location, found := reg.Lookup(tt.address)
			if found != tt.shouldExist {
				t.Errorf("Lookup(%q) found=%v, want %v", tt.address, found, tt.shouldExist)
			}
			if found {
				// Verify it resolves to the same location as the base
				baseLocation, _ := reg.Lookup(tt.expectedBase)
				if location.Line != baseLocation.Line {
					t.Errorf("Indexed lookup %q line=%d, base %q line=%d",
						tt.address, location.Line, tt.expectedBase, baseLocation.Line)
				}
			}
		})
	}
}

// extractAndRegisterAddresses is a simplified version of the function in terraform.go
// Used for testing without importing the entire terraform package
func extractAndRegisterAddresses(ctx context.Context, file *hcl.File, filePath string, reg *AddressRegistry) {
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return
	}

	for _, block := range body.Blocks {
		switch block.Type {
		case "resource":
			if len(block.Labels) >= 2 {
				address := block.Labels[0] + "." + block.Labels[1]
				defRange := block.DefRange()
				location := Location{
					FilePath: filePath,
					Line:     defRange.Start.Line,
					Column:   defRange.Start.Column,
				}
				reg.Register(address, location)
			}
		case "module":
			if len(block.Labels) >= 1 {
				address := "module." + block.Labels[0]
				defRange := block.DefRange()
				location := Location{
					FilePath: filePath,
					Line:     defRange.Start.Line,
					Column:   defRange.Start.Column,
				}
				reg.Register(address, location)
			}
		}
	}
}

// TestTFPlanToHCLMapping tests the full mapping from tfplan addresses to HCL locations
func TestTFPlanToHCLMapping(t *testing.T) {
	reg := New()

	// Simulate HCL file registration
	mainFile := "/project/main.tf"

	// Register root resources
	reg.Register("aws_vpc.main", Location{FilePath: mainFile, Line: 10, Column: 1})
	reg.Register("aws_instance.web", Location{FilePath: mainFile, Line: 20, Column: 1})

	// Register module calls
	reg.Register("module.vpc", Location{FilePath: mainFile, Line: 30, Column: 1})
	reg.Register("module.compute", Location{FilePath: mainFile, Line: 40, Column: 1})

	// Test various tfplan addresses
	tests := []struct {
		name         string
		tfplanAddr   string
		expectedFile string
		expectedLine int
		description  string
	}{
		{
			name:         "root resource exact match",
			tfplanAddr:   "aws_vpc.main",
			expectedFile: mainFile,
			expectedLine: 10,
			description:  "Direct root resource should map to its definition",
		},
		{
			name:         "root resource with count",
			tfplanAddr:   "aws_instance.web[0]",
			expectedFile: mainFile,
			expectedLine: 20,
			description:  "Indexed resource should map to base resource",
		},
		{
			name:         "module resource",
			tfplanAddr:   "module.vpc.aws_subnet.private",
			expectedFile: mainFile,
			expectedLine: 30,
			description:  "Module resource should map to module call",
		},
		{
			name:         "module with index",
			tfplanAddr:   "module.compute[1].aws_instance.app",
			expectedFile: mainFile,
			expectedLine: 40,
			description:  "Indexed module resource should map to module call",
		},
		{
			name:         "nested module",
			tfplanAddr:   "module.vpc.module.subnet.aws_subnet.private",
			expectedFile: mainFile,
			expectedLine: 30,
			description:  "Nested module should map to top-level module call (module.vpc)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For module resources, we need to extract the module part
			moduleAddr := ExtractModuleAddress(tt.tfplanAddr)
			var location Location
			var found bool

			if moduleAddr != "" {
				// For nested modules, we only register the top-level module call
				// So extract just the first module.name part
				parts := strings.Split(moduleAddr, ".")
				if len(parts) >= 2 {
					topLevelModule := parts[0] + "." + parts[1]
					location, found = reg.Lookup(topLevelModule)
				}
				if !found {
					location, found = reg.Lookup(moduleAddr)
				}
			} else {
				location, found = reg.Lookup(tt.tfplanAddr)
			}

			if !found {
				t.Errorf("%s: Failed to find mapping for %q", tt.description, tt.tfplanAddr)
				return
			}

			if location.FilePath != tt.expectedFile {
				t.Errorf("%s: Expected file %s, got %s", tt.description, tt.expectedFile, location.FilePath)
			}

			if location.Line != tt.expectedLine {
				t.Errorf("%s: Expected line %d, got %d", tt.description, tt.expectedLine, location.Line)
			}
		})
	}
}

// TestParserIntegration would test the actual terraform parser integration
// but is commented out to avoid circular dependency
// The integration is tested via the scan package tests instead
