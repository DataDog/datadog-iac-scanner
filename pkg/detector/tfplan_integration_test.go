/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/registry"
)

// TestTFPlanDetectLineWithJSONRoundTrip verifies that address extraction works
// after JSON round-trips (which convert model.Document to map[string]interface{})
func TestTFPlanDetectLineWithJSONRoundTrip(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.tf")

	// Write test HCL content
	hclContent := `resource "aws_instance" "web" {
  ami           = "ami-123456"
  instance_type = "t2.micro"
}

resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}`
	err := os.WriteFile(testFile, []byte(hclContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create registry and register test addresses
	reg := registry.New()
	reg.Register("aws_instance.web", registry.Location{
		FilePath: testFile,
		Line:     1,
		Column:   1,
	})
	reg.Register("aws_s3_bucket.data", registry.Location{
		FilePath: testFile,
		Line:     6,
		Column:   1,
	})

	ctx := context.Background()
	detector := NewTFPlanDetectLine(reg, nil)

	// Create a mock tfplan document with _dd_tf_address fields
	// This mimics what parseTFPlan creates
	mockDocument := model.Document{
		"resource": model.Document{
			"aws_instance": model.Document{
				"web": model.Document{
					"_dd_tf_address": "aws_instance.web",
					"ami":            "ami-123456",
					"instance_type":  "t2.micro",
				},
			},
			"aws_s3_bucket": model.Document{
				"data": model.Document{
					"_dd_tf_address": "aws_s3_bucket.data",
					"bucket":         "my-bucket",
				},
			},
		},
	}

	// Simulate the JSON round-trip that happens in production
	// This converts nested model.Document to map[string]interface{}
	jsonBytes, err := json.Marshal(mockDocument)
	if err != nil {
		t.Fatalf("Failed to marshal document: %v", err)
	}

	var roundTrippedDoc model.Document
	err = json.Unmarshal(jsonBytes, &roundTrippedDoc)
	if err != nil {
		t.Fatalf("Failed to unmarshal document: %v", err)
	}

	// Create a mock file metadata for tfplan with the round-tripped document
	fileMetadata := &model.FileMetadata{
		ID:               "test-file",
		FilePath:         "test.tfplan.json",
		Kind:             model.KindJSON,
		Document:         roundTrippedDoc, // This is now map[string]interface{} nested
		LineInfoDocument: roundTrippedDoc, // TFPlan detector reads _dd_tf_address from here
	}

	tests := []struct {
		name         string
		searchKey    string
		expectedLine int
		expectedFile string
	}{
		{
			name:         "root resource with dot notation",
			searchKey:    "aws_instance.web.ami",
			expectedLine: 1,
			expectedFile: testFile,
		},
		{
			name:         "s3 bucket resource with resource prefix",
			searchKey:    "resource.aws_s3_bucket.data.bucket",
			expectedLine: 6,
			expectedFile: testFile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.DetectLine(ctx, fileMetadata, tt.searchKey, 3)
			if result.Line != tt.expectedLine {
				t.Errorf("Expected line %d, got %d", tt.expectedLine, result.Line)
			}
			if result.ResolvedFile != tt.expectedFile {
				t.Errorf("Expected file %s, got %s", tt.expectedFile, result.ResolvedFile)
			}
			if result.ResourceSource != tt.expectedFile {
				t.Errorf("Expected resource source %s, got %s", tt.expectedFile, result.ResourceSource)
			}
		})
	}
}

// TestTFPlanModuleAttributeMappingIntegration tests the full e2e flow of module attribute mapping
// This verifies that findings on module resources are correctly mapped to the module input variable line
func TestTFPlanModuleAttributeMappingIntegration(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()
	mainFile := filepath.Join(tmpDir, "main.tf")

	// Write main.tf with module declarations
	mainContent := `module "vpc" {
  source = "./modules/networking"

  vpc_cidr = "10.0.0.0/16"

  # This is the attribute we expect to find (line 7)
  resource_tags = {
    Environment = "production"
    Team        = "platform"
  }

  enable_dns_hostnames = true
}

module "app_servers" {
  source = "./modules/compute"
  count  = 2

  instance_type = "t2.micro"

  # This is the attribute we expect to find (line 22)
  instance_tags = {
    Environment = "staging"
    Application = "web"
  }
}
`
	err := os.WriteFile(mainFile, []byte(mainContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.tf: %v", err)
	}

	// Create registry and register module addresses
	reg := registry.New()
	reg.Register("module.vpc", registry.Location{
		FilePath: mainFile,
		Line:     1, // Module declaration line
		Column:   1,
	})
	reg.Register("module.app_servers", registry.Location{
		FilePath: mainFile,
		Line:     15, // Module declaration line
		Column:   1,
	})

	// Create module mappings that simulate what the module parser would generate
	moduleMappings := map[string]interface{}{
		"vpc": map[string]interface{}{
			"AttributesData": map[string]interface{}{
				"aws": map[string]interface{}{
					"inputs": map[string]interface{}{
						"tags": "resource_tags", // tags attribute maps to resource_tags variable
					},
				},
			},
		},
		"app_servers": map[string]interface{}{
			"AttributesData": map[string]interface{}{
				"aws": map[string]interface{}{
					"inputs": map[string]interface{}{
						"tags": "instance_tags", // tags attribute maps to instance_tags variable
					},
				},
			},
		},
	}

	ctx := context.Background()
	detector := NewTFPlanDetectLine(reg, moduleMappings)

	// Create a mock tfplan document representing module resources
	mockDocument := model.Document{
		"resource": model.Document{
			"aws_vpc": model.Document{
				"main": model.Document{
					"_dd_tf_address": "module.vpc.aws_vpc.main",
					"cidr_block":     "10.0.0.0/16",
					"tags": map[string]interface{}{
						"Environment": "production",
						"Team":        "platform",
					},
				},
			},
			"aws_instance": model.Document{
				"bastion": model.Document{
					"_dd_tf_address": "module.vpc.aws_instance.bastion",
					"ami":            "ami-12345678",
					"instance_type":  "t2.micro",
					"tags": map[string]interface{}{
						"Environment": "production",
						"Team":        "platform",
					},
				},
				"app_0": model.Document{ // Use app_0 instead of app[0] for simpler testing
					// NORMALIZED address (no [0] index) - matches real tfplan.go behavior at line 96
					"_dd_tf_address": "module.app_servers.aws_instance.app",
					"ami":            "ami-87654321",
					"instance_type":  "t2.micro",
					"tags": map[string]interface{}{
						"Environment": "staging",
						"Application": "web",
					},
				},
				"app_1": model.Document{ // Use app_1 instead of app[1]
					// NORMALIZED address (no [1] index) - matches real tfplan.go behavior at line 96
					"_dd_tf_address": "module.app_servers.aws_instance.app",
					"ami":            "ami-87654321",
					"instance_type":  "t2.micro",
					"tags": map[string]interface{}{
						"Environment": "staging",
						"Application": "web",
					},
				},
			},
		},
	}

	// Simulate JSON round-trip
	jsonBytes, err := json.Marshal(mockDocument)
	if err != nil {
		t.Fatalf("Failed to marshal document: %v", err)
	}

	var roundTrippedDoc model.Document
	err = json.Unmarshal(jsonBytes, &roundTrippedDoc)
	if err != nil {
		t.Fatalf("Failed to unmarshal document: %v", err)
	}

	tests := []struct {
		name           string
		searchKey      string
		expectedLine   int
		expectedFile   string
		description    string
		tfplanFilePath string // Which tfplan file to use
	}{
		{
			name:           "vpc module resource tags",
			searchKey:      "aws_vpc.main.tags",
			expectedLine:   7, // resource_tags line, not module declaration (line 1)
			expectedFile:   mainFile,
			description:    "Should map to resource_tags attribute line in module block",
			tfplanFilePath: filepath.Join(tmpDir, "plan.tfplan.json"),
		},
		{
			name:           "vpc module instance tags",
			searchKey:      "aws_instance.bastion.tags",
			expectedLine:   7, // Same resource_tags line
			expectedFile:   mainFile,
			description:    "Multiple resources in same module should map to same variable",
			tfplanFilePath: filepath.Join(tmpDir, "plan.tfplan.json"),
		},
		{
			name:           "app_servers module instance 0",
			searchKey:      "aws_instance.app_0.tags", // Using app_0 as resource key
			expectedLine:   22,                        // instance_tags line, not module declaration (line 15)
			expectedFile:   mainFile,
			description:    "Should map to instance_tags attribute line for indexed module",
			tfplanFilePath: filepath.Join(tmpDir, "plan.tfplan.json"),
		},
		{
			name:           "app_servers module instance 1",
			searchKey:      "aws_instance.app_1.tags", // Using app_1 as resource key
			expectedLine:   22,                        // Same instance_tags line
			expectedFile:   mainFile,
			description:    "Different module instances should map to same variable line",
			tfplanFilePath: filepath.Join(tmpDir, "plan.tfplan.json"),
		},
		// Realistic module-prefixed search keys (as emitted by real rules)
		{
			name:           "vpc module with module prefix in searchKey",
			searchKey:      "module.vpc.aws_instance.bastion.tags",
			expectedLine:   7, // resource_tags line
			expectedFile:   mainFile,
			description:    "Real rule format: module.vpc.aws_instance.bastion.tags",
			tfplanFilePath: filepath.Join(tmpDir, "plan.tfplan.json"),
		},
		{
			name:           "indexed module with module prefix",
			searchKey:      "module.app_servers[0].aws_instance.app.tags",
			expectedLine:   22, // instance_tags line
			expectedFile:   mainFile,
			description:    "Real rule format with index: module.app_servers[0].aws_instance.app.tags",
			tfplanFilePath: filepath.Join(tmpDir, "plan.tfplan.json"),
		},
		{
			name:           "indexed module different instance",
			searchKey:      "module.app_servers[1].aws_instance.app.tags",
			expectedLine:   22, // Same instance_tags line (shared variable)
			expectedFile:   mainFile,
			description:    "Different indexed module instance should map to same variable",
			tfplanFilePath: filepath.Join(tmpDir, "plan.tfplan.json"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use specific file metadata for this test
			testFileMetadata := &model.FileMetadata{
				ID:               "test-tfplan",
				FilePath:         tt.tfplanFilePath,
				Kind:             model.KindJSON,
				Document:         roundTrippedDoc,
				LineInfoDocument: roundTrippedDoc,
			}
			result := detector.DetectLine(ctx, testFileMetadata, tt.searchKey, 5) // Use larger search range

			if result.ResolvedFile != tt.expectedFile {
				t.Errorf("Expected file %s, got %s", tt.expectedFile, result.ResolvedFile)
			}

			if result.Line != tt.expectedLine {
				t.Errorf("%s: Expected line %d, got %d", tt.description, tt.expectedLine, result.Line)
			}

			if result.ResourceSource != tt.expectedFile {
				t.Errorf("Expected resource source %s, got %s", tt.expectedFile, result.ResourceSource)
			}
		})
	}
}

// TestTFPlanModuleAttributeMappingFallback tests that the detector gracefully falls back
// when module mappings are not available or incomplete
func TestTFPlanModuleAttributeMappingFallback(t *testing.T) {
	tmpDir := t.TempDir()
	mainFile := filepath.Join(tmpDir, "main.tf")

	mainContent := `module "vpc" {
  source = "./modules/networking"
  cidr   = "10.0.0.0/16"
  tags   = { Environment = "test" }
}
`
	err := os.WriteFile(mainFile, []byte(mainContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.tf: %v", err)
	}

	reg := registry.New()
	reg.Register("module.vpc", registry.Location{
		FilePath: mainFile,
		Line:     1,
		Column:   1,
	})

	ctx := context.Background()

	tests := []struct {
		name           string
		moduleMappings map[string]interface{}
		expectedLine   int
		description    string
	}{
		{
			name:           "nil module mappings",
			moduleMappings: nil,
			expectedLine:   1, // Falls back to module declaration
			description:    "Should fall back to module declaration when no mappings",
		},
		{
			name:           "empty module mappings",
			moduleMappings: map[string]interface{}{},
			expectedLine:   1, // Falls back to module declaration
			description:    "Should fall back to module declaration when module not in mappings",
		},
		{
			name: "module exists but no attribute mapping",
			moduleMappings: map[string]interface{}{
				"vpc": map[string]interface{}{
					"AttributesData": map[string]interface{}{
						"aws": map[string]interface{}{
							"inputs": map[string]interface{}{
								// No "tags" mapping
								"cidr": "vpc_cidr",
							},
						},
					},
				},
			},
			expectedLine: 4, // Uses fallback transformation to find attribute line
			description:  "Should use fallback transformation to find attribute when not in mappings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := NewTFPlanDetectLine(reg, tt.moduleMappings)

			mockDocument := model.Document{
				"resource": model.Document{
					"aws_vpc": model.Document{
						"main": model.Document{
							"_dd_tf_address": "module.vpc.aws_vpc.main",
							"cidr_block":     "10.0.0.0/16",
							"tags": map[string]interface{}{
								"Environment": "test",
							},
						},
					},
				},
			}

			jsonBytes, _ := json.Marshal(mockDocument)
			var roundTrippedDoc model.Document
			json.Unmarshal(jsonBytes, &roundTrippedDoc)

			fileMetadata := &model.FileMetadata{
				ID:               "test-tfplan",
				FilePath:         filepath.Join(tmpDir, "plan.tfplan.json"),
				Kind:             model.KindJSON,
				Document:         roundTrippedDoc,
				LineInfoDocument: roundTrippedDoc,
			}

			result := detector.DetectLine(ctx, fileMetadata, "aws_vpc.main.tags", 3)

			if result.Line != tt.expectedLine {
				t.Errorf("%s: Expected line %d, got %d", tt.description, tt.expectedLine, result.Line)
			}
		})
	}
}

// TestTFPlanDetector_NoFallbackToPlanJSON is a CRITICAL test that asserts the core promise
// of the TFPlan feature: findings should NEVER point to .tfplan.json files, they should
// always resolve to .tf (HCL) source files.
//
// This test validates various search key patterns including:
// - Mixed notation: aws_instance.module.app_servers[0].app
// - Bracket notation: aws_instance[module.app_servers[0].app]
// - Template syntax: aws_instance.{{module.app_servers[0].app}}
// - Nested modules: aws_vpc[module.vpc.main]
//
// All patterns should correctly resolve to HCL source files.
func TestTFPlanDetector_NoFallbackToPlanJSON(t *testing.T) {
	tmpDir := t.TempDir()
	mainFile := filepath.Join(tmpDir, "main.tf")
	planFile := filepath.Join(tmpDir, "plan.tfplan.json")

	// Create realistic HCL with module calls
	mainContent := `module "vpc" {
  source = "./modules/networking"
  vpc_cidr = "10.0.0.0/16"
  resource_tags = {
    Environment = "production"
    Team        = "platform"
  }
}

module "app_servers" {
  source = "./modules/compute"
  count  = 3
  instance_type = "t2.micro"
  instance_tags = {
    Environment = "staging"
    Application = "web"
  }
}

resource "aws_instance" "web" {
  ami           = "ami-123456"
  instance_type = "t2.micro"
  tags = {
    Name = "web-server"
  }
}
`
	err := os.WriteFile(mainFile, []byte(mainContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.tf: %v", err)
	}

	// Create registry with all expected addresses
	reg := registry.New()

	// Register module calls
	reg.Register("module.vpc", registry.Location{
		FilePath: mainFile,
		Line:     1,
		Column:   1,
	})
	reg.Register("module.app_servers", registry.Location{
		FilePath: mainFile,
		Line:     9,
		Column:   1,
	})

	// Register root resource
	reg.Register("aws_instance.web", registry.Location{
		FilePath: mainFile,
		Line:     18,
		Column:   1,
	})

	// Register ONLY module call sites (as production HCL parser does at terraform.go:248-265)
	// Production NEVER registers module.vpc.aws_instance.bastion - only module.vpc
	reg.Register("module.vpc", registry.Location{
		FilePath: mainFile,
		Line:     1, // Module call site
		Column:   1,
	})
	reg.Register("module.app_servers", registry.Location{
		FilePath: mainFile,
		Line:     9, // Module call site
		Column:   1,
	})

	// Create TFPlan document structure (simulating parsed tfplan.json)
	tfplanDoc := model.Document{
		"resource": model.Document{
			"aws_instance": model.Document{
				"web": model.Document{
					"_dd_tf_address": "aws_instance.web",
					"ami":            "ami-123456",
					"tags": model.Document{
						"Name": "web-server",
					},
				},
				"bastion": model.Document{
					"_dd_tf_address": "module.vpc.aws_instance.bastion",
					"ami":            "ami-789012",
				},
				"app_0": model.Document{
					// NORMALIZED address (no [0] index) - matches real tfplan.go behavior at line 96
					"_dd_tf_address": "module.app_servers.aws_instance.app",
					"ami":            "ami-345678",
				},
				"app_1": model.Document{
					// NORMALIZED address (no [1] index) - matches real tfplan.go behavior at line 96
					"_dd_tf_address": "module.app_servers.aws_instance.app",
					"ami":            "ami-345678",
				},
			},
			"aws_vpc": model.Document{
				"main": model.Document{
					"_dd_tf_address": "module.vpc.aws_vpc.main",
					"cidr_block":     "10.0.0.0/16",
				},
			},
		},
	}

	// Round-trip through JSON to simulate real parsing
	jsonBytes, _ := json.Marshal(tfplanDoc)
	var roundTrippedDoc map[string]interface{}
	json.Unmarshal(jsonBytes, &roundTrippedDoc)

	fileMetadata := &model.FileMetadata{
		ID:               "test-tfplan",
		FilePath:         planFile,
		Kind:             model.KindJSON,
		Document:         roundTrippedDoc,
		LineInfoDocument: roundTrippedDoc,
	}

	detector := NewTFPlanDetectLine(reg, nil)
	ctx := context.Background()

	// Test cases covering all problematic search key patterns
	tests := []struct {
		name        string
		searchKey   string
		description string
	}{
		// Simple cases (should work)
		{
			name:        "simple resource",
			searchKey:   "aws_instance.web.tags",
			description: "Baseline: simple root resource should resolve to HCL",
		},

		// Module pattern variations
		{
			name:        "mixed notation with module",
			searchKey:   "aws_instance.module.app_servers[0].app",
			description: "Mixed notation: module path in middle of search key",
		},
		{
			name:        "bracket notation with module path",
			searchKey:   "aws_instance[module.app_servers[0].app]",
			description: "Bracket notation containing full module path",
		},
		{
			name:        "template syntax with module",
			searchKey:   "aws_instance.{{module.app_servers[0].app}}",
			description: "Template syntax with module path inside braces",
		},
		{
			name:        "bracket with nested module",
			searchKey:   "aws_vpc[module.vpc.main]",
			description: "Bracket notation with simple module path",
		},

		// Real rule patterns
		{
			name:        "indexed module with attribute",
			searchKey:   "module.app_servers[0].aws_instance.app.tags",
			description: "Real rule format from production",
		},
		{
			name:        "indexed module different instance",
			searchKey:   "module.app_servers[1].aws_instance.app.tags",
			description: "Different module index should also resolve to HCL",
		},
		{
			name:        "module resource with attribute",
			searchKey:   "module.vpc.aws_instance.bastion.tags",
			description: "Module resource attribute finding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.DetectLine(ctx, fileMetadata, tt.searchKey, 3)

			// CRITICAL ASSERTION: Result must NEVER point to .tfplan.json file
			if filepath.Ext(result.ResolvedFile) == ".json" {
				t.Errorf("FAIL: Finding points to JSON file instead of HCL source")
				t.Errorf("  SearchKey: %s", tt.searchKey)
				t.Errorf("  ResolvedFile: %s", result.ResolvedFile)
				t.Errorf("  Expected: %s (or other .tf file)", mainFile)
				t.Errorf("  Description: %s", tt.description)
				t.Errorf("  Line: %d", result.Line)
				t.Errorf("")
				t.Errorf("  This indicates the detector fell back to default detection,")
				t.Errorf("  which means the search key parser failed to extract the address.")
				t.Errorf("")
			}

			// Also check that we resolved to an actual file (not empty)
			if result.ResolvedFile == "" {
				t.Errorf("FAIL: ResolvedFile is empty")
				t.Errorf("  SearchKey: %s", tt.searchKey)
				t.Errorf("  Description: %s", tt.description)
			}

			// Check that we got a valid line number
			if result.Line <= 0 {
				t.Errorf("FAIL: Invalid line number %d", result.Line)
				t.Errorf("  SearchKey: %s", tt.searchKey)
				t.Errorf("  ResolvedFile: %s", result.ResolvedFile)
			}

			// Success logging
			if filepath.Ext(result.ResolvedFile) == ".tf" {
				t.Logf("✓ Correctly resolved to HCL: %s:%d", filepath.Base(result.ResolvedFile), result.Line)
			}
		})
	}
}
