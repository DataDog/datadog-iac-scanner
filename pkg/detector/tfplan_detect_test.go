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

func TestExtractResourceAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple resource",
			input:    "aws_instance.web.ami",
			expected: "aws_instance.web",
		},
		{
			name:     "resource with prefix",
			input:    "resource.aws_instance.web.ami",
			expected: "aws_instance.web",
		},
		{
			name:     "module resource",
			input:    "resource.module.vpc.aws_vpc.main.cidr_block",
			expected: "module.vpc.aws_vpc.main",
		},
		{
			name:     "nested module resource",
			input:    "resource.module.network.module.subnet.aws_subnet.private.cidr_block",
			expected: "module.network.module.subnet.aws_subnet.private",
		},
		{
			name:     "resource with index",
			input:    "aws_instance.web[0].ami",
			expected: "aws_instance.web",
		},
		{
			name:     "module with index",
			input:    "module.vpc[0].aws_vpc.main.cidr_block",
			expected: "module.vpc.aws_vpc.main",
		},
		{
			name:     "no resource prefix",
			input:    "module.vpc.aws_vpc.main.enable_dns_hostnames",
			expected: "module.vpc.aws_vpc.main",
		},
		{
			name:     "complex nested attribute",
			input:    "aws_instance.web.root_block_device.volume_size",
			expected: "aws_instance.web",
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
		},
		{
			name:     "single part",
			input:    "aws_instance",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractResourceAddress(tt.input)
			if result != tt.expected {
				t.Errorf("extractResourceAddress(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestTFPlanDetectLine(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.tf")

	// Write test HCL content
	hclContent := `resource "aws_instance" "web" {
  ami           = "ami-123456"
  instance_type = "t2.micro"
}

module "vpc" {
  source = "./modules/vpc"
  cidr   = "10.0.0.0/16"
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
	reg.Register("module.vpc", registry.Location{
		FilePath: testFile,
		Line:     6,
		Column:   1,
	})
	reg.Register("aws_s3_bucket.data", registry.Location{
		FilePath: testFile,
		Line:     11,
		Column:   1,
	})

	ctx := context.Background()
	detector := NewTFPlanDetectLine(reg, nil)

	// Create a mock tfplan document with _dd_tf_address fields
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
			name:         "root resource",
			searchKey:    "aws_instance.web.ami",
			expectedLine: 1,
			expectedFile: testFile,
		},
		{
			name:         "s3 bucket resource",
			searchKey:    "resource.aws_s3_bucket.data.acl",
			expectedLine: 11,
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

func TestTFPlanDetectLineFallback(t *testing.T) {
	// Create empty registry to test fallback behavior
	reg := registry.New()

	ctx := context.Background()
	detector := NewTFPlanDetectLine(reg, nil)

	// Create a mock file with actual content
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.json")
	jsonContent := `{
  "resource": {
    "aws_instance": {
      "web": {
        "ami": "ami-123456"
      }
    }
  }
}`
	err := os.WriteFile(testFile, []byte(jsonContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Read the file content
	content, _ := os.ReadFile(testFile)
	lines := make([]string, 0)
	for _, line := range string(content) {
		lines = append(lines, string(line))
	}

	fileMetadata := &model.FileMetadata{
		ID:                "test-file",
		FilePath:          testFile,
		Kind:              model.KindJSON,
		LinesOriginalData: &lines,
	}

	// Test fallback to default detector when no mapping exists
	result := detector.DetectLine(ctx, fileMetadata, "aws_instance.web.ami", 3)

	// Should fall back to default detection
	// Line number might be -1 or some default value since it's using fallback
	if result.ResolvedFile != testFile {
		t.Errorf("Expected fallback to use original file %s, got %s", testFile, result.ResolvedFile)
	}
}

func TestNormalizeTFPlanAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no indices",
			input:    "module.vpc.aws_instance.web",
			expected: "module.vpc.aws_instance.web",
		},
		{
			name:     "count index",
			input:    "module.vpc[0].aws_instance.web[1]",
			expected: "module.vpc.aws_instance.web",
		},
		{
			name:     "for_each key",
			input:    `module.network["us-east-1"].aws_vpc.main`,
			expected: "module.network.aws_vpc.main",
		},
		{
			name:     "mixed indices",
			input:    `module.env["prod"].module.region[0].aws_instance.web["app"]`,
			expected: "module.env.module.region.aws_instance.web",
		},
		{
			name:     "nested brackets",
			input:    `resource[0]["key"][1]`,
			expected: "resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeTFPlanAddress(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeTFPlanAddress(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBuildVulnerabilityLinesFromLocation(t *testing.T) {
	// Create a test file with known content
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.tf")
	content := `line 1
line 2
line 3
line 4
line 5`
	err := os.WriteFile(testFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	location := registry.Location{
		FilePath: testFile,
		Line:     3,
		Column:   1,
	}

	result := buildVulnerabilityLinesFromLocation(location, 1)

	// Check basic fields
	if result.Line != 3 {
		t.Errorf("Expected line 3, got %d", result.Line)
	}
	if result.ResolvedFile != testFile {
		t.Errorf("Expected file %s, got %s", testFile, result.ResolvedFile)
	}
	if result.ResourceSource != testFile {
		t.Errorf("Expected resource source %s, got %s", testFile, result.ResourceSource)
	}

	// Check vulnerability lines
	if result.VulnLines == nil || len(*result.VulnLines) == 0 {
		t.Error("Expected vulnerability lines to be populated")
	} else {
		vulnLines := *result.VulnLines
		// Should have 3 lines (line 2, 3, 4) with outputLines=1
		if len(vulnLines) != 3 {
			t.Errorf("Expected 3 vulnerability lines, got %d", len(vulnLines))
		}
		// Check that line 3 is included
		hasLine3 := false
		for _, vl := range vulnLines {
			if vl.Position == 3 {
				hasLine3 = true
				break
			}
		}
		if !hasLine3 {
			t.Error("Line 3 should be included in vulnerability lines")
		}
	}

	// Check location information
	if result.VulnerablilityLocation.Start.Line != 3 {
		t.Errorf("Expected start line 3, got %d", result.VulnerablilityLocation.Start.Line)
	}
}

func TestTFPlanDetectLineWithModuleMappings(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "main.tf")

	// Write test HCL content with module call
	hclContent := `module "vpc" {
  source = "./modules/vpc"

  # Line 4: Module inputs
  resource_tags = {
    Environment = "production"
    Team        = "platform"
  }

  cidr_block = "10.0.0.0/16"
}`
	err := os.WriteFile(testFile, []byte(hclContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create registry and register module address
	reg := registry.New()
	reg.Register("module.vpc", registry.Location{
		FilePath: testFile,
		Line:     1, // Module declaration line
		Column:   1,
	})

	// Create module mappings that simulate the module attribute mapping
	// This maps "tags" attribute → "resource_tags" variable
	moduleMappings := map[string]interface{}{
		"vpc": map[string]interface{}{
			"AttributesData": map[string]interface{}{
				"aws": map[string]interface{}{
					"inputs": map[string]interface{}{
						"tags": "resource_tags", // tags maps to resource_tags
					},
				},
			},
		},
	}

	ctx := context.Background()
	detector := NewTFPlanDetectLine(reg, moduleMappings)

	// Create a mock tfplan document with _dd_tf_address for a module resource
	mockDocument := model.Document{
		"resource": model.Document{
			"aws_instance": model.Document{
				"web": model.Document{
					"_dd_tf_address": "module.vpc.aws_instance.web",
					"tags": map[string]interface{}{
						"Environment": "production",
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

	// Create file metadata with the tfplan document
	fileMetadata := &model.FileMetadata{
		ID:               "test-file",
		FilePath:         filepath.Join(tmpDir, "plan.tfplan.json"),
		Kind:             model.KindJSON,
		Document:         roundTrippedDoc,
		LineInfoDocument: roundTrippedDoc,
	}

	// Test that the detector maps the module resource attribute to the module input variable line
	// searchKey should be in the format that comes from the query: "aws_instance.web.tags"
	// The detector will extract the address from the document ("module.vpc.aws_instance.web")
	result := detector.DetectLine(ctx, fileMetadata, "aws_instance.web.tags", 3)

	// Check that it resolved to the HCL file
	if result.ResolvedFile != testFile {
		t.Errorf("Expected resolved file %s, got %s", testFile, result.ResolvedFile)
	}

	// Check that it resolved to the resource_tags line (line 5), not the module declaration (line 1)
	if result.Line != 5 {
		t.Errorf("Expected line 5 (resource_tags attribute), got line %d", result.Line)
	}
}

func TestFindAttributeLineInFile(t *testing.T) {
	// Create a test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.tf")
	content := `module "vpc" {
  source = "./vpc"

  region = "us-east-1"
  resource_tags = {
    Team = "platform"
  }

  cidr_block = "10.0.0.0/16"
}`
	err := os.WriteFile(testFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	tests := []struct {
		name          string
		startLine     int
		attributeName string
		searchRange   int
		expectedLine  int
	}{
		{
			name:          "find resource_tags",
			startLine:     1,
			attributeName: "resource_tags",
			searchRange:   10,
			expectedLine:  5,
		},
		{
			name:          "find region",
			startLine:     1,
			attributeName: "region",
			searchRange:   10,
			expectedLine:  4,
		},
		{
			name:          "find cidr_block",
			startLine:     1,
			attributeName: "cidr_block",
			searchRange:   10,
			expectedLine:  9,
		},
		{
			name:          "attribute not found",
			startLine:     1,
			attributeName: "nonexistent",
			searchRange:   10,
			expectedLine:  -1,
		},
		{
			name:          "small search range with min window",
			startLine:     1,
			attributeName: "cidr_block",
			searchRange:   2, // With min window of 100, will still find it on line 9
			expectedLine:  9, // Now found due to minimum search window
		},
		{
			name:          "start from middle of file",
			startLine:     5,
			attributeName: "cidr_block",
			searchRange:   5,
			expectedLine:  9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findAttributeLineInFile(testFile, tt.startLine, tt.attributeName, tt.searchRange, "module")
			if result != tt.expectedLine {
				t.Errorf("Expected line %d, got %d", tt.expectedLine, result)
			}
		})
	}
}

func TestBuildFullSearchKey(t *testing.T) {
	detector := &TFPlanDetectLine{}

	tests := []struct {
		name        string
		address     string
		searchKey   string
		expected    string
		description string
	}{
		{
			name:        "simple module resource with attribute",
			address:     "module.vpc.aws_instance.web",
			searchKey:   "aws_instance.web.tags",
			expected:    "module.vpc.aws_instance.web.tags",
			description: "Should combine address and attribute",
		},
		{
			name:        "resource prefix in searchKey",
			address:     "module.vpc.aws_instance.web",
			searchKey:   "resource.aws_instance.web.tags",
			expected:    "module.vpc.aws_instance.web.tags",
			description: "Should strip resource prefix before combining",
		},
		{
			name:        "no attribute in searchKey",
			address:     "module.vpc.aws_instance.web",
			searchKey:   "aws_instance.web",
			expected:    "module.vpc.aws_instance.web",
			description: "Should return address when no attribute",
		},
		{
			name:        "nested attribute path",
			address:     "module.vpc.aws_instance.web",
			searchKey:   "aws_instance.web.root_block_device.volume_size",
			expected:    "module.vpc.aws_instance.web.root_block_device.volume_size",
			description: "Should handle nested attribute paths",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.buildFullSearchKey(tt.address, tt.searchKey)
			if result != tt.expected {
				t.Errorf("%s: Expected %q, got %q", tt.description, tt.expected, result)
			}
		})
	}
}

func TestTransformSearchKeyForModuleEdgeCases(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name              string
		moduleMappings    map[string]interface{}
		moduleAddress     string
		searchKey         string
		expectedSearchKey string
		expectedAttribute string
		description       string
	}{
		{
			name:              "nil module mappings",
			moduleMappings:    nil,
			moduleAddress:     "module.vpc",
			searchKey:         "module.vpc.aws_instance.web.tags",
			expectedSearchKey: "",
			expectedAttribute: "",
			description:       "Should return empty when no mappings",
		},
		{
			name: "module not in mappings",
			moduleMappings: map[string]interface{}{
				"other_module": map[string]interface{}{},
			},
			moduleAddress:     "module.vpc",
			searchKey:         "module.vpc.aws_instance.web.tags",
			expectedSearchKey: "",
			expectedAttribute: "",
			description:       "Should return empty when module not found",
		},
		{
			name: "attribute not in mappings",
			moduleMappings: map[string]interface{}{
				"vpc": map[string]interface{}{
					"AttributesData": map[string]interface{}{
						"aws": map[string]interface{}{
							"inputs": map[string]interface{}{
								"cidr": "vpc_cidr", // Different attribute
							},
						},
					},
				},
			},
			moduleAddress:     "module.vpc",
			searchKey:         "module.vpc.aws_instance.web.tags",
			expectedSearchKey: "module.vpc.aws_instance.web.tags", // Fallback uses full searchKey
			expectedAttribute: "tags",
			description:       "Should use fallback transformation when attribute not mapped",
		},
		{
			name: "successful transformation",
			moduleMappings: map[string]interface{}{
				"vpc": map[string]interface{}{
					"AttributesData": map[string]interface{}{
						"aws": map[string]interface{}{
							"inputs": map[string]interface{}{
								"tags": "resource_tags",
							},
						},
					},
				},
			},
			moduleAddress:     "module.vpc",
			searchKey:         "module.vpc.aws_instance.web.tags",
			expectedSearchKey: "module.vpc.resource_tags",
			expectedAttribute: "resource_tags",
			description:       "Should successfully transform with valid mappings",
		},
		{
			name: "searchKey too short",
			moduleMappings: map[string]interface{}{
				"vpc": map[string]interface{}{
					"AttributesData": map[string]interface{}{
						"aws": map[string]interface{}{
							"inputs": map[string]interface{}{
								"tags": "resource_tags",
							},
						},
					},
				},
			},
			moduleAddress:     "module.vpc",
			searchKey:         "module.vpc",
			expectedSearchKey: "",
			expectedAttribute: "",
			description:       "Should return empty when searchKey too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := NewTFPlanDetectLine(nil, tt.moduleMappings)
			transformedKey, attribute := detector.transformSearchKeyForModule(ctx, tt.moduleAddress, tt.searchKey)

			if transformedKey != tt.expectedSearchKey {
				t.Errorf("%s: Expected searchKey %q, got %q", tt.description, tt.expectedSearchKey, transformedKey)
			}
			if attribute != tt.expectedAttribute {
				t.Errorf("%s: Expected attribute %q, got %q", tt.description, tt.expectedAttribute, attribute)
			}
		})
	}
}

func roundTripDocument(doc model.Document) model.Document {
	b, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	var out model.Document
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

// TestOriginBranch_ModuleHardcoded verifies that a module_hardcoded origin resolves to
// the resource definition attribute line in the module's .tf file.
func TestOriginBranch_ModuleHardcoded(t *testing.T) {
	tmpDir := t.TempDir()

	// Write parent main.tf with module call
	mainTF := filepath.Join(tmpDir, "main.tf")
	err := os.WriteFile(mainTF, []byte(`module "rds" {
  source = "./modules/rds"
}
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Write module definition with hardcoded publicly_accessible
	modulesDir := filepath.Join(tmpDir, "modules", "rds")
	if err := os.MkdirAll(modulesDir, 0755); err != nil {
		t.Fatal(err)
	}
	moduleMainTF := filepath.Join(modulesDir, "main.tf")
	err = os.WriteFile(moduleMainTF, []byte(`resource "aws_db_instance" "this" {
  identifier          = "app-db"
  publicly_accessible = true
}
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Register both the module call and the resource definition
	reg := registry.New()
	reg.Register("module.rds", registry.Location{FilePath: mainTF, Line: 1, Column: 1})
	reg.Register("aws_db_instance.this", registry.Location{FilePath: moduleMainTF, Line: 1, Column: 1})

	ctx := context.Background()
	detector := NewTFPlanDetectLine(reg, nil)

	// Build document with module_hardcoded origin for publicly_accessible
	rawDoc := model.Document{
		"resource": map[string]interface{}{
			"aws_db_instance": map[string]interface{}{
				"module.rds.this": map[string]interface{}{
					"_dd_tf_address": "module.rds.aws_db_instance.this",
					"_dd_tf_origin": map[string]interface{}{
						"publicly_accessible": map[string]interface{}{
							"origin":    "module_hardcoded",
							"moduleDir": "./modules/rds",
						},
					},
					"publicly_accessible": true,
				},
			},
		},
	}
	roundTripped := roundTripDocument(rawDoc)

	fileMetadata := &model.FileMetadata{
		ID:               "plan",
		FilePath:         filepath.Join(tmpDir, "plan.tfplan.json"),
		Kind:             model.KindJSON,
		Document:         roundTripped,
		LineInfoDocument: roundTripped,
	}

	result := detector.DetectLine(ctx, fileMetadata, "module.rds.aws_db_instance.this.publicly_accessible", 3)

	// Should resolve to the module DEFINITION file (modules/rds/main.tf), not main.tf
	if result.ResolvedFile != moduleMainTF {
		t.Errorf("expected module definition file %q, got %q", moduleMainTF, result.ResolvedFile)
	}
	// Line 3 is "publicly_accessible = true"
	if result.Line != 3 {
		t.Errorf("expected attribute line 3, got %d", result.Line)
	}
	// No secondary finding for hardcoded
	if result.SecondaryLines != nil {
		t.Error("expected no SecondaryLines for module_hardcoded")
	}
}

// TestOriginBranch_ModuleDefault verifies that a module_default origin produces TWO findings:
// primary at the variable default line and secondary at the module call block.
func TestOriginBranch_ModuleDefault(t *testing.T) {
	tmpDir := t.TempDir()

	// Write parent main.tf with module call (omits publicly_accessible)
	mainTF := filepath.Join(tmpDir, "main.tf")
	err := os.WriteFile(mainTF, []byte(`module "rds" {
  source = "./modules/rds"
  identifier = "app-db"
}
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Write module variables.tf with insecure default
	modulesDir := filepath.Join(tmpDir, "modules", "rds")
	if err := os.MkdirAll(modulesDir, 0755); err != nil {
		t.Fatal(err)
	}
	variablesTF := filepath.Join(modulesDir, "variables.tf")
	err = os.WriteFile(variablesTF, []byte(`variable "publicly_accessible" {
  description = "Whether the DB is publicly accessible."
  type        = bool
  default     = true
}
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	reg := registry.New()
	reg.Register("module.rds", registry.Location{FilePath: mainTF, Line: 1, Column: 1})
	reg.Register("var.publicly_accessible", registry.Location{FilePath: variablesTF, Line: 1, Column: 1})

	ctx := context.Background()
	detector := NewTFPlanDetectLine(reg, nil)

	rawDoc := model.Document{
		"resource": map[string]interface{}{
			"aws_db_instance": map[string]interface{}{
				"module.rds.this": map[string]interface{}{
					"_dd_tf_address": "module.rds.aws_db_instance.this",
					"_dd_tf_origin": map[string]interface{}{
						"publicly_accessible": map[string]interface{}{
							"origin":    "module_default",
							"variable":  "publicly_accessible",
							"moduleDir": "./modules/rds",
						},
					},
					"publicly_accessible": true,
				},
			},
		},
	}
	roundTripped := roundTripDocument(rawDoc)

	fileMetadata := &model.FileMetadata{
		ID:               "plan",
		FilePath:         filepath.Join(tmpDir, "plan.tfplan.json"),
		Kind:             model.KindJSON,
		Document:         roundTripped,
		LineInfoDocument: roundTripped,
	}

	result := detector.DetectLine(ctx, fileMetadata, "module.rds.aws_db_instance.this.publicly_accessible", 3)

	// Primary should point at variables.tf default line (line 4: "default = true")
	if result.ResolvedFile != variablesTF {
		t.Errorf("expected variables.tf %q as primary, got %q", variablesTF, result.ResolvedFile)
	}
	if result.Line != 4 {
		t.Errorf("expected default line 4, got %d", result.Line)
	}

	// Secondary should point at the module call block in main.tf
	if result.SecondaryLines == nil {
		t.Fatal("expected SecondaryLines for module_default, got nil")
	}
	if result.SecondaryLines.ResolvedFile != mainTF {
		t.Errorf("expected secondary file %q (module call), got %q", mainTF, result.SecondaryLines.ResolvedFile)
	}
	if result.SecondaryLines.Line != 1 {
		t.Errorf("expected secondary line 1 (module block), got %d", result.SecondaryLines.Line)
	}
}

// TestOriginBranch_CallSite verifies that a call origin (or no hint) still resolves to the
// module call block as before, with no secondary finding.
func TestOriginBranch_CallSite(t *testing.T) {
	tmpDir := t.TempDir()

	mainTF := filepath.Join(tmpDir, "main.tf")
	err := os.WriteFile(mainTF, []byte(`module "rds" {
  source              = "./modules/rds"
  publicly_accessible = true
}
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	reg := registry.New()
	reg.Register("module.rds", registry.Location{FilePath: mainTF, Line: 1, Column: 1})

	ctx := context.Background()
	detector := NewTFPlanDetectLine(reg, nil)

	rawDoc := model.Document{
		"resource": map[string]interface{}{
			"aws_db_instance": map[string]interface{}{
				"module.rds.this": map[string]interface{}{
					"_dd_tf_address": "module.rds.aws_db_instance.this",
					"_dd_tf_origin": map[string]interface{}{
						"publicly_accessible": map[string]interface{}{
							"origin":   "call",
							"variable": "publicly_accessible",
						},
					},
					"publicly_accessible": true,
				},
			},
		},
	}
	roundTripped := roundTripDocument(rawDoc)

	fileMetadata := &model.FileMetadata{
		ID:               "plan",
		FilePath:         filepath.Join(tmpDir, "plan.tfplan.json"),
		Kind:             model.KindJSON,
		Document:         roundTripped,
		LineInfoDocument: roundTripped,
	}

	result := detector.DetectLine(ctx, fileMetadata, "module.rds.aws_db_instance.this.publicly_accessible", 3)

	// Should resolve to the module call in main.tf (module declaration line without mappings)
	if result.ResolvedFile != mainTF {
		t.Errorf("expected call file %q, got %q", mainTF, result.ResolvedFile)
	}
	// Without module mappings to translate the attribute name, resolves to the module declaration line
	if result.Line != 1 {
		t.Errorf("expected module declaration line 1, got %d", result.Line)
	}
	if result.SecondaryLines != nil {
		t.Error("expected no SecondaryLines for call origin")
	}
}

// TestOriginBranch_AbsentAttribute verifies that when an attribute (e.g. "tags") is completely
// absent from the module resource's expressions, it is treated as module_hardcoded and the
// finding resolves to the module definition — not the module call. This covers the case where
// a module simply never declares an attribute (e.g. no tags block), so the call cannot fix it.
func TestOriginBranch_AbsentAttribute(t *testing.T) {
	tmpDir := t.TempDir()

	// Parent main.tf: module call does not (and cannot) pass tags
	mainTF := filepath.Join(tmpDir, "main.tf")
	err := os.WriteFile(mainTF, []byte(`module "asg" {
  source            = "./modules/asg"
  security_group_id = ["sg-123"]
}
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Module definition: resource has no tags attribute at all
	modulesDir := filepath.Join(tmpDir, "modules", "asg")
	if err := os.MkdirAll(modulesDir, 0755); err != nil {
		t.Fatal(err)
	}
	moduleMainTF := filepath.Join(modulesDir, "main.tf")
	err = os.WriteFile(moduleMainTF, []byte(`resource "aws_launch_template" "this" {
  name                   = "web"
  vpc_security_group_ids = var.security_group_id
}
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	reg := registry.New()
	reg.Register("module.asg", registry.Location{FilePath: mainTF, Line: 1, Column: 1})
	reg.Register("aws_launch_template.this", registry.Location{FilePath: moduleMainTF, Line: 1, Column: 1})

	ctx := context.Background()
	detector := NewTFPlanDetectLine(reg, nil)

	// _dd_tf_origin has hints for the attributes that ARE in expressions (name, vpc_security_group_ids),
	// but NOT for "tags" — because it is absent from the module resource entirely.
	rawDoc := model.Document{
		"resource": map[string]interface{}{
			"aws_launch_template": map[string]interface{}{
				"module.asg.this": map[string]interface{}{
					"_dd_tf_address": "module.asg.aws_launch_template.this",
					"_dd_tf_origin": map[string]interface{}{
						// "name" is hardcoded in the module ("web")
						"name": map[string]interface{}{
							"origin":    "module_hardcoded",
							"moduleDir": "./modules/asg",
						},
						// "vpc_security_group_ids" is set by the call
						"vpc_security_group_ids": map[string]interface{}{
							"origin":   "call",
							"variable": "security_group_id",
							"moduleDir": "./modules/asg",
						},
						// "tags" is intentionally absent — not in module expressions at all
					},
					"name":                   "web",
					"vpc_security_group_ids": []interface{}{"sg-123"},
				},
			},
		},
	}
	roundTripped := roundTripDocument(rawDoc)

	fileMetadata := &model.FileMetadata{
		ID:               "plan",
		FilePath:         filepath.Join(tmpDir, "plan.tfplan.json"),
		Kind:             model.KindJSON,
		Document:         roundTripped,
		LineInfoDocument: roundTripped,
	}

	// searchKey has "tags" attribute — absent from module resource expressions
	result := detector.DetectLine(ctx, fileMetadata, "aws_launch_template[module.asg.this].tags", 3)

	// Must resolve to the module DEFINITION file (where the fix needs to happen: add a tags block)
	if result.ResolvedFile != moduleMainTF {
		t.Errorf("expected module definition %q, got %q", moduleMainTF, result.ResolvedFile)
	}
	// Line 1 is the resource block declaration — the attribute line won't be found since tags is absent
	if result.Line != 1 {
		t.Errorf("expected resource definition line 1, got %d", result.Line)
	}
	// No secondary finding — this is a single-location module_hardcoded finding
	if result.SecondaryLines != nil {
		t.Error("expected no SecondaryLines for absent-attribute (module_hardcoded) finding")
	}
}

// TestOriginBranch_NestedBlockHardcoded verifies that a hardcoded attribute inside a nested
// block (e.g. metadata_options { http_endpoint = "enabled" }) is correctly classified as
// module_hardcoded and resolves to the module definition file.
func TestOriginBranch_NestedBlockHardcoded(t *testing.T) {
	tmpDir := t.TempDir()

	mainTF := filepath.Join(tmpDir, "main.tf")
	err := os.WriteFile(mainTF, []byte(`module "ec2" {
  source     = "./modules/ec2"
  ami        = "ami-123"
  http_tokens = "required"
}
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	modulesDir := filepath.Join(tmpDir, "modules", "ec2")
	if err := os.MkdirAll(modulesDir, 0755); err != nil {
		t.Fatal(err)
	}
	moduleMainTF := filepath.Join(modulesDir, "main.tf")
	err = os.WriteFile(moduleMainTF, []byte(`resource "aws_instance" "this" {
  ami = var.ami

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = var.http_tokens
  }
}
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	reg := registry.New()
	reg.Register("module.ec2", registry.Location{FilePath: mainTF, Line: 1, Column: 1})
	reg.Register("aws_instance.this", registry.Location{FilePath: moduleMainTF, Line: 1, Column: 1})

	ctx := context.Background()
	detector := NewTFPlanDetectLine(reg, nil)

	// _dd_tf_origin reflects the nested block classification:
	// metadata_options.http_endpoint is module_hardcoded (constant "enabled")
	// metadata_options.http_tokens is call (caller sets it)
	rawDoc := model.Document{
		"resource": map[string]interface{}{
			"aws_instance": map[string]interface{}{
				"module.ec2.this": map[string]interface{}{
					"_dd_tf_address": "module.ec2.aws_instance.this",
					"_dd_tf_origin": map[string]interface{}{
						"ami": map[string]interface{}{
							"origin":    "call",
							"variable":  "ami",
							"moduleDir": "./modules/ec2",
						},
						"metadata_options.http_endpoint": map[string]interface{}{
							"origin":    "module_hardcoded",
							"moduleDir": "./modules/ec2",
						},
						"metadata_options.http_tokens": map[string]interface{}{
							"origin":    "call",
							"variable":  "http_tokens",
							"moduleDir": "./modules/ec2",
						},
					},
					"ami": "ami-123",
				},
			},
		},
	}
	roundTripped := roundTripDocument(rawDoc)

	fileMetadata := &model.FileMetadata{
		ID:               "plan",
		FilePath:         filepath.Join(tmpDir, "plan.tfplan.json"),
		Kind:             model.KindJSON,
		Document:         roundTripped,
		LineInfoDocument: roundTripped,
	}

	// Resource-level finding (no attribute): should pick module_hardcoded as the dominant origin
	result := detector.DetectLine(ctx, fileMetadata, "aws_instance.{{module.ec2.this}}", 3)

	// Must resolve to the module DEFINITION file
	if result.ResolvedFile != moduleMainTF {
		t.Errorf("expected module definition %q, got %q", moduleMainTF, result.ResolvedFile)
	}
	if result.SecondaryLines != nil {
		t.Error("expected no SecondaryLines for module_hardcoded resource-level finding")
	}
}
