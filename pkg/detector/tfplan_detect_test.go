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
	detector := NewTFPlanDetectLine(reg)

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
		ID:              "test-file",
		FilePath:        "test.tfplan.json",
		Kind:            model.KindJSON,
		Document:        roundTrippedDoc,     // This is now map[string]interface{} nested
		LineInfoDocument: roundTrippedDoc,    // TFPlan detector reads _dd_tf_address from here
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
	detector := NewTFPlanDetectLine(reg)

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
