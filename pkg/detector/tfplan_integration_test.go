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
	detector := NewTFPlanDetectLine(reg)

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
		ID:              "test-file",
		FilePath:        "test.tfplan.json",
		Kind:            model.KindJSON,
		Document:        roundTrippedDoc, // This is now map[string]interface{} nested
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
