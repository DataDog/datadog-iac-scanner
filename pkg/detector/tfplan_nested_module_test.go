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

// TestTFPlanDetectLineNestedModules verifies that nested module resources
// resolve to top-level module calls when only the top-level is registered
func TestTFPlanDetectLineNestedModules(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "main.tf")

	// Write test HCL content with a top-level module call
	hclContent := `module "network" {
  source = "./modules/network"
  cidr   = "10.0.0.0/16"
}`
	err := os.WriteFile(testFile, []byte(hclContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create registry and register only the top-level module call
	// (not the nested module.subnet)
	reg := registry.New()
	reg.Register("module.network", registry.Location{
		FilePath: testFile,
		Line:     1,
		Column:   1,
	})

	ctx := context.Background()
	detector := NewTFPlanDetectLine(reg, nil)

	// Create a mock tfplan document with a resource in a nested module
	// The address is: module.network.module.subnet.aws_subnet.private
	mockDocument := model.Document{
		"resource": model.Document{
			"aws_subnet": model.Document{
				"module.network.module.subnet.private": model.Document{
					"_dd_tf_address": "module.network.module.subnet.aws_subnet.private",
					"cidr_block":     "10.0.1.0/24",
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

	// Create file metadata
	fileMetadata := &model.FileMetadata{
		ID:               "test-file",
		FilePath:         "test.tfplan.json",
		Kind:             model.KindJSON,
		Document:         roundTrippedDoc,
		LineInfoDocument: roundTrippedDoc, // TFPlan detector reads _dd_tf_address from here
	}

	// Test that nested module resource resolves to top-level module call
	searchKey := "aws_subnet[module.network.module.subnet.private].cidr_block"
	result := detector.DetectLine(ctx, fileMetadata, searchKey, 3)

	// Should resolve to the top-level module.network call
	if result.Line != 1 {
		t.Errorf("Expected line 1 (top-level module call), got %d", result.Line)
	}
	if result.ResolvedFile != testFile {
		t.Errorf("Expected file %s, got %s", testFile, result.ResolvedFile)
	}
	if result.ResourceSource != testFile {
		t.Errorf("Expected resource source %s, got %s", testFile, result.ResourceSource)
	}
}

// TestTFPlanDetectLineTripleNestedModules tests that deeply nested modules
// (e.g., module.a.module.b.module.c) resolve correctly
func TestTFPlanDetectLineTripleNestedModules(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "main.tf")

	hclContent := `module "env" {
  source = "./modules/env"
}`
	err := os.WriteFile(testFile, []byte(hclContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	reg := registry.New()
	reg.Register("module.env", registry.Location{
		FilePath: testFile,
		Line:     1,
		Column:   1,
	})

	ctx := context.Background()
	detector := NewTFPlanDetectLine(reg, nil)

	// Triple nested: module.env.module.region.module.vpc.aws_vpc.main
	mockDocument := model.Document{
		"resource": model.Document{
			"aws_vpc": model.Document{
				"module.env.module.region.module.vpc.main": model.Document{
					"_dd_tf_address": "module.env.module.region.module.vpc.aws_vpc.main",
					"cidr_block":     "10.0.0.0/16",
				},
			},
		},
	}

	jsonBytes, err := json.Marshal(mockDocument)
	if err != nil {
		t.Fatalf("Failed to marshal document: %v", err)
	}

	var roundTrippedDoc model.Document
	err = json.Unmarshal(jsonBytes, &roundTrippedDoc)
	if err != nil {
		t.Fatalf("Failed to unmarshal document: %v", err)
	}

	fileMetadata := &model.FileMetadata{
		ID:               "test-file",
		FilePath:         "test.tfplan.json",
		Kind:             model.KindJSON,
		Document:         roundTrippedDoc,
		LineInfoDocument: roundTrippedDoc, // TFPlan detector reads _dd_tf_address from here
	}

	searchKey := "aws_vpc[module.env.module.region.module.vpc.main].cidr_block"
	result := detector.DetectLine(ctx, fileMetadata, searchKey, 3)

	// Should resolve to the top-level module.env call
	if result.Line != 1 {
		t.Errorf("Expected line 1 (top-level module call), got %d", result.Line)
	}
	if result.ResolvedFile != testFile {
		t.Errorf("Expected file %s, got %s", testFile, result.ResolvedFile)
	}
}
