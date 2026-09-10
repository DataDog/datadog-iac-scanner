/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package registry

import (
	"sync"
	"testing"
)

func TestNormalizeAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple resource",
			input:    "aws_instance.web",
			expected: "aws_instance.web",
		},
		{
			name:     "resource with count index",
			input:    "aws_instance.web[0]",
			expected: "aws_instance.web",
		},
		{
			name:     "resource with for_each key",
			input:    `aws_instance.app["prod"]`,
			expected: "aws_instance.app",
		},
		{
			name:     "module with resource",
			input:    "module.vpc.aws_instance.web",
			expected: "module.vpc.aws_instance.web",
		},
		{
			name:     "module with index and resource with index",
			input:    "module.vpc[0].aws_instance.web[1]",
			expected: "module.vpc.aws_instance.web",
		},
		{
			name:     "nested modules with indices",
			input:    `module.network["us-east-1"].module.subnet[0].aws_subnet.private["a"]`,
			expected: "module.network.module.subnet.aws_subnet.private",
		},
		{
			name:     "complex nested modules",
			input:    `module.env["prod"].module.region["us-east-1"].module.vpc[0].aws_vpc.main`,
			expected: "module.env.module.region.module.vpc.aws_vpc.main",
		},
		{
			name:     "for_each key containing a literal closing bracket",
			input:    `module.secrets["prod]eu"].aws_instance.web`,
			expected: "module.secrets.aws_instance.web",
		},
		{
			name:     "for_each key containing a literal opening bracket",
			input:    `module.secrets["prod[eu"].aws_instance.web`,
			expected: "module.secrets.aws_instance.web",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeAddress(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeAddress(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractModuleAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple module",
			input:    "module.vpc.aws_instance.web",
			expected: "module.vpc",
		},
		{
			name:     "nested modules",
			input:    "module.network.module.subnet.aws_subnet.private",
			expected: "module.network.module.subnet",
		},
		{
			name:     "no module (root resource)",
			input:    "aws_instance.web",
			expected: "",
		},
		{
			name:     "module with indices",
			input:    "module.vpc[0].aws_instance.web[1]",
			expected: "module.vpc",
		},
		{
			name:     "deeply nested modules",
			input:    "module.env.module.region.module.vpc.aws_vpc.main",
			expected: "module.env.module.region.module.vpc",
		},
		{
			name:     "single module",
			input:    "module.vpc",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractModuleAddress(tt.input)
			if result != tt.expected {
				t.Errorf("ExtractModuleAddress(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestRegisterAndLookup(t *testing.T) {
	// Create new registry instance for test
	reg := New()

	// Test basic registration and lookup
	location1 := Location{FilePath: "main.tf", Line: 10, Column: 1}
	reg.Register("aws_instance.web", location1)

	// LookupWithScope with exact address
	found, ok := reg.LookupWithScope("aws_instance.web", "main.tf")
	if !ok {
		t.Error("Failed to find registered address")
	}
	if found.FilePath != "main.tf" || found.Line != 10 {
		t.Errorf("Unexpected location: %+v", found)
	}

	// LookupWithScope with indexed address (should normalize)
	found, ok = reg.LookupWithScope("aws_instance.web[0]", "main.tf")
	if !ok {
		t.Error("Failed to find address with index")
	}
	if found.FilePath != "main.tf" || found.Line != 10 {
		t.Errorf("Unexpected location for indexed lookup: %+v", found)
	}

	// Create new registry and verify it's empty
	reg2 := New()
	if reg2.GetMappingCount() != 0 {
		t.Error("New registry should be empty")
	}
}

func TestDuplicateHandling(t *testing.T) {
	// Create new registry instance for test
	reg := New()

	location1 := Location{FilePath: "/dir1/file1.tf", Line: 10, Column: 1}
	location2 := Location{FilePath: "/dir2/file2.tf", Line: 20, Column: 1}

	// Register first occurrence
	reg.Register("module.vpc", location1)
	if reg.GetMappingCount() != 1 {
		t.Error("First registration failed")
	}

	// Register duplicate (should now store BOTH locations)
	reg.Register("module.vpc", location2)
	if reg.GetMappingCount() != 1 {
		t.Error("Duplicate created new mapping - should store under same key")
	}
	if !reg.HasDuplicates("module.vpc") {
		t.Error("Duplicate not tracked")
	}
	if reg.GetLocationCount("module.vpc") != 2 {
		t.Errorf("Expected 2 locations, got %d", reg.GetLocationCount("module.vpc"))
	}

	// LookupWithScope should still resolve to a registered location
	found, ok := reg.LookupWithScope("module.vpc", location1.FilePath)
	if !ok {
		t.Error("LookupWithScope should succeed")
	}
	if found.FilePath != location1.FilePath || found.Line != location1.Line {
		t.Errorf("Expected location1 (matching scope), got %+v", found)
	}

	// Try to register a third occurrence (should be stored as well)
	location3 := Location{FilePath: "/dir3/file3.tf", Line: 30, Column: 1}
	reg.Register("module.vpc", location3)
	if reg.GetLocationCount("module.vpc") != 3 {
		t.Errorf("Expected 3 locations, got %d", reg.GetLocationCount("module.vpc"))
	}

	// LookupWithScope should still resolve to the location matching the scope
	found, ok = reg.LookupWithScope("module.vpc", location3.FilePath)
	if !ok || found.FilePath != location3.FilePath {
		t.Errorf("Expected location3 (matching scope), got %+v", found)
	}
}

func TestConcurrentAccess(t *testing.T) {
	// Create new registry instance for test
	reg := New()

	var wg sync.WaitGroup
	numGoroutines := 100
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				address := "aws_instance.web"
				if j%2 == 0 {
					address = "module.vpc.aws_instance.web"
				}
				location := Location{
					FilePath: "concurrent.tf",
					Line:     id*100 + j,
					Column:   1,
				}
				reg.Register(address, location)
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				reg.LookupWithScope("aws_instance.web[0]", "concurrent.tf")
				reg.LookupWithScope("module.vpc[1].aws_instance.web", "concurrent.tf")
			}
		}(i)
	}

	wg.Wait()

	// Verify state after concurrent operations
	// Due to duplicate handling and keeping the first registration,
	// we should have at least some mappings (the first ones registered for each unique address)
	mappingCount := reg.GetMappingCount()
	if mappingCount == 0 {
		t.Error("Expected some mappings to be kept (first registrations)")
	}
	// We registered 2 unique addresses, so we should have 1-2 mappings depending on race conditions
	if mappingCount > 2 {
		t.Errorf("Expected at most 2 mappings, got %d", mappingCount)
	}
}

func TestModuleWithCountAndResource(t *testing.T) {
	// Create new registry instance for test
	reg := New()

	// Register a module call location
	moduleLocation := Location{FilePath: "main.tf", Line: 15, Column: 1}
	reg.Register("module.networking", moduleLocation)

	// Register a resource in root
	resourceLocation := Location{FilePath: "main.tf", Line: 30, Column: 1}
	reg.Register("aws_vpc.main", resourceLocation)

	// LookupWithScope module with index
	found, ok := reg.LookupWithScope("module.networking[0]", moduleLocation.FilePath)
	if !ok {
		t.Error("Failed to find module with index")
	}
	if found.Line != 15 {
		t.Errorf("Wrong line for module: %d", found.Line)
	}

	// LookupWithScope resource directly
	found, ok = reg.LookupWithScope("aws_vpc.main", resourceLocation.FilePath)
	if !ok {
		t.Error("Failed to find resource")
	}
	if found.Line != 30 {
		t.Errorf("Wrong line for resource: %d", found.Line)
	}
}

// TestScopeBasedDisambiguation tests P2: Two directories with same module name
// This is the critical test case identified in the user's feedback:
// "I don't see a test with two directories/files both containing module "vpc" plus a tfplan beside one of them.
// That exact case should assert the plan maps to the same-directory HCL file, not the first registered fixture and not JSON fallback."
func TestScopeBasedDisambiguation(t *testing.T) {
	reg := New()

	// Simulate two different directories, both with module "vpc"
	// This mimics real scenarios with rule fixtures or multi-root scans
	location1 := Location{
		FilePath: "/project/fixtures/test1/main.tf",
		Line:     10,
		Column:   1,
	}
	location2 := Location{
		FilePath: "/project/fixtures/test2/main.tf",
		Line:     20,
		Column:   1,
	}

	// Register both module "vpc" instances
	reg.Register("module.vpc", location1)
	reg.Register("module.vpc", location2)

	// Verify both are stored
	if reg.GetLocationCount("module.vpc") != 2 {
		t.Errorf("Expected 2 locations for module.vpc, got %d", reg.GetLocationCount("module.vpc"))
	}
	if !reg.HasDuplicates("module.vpc") {
		t.Error("module.vpc should be marked as duplicate")
	}

	// Test 1: tfplan in test1 directory should resolve to test1 HCL
	tfplanFile1 := "/project/fixtures/test1/plan.tfplan.json"
	found1, ok := reg.LookupWithScope("module.vpc", tfplanFile1)
	if !ok {
		t.Error("LookupWithScope should find module.vpc for test1")
	}
	if found1.FilePath != location1.FilePath {
		t.Errorf("Expected test1 location %s, got %s", location1.FilePath, found1.FilePath)
	}
	if found1.Line != location1.Line {
		t.Errorf("Expected line %d, got %d", location1.Line, found1.Line)
	}

	// Test 2: tfplan in test2 directory should resolve to test2 HCL
	tfplanFile2 := "/project/fixtures/test2/plan.tfplan.json"
	found2, ok := reg.LookupWithScope("module.vpc", tfplanFile2)
	if !ok {
		t.Error("LookupWithScope should find module.vpc for test2")
	}
	if found2.FilePath != location2.FilePath {
		t.Errorf("Expected test2 location %s, got %s", location2.FilePath, found2.FilePath)
	}
	if found2.Line != location2.Line {
		t.Errorf("Expected line %d, got %d", location2.Line, found2.Line)
	}

	// Test 3: Verify it picks the closest match even with nested paths
	tfplanFile3 := "/project/fixtures/test1/subdir/another.tfplan.json"
	found3, ok := reg.LookupWithScope("module.vpc", tfplanFile3)
	if !ok {
		t.Error("LookupWithScope should find module.vpc for test1/subdir")
	}
	// Should still choose test1 (longer common path prefix)
	if found3.FilePath != location1.FilePath {
		t.Errorf("Expected test1 location (closer match), got %s", found3.FilePath)
	}
}

// TestScopeBasedDisambiguation_SiblingDirectoryNameDoesNotOutrankSameDirectory guards against
// commonPathLength comparing raw characters instead of directory components: a scope file whose
// name happens to share a character prefix with a sibling directory name (here, scope
// "/project/plan.tfplan.json" starts with "plan", matching the directory "/project/plan") must
// not be scored as closer to that sibling than to the scope's own directory.
func TestScopeBasedDisambiguation_SiblingDirectoryNameDoesNotOutrankSameDirectory(t *testing.T) {
	reg := New()

	sameDir := Location{FilePath: "/project/main.tf", Line: 5, Column: 1}
	siblingDir := Location{FilePath: "/project/plan/resource.tf", Line: 9, Column: 1}

	reg.Register("aws_instance.web", sameDir)
	reg.Register("aws_instance.web", siblingDir)

	found, ok := reg.LookupWithScope("aws_instance.web", "/project/plan.tfplan.json")
	if !ok {
		t.Fatal("LookupWithScope should find aws_instance.web")
	}
	if found.FilePath != sameDir.FilePath {
		t.Errorf("Expected same-directory location %s, got %s", sameDir.FilePath, found.FilePath)
	}
}

// TestCommonPathLength verifies the path similarity calculation
func TestCommonPathLength(t *testing.T) {
	tests := []struct {
		name     string
		path1    string
		path2    string
		expected int
	}{
		{
			// Same directory ("/a/b/c"): exact match, scored higher than any prefix match.
			name:     "identical paths",
			path1:    "/a/b/c/file.tf",
			path2:    "/a/b/c/file.tf",
			expected: 5, // len(["", "a", "b", "c"]) + 1
		},
		{
			// Different filenames don't matter: both directories are "/a/b/c".
			name:     "same directory different files",
			path1:    "/a/b/c/file1.tf",
			path2:    "/a/b/c/file2.tf",
			expected: 5,
		},
		{
			// Directories "/a/b/c" vs "/a/b/d": share "", "a", "b" (3), diverge at "c"/"d".
			name:     "different directories same parent",
			path1:    "/a/b/c/file1.tf",
			path2:    "/a/b/d/file2.tf",
			expected: 3,
		},
		{
			// Directories "/x/y/z" vs "/a/b/c": share only the leading "".
			name:     "completely different paths",
			path1:    "/x/y/z/file.tf",
			path2:    "/a/b/c/file.tf",
			expected: 1,
		},
		{
			// Same directory once backslashes are normalized: "C:/Users/test".
			name:     "windows paths normalized",
			path1:    "C:\\Users\\test\\file.tf",
			path2:    "C:/Users/test/file.tf",
			expected: 4, // len(["C:", "Users", "test"]) + 1
		},
		{
			// A parent/child directory relationship must score below an exact match,
			// even though "/project/plan" shares every component of "/project".
			name:     "parent directory is not an exact match",
			path1:    "/project/main.tf",
			path2:    "/project/plan/resource.tf",
			expected: 2, // len(["", "project"]), no exact-match bonus
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := commonPathLength(tt.path1, tt.path2)
			if result != tt.expected {
				t.Errorf("commonPathLength(%q, %q) = %d, want %d", tt.path1, tt.path2, result, tt.expected)
			}
		})
	}
}
