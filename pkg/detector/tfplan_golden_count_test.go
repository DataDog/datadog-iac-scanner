/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com/)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/registry"
	"github.com/stretchr/testify/require"
)

// TestTFPlanGoldenCount_ModuleIndexedResources validates that module resources
// with count or for_each correctly deduplicate across module instances.
//
// This validates the transformation logic that strips indices from module paths.
func TestTFPlanGoldenCount_ModuleIndexedResources(t *testing.T) {
	ctx := context.Background()

	// Create registry with module call site (production behavior)
	reg := registry.New()
	reg.Register("module.app_servers", registry.Location{
		FilePath: "main.tf",
		Line:     10,
		Column:   1,
	})

	// Create TFPlan document with TWO module instances
	tfplanDoc := model.Document{
		"resource": model.Document{
			"aws_instance": model.Document{
				"app_0": model.Document{
					"_dd_tf_address": "module.app_servers.aws_instance.app", // Normalized
					"tags": model.Document{
						"Environment": "prod",
					},
				},
				"app_1": model.Document{
					"_dd_tf_address": "module.app_servers.aws_instance.app", // Normalized
					"tags": model.Document{
						"Environment": "prod",
					},
				},
			},
		},
	}

	// Round-trip through JSON
	jsonBytes, _ := json.Marshal(tfplanDoc)
	var roundTrippedDoc map[string]interface{}
	json.Unmarshal(jsonBytes, &roundTrippedDoc)

	fileMetadata := &model.FileMetadata{
		ID:               "test-tfplan",
		FilePath:         "plan.tfplan.json",
		Kind:             model.KindJSON,
		Document:         roundTrippedDoc,
		LineInfoDocument: roundTrippedDoc,
	}

	detector := NewTFPlanDetectLine(reg, nil)

	// Detect line for FIRST module instance
	result1 := detector.DetectLine(ctx, fileMetadata, "module.app_servers[0].aws_instance.app.tags", 3)
	// Detect line for SECOND module instance
	result2 := detector.DetectLine(ctx, fileMetadata, "module.app_servers[1].aws_instance.app.tags", 3)

	// Both should resolve to the SAME module call site
	require.Equal(t, "main.tf", result1.ResolvedFile, "First module instance should resolve to HCL")
	require.Equal(t, "main.tf", result2.ResolvedFile, "Second module instance should resolve to HCL")
	require.Equal(t, 10, result1.Line, "First instance should resolve to module call line")
	require.Equal(t, 10, result2.Line, "Second instance should resolve to module call line")

	// GOLDEN COUNT ASSERTION: Both module instances point to same location
	// → Same similarity ID → Deduplicates to 1 finding
}

// TestTFPlanGoldenCount_PrefixCollisionPrevention validates that resources with
// similar names don't incorrectly match due to prefix collisions.
//
// This is a regression test for Issue #2 from CRITICAL_FIXES_APPLIED.md:
// "module.x.aws_instance.web" should NOT match "module.x.aws_instance.web_extra"
func TestTFPlanGoldenCount_PrefixCollisionPrevention(t *testing.T) {
	ctx := context.Background()

	// Create registry with TWO different resources
	reg := registry.New()
	reg.Register("aws_instance.web", registry.Location{
		FilePath: "main.tf",
		Line:     1,
		Column:   1,
	})
	reg.Register("aws_instance.web_extra", registry.Location{
		FilePath: "main.tf",
		Line:     10,
		Column:   1,
	})

	// Create TFPlan document with BOTH resources
	tfplanDoc := model.Document{
		"resource": model.Document{
			"aws_instance": model.Document{
				"web": model.Document{
					"_dd_tf_address": "aws_instance.web",
					"ami":            "ami-111111",
				},
				"web_extra": model.Document{
					"_dd_tf_address": "aws_instance.web_extra",
					"ami":            "ami-222222",
				},
			},
		},
	}

	// Round-trip through JSON
	jsonBytes, _ := json.Marshal(tfplanDoc)
	var roundTrippedDoc map[string]interface{}
	json.Unmarshal(jsonBytes, &roundTrippedDoc)

	fileMetadata := &model.FileMetadata{
		ID:               "test-tfplan",
		FilePath:         "plan.tfplan.json",
		Kind:             model.KindJSON,
		Document:         roundTrippedDoc,
		LineInfoDocument: roundTrippedDoc,
	}

	detector := NewTFPlanDetectLine(reg, nil)

	// Detect line for FIRST resource
	result1 := detector.DetectLine(ctx, fileMetadata, "aws_instance.web.ami", 3)
	// Detect line for SECOND resource
	result2 := detector.DetectLine(ctx, fileMetadata, "aws_instance.web_extra.ami", 3)

	// Both should resolve to HCL, but DIFFERENT lines
	require.Equal(t, "main.tf", result1.ResolvedFile, "First resource should resolve to HCL")
	require.Equal(t, "main.tf", result2.ResolvedFile, "Second resource should resolve to HCL")
	require.Equal(t, 1, result1.Line, "First resource should resolve to line 1")
	require.Equal(t, 10, result2.Line, "Second resource should resolve to line 10")

	// GOLDEN COUNT ASSERTION: Different resources → Different lines → Different similarity IDs → 2 findings
	require.NotEqual(t, result1.Line, result2.Line, "Different resources must resolve to different lines to prevent over-deduplication")
}

// TestTFPlanGoldenCount_ModulePrefixCollision validates that module resources
// with similar paths don't incorrectly match.
//
// Example: "module.vpc.aws_instance.web" should NOT match "module.vpc_extra.aws_instance.web"
func TestTFPlanGoldenCount_ModulePrefixCollision(t *testing.T) {
	ctx := context.Background()

	// Create registry with TWO different module call sites
	reg := registry.New()
	reg.Register("module.vpc", registry.Location{
		FilePath: "main.tf",
		Line:     1,
		Column:   1,
	})
	reg.Register("module.vpc_extra", registry.Location{
		FilePath: "main.tf",
		Line:     20,
		Column:   1,
	})

	// Create TFPlan document with resources in BOTH modules
	tfplanDoc := model.Document{
		"resource": model.Document{
			"aws_instance": model.Document{
				"web": model.Document{
					"_dd_tf_address": "module.vpc.aws_instance.web",
					"ami":            "ami-111111",
				},
				"web_extra": model.Document{
					"_dd_tf_address": "module.vpc_extra.aws_instance.web",
					"ami":            "ami-222222",
				},
			},
		},
	}

	// Round-trip through JSON
	jsonBytes, _ := json.Marshal(tfplanDoc)
	var roundTrippedDoc map[string]interface{}
	json.Unmarshal(jsonBytes, &roundTrippedDoc)

	fileMetadata := &model.FileMetadata{
		ID:               "test-tfplan",
		FilePath:         "plan.tfplan.json",
		Kind:             model.KindJSON,
		Document:         roundTrippedDoc,
		LineInfoDocument: roundTrippedDoc,
	}

	detector := NewTFPlanDetectLine(reg, nil)

	// Detect line for FIRST module's resource
	result1 := detector.DetectLine(ctx, fileMetadata, "module.vpc.aws_instance.web.ami", 3)
	// Detect line for SECOND module's resource
	result2 := detector.DetectLine(ctx, fileMetadata, "module.vpc_extra.aws_instance.web.ami", 3)

	// Both should resolve to HCL, but DIFFERENT module call lines
	require.Equal(t, "main.tf", result1.ResolvedFile, "First module resource should resolve to HCL")
	require.Equal(t, "main.tf", result2.ResolvedFile, "Second module resource should resolve to HCL")
	require.Equal(t, 1, result1.Line, "First module should resolve to line 1")
	require.Equal(t, 20, result2.Line, "Second module should resolve to line 20")

	// GOLDEN COUNT ASSERTION: Different modules → Different lines → 2 findings
	require.NotEqual(t, result1.Line, result2.Line, "Different modules must resolve to different lines")
}
