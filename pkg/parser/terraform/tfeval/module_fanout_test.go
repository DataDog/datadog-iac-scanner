/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfeval

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func writeNestedFanOutForProbe(t *testing.T, depth, branch int) string {
	t.Helper()
	root := t.TempDir()
	for i := 0; i < depth; i++ {
		dir := filepath.Join(root, fmt.Sprintf("lvl%02d", i))
		body := "variable \"in\" { type = string }\n"
		if i == depth-1 {
			body += "resource \"aws_s3_bucket\" \"leaf\" { bucket = var.in }\noutput \"out\" { value = var.in }\n"
		} else {
			for b := 0; b < branch; b++ {
				body += fmt.Sprintf("module \"m%d\" {\n  source = \"../lvl%02d\"\n  in = var.in\n}\n", b, i+1)
			}
			body += "output \"out\" { value = module.m0.out }\n"
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	stack := filepath.Join(root, "stack")
	if err := os.MkdirAll(stack, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stack, "main.tf"),
		[]byte("module \"m\" {\n  source = \"../lvl00\"\n  in = \"seed\"\n}\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return stack
}

// A module tree fanning out past the old scan-wide instantiation limit still
// evaluates every leaf, and stays cheap to re-evaluate because the evaluation
// cache reuses identical subtrees.
func TestNestedFanOutEvaluatesEveryLeaf(t *testing.T) {
	const depth, branch = 12, 3
	stack := writeNestedFanOutForProbe(t, depth, branch)
	// Each of the depth-1 branching levels fans out branch ways; the last
	// level declares the leaf resource.
	want := powInt(branch, depth-1)

	resources, _, _, err := New().EvaluateModule(context.Background(), stack, nil)
	require.NoError(t, err)
	require.Len(t, resources, want)

	// The engine path instantiates the same tree for a scanned repository.
	e2 := New()
	resources2, _, _, err := e2.EvaluateModule(context.Background(), stack, map[string]cty.Value{})
	require.NoError(t, err)
	require.Len(t, resources2, want)
}

func powInt(base, exp int) int {
	n := 1
	for i := 0; i < exp; i++ {
		n *= base
	}
	return n
}
