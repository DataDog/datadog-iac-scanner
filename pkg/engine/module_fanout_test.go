/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// writeFanOutFixture writes a module tree where each of depth-1 levels calls
// branch modules of the next level and the last level declares one resource,
// and returns the root stack directory.
func writeFanOutFixture(t *testing.T, depth, branch int) (root string, stack string, want int) {
	t.Helper()
	root = t.TempDir()
	for i := 0; i < depth; i++ {
		dir := filepath.Join(root, fmt.Sprintf("lvl%02d", i))
		require.NoError(t, os.MkdirAll(dir, 0o755))
		body := "variable \"in\" { type = string }\n"
		if i == depth-1 {
			body += "resource \"aws_s3_bucket\" \"leaf\" { bucket = var.in }\noutput \"out\" { value = var.in }\n"
		} else {
			for b := 0; b < branch; b++ {
				body += fmt.Sprintf("module \"m%d\" {\n  source = \"../lvl%02d\"\n  in = var.in\n}\n", b, i+1)
			}
			body += "output \"out\" { value = module.m0.out }\n"
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(body), 0o644))
	}
	stack = filepath.Join(root, "stack")
	require.NoError(t, os.MkdirAll(stack, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(stack, "main.tf"),
		[]byte("module \"m\" {\n  source = \"../lvl00\"\n  in = \"seed\"\n}\n"), 0o644))
	return root, stack, 1
}

// Module resolution instantiates every leaf of a deeply nested fan-out: past
// the instantiation limits earlier engine builds stopped at, nothing is left
// unevaluated, and every leaf reaches the scan as a document.
func TestResolveModuleDocuments_InstantiatesEveryLeafOfANestedFanOut(t *testing.T) {
	const depth, branch = 12, 3
	root, stack, _ := writeFanOutFixture(t, depth, branch)
	// Each of the depth-1 branching levels fans out branch ways.
	want := 1
	for i := 0; i < depth-1; i++ {
		want *= branch
	}

	stackFile := writeFile(t, stack, "main.tf", "module \"m\" {\n  source = \"../lvl00\"\n  in = \"seed\"\n}\n")
	var files model.FileMetadatas
	for i := 0; i < depth; i++ {
		files = append(files, parseTerraform(t, filepath.Join(root, fmt.Sprintf("lvl%02d", i), "main.tf"))...)
	}
	files = append(files, fileMeta("stack-id", stackFile))

	res := resolveModuleDocuments(context.Background(), files, root, nil, nil, nil, nil, nil, nil)
	require.True(t, res.ok)
	require.Equal(t, want, res.resourceCount, "every leaf of the fan-out must be instantiated")
	require.NotEmpty(t, res.docs)
	require.NotEmpty(t, res.syntheticFiles)

	// The defining files of the leaves are fully replaced by their instances.
	leaf := filepath.Join(root, fmt.Sprintf("lvl%02d", depth-1), "main.tf")
	suppressed := false
	for _, f := range files {
		if f.FilePath == leaf {
			suppressed = res.suppressed[f.ID]["aws_s3_bucket"]["leaf"]
		}
	}
	require.True(t, suppressed, "the leaf resource must be suppressed where it is written")
}
