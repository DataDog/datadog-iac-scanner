/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/stretchr/testify/require"
)

// A canceled or timed-out scan stops module resolution promptly and reports the
// context error instead of scanning the modules that were evaluated only in
// part. resolveModuleDocuments mutates nothing in that case.
func TestResolveModuleDocuments_StopsWhenTheContextIsDone(t *testing.T) {
	root := t.TempDir()
	files := model.FileMetadatas{
		fileMeta("root-id", writeFile(t, root, "main.tf", `
module "m" {
  source = "./child"
  count  = 1000000000000
  in     = "in-${count.index}"
}
`)),
	}
	// The child exists and expands, so the count runs until the context stops it.
	writeFile(t, filepath.Join(root, "child"), "main.tf", `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
`)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	res := resolveModuleDocuments(canceled, files, root, nil, nil, nil, nil, nil, nil)
	require.False(t, res.ok)
	require.Empty(t, res.docs)

	deadline, dl := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer dl()
	start := time.Now()
	res = resolveModuleDocuments(deadline, files, root, nil, nil, nil, nil, nil, nil)
	require.False(t, res.ok)
	require.Empty(t, res.docs)
	require.Less(t, time.Since(start), 10*time.Second, "module resolution must stop promptly at the deadline")
}

// One sane call and one whose count cannot be enumerated: planning the huge
// call must neither panic nor run to completion — the scan stops at the
// context, reports the error, and mutates nothing.
func TestResolveModuleDocuments_HugeCountSiblingStopsWhenTheContextIsDone(t *testing.T) {
	root := t.TempDir()
	files := model.FileMetadatas{
		fileMeta("root-id", writeFile(t, root, "main.tf", `
module "sane" {
  source = "./child"
  count  = 2
  in     = "sane-${count.index}"
}
module "huge" {
  source = "./child"
  count  = 9223372036854775807
  in     = "huge-${count.index}"
}
`)),
	}
	writeFile(t, filepath.Join(root, "child"), "main.tf", `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
`)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	require.NotPanics(t, func() {
		res := resolveModuleDocuments(canceled, files, root, nil, nil, nil, nil, nil, nil)
		require.False(t, res.ok)
		require.Empty(t, res.docs)
	})

	deadline, dl := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer dl()
	start := time.Now()
	require.NotPanics(t, func() {
		res := resolveModuleDocuments(deadline, files, root, nil, nil, nil, nil, nil, nil)
		require.False(t, res.ok)
		require.Empty(t, res.docs)
	})
	require.Less(t, time.Since(start), 10*time.Second, "module resolution must stop promptly at the deadline")
}

// Inspect returns the context error for a canceled scan rather than findings
// computed from partly evaluated modules.
func TestInspect_StopsWhenTheContextIsDone(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.tf", `
module "m" {
  source = "./child"
  count  = 1000000000000
  in     = "in-${count.index}"
}
`)
	writeFile(t, filepath.Join(root, "child"), "main.tf", `
variable "in" { type = string }
resource "aws_s3_bucket" "b" { bucket = var.in }
`)

	var files model.FileMetadatas
	for _, name := range []string{"main.tf", filepath.Join("child", "main.tf")} {
		files = append(files, parseTerraform(t, filepath.Join(root, name))...)
	}
	ins := newTestInspector(t, inspectorOpts{
		queries:       []model.QueryMetadata{},
		repoPath:      root,
		vb:            DefaultVulnerabilityBuilder,
		flagEvaluator: featureflags.NewLocalEvaluator(),
	})

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ins.Inspect(canceled, "scan", files, []string{"terraform"})
	require.ErrorIs(t, err, context.Canceled)

	deadline, dl := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer dl()
	start := time.Now()
	_, err = ins.Inspect(deadline, "scan", files, []string{"terraform"})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 10*time.Second, "the scan must stop promptly at the deadline")
}
