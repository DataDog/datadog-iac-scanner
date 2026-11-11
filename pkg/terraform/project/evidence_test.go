/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/stretchr/testify/require"
)

func TestEvidenceRootExclusions(t *testing.T) {
	dir := t.TempDir()
	ok := &model.Root{ID: "envs/prod", Dir: dir}
	require.True(t, EvidenceRoot(ok, nil))

	require.False(t, EvidenceRoot(&model.Root{ID: "examples/demo", Dir: dir}, nil))
	require.False(t, EvidenceRoot(&model.Root{ID: "test/unit", Dir: dir}, nil))
	require.False(t, EvidenceRoot(&model.Root{ID: "tests/unit", Dir: dir}, nil))
	require.False(t, EvidenceRoot(&model.Root{ID: "testdata/sample", Dir: dir}, nil))
	require.False(t, EvidenceRoot(&model.Root{ID: "fixtures/case", Dir: dir}, nil))
	require.False(t, EvidenceRoot(&model.Root{ID: ".terraform/modules/x", Dir: dir}, nil))
	require.False(t, EvidenceRoot(&model.Root{ID: "plan", Dir: dir, Plan: true}, nil))

	calledDir := filepath.Join(dir, "shared")
	require.NoError(t, os.MkdirAll(calledDir, 0o755))
	require.False(t, EvidenceRoot(&model.Root{ID: "shared", Dir: calledDir}, map[string]bool{filepath.Clean(calledDir): true}))

	testRoot := filepath.Join(dir, "with-test")
	require.NoError(t, os.MkdirAll(testRoot, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(testRoot, "main.tftest.hcl"), []byte(""), 0o600))
	require.False(t, EvidenceRoot(&model.Root{ID: "with-test", Dir: testRoot}, nil))
}

func TestHoldsCompanion(t *testing.T) {
	keys := LiteralKeys{"aws_s3_bucket_versioning": {"bucket": {"aws_s3_bucket": {"bucket"}}}}
	with := &model.Root{Modules: []*model.Module{{
		Blocks: []*model.Block{{Kind: address.KindResource, Type: "aws_s3_bucket_versioning"}},
	}}}
	require.True(t, HoldsCompanion(with, keys))

	other := &model.Root{Modules: []*model.Module{{
		Blocks: []*model.Block{{Kind: address.KindResource, Type: "aws_s3_bucket"}},
	}}}
	require.False(t, HoldsCompanion(other, keys))
	require.False(t, HoldsCompanion(with, nil))
}
