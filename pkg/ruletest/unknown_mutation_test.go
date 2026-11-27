/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package ruletest

import (
	"bytes"
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	tfcontract "github.com/DataDog/datadog-iac-scanner/pkg/terraform/contract"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

func TestMutateAttributesToUnknownProducesValidUnknownStates(t *testing.T) {
	fixture := []byte(`
resource "aws_rds_cluster" "db" {
  engine_mode       = "provisioned"
  storage_encrypted = false
}
`)
	muts, err := MutateAttributesToUnknown("main.tf", fixture)
	require.NoError(t, err)
	require.Len(t, muts, 2)
	require.Equal(t, "engine_mode", muts[0].Attribute)
	require.Equal(t, "storage_encrypted", muts[1].Attribute)

	// Each mutated fixture evaluates cleanly with the mutated attribute marked Unknown.
	for _, m := range muts {
		fs := vfs.NewMemFS(map[string][]byte{"/repo/main.tf": m.Source})
		eval := tfeval.NewWithFS(fs)
		unit, err := tfcontract.EvaluateRoot(context.Background(), eval, "/repo", &tfcontract.RootOptions{
			FS:       fs,
			RepoPath: "/repo",
		})
		require.NoError(t, err)
		require.Len(t, unit.Resources, 1) // single resource (static variable omitted unless NeedStaticBlocks)
		var rdsFound bool
		for _, res := range unit.Resources {
			if res.Type == "aws_rds_cluster" {
				rdsFound = true
				require.True(t, res.State.Unknown[m.Attribute], "expected %s to be marked Unknown", m.Attribute)
				require.NotContains(t, res.Attributes, m.Attribute)
			}
		}
		require.True(t, rdsFound)
	}

	pairs, err := MutateAttributePairsToUnknown("main.tf", fixture)
	require.NoError(t, err)
	require.Len(t, pairs, 1)
	require.Equal(t, []string{"engine_mode", "storage_encrypted"}, pairs[0].Attributes)
	fs := vfs.NewMemFS(map[string][]byte{"/repo/main.tf": pairs[0].Source})
	eval := tfeval.NewWithFS(fs)
	unit, err := tfcontract.EvaluateRoot(context.Background(), eval, "/repo", &tfcontract.RootOptions{
		FS:       fs,
		RepoPath: "/repo",
	})
	require.NoError(t, err)
	for _, res := range unit.Resources {
		if res.Type == "aws_rds_cluster" {
			require.True(t, res.State.Unknown["engine_mode"])
			require.True(t, res.State.Unknown["storage_encrypted"])
		}
	}

	// Nested + dynamic block fixtures keep indexed attribute paths and never mutate dynamic meta-attributes.
	nestedFixture := []byte(`
resource "aws_security_group" "sg" {
  ingress {
    from_port   = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
  dynamic "egress" {
    for_each = [1]
    iterator = rule
    content {
      to_port = 443
    }
  }
}
`)
	nMuts, err := MutateAttributesToUnknown("sg.tf", nestedFixture)
	require.NoError(t, err)
	attrs := make([]string, 0, len(nMuts))
	for _, m := range nMuts {
		attrs = append(attrs, m.Attribute)
		require.NotContains(t, m.Attribute, "iterator")
		require.NotContains(t, m.Attribute, "for_each")
	}
	require.Equal(t, []string{"ingress.0.cidr_blocks", "ingress.0.from_port", "egress.0.to_port"}, attrs)
	nPairs, err := MutateAttributePairsToUnknown("sg.tf", nestedFixture)
	require.NoError(t, err)
	require.Len(t, nPairs, 3)
	multiline := []byte(`resource "aws_s3_bucket" "first" {
  tags = {
    Env = "prod"
  }
  acl = "private"
}
resource "aws_s3_bucket" "independent" {
  acl = "public-read"
}
`)
	marker := []byte(`resource "aws_s3_bucket" "independent"`)
	wantLine := bytes.Count(multiline[:bytes.Index(multiline, marker)], []byte("\n"))
	checkLocation := func(src []byte) {
		t.Helper()
		index := bytes.Index(src, marker)
		require.NotEqual(t, -1, index)
		require.Equal(t, wantLine, bytes.Count(src[:index], []byte("\n")), "mutating a multiline expression must preserve later finding locations")
	}
	multilineSingles, err := MutateAttributesToUnknown("main.tf", multiline)
	require.NoError(t, err)
	for _, mutation := range multilineSingles {
		checkLocation(mutation.Source)
	}
	multilinePairs, err := MutateAttributePairsToUnknown("main.tf", multiline)
	require.NoError(t, err)
	for _, mutation := range multilinePairs {
		checkLocation(mutation.Source)
	}

}
