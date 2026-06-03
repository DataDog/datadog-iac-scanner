/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilterHelmGeneratedLines(t *testing.T) {
	// Rendered Helm split content that resembles real scanner output.
	// Line 1: empty
	// Line 2: # Source: … (Helm-generated)
	// Line 3: # KICS_HELM_ID_2: (scanner-injected)
	// Line 4: apiVersion: apps/v1
	// Line 5: kind: Deployment
	// Line 6: # some user comment
	// Line 7: metadata:
	renderedContent := []byte("\n# Source: dsm-demo/templates/deployment.yaml\n# KICS_HELM_ID_2:\napiVersion: apps/v1\nkind: Deployment\n# some user comment\nmetadata:\n")

	tests := []struct {
		name        string
		content     []byte
		ignoreLines []int
		want        []int
	}{
		{
			name:        "removes Source and KICS_HELM_ID lines",
			content:     renderedContent,
			ignoreLines: []int{2, 3, 6},
			want:        []int{6},
		},
		{
			name:        "keeps user comment lines untouched",
			content:     renderedContent,
			ignoreLines: []int{6, 7},
			want:        []int{6, 7},
		},
		{
			name:        "no generated lines present — input unchanged",
			content:     renderedContent,
			ignoreLines: []int{4, 5, 7},
			want:        []int{4, 5, 7},
		},
		{
			name:        "empty ignore list stays empty",
			content:     renderedContent,
			ignoreLines: []int{},
			want:        []int{},
		},
		{
			name:        "out-of-range line numbers are kept as-is",
			content:     renderedContent,
			ignoreLines: []int{99, 100},
			want:        []int{99, 100},
		},
		{
			name:        "only generated lines — all removed",
			content:     renderedContent,
			ignoreLines: []int{2, 3},
			want:        []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterHelmGeneratedLines(tt.content, tt.ignoreLines)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFilterHelmGeneratedLines_DDIacScanCommentKept(t *testing.T) {
	// Content where the dd-iac-scan directive appears alongside generated headers.
	// Line 1: empty
	// Line 2: # Source: chart/templates/deploy.yaml
	// Line 3: # KICS_HELM_ID_0:
	// Line 4: # dd-iac-scan ignore-block
	// Line 5: apiVersion: apps/v1
	content := []byte("\n# Source: chart/templates/deploy.yaml\n# KICS_HELM_ID_0:\n# dd-iac-scan ignore-block\napiVersion: apps/v1\n")

	// Suppose processBlock added lines 4 and 5 (not 2 and 3, since it anchors to
	// apiVersion.Line and apiVersion.Line-1). But even if 2 and 3 were included,
	// they should be removed while 4 stays.
	ignoreLines := []int{2, 3, 4, 5}
	got := filterHelmGeneratedLines(content, ignoreLines)

	// Lines 2 and 3 are generated; lines 4 and 5 are real content.
	require.Equal(t, []int{4, 5}, got)
}
