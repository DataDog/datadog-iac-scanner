/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package server

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/stretchr/testify/require"
)

// TestSupportedFiles_NoDrift ensures every file type in the scanner's routing
// registry has a declared IDE resolution strategy, and no stale patterns remain.
func TestSupportedFiles_NoDrift(t *testing.T) {
	registered := make(map[string]struct{})
	for _, rule := range utils.FilePatterns() {
		registered[rule.Pattern] = struct{}{}
		if _, ok := strategyByPattern[rule.Pattern]; !ok {
			t.Errorf("file type %q (pattern %q) has no strategy in strategyByPattern", rule.Token, rule.Pattern)
		}
	}
	for pattern := range strategyByPattern {
		if pattern == "Chart.yaml" {
			continue
		}
		if _, ok := registered[pattern]; !ok {
			t.Errorf("strategyByPattern entry %q is not in utils.FilePatterns()", pattern)
		}
	}
}

// TestSupportedFiles_Entries checks priorities, metadata flags, and matching
// precedence across Dockerfile variants and registered formats.
func TestSupportedFiles_Entries(t *testing.T) {
	entries := supportedFiles()
	require.Len(t, entries, len(strategyByPattern))

	byPattern := make(map[string]SupportedFileEntry, len(entries))
	for i, e := range entries {
		require.Len(t, e.Patterns, 1)
		require.Equal(t, i+1, e.Priority, "priorities must be 1-based and contiguous")
		byPattern[e.Patterns[0]] = e
	}

	require.Equal(t, strategyDirectory, byPattern[".tf"].Strategy)
	require.True(t, byPattern[".tf"].CaseSensitive)
	require.False(t, byPattern[".tf"].RequiresContentCheck)

	require.Equal(t, strategyChart, byPattern["Chart.yaml"].Strategy)
	require.True(t, byPattern["Chart.yaml"].CaseSensitive)
	require.False(t, byPattern["Chart.yaml"].RequiresContentCheck)

	require.Equal(t, strategySingleFile, byPattern["Dockerfile"].Strategy)
	require.False(t, byPattern["Dockerfile"].CaseSensitive)
	require.False(t, byPattern["Dockerfile"].RequiresContentCheck)

	require.Equal(t, strategySingleFile, byPattern[".dockerfile"].Strategy)
	require.False(t, byPattern[".dockerfile"].CaseSensitive)
	require.False(t, byPattern[".dockerfile"].RequiresContentCheck)

	glob := byPattern["Dockerfile.*"]
	require.Equal(t, strategySingleFile, glob.Strategy)
	require.False(t, glob.CaseSensitive)
	require.True(t, glob.RequiresContentCheck)
	require.Equal(t, len(entries), glob.Priority, "glob should have lowest precedence")
	require.Contains(t, glob.ExcludedSuffixes, ".yaml")
	require.Contains(t, glob.ExcludedSuffixes, ".tf.json")
	require.NotContains(t, glob.ExcludedSuffixes, ".dockerfile")
	require.NotContains(t, glob.ExcludedSuffixes, ".debian")
	require.NotContains(t, glob.ExcludedSuffixes, ".ubi8")

	require.Less(t, byPattern[".tf.json"].Priority, byPattern[".json"].Priority)
	require.Less(t, byPattern[".tofu.json"].Priority, byPattern[".json"].Priority)
	require.False(t, byPattern[".tf.json"].CaseSensitive)
	require.False(t, byPattern[".tofu.json"].CaseSensitive)

	// Simulate the IDE matching contract described on supportedFiles().
	matchIDE := func(name string) (string, bool) {
		var best *SupportedFileEntry
		for i := range entries {
			e := &entries[i]
			if !matchesSupportedEntry(name, e) {
				continue
			}
			if best == nil || e.Priority < best.Priority {
				best = e
			}
		}
		if best == nil {
			return "", false
		}
		return best.Patterns[0], true
	}

	tests := []struct {
		name        string
		wantPattern string
		wantMatched bool
	}{
		{"Dockerfile", "Dockerfile", true},
		{"dockerfile", "Dockerfile", true},
		{"DOCKERFILE", "Dockerfile", true},
		{"app.Dockerfile", ".dockerfile", true},
		{"app.DOCKERFILE", ".dockerfile", true},
		{"Dockerfile.dockerfile", ".dockerfile", true},
		{"Dockerfile.prod", "Dockerfile.*", true},
		{"dockerfile.dev", "Dockerfile.*", true},
		{"Dockerfile.DEBIAN", "Dockerfile.*", true},
		{"Dockerfile.debian", ".debian", true},
		{"Dockerfile.yaml", ".yaml", true},
		{"Dockerfile.tf", ".tf", true},
		{"Dockerfile.tf.json", ".tf.json", true},
		{"Dockerfile.TF.JSON", ".tf.json", true},
		// Uppercase registered non-Dockerfile suffix is vetoed from Dockerfile.*
		{"Dockerfile.YAML", "", false},
		{"Dockerfile.JSON", "", false},
		{"Chart.yaml", "Chart.yaml", true},
		{"main.tf", ".tf", true},
		{"README.md", "", false},
	}
	for _, tt := range tests {
		got, ok := matchIDE(tt.name)
		require.Equal(t, tt.wantMatched, ok, tt.name)
		require.Equal(t, tt.wantPattern, got, tt.name)
	}
}

func matchesSupportedEntry(name string, entry *SupportedFileEntry) bool {
	lowerName := strings.ToLower(name)
	for _, excluded := range entry.ExcludedSuffixes {
		if strings.HasSuffix(lowerName, strings.ToLower(excluded)) {
			return false
		}
	}
	for _, pattern := range entry.Patterns {
		candidate, pat := name, pattern
		if !entry.CaseSensitive {
			candidate, pat = lowerName, strings.ToLower(pattern)
		}
		if strings.HasPrefix(pat, ".") {
			if strings.HasSuffix(candidate, pat) {
				return true
			}
			continue
		}
		if matched, _ := filepath.Match(pat, candidate); matched {
			return true
		}
	}
	return false
}
