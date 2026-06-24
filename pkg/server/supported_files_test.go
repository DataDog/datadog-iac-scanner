/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package server

import (
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/analyzer"
)

// normalizePattern converts an analyzer file-type key into the IDE-facing
// pattern used as a strategyByPattern key.
func normalizePattern(fileType string) string {
	if fileType == "" || strings.HasPrefix(fileType, ".") {
		return fileType
	}
	if fileType[0] >= 'A' && fileType[0] <= 'Z' {
		return fileType
	}
	return "." + fileType
}

// TestSupportedFiles_NoDrift ensures every file type the scanner can analyze has
// a declared resolution strategy, so a newly supported type can't be silently
// omitted from the supported-files endpoint.
func TestSupportedFiles_NoDrift(t *testing.T) {
	for _, ft := range analyzer.PossibleFileTypes() {
		pattern := normalizePattern(ft)
		if _, ok := strategyByPattern[pattern]; !ok {
			t.Errorf("analyzer file type %q (pattern %q) has no strategy in strategyByPattern", ft, pattern)
		}
	}
}

// TestSupportedFiles_Entries checks the response shape and a couple of
// well-known strategies.
func TestSupportedFiles_Entries(t *testing.T) {
	entries := supportedFiles()
	if len(entries) != len(strategyByPattern) {
		t.Fatalf("expected %d entries, got %d", len(strategyByPattern), len(entries))
	}
	got := make(map[string]fileStrategy, len(entries))
	for _, e := range entries {
		if len(e.Patterns) != 1 {
			t.Errorf("expected single-pattern entries, got %v", e.Patterns)
		}
		got[e.Patterns[0]] = e.Strategy
	}
	if got[".tf"] != strategyDirectory {
		t.Errorf(".tf should be %q, got %q", strategyDirectory, got[".tf"])
	}
	if got["Dockerfile"] != strategySingleFile {
		t.Errorf("Dockerfile should be %q, got %q", strategySingleFile, got["Dockerfile"])
	}
}
