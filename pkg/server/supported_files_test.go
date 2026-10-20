/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/analyzer"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/stretchr/testify/require"
)

// normalizePattern converts an analyzer file-type key into the IDE-facing
// pattern used as a strategyByPattern key.
func normalizePattern(fileType string) string {
	if fileType == utils.PossibleDockerfile {
		return "Dockerfile.*"
	}
	if fileType == "" || strings.HasPrefix(fileType, ".") {
		return fileType
	}
	if fileType[0] >= 'A' && fileType[0] <= 'Z' {
		return fileType
	}
	return "." + fileType
}

func TestSupportedFiles_DockerfileCandidates(t *testing.T) {
	if !slices.Contains(analyzer.PossibleFileTypes(), utils.PossibleDockerfile) {
		t.Error("Dockerfile candidates must be included in the analyzer's supported types")
	}
	w := httptest.NewRecorder()
	(&Server{}).handleSupportedFiles(w, httptest.NewRequest(http.MethodGet, "/ide/v1/iac/supported-files", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("supported-files status: got %d, want %d", w.Code, http.StatusOK)
	}
	var entries []SupportedFileEntry
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		for _, pattern := range entry.Patterns {
			if pattern == "Dockerfile.*" {
				found = true
				if entry.Strategy != strategySingleFile {
					t.Errorf("Dockerfile.* strategy: got %q, want %q", entry.Strategy, strategySingleFile)
				}
			}
			if strings.Contains(pattern, utils.PossibleDockerfile) {
				t.Errorf("internal extension token exposed as a filename pattern: %q", pattern)
			}
		}
	}
	if !found {
		t.Error("supported-files must advertise Dockerfile.* so IDE clients push suffixed Dockerfiles")
	}
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
	if got["Chart.yaml"] != strategyChart {
		t.Errorf("Chart.yaml should be %q, got %q", strategyChart, got["Chart.yaml"])
	}
}

// Interpret the wire contract, deliberately reversing entries to prove array
// order is unnecessary. Patterns starting with a dot match suffixes; other
// patterns match basenames as filename globs.
func TestSupportedFiles_MatchingPrecedence(t *testing.T) {
	w := httptest.NewRecorder()
	(&Server{}).handleSupportedFiles(w, httptest.NewRequest(http.MethodGet, "/ide/v1/iac/supported-files", nil))
	var entries []SupportedFileEntry
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &entries))
	slices.Reverse(entries)
	for _, tt := range []struct {
		path, pattern string
		strategy      fileStrategy
	}{
		{"Dockerfile.yaml", ".yaml", strategyDirectory},
		{"Dockerfile.CFG", "", ""},
		{"Dockerfile.tf", ".tf", strategyDirectory},
		{"DOCKERFILE.TF", "", ""},
		{"Dockerfile.tf.json", ".tf.json", strategyDirectory},
		{"Dockerfile.tofu.json", ".tofu.json", strategyDirectory},
		{"Chart.yaml", "Chart.yaml", strategyChart},
		{"Dockerfile", "Dockerfile", strategySingleFile},
		{"DOCKERFILE", "Dockerfile", strategySingleFile},
		{"dockerfile.PROD", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.md", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.YAML", "", ""},
		{"Dockerfile.bak", "Dockerfile.*", strategySingleFile},
		{"dockerfile.prod.BAK", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.prod~", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.orig", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.j2", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.gotmpl", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.tmpl", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.in", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.jinja2", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.mustache", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.old", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.backup", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.example", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.swo", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.jinja", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.sample", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.dist", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.bk", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.disabled", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.hbs", "Dockerfile.*", strategySingleFile},
		{"Dockerfile.njk", "Dockerfile.*", strategySingleFile},

		{"Dockerfile.tar.gz", "Dockerfile.*", strategySingleFile},
		{"api.DOCKERFILE", ".dockerfile", strategySingleFile},
		{"main.TF", "", ""},
		{"values.YAML", "", ""},
		{"config.JSON", "", ""},
	} {
		t.Run(tt.path, func(t *testing.T) {
			var selected *SupportedFileEntry
			for i := range entries {
				entry := &entries[i]
				excluded := false
				for _, suffix := range entry.ExcludedSuffixes {
					if strings.HasSuffix(strings.ToLower(tt.path), suffix) {
						excluded = true
						break
					}
				}
				if excluded {
					continue
				}
				sensitive := entry.CaseSensitive
				for _, pattern := range entry.Patterns {
					if matchFilePattern(tt.path, pattern, sensitive) && (selected == nil || entry.Priority < selected.Priority) {
						selected = entry
					}
				}
			}
			if tt.pattern == "" {
				require.Nil(t, selected)
				return
			}
			require.NotNil(t, selected)
			require.Equal(t, tt.pattern, selected.Patterns[0])
			require.Equal(t, tt.strategy, selected.Strategy)
		})
	}
}

func matchFilePattern(path, pattern string, sensitive bool) bool {
	if !sensitive {
		path, pattern = strings.ToLower(path), strings.ToLower(pattern)
	}
	if strings.HasPrefix(pattern, ".") {
		return strings.HasSuffix(path, pattern)
	}
	matched, _ := filepath.Match(pattern, filepath.Base(path))
	return matched
}

func TestSupportedFiles_WireMatchingMetadata(t *testing.T) {
	data, err := json.Marshal(supportedFiles())
	require.NoError(t, err)
	var entries []map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &entries))
	priorities := map[float64]bool{}
	for _, entry := range entries {
		priority, ok := entry["priority"].(float64)
		require.True(t, ok)
		require.Positive(t, priority)
		require.False(t, priorities[priority], "priorities are unique")
		priorities[priority] = true
		require.IsType(t, false, entry["case_sensitive"])
		require.IsType(t, false, entry["requires_content_check"])
		pattern := entry["patterns"].([]interface{})[0].(string)
		if pattern == "Dockerfile.*" {
			require.Equal(t, false, entry["case_sensitive"])
			require.Equal(t, true, entry["requires_content_check"])
		}
	}
}
