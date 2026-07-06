/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package datadog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLocalFileClient_RoundTrip(t *testing.T) {
	ruleset := &Ruleset{
		ID:   "default-ruleset",
		Name: "Default",
		Rules: []*Rule{
			{ID: "rule-1", Name: "rule-1", Platform: "Terraform", RegoQuery: []byte("query"), IsPublished: true},
		},
	}
	libraries := map[string]Library{
		"terraform": {ID: "terraform", RegoCode: "package terraform"},
	}

	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "rules.json"), ruleset)
	writeJSON(t, filepath.Join(dir, "libraries.json"), libraries)

	client, err := NewLocalFileClient(filepath.Join(dir, "rules.json"), filepath.Join(dir, "libraries.json"))
	require.NoError(t, err)

	gotRuleset, err := client.GetDefaultRuleset(t.Context())
	require.NoError(t, err)
	assert.Equal(t, ruleset, gotRuleset)

	gotRulesetWithTests, err := client.GetDefaultRulesetWithTests(t.Context())
	require.NoError(t, err)
	assert.Equal(t, ruleset, gotRulesetWithTests)

	gotLibraries, err := client.GetLibraries(t.Context())
	require.NoError(t, err)
	assert.Equal(t, libraries, gotLibraries)

	localConfig := []byte("local config bytes")
	gotConfig, err := client.GetRemoteConfig(t.Context(), "https://example.com/repo", localConfig)
	require.NoError(t, err)
	assert.Equal(t, localConfig, gotConfig)
}

func TestNewLocalFileClient_MissingFile(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "libraries.json"), map[string]Library{})

	_, err := NewLocalFileClient(filepath.Join(dir, "rules.json"), filepath.Join(dir, "libraries.json"))
	assert.Error(t, err)
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, b, 0o600))
}
