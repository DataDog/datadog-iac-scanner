package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cfgFile = `
schema-version: v1.1
iac:
  ignore-rules: [query1, query2]
  global-config:
    ignore-paths: [path1, path2]
    only-paths: [path3, path4]
    ignore-severities: [sev1, sev2]
    only-severities: [sev3, sev4]
    ignore-categories: [cat1, cat2]
    only-categories: [cat3, cat4]
`

var parsedCfgFile = IacConfig{
	IgnoreRules:      []string{"query1", "query2"},
	IgnorePaths:      []string{"path1", "path2"},
	OnlyPaths:        []string{"path3", "path4"},
	IgnoreSeverities: []string{"sev1", "sev2"},
	OnlySeverities:   []string{"sev3", "sev4"},
	IgnoreCategories: []string{"cat1", "cat2"},
	OnlyCategories:   []string{"cat3", "cat4"},
}

const legacyCfg = `
exclude-categories: [cat1, cat2]
exclude-paths: [path1, path2]
exclude-queries: [query1, query2]
exclude-results: [res1, res2]
exclude-severities: [sev1, sev2]
include-queries: [query3, query4]
`

var parsedLegacyCfg = IacConfig{
	IgnoreRules:          []string{"query1", "query2"},
	IgnorePaths:          []string{"path1", "path2"},
	IgnoreSeverities:     []string{"sev1", "sev2"},
	IgnoreCategories:     []string{"cat1", "cat2"},
	LegacyExcludeResults: []string{"res1", "res2"},
	LegacyIncludeQueries: []string{"query3", "query4"},
}

func TestNoConfig(t *testing.T) {
	tmp := t.TempDir()

	cfg, err := ReadConfiguration(t.Context(), tmp)
	assert.NoError(t, err)

	expected := IacConfig{}
	assert.Equal(t, expected, *cfg)
}

func TestReadConfig(t *testing.T) {
	for _, ext := range []string{".yaml", ".yml"} {
		t.Run(ConfigFileNameBase+ext, func(t *testing.T) {
			tmp := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(tmp, ConfigFileNameBase+ext), []byte(cfgFile), 0644))

			cfg, err := ReadConfiguration(t.Context(), tmp)
			assert.NoError(t, err)

			assert.Equal(t, parsedCfgFile, *cfg)
		})
	}
}

func TestReadLegacyOnly(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, LegacyConfigFileName), []byte(legacyCfg), 0644))

	cfg, err := ReadConfiguration(t.Context(), tmp)
	assert.NoError(t, err)

	assert.Equal(t, parsedLegacyCfg, *cfg)
}

func TestConfigFilePrecedence(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, ConfigFileNameBase+".yaml"), []byte(cfgFile), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, LegacyConfigFileName), []byte(legacyCfg), 0644))

	cfg, err := ReadConfiguration(t.Context(), tmp)
	assert.NoError(t, err)

	assert.Equal(t, parsedCfgFile, *cfg)
}
