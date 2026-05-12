package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cfgFile = `schema-version: v1.2
iac:
  ignore-rules:
    - query1
    - query2
  use-rules:
    - query3
    - query4
  global-config:
    ignore-paths:
      - path1
      - path2
    only-paths:
      - path3
      - path4
    ignore-severities:
      - sev1
      - sev2
    only-severities:
      - sev3
      - sev4
    ignore-categories:
      - cat1
      - cat2
    only-categories:
      - cat3
      - cat4
`

var parsedCfgFile = IacConfig{
	IgnoreRules:      []string{"query1", "query2"},
	OnlyRules:        []string{"query3", "query4"},
	IgnorePaths:      []string{"path1", "path2"},
	OnlyPaths:        []string{"path3", "path4"},
	IgnoreSeverities: []string{"sev1", "sev2"},
	OnlySeverities:   []string{"sev3", "sev4"},
	IgnoreCategories: []string{"cat1", "cat2"},
	OnlyCategories:   []string{"cat3", "cat4"},
}

const legacyCfg = `exclude-categories: [cat1, cat2]
exclude-paths: [path1, path2]
exclude-queries: [query1, query2]
exclude-results: [res1, res2]
exclude-severities: [sev1, sev2]
`

var parsedLegacyCfg = IacConfig{
	IgnoreRules:          []string{"query1", "query2"},
	IgnorePaths:          []string{"path1", "path2"},
	IgnoreSeverities:     []string{"sev1", "sev2"},
	IgnoreCategories:     []string{"cat1", "cat2"},
	LegacyExcludeResults: []string{"res1", "res2"},
}

const convertedLegacyCfg = `schema-version: v1.2
iac:
  ignore-rules:
    - query1
    - query2
  global-config:
    ignore-paths:
      - path1
      - path2
    ignore-severities:
      - sev1
      - sev2
    ignore-categories:
      - cat1
      - cat2
`

const excludeSuffix = `# These settings have been applied, but they cannot be expressed in the new configuration format:
# exclude-results: [ "res1", "res2" ]
`

const emptyCfgFile = `
schema-version: v1.2
sast:
  use-rulesets: [foo]
`

const oldCfgFile = `
schema-version: v1.1
iac:
  use-rules: [foo]
`

func TestNoConfig(t *testing.T) {
	tmp := t.TempDir()

	cfg, b, err := ReadConfiguration(t.Context(), tmp)
	assert.NoError(t, err)
	assert.Empty(t, b)
	assert.Equal(t, IacConfig{}, *cfg)
}

func TestReadConfig(t *testing.T) {
	for _, ext := range []string{".yaml", ".yml"} {
		t.Run(ConfigFileNameBase+ext, func(t *testing.T) {
			tmp := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(tmp, ConfigFileNameBase+ext), []byte(cfgFile), 0644))

			cfg, b, err := ReadConfiguration(t.Context(), tmp)
			assert.NoError(t, err)
			assert.Equal(t, cfgFile, string(b))
			assert.Equal(t, parsedCfgFile, *cfg)
		})
	}
}

// Parsers MUST reject schema major versions >= 2.
func TestUnsupportedSchemaVersion(t *testing.T) {
	for _, tc := range []struct {
		name, cfg string
	}{
		{name: "v2.0", cfg: "schema-version: v2.0\niac:\n  ignore-rules:\n    - r1\n"},
		{name: "v3.0", cfg: "schema-version: v3.0\niac:\n  ignore-rules:\n    - r1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(tmp, ConfigFileNameBase+".yaml"), []byte(tc.cfg), 0644))

			_, _, err := ReadConfiguration(t.Context(), tmp)
			assert.Error(t, err)
		})
	}
}

// When the new config file has an unsupported major version, the legacy config is NOT used as fallback.
func TestUnsupportedSchemaVersionIgnoresLegacy(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, ConfigFileNameBase+".yaml"), []byte("schema-version: v2.0\niac:\n  ignore-rules:\n    - r1\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, LegacyConfigFileName), []byte(legacyCfg), 0644))

	_, _, err := ReadConfiguration(t.Context(), tmp)
	assert.Error(t, err)
}

func TestIgnoredConfigFile(t *testing.T) {
	for _, tc := range []struct {
		name, cfg string
	}{
		{
			name: "empty IaC config",
			cfg:  emptyCfgFile,
		},
		{
			name: "old schema version",
			cfg:  oldCfgFile,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(tmp, ConfigFileNameBase+".yaml"), []byte(tc.cfg), 0644))

			cfg, b, err := ReadConfiguration(t.Context(), tmp)
			assert.NoError(t, err)
			assert.Empty(t, b)
			assert.Equal(t, IacConfig{}, *cfg)
		})
	}
}

func TestReadLegacyOnly(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, LegacyConfigFileName), []byte(legacyCfg), 0644))

	cfg, b, err := ReadConfiguration(t.Context(), tmp)
	assert.NoError(t, err)
	assert.Equal(t, convertedLegacyCfg+excludeSuffix, string(b))
	assert.Equal(t, parsedLegacyCfg, *cfg)
}

func TestReadLegacyWithIncludeRulesOnly(t *testing.T) {
	tmp := t.TempDir()
	myCfgFile := legacyCfg + "include-queries: [query3, query4]\n"
	includeOnly := "schema-version: v1.2\niac:\n  use-rules:\n    - query3\n    - query4\n"
	require.NoError(t, os.WriteFile(filepath.Join(tmp, LegacyConfigFileName), []byte(myCfgFile), 0644))

	cfg, b, err := ReadConfiguration(t.Context(), tmp)
	assert.NoError(t, err)
	assert.Equal(t, includeOnly, string(b))
	assert.Equal(t, IacConfig{
		OnlyRules: []string{"query3", "query4"},
	}, *cfg)
}

func TestConfigFilePrecedence(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, ConfigFileNameBase+".yaml"), []byte(cfgFile), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, LegacyConfigFileName), []byte(legacyCfg), 0644))

	cfg, b, err := ReadConfiguration(t.Context(), tmp)
	assert.NoError(t, err)
	assert.Equal(t, cfgFile, string(b))
	assert.Equal(t, parsedCfgFile, *cfg)
}

func TestConfigFilePrecedenceWithIgnoredConfigFile(t *testing.T) {
	for _, tc := range []struct {
		name, cfg string
	}{
		{
			name: "empty IaC config",
			cfg:  emptyCfgFile,
		},
		{
			name: "old schema version",
			cfg:  oldCfgFile,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(tmp, ConfigFileNameBase+".yaml"), []byte(tc.cfg), 0644))
			require.NoError(t, os.WriteFile(filepath.Join(tmp, LegacyConfigFileName), []byte(legacyCfg), 0644))

			// New config file has no iac section, so legacy takes over.
			cfg, b, err := ReadConfiguration(t.Context(), tmp)
			assert.NoError(t, err)
			assert.Equal(t, convertedLegacyCfg+excludeSuffix, string(b))
			assert.Equal(t, parsedLegacyCfg, *cfg)
		})
	}
}

func TestNoConfigWithDatadog(t *testing.T) {
	const repoUrl = "https://example.com/repo.git"
	client := &fakeDatadogClient{
		t:                  t,
		expectedSentConfig: nil,
		expectedRepoUrl:    repoUrl,
		remoteConfig:       []byte(cfgFile),
	}

	// No local config file — options must still be applied so server-side config is fetched.
	cfg, b, err := ReadConfiguration(t.Context(), t.TempDir(), WithDatadog(client, repoUrl))
	assert.NoError(t, err)
	assert.Equal(t, cfgFile, string(b))
	assert.Equal(t, parsedCfgFile, *cfg)
}

func TestConfigFileFromDatadog(t *testing.T) {
	const repoUrl = "https://example.com/repo.git"
	const cfgWithExclude = cfgFile + excludeSuffix
	parsedCfgWithExclude := parsedCfgFile
	parsedCfgWithExclude.LegacyExcludeResults = []string{"res1", "res2"}
	for _, tc := range []struct {
		name           string
		isLegacyConfig bool
		localConfig    string
		sentConfig     string
		finalConfig    string
		expectedConfig string
		parsedConfig   *IacConfig
	}{
		{
			// New config file has no iac section: falls through, sending nil to the API.
			name:           "regular config without iac section",
			localConfig:    emptyCfgFile,
			sentConfig:     "",
			finalConfig:    cfgFile,
			expectedConfig: cfgFile,
			parsedConfig:   &parsedCfgFile,
		},
		{
			// New config file has an iac section: bytes sent directly to the API.
			name:           "regular config with iac section",
			localConfig:    cfgFile,
			sentConfig:     cfgFile,
			finalConfig:    cfgFile,
			expectedConfig: cfgFile,
			parsedConfig:   &parsedCfgFile,
		},
		{
			// v1.5 file with an unknown root key and no iac section: lenient check sees no iac key,
			// falls through, sends nil to the API (same as no local file).
			name:           "future minor version without iac section",
			localConfig:    "schema-version: v1.5\nfuture-product:\n  config: foo\n",
			sentConfig:     "",
			finalConfig:    cfgFile,
			expectedConfig: cfgFile,
			parsedConfig:   &parsedCfgFile,
		},
		{
			name:           "legacy config",
			isLegacyConfig: true,
			localConfig:    legacyCfg,
			sentConfig:     convertedLegacyCfg,
			finalConfig:    cfgFile,
			expectedConfig: cfgWithExclude,
			parsedConfig:   &parsedCfgWithExclude,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeDatadogClient{
				t:                  t,
				expectedSentConfig: []byte(tc.sentConfig),
				expectedRepoUrl:    repoUrl,
				remoteConfig:       []byte(tc.finalConfig),
			}

			tmp := t.TempDir()
			if tc.isLegacyConfig {
				require.NoError(t, os.WriteFile(filepath.Join(tmp, LegacyConfigFileName), []byte(tc.localConfig), 0644))
			} else {
				require.NoError(t, os.WriteFile(filepath.Join(tmp, ConfigFileNameBase+".yaml"), []byte(tc.localConfig), 0644))
			}

			cfg, b, err := ReadConfiguration(t.Context(), tmp, WithDatadog(client, repoUrl))
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedConfig, string(b))
			assert.Equal(t, *tc.parsedConfig, *cfg)
		})
	}
}

type fakeDatadogClient struct {
	t                  *testing.T
	expectedRepoUrl    string
	expectedSentConfig []byte
	remoteConfig       []byte
}

func (f *fakeDatadogClient) GetDefaultRuleset(ctx context.Context) (*datadog.Ruleset, error) {
	panic("unimplemented")
}

func (f *fakeDatadogClient) GetRemoteConfig(_ context.Context, repoUrl string, localConfig []byte) ([]byte, error) {
	assert.Equal(f.t, f.expectedRepoUrl, repoUrl)
	assert.Equal(f.t, string(f.expectedSentConfig), string(localConfig))
	return f.remoteConfig, nil
}
