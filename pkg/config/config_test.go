package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHappyPath(t *testing.T) {
	cfg, err := ParseConfig([]byte(cfgFile))
	assert.NoError(t, err)
	assert.Equal(t, parsedCfgFile, *cfg)
}

func TestParseSchemaVersion(t *testing.T) {
	_, err := ParseConfig([]byte(`iac: {ignore-rules: ["abc"]}`))
	assert.Error(t, err, "Missing schema-version was expected to be rejected")

	_, err = ParseConfig([]byte("schema-version: v1\niac: {ignore-rules: [\"abc\"]}"))
	assert.Error(t, err, "Invalid schema-version was expected to be rejected")

	_, err = ParseConfig([]byte("schema-version: 1.1\niac: {ignore-rules: [\"abc\"]}"))
	assert.Error(t, err, "Invalid schema-version was expected to be rejected")

	cfg, err := ParseConfig([]byte("schema-version: v1.2\niac: {ignore-rules: [\"abc\"]}"))
	assert.NotNil(t, cfg, "The current schema-version should result in parsed IaC config")
	assert.NoError(t, err)

	cfg, err = ParseConfig([]byte("schema-version: v1.0\niac: {ignore-rules: [\"abc\"]}"))
	assert.NotNil(t, cfg, "An old v1.x schema-version should also result in parsed IaC config")
	assert.NoError(t, err)

	_, err = ParseConfig([]byte("schema-version: v1.3\niac: {ignore-rules: [\"abc\"]}"))
	assert.NotNil(t, cfg, "The schema-version with future minor number should result in parsed IaC config")
	assert.NoError(t, err)

	_, err = ParseConfig([]byte("schema-version: v2.1\niac: {ignore-rules: [\"abc\"]}"))
	assert.Error(t, err, "The schema-version with future major number was expected to be rejected")
}

func TestParseUnknownProduct(t *testing.T) {
	_, err := ParseConfig([]byte("schema-version: v1.1\nxinvalid:"))
	assert.Error(t, err, "The unknown product was expected to be rejected")

	_, err = ParseConfig([]byte("schema-version: v1.1\nsca:"))
	assert.NoError(t, err, "Missing iac product was expected to be accepted")

	_, err = ParseConfig([]byte("schema-version: v1.1\nsca:\n  foo: 1\n  bar: 2"))
	assert.NoError(t, err, "Values in another product configuration were expected to be accepted")
}

func TestParseUnknownField(t *testing.T) {
	_, err := ParseConfig([]byte("schema-version: v1.1\niac:\n  xinvalid: abc"))
	assert.Error(t, err, "The unknown field was expected to be rejected")

	_, err = ParseConfig([]byte("schema-version: v1.1\niac:\n  global-config:\n    xinvalid: abc"))
	assert.Error(t, err, "The unknown field was expected to be rejected")
}

func TestUnparseConfig(t *testing.T) {
	b, err := UnparseConfig(&parsedCfgFile)
	assert.NoError(t, err)
	assert.Equal(t, cfgFile, string(b))
}

func TestUnparseConfigV13SchemaVersion(t *testing.T) {
	t.Run("v1.2 config keeps v1.2 schema version", func(t *testing.T) {
		b, err := UnparseConfig(&parsedCfgFile)
		require.NoError(t, err)
		assert.Contains(t, string(b), "schema-version: v1.2")
	})

	t.Run("config with only-platforms emits v1.3", func(t *testing.T) {
		cfg := parsedCfgFile
		cfg.OnlyPlatforms = []string{"Terraform"}
		b, err := UnparseConfig(&cfg)
		require.NoError(t, err)
		assert.Contains(t, string(b), "schema-version: v1.3")
		assert.Contains(t, string(b), "only-platforms:")
	})

	t.Run("config with ignore-platforms emits v1.3", func(t *testing.T) {
		cfg := parsedCfgFile
		cfg.IgnorePlatforms = []string{"Dockerfile"}
		b, err := UnparseConfig(&cfg)
		require.NoError(t, err)
		assert.Contains(t, string(b), "schema-version: v1.3")
	})

	t.Run("config with rule-configs emits v1.3", func(t *testing.T) {
		cfg := parsedCfgFile
		cfg.RuleConfigs = map[string]IacRuleConfig{
			"my-rule": {IgnorePaths: []string{"test/"}, Severity: "low"},
		}
		b, err := UnparseConfig(&cfg)
		require.NoError(t, err)
		assert.Contains(t, string(b), "schema-version: v1.3")
		assert.Contains(t, string(b), "rule-configs:")
		assert.Contains(t, string(b), "my-rule:")
	})
}

func TestParseUnparseRoundTripV13(t *testing.T) {
	input := `schema-version: v1.3
iac:
  ignore-rules:
    - query1
  global-config:
    only-platforms:
      - Terraform
      - Kubernetes
    ignore-platforms:
      - Dockerfile
  rule-configs:
    terraform-aws-s3-unencrypted:
      ignore-paths:
        - test/
      severity: low
`
	cfg, err := ParseConfig([]byte(input))
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, []string{"Terraform", "Kubernetes"}, cfg.OnlyPlatforms)
	assert.Equal(t, []string{"Dockerfile"}, cfg.IgnorePlatforms)
	require.Len(t, cfg.RuleConfigs, 1)
	rc := cfg.RuleConfigs["terraform-aws-s3-unencrypted"]
	assert.Equal(t, []string{"test/"}, rc.IgnorePaths)
	assert.Equal(t, "low", rc.Severity)
}
