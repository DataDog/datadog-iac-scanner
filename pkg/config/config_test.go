package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

	cfg, err := ParseConfig([]byte("schema-version: v1.0\niac: {ignore-rules: [\"abc\"]}"))
	assert.Nil(t, cfg, "Too low schema-version should result in empty IaC config")
	assert.NoError(t, err)

	cfg, err = ParseConfig([]byte("schema-version: v1.2\niac: {ignore-rules: [\"abc\"]}"))
	assert.NotNil(t, cfg, "The current schema-version should result in parsed IaC config")
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
