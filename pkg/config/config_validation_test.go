package config

import (
	"fmt"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSeverityValues(t *testing.T) {
	happy := []struct {
		name, input, expected string
	}{
		{"exact lowercase", "critical", "critical"},
		{"uppercase", "HIGH", "high"},
		{"whitespace", `"  medium  "`, "medium"},
		{"mixed case", "Low", "low"},
		{"info", "info", "info"},
	}
	invalid := []struct {
		name, input, errFragment string
	}{
		{"trace is excluded", "trace", `invalid severity: "trace"`},
		{"unknown value", "bogus", `invalid severity: "bogus"`},
	}

	for _, field := range []string{"ignore-severities", "only-severities"} {
		for _, tc := range happy {
			t.Run(field+"/happy/"+tc.name, func(t *testing.T) {
				yaml := fmt.Sprintf("schema-version: v1.2\niac:\n  global-config:\n    %s:\n      - %s\n", field, tc.input)
				cfg, err := ParseConfig([]byte(yaml))
				require.NoError(t, err)
				require.NotNil(t, cfg)
				got := cfg.IgnoreSeverities
				if field == "only-severities" {
					got = cfg.OnlySeverities
				}
				assert.Equal(t, []string{tc.expected}, got)
			})
		}
		for _, tc := range invalid {
			t.Run(field+"/invalid/"+tc.name, func(t *testing.T) {
				yaml := fmt.Sprintf("schema-version: v1.2\niac:\n  global-config:\n    %s:\n      - %s\n", field, tc.input)
				_, err := ParseConfig([]byte(yaml))
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errFragment)
			})
		}
	}
}

func TestParseCategoryValues(t *testing.T) {
	for _, cat := range []string{"Access Control", "Encryption", "Best Practices"} {
		require.Contains(t, constants.AvailableCategories, cat, "fixture references removed category")
	}

	happy := []struct {
		name, input, expected string
	}{
		{"exact", "Encryption", "Encryption"},
		{"lowercase", "encryption", "Encryption"},
		{"whitespace and case", `"  access control  "`, "Access Control"},
		{"multi-word exact", `"Best Practices"`, "Best Practices"},
	}
	invalid := []struct {
		name, input, errFragment string
	}{
		{"unknown value", "bogus", `invalid category: "bogus"`},
	}

	for _, field := range []string{"ignore-categories", "only-categories"} {
		for _, tc := range happy {
			t.Run(field+"/happy/"+tc.name, func(t *testing.T) {
				yaml := fmt.Sprintf("schema-version: v1.2\niac:\n  global-config:\n    %s:\n      - %s\n", field, tc.input)
				cfg, err := ParseConfig([]byte(yaml))
				require.NoError(t, err)
				require.NotNil(t, cfg)
				got := cfg.IgnoreCategories
				if field == "only-categories" {
					got = cfg.OnlyCategories
				}
				assert.Equal(t, []string{tc.expected}, got)
			})
		}
		for _, tc := range invalid {
			t.Run(field+"/invalid/"+tc.name, func(t *testing.T) {
				yaml := fmt.Sprintf("schema-version: v1.2\niac:\n  global-config:\n    %s:\n      - %s\n", field, tc.input)
				_, err := ParseConfig([]byte(yaml))
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errFragment)
			})
		}
	}
}

func TestParsePlatformValues(t *testing.T) {
	happy := []struct {
		name, input, expected string
	}{
		{"exact", "Terraform", "Terraform"},
		{"lowercase", "terraform", "Terraform"},
		{"uppercase", "KUBERNETES", "Kubernetes"},
		{"mixed case", "cloudFormation", "CloudFormation"},
		{"ansible", "ansible", "Ansible"},
		{"cicd", "cicd", "CICD"},
		{"dockerfile", "Dockerfile", "Dockerfile"},
	}
	invalid := []struct {
		name, input, errFragment string
	}{
		{"unknown platform", "bogus", `invalid platform: "bogus"`},
		{"unreleased platform", "pulumi", `invalid platform: "pulumi"`},
	}

	for _, field := range []string{"only-platforms", "ignore-platforms"} {
		for _, tc := range happy {
			t.Run(field+"/happy/"+tc.name, func(t *testing.T) {
				yamlStr := fmt.Sprintf("schema-version: v1.3\niac:\n  global-config:\n    %s:\n      - %s\n", field, tc.input)
				cfg, err := ParseConfig([]byte(yamlStr))
				require.NoError(t, err)
				require.NotNil(t, cfg)
				got := cfg.OnlyPlatforms
				if field == "ignore-platforms" {
					got = cfg.IgnorePlatforms
				}
				assert.Equal(t, []string{tc.expected}, got)
			})
		}
		for _, tc := range invalid {
			t.Run(field+"/invalid/"+tc.name, func(t *testing.T) {
				yamlStr := fmt.Sprintf("schema-version: v1.3\niac:\n  global-config:\n    %s:\n      - %s\n", field, tc.input)
				_, err := ParseConfig([]byte(yamlStr))
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errFragment)
			})
		}
	}
}

func TestParseRuleConfigs(t *testing.T) {
	t.Run("full rule config", func(t *testing.T) {
		input := `schema-version: v1.3
iac:
  rule-configs:
    terraform-aws-s3-unencrypted:
      ignore-paths:
        - test/
      only-paths:
        - src/
      severity: low
`
		cfg, err := ParseConfig([]byte(input))
		require.NoError(t, err)
		require.NotNil(t, cfg)
		require.Len(t, cfg.RuleConfigs, 1)
		rc := cfg.RuleConfigs["terraform-aws-s3-unencrypted"]
		assert.Equal(t, []string{"test/"}, rc.IgnorePaths)
		assert.Equal(t, []string{"src/"}, rc.OnlyPaths)
		assert.Equal(t, "low", rc.Severity)
	})

	t.Run("severity override only", func(t *testing.T) {
		input := `schema-version: v1.3
iac:
  rule-configs:
    some-rule:
      severity: high
`
		cfg, err := ParseConfig([]byte(input))
		require.NoError(t, err)
		require.NotNil(t, cfg)
		rc := cfg.RuleConfigs["some-rule"]
		assert.Equal(t, "high", rc.Severity)
		assert.Nil(t, rc.IgnorePaths)
		assert.Nil(t, rc.OnlyPaths)
	})

	t.Run("invalid severity in rule-config", func(t *testing.T) {
		input := `schema-version: v1.3
iac:
  rule-configs:
    some-rule:
      severity: bogus
`
		_, err := ParseConfig([]byte(input))
		require.Error(t, err)
		assert.Contains(t, err.Error(), `invalid severity: "bogus"`)
	})

	t.Run("unknown field in rule-config", func(t *testing.T) {
		input := `schema-version: v1.3
iac:
  rule-configs:
    some-rule:
      xinvalid: foo
`
		_, err := ParseConfig([]byte(input))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "iac.rule-configs.<rule-id>")
	})
}

func TestRewriteDecodeErrors(t *testing.T) {
	for _, tc := range []struct {
		name, input, expectedFragment string
	}{
		{
			name:             "unknown field in iac section",
			input:            "schema-version: v1.2\niac:\n  xinvalid: abc\n",
			expectedFragment: "field `xinvalid` is not valid in the `iac` section",
		},
		{
			name:             "unknown field in iac.global-config section",
			input:            "schema-version: v1.2\niac:\n  global-config:\n    xinvalid: abc\n",
			expectedFragment: "field `xinvalid` is not valid in the `iac.global-config` section",
		},
		{
			name:             "global-config field placed under iac",
			input:            "schema-version: v1.2\niac:\n  ignore-paths: [p]\n",
			expectedFragment: "you should include it in the `iac.global-config` section instead",
		},
		{
			name:             "iac field placed at top level",
			input:            "schema-version: v1.2\nignore-rules: [r]\n",
			expectedFragment: "you should include it in the `iac` section instead",
		},
		{
			name:             "top-level field placed under iac",
			input:            "schema-version: v1.2\niac:\n  sast: foo\n",
			expectedFragment: "you should include it in the top-level configuration instead",
		},
		{
			name:             "sast field placed in iac scanner config",
			input:            "schema-version: v1.2\niac:\n  use-rulesets: [r]\n",
			expectedFragment: "it looks like a datadog-static-analyzer configuration option, not a datadog-iac-scanner option",
		},
		{
			name:             "duplicate mapping key",
			input:            "schema-version: v1.2\niac:\n  ignore-rules: [a]\n  ignore-rules: [b]\n",
			expectedFragment: "field `ignore-rules` has already been set in line",
		},
		{
			name:             "wrong scalar value for known field",
			input:            "schema-version: v1.2\niac:\n  ignore-rules: 42\n",
			expectedFragment: "value `42` of type int is not valid here; a []string was expected",
		},
		{
			name:             "wrong scalar type for known field",
			input:            "schema-version: v1.2\niac:\n  ignore-rules:\n    nested: true\n",
			expectedFragment: "value of type map is not valid here; a []string was expected",
		},
		{
			name:             "wrong type for iac section",
			input:            "schema-version: v1.2\niac: foo\n",
			expectedFragment: "value `foo` of type str is not valid here; the content of the `iac` section was expected",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tc.input))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedFragment)
		})
	}
}
