package config

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type cfgFileYaml struct {
	SchemaVersion string    `yaml:"schema-version"`
	Iac           iacConfig `yaml:"iac,omitempty"`
	Sast          any       `yaml:"sast,omitempty"`
	Secrets       any       `yaml:"secrets,omitempty"`
	Sca           any       `yaml:"sca,omitempty"`
	Iast          any       `yaml:"iast,omitempty"`
}

type iacConfig struct {
	IgnoreRules  []string        `yaml:"ignore-rules,omitempty"`
	UseRules     []string        `yaml:"use-rules,omitempty"`
	GlobalConfig iacGlobalConfig `yaml:"global-config,omitempty"`
}

type iacGlobalConfig struct {
	IgnorePaths      []string `yaml:"ignore-paths,omitempty"`
	OnlyPaths        []string `yaml:"only-paths,omitempty"`
	IgnoreSeverities []string `yaml:"ignore-severities,omitempty"`
	OnlySeverities   []string `yaml:"only-severities,omitempty"`
	IgnoreCategories []string `yaml:"ignore-categories,omitempty"`
	OnlyCategories   []string `yaml:"only-categories,omitempty"`
}

func ParseConfig(cfgBytes []byte) (*IacConfig, error) {
	var cfg *cfgFileYaml
	decoder := yaml.NewDecoder(bytes.NewReader(cfgBytes))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("could not decode configuration file: %w", err)
	}

	if err := verifySchema(cfg.SchemaVersion); err != nil {
		return nil, err
	}
	out := &IacConfig{
		IgnoreRules:      cfg.Iac.IgnoreRules,
		OnlyRules:        cfg.Iac.UseRules,
		IgnorePaths:      cfg.Iac.GlobalConfig.IgnorePaths,
		OnlyPaths:        cfg.Iac.GlobalConfig.OnlyPaths,
		IgnoreSeverities: cfg.Iac.GlobalConfig.IgnoreSeverities,
		OnlySeverities:   cfg.Iac.GlobalConfig.OnlySeverities,
		IgnoreCategories: cfg.Iac.GlobalConfig.IgnoreCategories,
		OnlyCategories:   cfg.Iac.GlobalConfig.OnlyCategories,
	}
	return out, nil
}

func verifySchema(schema string) error {
	if schema == "" {
		return errors.New("schema-version must be specified")
	}
	if schema[0] == 'v' {
		if majorStr, minorStr, ok := strings.Cut(schema[1:], "."); ok {
			major, _ := strconv.Atoi(majorStr)
			minor, _ := strconv.Atoi(minorStr)
			if major == 1 && minor >= 1 {
				return nil
			}
		}
	}
	return errors.New("schema-version must be \"v1.1\" or above")
}
