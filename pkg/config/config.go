package config

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type cfgFileYaml struct {
	SchemaVersion string     `yaml:"schema-version"`
	Iac           *iacConfig `yaml:"iac,omitempty"`
	Sast          any        `yaml:"sast,omitempty"`
	Secrets       any        `yaml:"secrets,omitempty"`
	Sca           any        `yaml:"sca,omitempty"`
	Iast          any        `yaml:"iast,omitempty"`
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

// ParseConfig turns a YAML configuration file into a parsed configuration
func ParseConfig(cfgBytes []byte) (*IacConfig, error) {
	if len(cfgBytes) == 0 {
		return nil, nil
	}

	var cfg *cfgFileYaml
	decoder := yaml.NewDecoder(bytes.NewReader(cfgBytes))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("could not decode configuration file: %w", err)
	}

	version, err := parseSchemaVersion(cfg.SchemaVersion)
	if err != nil {
		return nil, err
	}
	// Versions older than v1.2 can't have an IaC configuration
	if version.compare(schemaVersion{1, 2}) < 0 {
		return nil, nil
	}
	// Versions v2.0 and higher are not supported
	if version.compare(schemaVersion{2, 0}) >= 0 {
		return nil, fmt.Errorf("configuration schema version %s is not supported", version)
	}

	if cfg.Iac == nil {
		return nil, nil
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

// UnparseConfig turns a parsed configuration into a YAML file.
// It ignores the LegacyExcludeResults field, since it's not representable in YAML.
// You will need to handle it externally if you need to.
func UnparseConfig(cfg *IacConfig) ([]byte, error) {
	if cfg == nil {
		return nil, nil
	}

	iac := iacConfig{
		IgnoreRules: cfg.IgnoreRules,
		UseRules:    cfg.OnlyRules,
		GlobalConfig: iacGlobalConfig{
			IgnorePaths:      cfg.IgnorePaths,
			OnlyPaths:        cfg.OnlyPaths,
			IgnoreSeverities: cfg.IgnoreSeverities,
			OnlySeverities:   cfg.OnlySeverities,
			IgnoreCategories: cfg.IgnoreCategories,
			OnlyCategories:   cfg.OnlyCategories,
		},
	}

	if reflect.DeepEqual(iac, iacConfig{}) {
		return []byte{}, nil
	}

	outCfg := cfgFileYaml{
		SchemaVersion: "v1.2",
		Iac:           &iac,
	}

	out := bytes.Buffer{}
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(outCfg); err != nil {
		return nil, fmt.Errorf("could not encode configuration: %w", err)
	}
	return out.Bytes(), nil
}

func parseSchemaVersion(schema string) (version schemaVersion, err error) {
	if schema == "" {
		return schemaVersion{}, errors.New("schema must not be empty")
	}
	if schema[0] != 'v' {
		return schemaVersion{}, errors.New("schema must be in vX.Y format")
	}
	majorStr, minorStr, ok := strings.Cut(schema[1:], ".")
	if !ok {
		return schemaVersion{}, errors.New("schema must be in vX.Y format")
	}
	major64, err := strconv.ParseInt(majorStr, 10, strconv.IntSize)
	if err != nil {
		return schemaVersion{}, errors.New("major version must be a number")
	}
	minor64, err := strconv.ParseInt(minorStr, 10, strconv.IntSize)
	if err != nil {
		return schemaVersion{}, errors.New("minor version must be a number")
	}
	return schemaVersion{major: int(major64), minor: int(minor64)}, nil
}

type schemaVersion struct {
	major, minor int
}

// compare returns a positive number if this schema version is higher than the other schema version,
// a negative number if it's smaller, or zero if they are equal
func (v schemaVersion) compare(other schemaVersion) int {
	if dif := v.major - other.major; dif != 0 {
		return dif
	}
	return v.minor - other.minor
}

func (v schemaVersion) String() string {
	return fmt.Sprintf("v%d.%d", v.major, v.minor)
}
