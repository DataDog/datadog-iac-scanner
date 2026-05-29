package config

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
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
	IgnoreRules  []string                     `yaml:"ignore-rules,omitempty"`
	UseRules     []string                     `yaml:"use-rules,omitempty"`
	GlobalConfig iacGlobalConfig              `yaml:"global-config,omitempty"`
	RuleConfigs  map[string]iacRuleConfigYaml `yaml:"rule-configs,omitempty"`
}

type iacGlobalConfig struct {
	IgnorePaths      []string      `yaml:"ignore-paths,omitempty"`
	OnlyPaths        []string      `yaml:"only-paths,omitempty"`
	IgnoreSeverities []iacSeverity `yaml:"ignore-severities,omitempty"`
	OnlySeverities   []iacSeverity `yaml:"only-severities,omitempty"`
	IgnoreCategories []iacCategory `yaml:"ignore-categories,omitempty"`
	OnlyCategories   []iacCategory `yaml:"only-categories,omitempty"`
	IgnorePlatforms  []iacPlatform `yaml:"ignore-platforms,omitempty"`
	OnlyPlatforms    []iacPlatform `yaml:"only-platforms,omitempty"`
}

// iacRuleConfigYaml is the YAML representation of a per-rule override block.
type iacRuleConfigYaml struct {
	IgnorePaths []string     `yaml:"ignore-paths,omitempty"`
	OnlyPaths   []string     `yaml:"only-paths,omitempty"`
	Severity    *iacSeverity `yaml:"severity,omitempty"`
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
		return nil, rewriteDecodeErrors(err)
	}

	version, err := parseSchemaVersion(cfg.SchemaVersion)
	if err != nil {
		return nil, err
	}
	if version.compare(minRequiredVersion) < 0 {
		return nil, nil
	}
	if version.compare(minUnsupportedVersion) >= 0 {
		return nil, fmt.Errorf("configuration schema version %s is not supported", version)
	}

	if cfg.Iac == nil {
		return nil, nil
	}

	if version.compare(minIacVersion) < 0 {
		log.Warn().Msgf("Your configuration file has version %s but the `iac` section was defined in version %s. "+
			"Please update your configuration file to avoid issues.", version, minIacVersion)
	}

	out := &IacConfig{
		IgnoreRules:      cfg.Iac.IgnoreRules,
		OnlyRules:        cfg.Iac.UseRules,
		IgnorePaths:      cfg.Iac.GlobalConfig.IgnorePaths,
		OnlyPaths:        cfg.Iac.GlobalConfig.OnlyPaths,
		IgnoreSeverities: mapSlice[string](cfg.Iac.GlobalConfig.IgnoreSeverities),
		OnlySeverities:   mapSlice[string](cfg.Iac.GlobalConfig.OnlySeverities),
		IgnoreCategories: mapSlice[string](cfg.Iac.GlobalConfig.IgnoreCategories),
		OnlyCategories:   mapSlice[string](cfg.Iac.GlobalConfig.OnlyCategories),
		OnlyPlatforms:    mapSlice[string](cfg.Iac.GlobalConfig.OnlyPlatforms),
		IgnorePlatforms:  mapSlice[string](cfg.Iac.GlobalConfig.IgnorePlatforms),
		RuleConfigs:      parseRuleConfigs(cfg.Iac.RuleConfigs),
	}
	return out, nil
}

func parseRuleConfigs(in map[string]iacRuleConfigYaml) map[string]IacRuleConfig {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]IacRuleConfig, len(in))
	for ruleID, rc := range in {
		var sev *string
		if rc.Severity != nil {
			s := string(*rc.Severity)
			sev = &s
		}
		out[ruleID] = IacRuleConfig{
			IgnorePaths: rc.IgnorePaths,
			OnlyPaths:   rc.OnlyPaths,
			Severity:    sev,
		}
	}
	return out
}

func unparseRuleConfigs(in map[string]IacRuleConfig) map[string]iacRuleConfigYaml {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]iacRuleConfigYaml, len(in))
	for ruleID, rc := range in {
		var sev *iacSeverity
		if rc.Severity != nil {
			s := iacSeverity(*rc.Severity)
			sev = &s
		}
		out[ruleID] = iacRuleConfigYaml{
			IgnorePaths: rc.IgnorePaths,
			OnlyPaths:   rc.OnlyPaths,
			Severity:    sev,
		}
	}
	return out
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
			IgnoreSeverities: mapSlice[iacSeverity](cfg.IgnoreSeverities),
			OnlySeverities:   mapSlice[iacSeverity](cfg.OnlySeverities),
			IgnoreCategories: mapSlice[iacCategory](cfg.IgnoreCategories),
			OnlyCategories:   mapSlice[iacCategory](cfg.OnlyCategories),
			OnlyPlatforms:    mapSlice[iacPlatform](cfg.OnlyPlatforms),
			IgnorePlatforms:  mapSlice[iacPlatform](cfg.IgnorePlatforms),
		},
		RuleConfigs: unparseRuleConfigs(cfg.RuleConfigs),
	}

	if reflect.DeepEqual(iac, iacConfig{}) {
		return []byte{}, nil
	}

	outCfg := cfgFileYaml{
		SchemaVersion: currentVersion.String(),
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

var (
	// minIacVersion is the minimum schema version supporting the iac: configuration section.
	minIacVersion = schemaVersion{1, 2}
	// currentVersion is the current schema version emitted by UnparseConfig.
	currentVersion = schemaVersion{1, 3}
	// minRequiredVersion is the minimum schema version supported by this scanner.
	// It's different from minIacVersion for user-friendliness in case people add an `iac`
	// section to an old configuration file and forget to upgrade the version number.
	// The configuration will be accepted but a warning message will be displayed.
	minRequiredVersion = schemaVersion{1, 0}
	// minUnsupportedVersion is the minimum schema version not supported by this scanner.
	minUnsupportedVersion = schemaVersion{2, 0}
)

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

func mapSlice[T, F ~string](orig []F) []T {
	var out []T
	for _, e := range orig {
		out = append(out, T(e))
	}
	return out
}
