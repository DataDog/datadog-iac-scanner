package config

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"gopkg.in/yaml.v3"
)

const (
	ConfigFileNameBase   = "code-security.datadog"
	LegacyConfigFileName = "dd-iac-scan.config"
)

// ReadConfiguration reads the local config file (if any), applies all options
// (e.g. WithDatadog), and returns the parsed result.
// Options are always applied even when no local file exists, so server-side
// customizations are fetched regardless of local file presence.
func ReadConfiguration(ctx context.Context, rootPath string, options ...ReadConfigurationOption) (*IacConfig, []byte, error) {
	cfgBytes, legacyExcludeResults, err := findLocalConfig(ctx, rootPath)
	if err != nil {
		return nil, nil, err
	}

	for _, option := range options {
		cfgBytes, err = option(ctx, cfgBytes)
		if err != nil {
			return nil, nil, err
		}
	}

	cfg, err := ParseConfig(cfgBytes)
	if err != nil {
		return nil, nil, newInvalidLocalConfigError(fmt.Errorf("could not parse configuration file: %w", err))
	}

	if len(legacyExcludeResults) > 0 {
		if cfg == nil {
			cfg = &IacConfig{}
		}
		cfg.LegacyExcludeResults = legacyExcludeResults
		cfgBytes = appendLegacyExcludeResultsComment(cfgBytes, legacyExcludeResults)
	}

	if cfg != nil {
		return cfg, cfgBytes, nil
	}
	return &IacConfig{}, cfgBytes, nil
}

// knownRootsCfgFile is the exhaustive set of valid root-level product keys. Used with
// KnownFields to reject unrecognized root properties per the RFC requirement.
type knownRootsCfgFile struct {
	SchemaVersion string `yaml:"schema-version"`
	Iac           any    `yaml:"iac"`
	Sast          any    `yaml:"sast"`
	Secrets       any    `yaml:"secrets"`
	Sca           any    `yaml:"sca"`
	Iast          any    `yaml:"iast"`
}

// hasIacSectionForSupportedVersion reports whether b contains an iac: section for a supported
// schema version. Unknown root keys are rejected (all products fail per the RFC). Unknown
// fields within known sections are accepted because each product key is typed as any.
func hasIacSectionForSupportedVersion(b []byte) (bool, error) {
	var doc knownRootsCfgFile
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		return false, newInvalidLocalConfigError(fmt.Errorf("could not parse configuration file: %w", err))
	}
	version, err := parseSchemaVersion(doc.SchemaVersion)
	if err != nil {
		return false, newInvalidLocalConfigError(fmt.Errorf("invalid schema version: %w", err))
	}
	if version.compare(minUnsupportedVersion) >= 0 {
		return false, newInvalidLocalConfigError(fmt.Errorf("configuration schema version %s is not supported", version))
	}
	if version.compare(minIacVersion) < 0 {
		return false, nil
	}
	return doc.Iac != nil, nil
}

// findLocalConfig returns the local configuration as YAML bytes.
// The new config format (code-security.datadog.yaml) takes priority over the legacy
// format only when it contains an iac section. If the new file exists but has no iac
// section, the legacy format is used as a fallback. Returns (nil, nil, nil) when no
// config file is found. legacyExcludeResults is populated only for legacy configs.
func findLocalConfig(ctx context.Context, rootPath string) (cfgBytes []byte, legacyExcludeResults []string, err error) {
	if path, found := fileExists(rootPath, ConfigFileNameBase, ".yaml", ".yml"); found {
		b, err := os.ReadFile(path) // nolint:gosec
		if err != nil {
			return nil, nil, newInvalidLocalConfigError(fmt.Errorf("could not read configuration file %s: %w", path, err))
		}
		hasIac, err := hasIacSectionForSupportedVersion(b)
		if err != nil {
			return nil, nil, err
		}
		if hasIac {
			return b, nil, nil
		}
		// No iac section or schema too old: fall through to legacy.
	}

	return readLegacyConfigBytes(ctx, rootPath)
}

// readLegacyConfigBytes reads and converts the legacy config file to YAML bytes.
// Returns (nil, nil, nil) if no legacy config file is found.
func readLegacyConfigBytes(ctx context.Context, rootPath string) (cfgBytes []byte, legacyExcludeResults []string, err error) {
	if _, found := fileExists(rootPath, LegacyConfigFileName); !found {
		return nil, nil, nil
	}

	converted, err := readLegacyConfiguration(ctx, rootPath)
	if err != nil {
		return nil, nil, newInvalidLocalConfigError(fmt.Errorf("could not read legacy configuration file: %w", err))
	}

	b, err := UnparseConfig(converted)
	if err != nil {
		return nil, nil, newInvalidLocalConfigError(fmt.Errorf("could not convert legacy configuration file: %w", err))
	}

	return b, converted.LegacyExcludeResults, nil
}

func appendLegacyExcludeResultsComment(cfgBytes []byte, excludeResults []string) []byte {
	var names []string
	for _, rn := range excludeResults {
		names = append(names, fmt.Sprintf("%q", rn))
	}
	return []byte(string(cfgBytes) + fmt.Sprintf(
		"# These settings have been applied, but they cannot be expressed in the new configuration format:\n"+
			"# exclude-results: [ %s ]\n", strings.Join(names, ", ")))
}

type ReadConfigurationOption func(context.Context, []byte) ([]byte, error)

// WithDatadog calls the Datadog backend to append server-side customizations to the local repo config.
func WithDatadog(client datadog.Client, repoUrl string) ReadConfigurationOption {
	return func(ctx context.Context, cfgBytes []byte) ([]byte, error) {
		return client.GetRemoteConfig(ctx, repoUrl, cfgBytes)
	}
}

func fileExists(rootPath, name string, exts ...string) (string, bool) {
	if len(exts) == 0 {
		exts = []string{""}
	}
	for _, ext := range exts {
		path := filepath.Join(rootPath, name+ext)
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}
