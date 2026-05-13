package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
)

const (
	ConfigFileNameBase   = "code-security.datadog"
	LegacyConfigFileName = "dd-iac-scan.config"
)

// ReadConfiguration reads and parses the configuration file in the local repository.
// It returns the parsed configuration and the YAML file (or a YAML conversion, in the case of legacy configurations).
func ReadConfiguration(ctx context.Context, rootPath string, options ...ReadConfigurationOption) (*IacConfig, []byte, error) {
	var cfgContent []byte
	if cfg, cfgBytes, err := readAndParseConfiguration(ctx, rootPath, options...); cfg != nil || err != nil {
		return cfg, cfgBytes, err
	} else if cfgBytes != nil {
		cfgContent = cfgBytes
	}

	if cfg, cfgBytes, err := readAndParseLegacyConfiguration(ctx, rootPath, options...); cfg != nil || err != nil {
		return cfg, cfgBytes, err
	} else if cfgBytes != nil {
		cfgContent = cfgBytes
	}

	return &IacConfig{}, cfgContent, nil
}

func readAndParseConfiguration(ctx context.Context, rootPath string, options ...ReadConfigurationOption) (*IacConfig, []byte, error) {
	path, found := fileExists(rootPath, ConfigFileNameBase, ".yaml", ".yml")
	if !found {
		return nil, nil, nil
	}

	cfgBytes, err := os.ReadFile(path) // nolint:gosec
	if err != nil {
		return nil, nil, newInvalidLocalConfigError(fmt.Errorf("could not read configuration file %s: %w", path, err))
	}

	for _, option := range options {
		newCfg, err := option(ctx, cfgBytes)
		if err != nil {
			return nil, nil, err
		}
		cfgBytes = newCfg
	}

	cfg, err := ParseConfig(cfgBytes)
	if err != nil {
		return nil, nil, newInvalidLocalConfigError(fmt.Errorf("could not parse configuration file: %w", err))
	}
	return cfg, cfgBytes, nil
}

func readAndParseLegacyConfiguration(ctx context.Context, rootPath string, options ...ReadConfigurationOption) (*IacConfig, []byte, error) {
	_, found := fileExists(rootPath, LegacyConfigFileName)
	if !found {
		return nil, nil, nil
	}

	converted, err := readLegacyConfiguration(ctx, rootPath)
	if err != nil {
		return nil, nil, newInvalidLocalConfigError(fmt.Errorf("could not read legacy configuration file: %w", err))
	}

	// Try to convert the legacy configuration to the new format so we can apply the options
	cfgBytes, err := UnparseConfig(converted)
	if err != nil {
		return nil, nil, newInvalidLocalConfigError(fmt.Errorf("could not convert legacy configuration file: %w", err))
	}

	for _, option := range options {
		newCfg, err := option(ctx, cfgBytes)
		if err != nil {
			return nil, nil, err
		}
		cfgBytes = newCfg
	}

	cfg, err := ParseConfig(cfgBytes)
	if err != nil {
		return nil, nil, newInvalidLocalConfigError(fmt.Errorf("could not parse configuration file: %w", err))
	}

	// Restore the original file's 'exclude-results' setting on the final configuration
	if len(converted.LegacyExcludeResults) > 0 {
		if cfg == nil {
			cfg = &IacConfig{}
		}
		cfg.LegacyExcludeResults = converted.LegacyExcludeResults
	}

	if cfg != nil && len(cfg.LegacyExcludeResults) > 0 {
		// We are returning a converted configuration but the original had settings that are not available
		// in the new, so add a comment.
		var resultNames []string
		for _, rn := range cfg.LegacyExcludeResults {
			resultNames = append(resultNames, fmt.Sprintf("%q", rn))
		}
		cfgBytes = []byte(
			string(cfgBytes) +
				fmt.Sprintf(
					"# These settings have been applied, but they cannot be expressed in the new configuration format:\n"+
						"# exclude-results: [ %s ]\n", strings.Join(resultNames, ", ")),
		)
	}
	return cfg, cfgBytes, nil
}

type ReadConfigurationOption func(context.Context, []byte) ([]byte, error)

// WithDatadog calls the Datadog backend to append server-side customizations to the local repo config
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
