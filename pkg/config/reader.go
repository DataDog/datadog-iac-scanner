package config

import (
	"context"
	"os"
	"path/filepath"
)

const (
	ConfigFileNameBase   = "code-security.datadog"
	LegacyConfigFileName = "dd-iac-scan.config"
)

func ReadConfiguration(ctx context.Context, rootPath string) (*IacConfig, error) {
	if path, found := fileExists(rootPath, ConfigFileNameBase, ".yaml", ".yml"); found {
		b, err := os.ReadFile(path) // nolint:gosec
		if err != nil {
			return nil, err
		}
		cfg, err := ParseConfig(b)
		if cfg != nil || err != nil {
			return cfg, err
		}
	}

	if _, found := fileExists(rootPath, LegacyConfigFileName); found {
		return readLegacyConfiguration(ctx, rootPath)
	}

	return &IacConfig{}, nil
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
