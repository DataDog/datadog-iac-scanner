package config

import (
	"context"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/internal/console/helpers"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

func readLegacyConfiguration(ctx context.Context, rootPath string) (*IacConfig, error) {
	configParams := &IacConfig{}

	v := viper.New()
	v.SetEnvPrefix("KICS")
	v.AutomaticEnv()

	configPath := filepath.Join(rootPath, LegacyConfigFileName)
	v.SetConfigName(LegacyConfigFileName)
	v.AddConfigPath(rootPath)
	ext, err := helpers.FileAnalyzer(configPath)
	if err != nil {
		log.Ctx(ctx).Debug().Msgf("Error analyzing config file %s", configPath)
		return configParams, err
	}
	v.SetConfigType(ext)
	if err := v.ReadInConfig(); err != nil {
		log.Ctx(ctx).Debug().Msgf("Error reading config file %s", configPath)
		return configParams, err
	}

	if v.Get("include-queries") != nil {
		// In the legacy configuration, the `include-queries` field causes all other `exclude-*` fields to be ignored.
		// So populate the field and return early to skip the rest.
		configParams.OnlyRules = v.GetStringSlice("include-queries")
		return configParams, nil
	}

	if v.Get("exclude-categories") != nil {
		configParams.IgnoreCategories = v.GetStringSlice("exclude-categories")
	}
	if v.Get("exclude-paths") != nil {
		configParams.IgnorePaths = v.GetStringSlice("exclude-paths")
	}
	if v.Get("exclude-queries") != nil {
		configParams.IgnoreRules = v.GetStringSlice("exclude-queries")
	}
	if v.Get("exclude-results") != nil {
		configParams.LegacyExcludeResults = v.GetStringSlice("exclude-results")
	}
	if v.Get("exclude-severities") != nil {
		configParams.IgnoreSeverities = v.GetStringSlice("exclude-severities")
	}

	return configParams, nil
}
