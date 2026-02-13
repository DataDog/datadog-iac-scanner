package scan

import (
	"context"
	"os"
	"path/filepath"

	consoleHelpers "github.com/DataDog/datadog-iac-scanner/internal/console/helpers"
	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type ConfigParameters struct {
	ExcludeCategories []string
	ExcludePaths      []string
	ExcludeQueries    []string
	ExcludeResults    []string
	ExcludeSeverities []string
	IncludeQueries    []string
}

func setupConfigFile(ctx context.Context, rootPath string) (bool, error) {
	contextLogger := logger.FromContext(ctx)
	configPath := filepath.Join(rootPath, constants.DefaultConfigFilename)
	_, err := os.Stat(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			contextLogger.Info().Msgf("Config file not found at %s", configPath)
			return true, nil
		}
		contextLogger.Info().Msgf("Error reading config file at %s", configPath)
		return true, err
	}

	contextLogger.Info().Msgf("Config file found at %s", configPath)
	return false, nil
}

func ReadConfiguration(ctx context.Context, rootPath string) (*ConfigParameters, error) {
	configParams := &ConfigParameters{}

	v := viper.New()
	v.SetEnvPrefix("KICS")
	v.AutomaticEnv()

	exit, err := setupConfigFile(ctx, rootPath)
	if err != nil {
		return configParams, err
	}
	if exit {
		return configParams, nil
	}
	configPath := filepath.Join(rootPath, constants.DefaultConfigFilename)

	base := filepath.Base(constants.DefaultConfigFilename)
	v.SetConfigName(base)
	v.AddConfigPath(rootPath)
	ext, err := consoleHelpers.FileAnalyzer(configPath)
	if err != nil {
		log.Ctx(ctx).Debug().Msgf("Error analyzing config file base %s at %s", base, configPath)
		return configParams, err
	}
	v.SetConfigType(ext)
	if err := v.ReadInConfig(); err != nil {
		log.Ctx(ctx).Debug().Msgf("Error reading config file base %s at %s", base, configPath)
		return configParams, err
	}

	if v.Get("exclude-categories") != nil {
		configParams.ExcludeCategories = v.GetStringSlice("exclude-categories")
	}
	if v.Get("exclude-paths") != nil {
		configParams.ExcludePaths = v.GetStringSlice("exclude-paths")
	}
	if v.Get("exclude-queries") != nil {
		configParams.ExcludeQueries = v.GetStringSlice("exclude-queries")
	}
	if v.Get("exclude-results") != nil {
		configParams.ExcludeResults = v.GetStringSlice("exclude-results")
	}
	if v.Get("exclude-severities") != nil {
		configParams.ExcludeSeverities = v.GetStringSlice("exclude-severities")
	}
	if v.Get("include-queries") != nil {
		configParams.IncludeQueries = v.GetStringSlice("include-queries")
	}

	return configParams, nil
}

func initializeConfig(ctx context.Context, rootPath string) (ConfigParameters, context.Context, error) {
	var logCtx context.Context
	baseLogger := log.Logger
	logCtx = baseLogger.WithContext(ctx)

	baseLogger.Debug().Msg("console.initializeConfig()")

	configParams, err := ReadConfiguration(ctx, rootPath)

	return *configParams, logCtx, err
}
