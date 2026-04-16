package scan

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/rs/zerolog/log"
)

func initializeConfig(ctx context.Context, rootPath string) (*config.IacConfig, context.Context, error) {
	var logCtx context.Context
	baseLogger := log.Logger
	logCtx = baseLogger.WithContext(ctx)

	baseLogger.Debug().Msg("console.initializeConfig()")

	configParams, err := config.ReadConfiguration(ctx, rootPath)

	return configParams, logCtx, err
}
