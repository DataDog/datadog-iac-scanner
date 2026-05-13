package scan

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/rs/zerolog/log"
)

func initializeConfig(ctx context.Context, rootPath string) (*config.IacConfig, context.Context, error) {
	var logCtx context.Context
	baseLogger := log.Logger
	logCtx = baseLogger.WithContext(ctx)

	baseLogger.Debug().Msg("console.initializeConfig()")

	configParams, _, err := config.ReadConfiguration(ctx, rootPath, configurationOptions(rootPath)...)

	return configParams, logCtx, err
}

// configurationOptions returns the ReadConfigurationOptions applied to every scan
// performed via the library entrypoint. Remote configuration is fetched when a git
// `origin` remote is resolvable for rootPath; otherwise only the local
// configuration is used.
func configurationOptions(rootPath string) []config.ReadConfigurationOption {
	repoURL := lookupRepositoryURL(rootPath)
	if repoURL == "" {
		return nil
	}
	return []config.ReadConfigurationOption{
		bestEffortDatadog(datadog.NewDatadogClient(), repoURL),
	}
}

// bestEffortDatadog wraps config.WithDatadog so that a failure to fetch the
// remote configuration is logged and the local configuration is preserved.
// Transient Datadog API issues must not break the scan for library callers.
func bestEffortDatadog(client datadog.Client, repoURL string) config.ReadConfigurationOption {
	inner := config.WithDatadog(client, repoURL)
	return func(ctx context.Context, cfgBytes []byte) ([]byte, error) {
		out, err := inner(ctx, cfgBytes)
		if err != nil {
			log.Ctx(ctx).Warn().Err(err).Msg("could not fetch remote configuration from Datadog; using local configuration only")
			return cfgBytes, nil
		}
		return out, nil
	}
}
