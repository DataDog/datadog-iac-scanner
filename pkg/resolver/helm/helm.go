package helm

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/pkg/errors"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/release"
)

// credit: https://github.com/helm/helm

var (
	settings = cli.New()
)

func runInstall(ctx context.Context, args []string, client *action.Install,
	valueOpts *values.Options) (*release.Release, []string, error) {
	contextLogger := logger.FromContext(ctx)
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	contextLogger.Debug().Msgf("Starting helm install process with args: %v", args)

	if client.Version == "" && client.Devel {
		client.Version = ">0.0.0-0"
		contextLogger.Debug().Msg("Set development version for helm client")
	}

	name, charts, err := client.NameAndChart(args)
	if err != nil {
		contextLogger.Error().Msgf("failed to parse chart name and path from args %v: %s", args, err)
		return nil, []string{}, err
	}
	contextLogger.Debug().Msgf("Parsed chart name: '%s', chart path: '%s'", name, charts)
	client.ReleaseName = name

	cp, err := client.LocateChart(charts, settings)
	if err != nil {
		contextLogger.Error().Msgf("failed to locate chart '%s': %s", charts, err)
		return nil, []string{}, err
	}
	contextLogger.Debug().Msgf("Located chart at path: '%s'", cp)

	p := getter.All(settings)
	vals, err := valueOpts.MergeValues(p)
	if err != nil {
		contextLogger.Error().Msgf("failed to merge helm values: %s", err)
		return nil, []string{}, err
	}
	contextLogger.Debug().Msgf("Merged helm values successfully, values count: %d", len(vals))

	// Check chart dependencies to make sure all are present in /charts
	contextLogger.Debug().Msgf("Loading chart from path: '%s'", cp)
	chartRequested, err := loader.Load(cp)
	if err != nil {
		contextLogger.Error().Msgf("failed to load chart from '%s': %s", cp, err)
		return nil, []string{}, err
	}

	excluded := getExcluded(ctx, chartRequested, cp)

	chartRequested = setID(chartRequested)

	if instErr := checkIfInstallable(chartRequested); instErr != nil {
		contextLogger.Error().Msgf("chart is not installable: %s", instErr)
		return nil, []string{}, instErr
	}
	contextLogger.Debug().Msg("Chart installability check passed")

	client.Namespace = "kics-namespace"
	contextLogger.Debug().Msgf("Running helm chart with namespace: '%s', release name: '%s'", client.Namespace, client.ReleaseName)
	helmRelease, err := client.Run(chartRequested, vals)
	if err != nil {
		contextLogger.Error().Msgf("failed to run helm chart '%s': %s", chartRequested.Metadata.Name, err)
		return nil, []string{}, err
	}

	contextLogger.Debug().Msgf("Successfully rendered helm chart '%s', manifest length: %d bytes",
		chartRequested.Metadata.Name, len(helmRelease.Manifest))
	return helmRelease, excluded, nil
}

// checkIfInstallable validates if a chart can be installed
//
// Application chart type is only installable
func checkIfInstallable(ch *chart.Chart) error {
	switch ch.Metadata.Type {
	case "", "application":
		return nil
	}
	return errors.Errorf("%s charts are not installable (only 'application' type charts are supported)", ch.Metadata.Type)
}

// newClient will create a new instance on helm client used to render the chart
func newClient(ctx context.Context) *action.Install {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("Creating new helm client for chart rendering")

	cfg := new(action.Configuration)
	client := action.NewInstall(cfg)
	client.DryRun = true
	client.ReleaseName = "kics-helm"
	client.Replace = true // Skip the name check
	client.ClientOnly = true
	client.APIVersions = chartutil.VersionSet([]string{})
	client.IncludeCRDs = false

	contextLogger.Debug().Msgf("Configured helm client - DryRun: %t, ClientOnly: %t, IncludeCRDs: %t, ReleaseName: '%s'",
		client.DryRun, client.ClientOnly, client.IncludeCRDs, client.ReleaseName)

	return client
}

// setID will add auxiliary lines for each template as well as its dependencies
func setID(chartReq *chart.Chart) *chart.Chart {
	for _, temp := range chartReq.Templates {
		temp = addID(temp)
		if temp != nil {
			continue
		}
	}
	for _, dep := range chartReq.Dependencies() {
		dep = setID(dep)
		if dep != nil {
			continue
		}
	}
	return chartReq
}

// addID will add auxiliary lines used to detect line
// one for each "apiVersion:" where the id will be the line
func addID(file *chart.File) *chart.File {
	split := strings.Split(string(file.Data), "\n")
	for i := 0; i < len(split); i++ {
		if strings.Contains(split[i], "apiVersion:") {
			split = append(split, "")
			copy(split[i+1:], split[i:])
			split[i] = fmt.Sprintf("# KICS_HELM_ID_%d:", i)
			i++
		}
	}
	file.Data = []byte(strings.Join(split, "\n"))
	return file
}

// getExcluded will return all files rendered to be excluded from scan
func getExcluded(ctx context.Context, charterino *chart.Chart, chartpath string) []string {
	contextLogger := logger.FromContext(ctx)
	excluded := make([]string, 0)
	for _, file := range charterino.Raw {
		excluded = append(excluded, filepath.Join(chartpath, file.Name))
	}

	contextLogger.Debug().Msgf("Found %d excluded files from chart", len(excluded))
	return excluded
}
