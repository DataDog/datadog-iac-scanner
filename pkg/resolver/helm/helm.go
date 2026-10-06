package helm

import (
	"context"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/pkg/errors"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/release"
)

// credit: https://github.com/helm/helm

// Fixed dry-run cluster version for Helm scan rendering.
const defaultDryRunKubeVersion = "v1.30.0"

// Search bounds when the default does not satisfy a chart's kubeVersion.
const (
	maxCandidateMinor = 40
	minCandidateMinor = 0
	maxCandidatePatch = 30

	crdDirPrefix = "crds/"
	extYAML      = ".yaml"
	extYML       = ".yml"
	extJSON      = ".json"
	crdDirName   = "crds"
)

var (
	settings = cli.New()

	kubeVersionOnce   sync.Once
	cachedKubeVersion *chartutil.KubeVersion
)

// filesystem returns the resolver's scan FS, defaulting to the real disk.
func (r *Resolver) filesystem() vfs.FS {
	if r.fsys != nil {
		return r.fsys
	}
	return vfs.Default()
}

func dryRunKubeVersion() *chartutil.KubeVersion {
	kubeVersionOnce.Do(func() {
		cachedKubeVersion, _ = chartutil.ParseKubeVersion(defaultDryRunKubeVersion)
	})
	return cachedKubeVersion
}

// resolveChartKubeVersion returns a version satisfying constraint; unsatisfiable
// means nothing in range satisfies it (caller should drop the constraint).
func resolveChartKubeVersion(constraint string) (kv *chartutil.KubeVersion, unsatisfiable bool) {
	def := dryRunKubeVersion()
	if constraint == "" || chartutil.IsCompatibleRange(constraint, def.Version) {
		return def, false
	}
	defMinor, _ := strconv.Atoi(def.Minor)
	// Walk minors outward from the default, probing all patch levels per minor.
	minors := []int{defMinor}
	for d := 1; d <= maxCandidateMinor+1; d++ {
		for _, minor := range minors {
			if minor < minCandidateMinor || minor > maxCandidateMinor {
				continue
			}
			for patch := 0; patch <= maxCandidatePatch; patch++ {
				candidate := fmt.Sprintf("v1.%d.%d", minor, patch)
				if candidate == def.Version {
					continue // already checked at the top
				}
				if chartutil.IsCompatibleRange(constraint, candidate) {
					if kv, err := chartutil.ParseKubeVersion(candidate); err == nil {
						return kv, false
					}
				}
			}
		}
		minors = []int{defMinor - d, defMinor + d}
	}
	return def, true
}

func chartKubeVersionConstraint(ch *chart.Chart) string {
	if ch == nil || ch.Metadata == nil {
		return ""
	}
	return ch.Metadata.KubeVersion
}

var (
	stdLogMu      sync.Mutex
	stdLogSilence int
	stdLogOutput  io.Writer
)

// silenceStdLog discards the standard logger, which Helm writes render noise
// to, until the returned func runs. Charts render concurrently, so the logger
// is restored only when the last render ends, to the output it had before.
func silenceStdLog() func() {
	stdLogMu.Lock()
	defer stdLogMu.Unlock()
	if stdLogSilence == 0 {
		stdLogOutput = log.Writer()
		log.SetOutput(io.Discard)
	}
	stdLogSilence++
	return func() {
		stdLogMu.Lock()
		defer stdLogMu.Unlock()
		stdLogSilence--
		if stdLogSilence == 0 {
			log.SetOutput(stdLogOutput)
		}
	}
}

func runInstall(ctx context.Context, chartPath string, fsys vfs.FS, client *action.Install,
	valueOpts *values.Options, markInvocations bool) (*release.Release, *chart.Chart, stampedSources, []string, error) {
	contextLogger := logger.FromContext(ctx)
	defer silenceStdLog()()

	contextLogger.Debug().Msgf("Starting helm install process for chart path: %s", chartPath)

	// The release name is fixed in newClient and the chart path is local, so
	// LocateChart's disk stat and repository resolution is unnecessary.

	p := getter.All(settings)
	vals, err := valueOpts.MergeValues(p)
	if err != nil {
		return nil, nil, nil, []string{}, err
	}
	contextLogger.Debug().Msgf("Merged helm values successfully, values count: %d", len(vals))

	// Check chart dependencies to make sure all are present in /charts
	contextLogger.Debug().Msgf("Loading chart from path: '%s'", chartPath)
	chartRequested, err := loadChart(ctx, fsys, chartPath)
	if err != nil {
		return nil, nil, nil, []string{}, err
	}

	// Set KubeVersion; clear the constraint only when unsatisfiable.
	kubeVersion, dropConstraint := resolveChartKubeVersion(chartKubeVersionConstraint(chartRequested))
	client.KubeVersion = kubeVersion
	if dropConstraint && chartRequested.Metadata != nil {
		chartRequested.Metadata.KubeVersion = ""
	}

	excluded := getExcluded(ctx, chartRequested, chartPath)

	chartRequested = makeDeterministic(chartRequested)
	sources := setID(chartRequested, markInvocations)

	if instErr := checkIfInstallable(chartRequested); instErr != nil {
		return nil, nil, nil, []string{}, instErr
	}
	contextLogger.Debug().Msg("Chart installability check passed")

	client.Namespace = "dd-namespace"
	contextLogger.Debug().Msgf("Running helm chart with namespace: '%s', release name: '%s'", client.Namespace, client.ReleaseName)
	helmRelease, err := client.Run(chartRequested, vals)
	if err != nil {
		return nil, nil, nil, []string{}, err
	}

	contextLogger.Debug().Msgf("Successfully rendered helm chart '%s', manifest length: %d bytes",
		chartRequested.Metadata.Name, len(helmRelease.Manifest))
	return helmRelease, chartRequested, sources, excluded, nil
}

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
	client.ReleaseName = "dd-helm"
	client.Replace = true // Skip the name check
	client.ClientOnly = true
	client.APIVersions = chartutil.VersionSet([]string{})
	client.IncludeCRDs = true

	contextLogger.Debug().Msgf("Configured helm client - DryRun: %t, ClientOnly: %t, IncludeCRDs: %t, ReleaseName: '%s'",
		client.DryRun, client.ClientOnly, client.IncludeCRDs, client.ReleaseName)

	return client
}

// normalizeChartPath converts a chart file path to forward-slash form.
func normalizeChartPath(name string) string {
	return strings.ReplaceAll(filepath.ToSlash(name), "\\", "/")
}

// isCRDManifest reports whether a chart file is a CRD manifest under crds/.
func isCRDManifest(name string) bool {
	name = normalizeChartPath(name)
	ext := strings.ToLower(filepath.Ext(name))
	if ext != extYAML && ext != extYML && ext != extJSON {
		return false
	}
	return strings.HasPrefix(name, crdDirPrefix)
}

// isYAMLCRD reports whether a raw chart file is a YAML CRD. JSON is excluded
// because addID stamps files with YAML comments that would corrupt JSON content.
func isYAMLCRD(name string) bool {
	name = normalizeChartPath(name)
	ext := strings.ToLower(filepath.Ext(name))
	if ext != extYAML && ext != extYML {
		return false
	}
	return strings.HasPrefix(name, crdDirPrefix)
}

// crdChartRelativePath returns the chart-relative crds/ path for a CRD file name.
func crdChartRelativePath(name string) string {
	name = normalizeChartPath(name)
	if strings.HasPrefix(name, crdDirPrefix) {
		return name
	}
	if idx := strings.Index(name, "/crds/"); idx >= 0 {
		return name[idx+1:]
	}
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if part == crdDirName && i+1 < len(parts) {
			return strings.Join(parts[i:], "/")
		}
	}
	return name
}

// resolvedChartFilePath maps a chart-relative path to a path beside chartPath.
// slashPaths forces forward slashes, so a pushed chart's findings match the
// pushed path shape on every platform; otherwise (the CLI on disk) the OS
// separator is kept.
func resolvedChartFilePath(chartPath, chartRelative string, slashPaths bool) string {
	subFolder := filepath.Base(chartPath)
	joined := filepath.Join(filepath.Dir(chartPath), subFolder, filepath.FromSlash(chartRelative))
	if slashPaths {
		joined = filepath.ToSlash(joined)
	}
	return joined
}

func localCRDFiles(ch *chart.Chart) []*chart.File {
	if ch == nil {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]*chart.File, 0)
	add := func(f *chart.File) {
		if f == nil || !isCRDManifest(f.Name) {
			return
		}
		key := chartSourceKey(crdChartRelativePath(f.Name))
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	for _, f := range ch.Files {
		add(f)
	}
	return out
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
