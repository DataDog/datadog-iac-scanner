package helm

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

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

// Fixed dry-run cluster version for Helm scan rendering.
const defaultDryRunKubeVersion = "v1.30.0"

// Search bounds when the default does not satisfy a chart's kubeVersion.
const (
	maxCandidateMinor = 40
	minCandidateMinor = 0
	maxCandidatePatch = 30
)

var (
	settings = cli.New()

	kubeVersionOnce   sync.Once
	cachedKubeVersion *chartutil.KubeVersion
)

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
		return nil, []string{}, err
	}
	contextLogger.Debug().Msgf("Parsed chart name: '%s', chart path: '%s'", name, charts)
	client.ReleaseName = name

	cp, err := client.LocateChart(charts, settings)
	if err != nil {
		return nil, []string{}, err
	}
	contextLogger.Debug().Msgf("Located chart at path: '%s'", cp)

	p := getter.All(settings)
	vals, err := valueOpts.MergeValues(p)
	if err != nil {
		return nil, []string{}, err
	}
	contextLogger.Debug().Msgf("Merged helm values successfully, values count: %d", len(vals))

	// Check chart dependencies to make sure all are present in /charts
	contextLogger.Debug().Msgf("Loading chart from path: '%s'", cp)
	chartRequested, err := loader.Load(cp)
	if err != nil {
		return nil, []string{}, err
	}

	// Set KubeVersion; clear the constraint only when unsatisfiable.
	kubeVersion, dropConstraint := resolveChartKubeVersion(chartKubeVersionConstraint(chartRequested))
	client.KubeVersion = kubeVersion
	if dropConstraint && chartRequested.Metadata != nil {
		chartRequested.Metadata.KubeVersion = ""
	}

	excluded := getExcluded(ctx, chartRequested, cp)

	chartRequested = makeDeterministic(chartRequested)
	chartRequested = setID(chartRequested)

	if instErr := checkIfInstallable(chartRequested); instErr != nil {
		return nil, []string{}, instErr
	}
	contextLogger.Debug().Msg("Chart installability check passed")

	client.Namespace = "dd-namespace"
	contextLogger.Debug().Msgf("Running helm chart with namespace: '%s', release name: '%s'", client.Namespace, client.ReleaseName)
	helmRelease, err := client.Run(chartRequested, vals)
	if err != nil {
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
	client.ReleaseName = "dd-helm"
	client.Replace = true // Skip the name check
	client.ClientOnly = true
	client.APIVersions = chartutil.VersionSet([]string{})
	client.IncludeCRDs = false

	contextLogger.Debug().Msgf("Configured helm client - DryRun: %t, ClientOnly: %t, IncludeCRDs: %t, ReleaseName: '%s'",
		client.DryRun, client.ClientOnly, client.IncludeCRDs, client.ReleaseName)

	return client
}

// deterministicPatterns maps each non-deterministic sprig function regex to a replacement generator.
// The generator receives the line number of the match.
var deterministicPatterns = []struct {
	re      *regexp.Regexp
	replace func(lineNum int) string
}{
	{
		re:      regexp.MustCompile(`\brandAlphaNum\s+\d+`),
		replace: func(lineNum int) string { return fmt.Sprintf(`"ddscan%04d"`, lineNum) },
	},
	{
		re:      regexp.MustCompile(`\brandAlpha\s+\d+`),
		replace: func(lineNum int) string { return fmt.Sprintf(`"ddscan%04d"`, lineNum) },
	},
	{
		re:      regexp.MustCompile(`\brandAscii\s+\d+`),
		replace: func(lineNum int) string { return fmt.Sprintf(`"ddscan%04d"`, lineNum) },
	},
	{
		re:      regexp.MustCompile(`\brandNumeric\s+\d+`),
		replace: func(lineNum int) string { return fmt.Sprintf(`"%08d"`, lineNum) },
	},
	{
		re:      regexp.MustCompile(`\buuidv4\b`),
		replace: func(lineNum int) string { return fmt.Sprintf(`"00000000-0000-0000-%04d-%012d"`, lineNum, lineNum) },
	},
	{
		re:      regexp.MustCompile(`\bnow\b`),
		replace: func(_ int) string { return `(toDate "2006-01-02" "2000-01-01")` },
	},
}

// replacement is a single pending substitution collected before applying back-to-front.
type replacement struct {
	start int
	end   int
	text  string
}

// applyDeterministicSubstitutions replaces non-deterministic sprig function calls in a Helm
// template with stable, line-number-seeded stubs so that repeated renders produce identical output.
func applyDeterministicSubstitutions(data []byte) []byte {
	s := string(data)
	var replacements []replacement

	for _, p := range deterministicPatterns {
		matches := p.re.FindAllStringIndex(s, -1)
		for _, m := range matches {
			lineNum := strings.Count(s[:m[0]], "\n") + 1
			replacements = append(replacements, replacement{
				start: m[0],
				end:   m[1],
				text:  p.replace(lineNum),
			})
		}
	}

	// Apply back-to-front so earlier offsets remain valid.
	sort.Slice(replacements, func(i, j int) bool {
		return replacements[i].start > replacements[j].start
	})

	b := []byte(s)
	for _, r := range replacements {
		b = append(b[:r.start], append([]byte(r.text), b[r.end:]...)...)
	}
	return b
}

// makeDeterministic replaces all non-deterministic sprig calls in every template of the chart
// and its dependencies, making repeated renders produce identical manifests.
func makeDeterministic(ch *chart.Chart) *chart.Chart {
	for _, temp := range ch.Templates {
		temp.Data = applyDeterministicSubstitutions(temp.Data)
	}
	for _, dep := range ch.Dependencies() {
		makeDeterministic(dep)
	}
	return ch
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
