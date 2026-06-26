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

// templateActionRE matches Helm/Go template action delimiters including trim markers.
var templateActionRE = regexp.MustCompile(`(?s)\{\{-?.*?-?\}\}`)

// templateActionSpans returns the [start, end) byte ranges of all {{ ... }} blocks in s.
// The returned slice is sorted by start (FindAllStringIndex guarantees this).
func templateActionSpans(s string) [][2]int {
	matches := templateActionRE.FindAllStringIndex(s, -1)
	spans := make([][2]int, len(matches))
	for i, m := range matches {
		spans[i] = [2]int{m[0], m[1]}
	}
	return spans
}

// inAnySpan reports whether pos falls within any of the sorted, non-overlapping spans.
func inAnySpan(pos int, spans [][2]int) bool {
	// Binary search for the last span with start <= pos.
	lo, hi := 0, len(spans)
	for lo < hi {
		mid := (lo + hi) / 2
		if spans[mid][0] <= pos {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return false
	}
	span := spans[lo-1]
	return pos < span[1]
}

// notPrecededByVarOrField rejects matches that are variable references ($name) or
// field accesses (.field). Quoted-string detection is handled separately by
// insideQuotedStringInSpan, which is more accurate than a single-byte check.
func notPrecededByVarOrField(s string, pos int) bool {
	if pos == 0 {
		return true
	}
	prev := s[pos-1]
	return prev != '$' && prev != '.'
}

// insideQuotedStringInSpan reports whether pos is inside a Go template string literal
// within the action span that contains it. It counts unescaped double-quotes from the
// span's opening {{ to pos; an odd count means we are inside a string.
func insideQuotedStringInSpan(s string, pos int, spans [][2]int) bool {
	lo, hi := 0, len(spans)
	for lo < hi {
		mid := (lo + hi) / 2
		if spans[mid][0] <= pos {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return false
	}
	span := spans[lo-1]
	if pos >= span[1] {
		return false
	}
	text := s[span[0]:pos]
	quoteCount := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '"' && (i == 0 || text[i-1] != '\\') {
			quoteCount++
		}
	}
	return quoteCount%2 == 1
}

// deterministicPattern represents a non-deterministic sprig function to replace.
type deterministicPattern struct {
	re      *regexp.Regexp
	replace func(lineNum int) string
	// guard is an optional function that can reject a match. Returns true to accept, false to skip.
	// If nil, all matches are accepted.
	guard func(s string, matchStart int) bool
}

// deterministicPatterns maps each non-deterministic sprig function regex to a replacement generator.
// The generator receives the line number of the match.
var deterministicPatterns = []deterministicPattern{
	{
		re:      regexp.MustCompile(`\brandAlphaNum\s+\d+`),
		replace: func(lineNum int) string { return fmt.Sprintf(`"ddscan%04d"`, lineNum) },
		guard:   notPrecededByVarOrField,
	},
	{
		re:      regexp.MustCompile(`\brandAlpha\s+\d+`),
		replace: func(lineNum int) string { return fmt.Sprintf(`"ddscan%04d"`, lineNum) },
		guard:   notPrecededByVarOrField,
	},
	{
		re:      regexp.MustCompile(`\brandAscii\s+\d+`),
		replace: func(lineNum int) string { return fmt.Sprintf(`"ddscan%04d"`, lineNum) },
		guard:   notPrecededByVarOrField,
	},
	{
		re:      regexp.MustCompile(`\brandNumeric\s+\d+`),
		replace: func(lineNum int) string { return fmt.Sprintf(`"%08d"`, lineNum) },
		guard:   notPrecededByVarOrField,
	},
	{
		re:      regexp.MustCompile(`\buuidv4\b`),
		replace: func(lineNum int) string { return fmt.Sprintf(`"00000000-0000-0000-%04d-%012d"`, lineNum, lineNum) },
		guard:   notPrecededByVarOrField,
	},
	{
		re:      regexp.MustCompile(`\bnow\b`),
		replace: func(_ int) string { return `(toDate "2006-01-02" "2000-01-01")` },
		guard:   notPrecededByVarOrField,
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

	// Pre-compute the spans of all {{ ... }} action blocks so we only substitute
	// inside them, not in literal text (e.g. shell scripts in ConfigMap data).
	spans := templateActionSpans(s)

	for _, p := range deterministicPatterns {
		matches := p.re.FindAllStringIndex(s, -1)
		for _, m := range matches {
			// Only substitute inside {{ ... }} action blocks.
			if !inAnySpan(m[0], spans) {
				continue
			}

			// Skip matches inside string literals within the action (e.g. printf "...now...").
			if insideQuotedStringInSpan(s, m[0], spans) {
				continue
			}

			// Check guard if present (variable/field references).
			if p.guard != nil && !p.guard(s, m[0]) {
				continue
			}

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
