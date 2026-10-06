package helm

import (
	"context"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
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
const helmIDNumberBase = 10

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
	valueOpts *values.Options) (*release.Release, *chart.Chart, []string, error) {
	contextLogger := logger.FromContext(ctx)
	defer silenceStdLog()()

	contextLogger.Debug().Msgf("Starting helm install process for chart path: %s", chartPath)

	// The release name is fixed in newClient and the chart path is local, so
	// LocateChart's disk stat and repository resolution is unnecessary.

	p := getter.All(settings)
	vals, err := valueOpts.MergeValues(p)
	if err != nil {
		return nil, nil, []string{}, err
	}
	contextLogger.Debug().Msgf("Merged helm values successfully, values count: %d", len(vals))

	// Check chart dependencies to make sure all are present in /charts
	contextLogger.Debug().Msgf("Loading chart from path: '%s'", chartPath)
	chartRequested, err := loadChart(ctx, fsys, chartPath)
	if err != nil {
		return nil, nil, []string{}, err
	}

	// Set KubeVersion; clear the constraint only when unsatisfiable.
	kubeVersion, dropConstraint := resolveChartKubeVersion(chartKubeVersionConstraint(chartRequested))
	client.KubeVersion = kubeVersion
	if dropConstraint && chartRequested.Metadata != nil {
		chartRequested.Metadata.KubeVersion = ""
	}

	excluded := getExcluded(ctx, chartRequested, chartPath)

	chartRequested = makeDeterministic(chartRequested)
	chartRequested = setID(chartRequested)

	if instErr := checkIfInstallable(chartRequested); instErr != nil {
		return nil, nil, []string{}, instErr
	}
	contextLogger.Debug().Msg("Chart installability check passed")

	client.Namespace = "dd-namespace"
	contextLogger.Debug().Msgf("Running helm chart with namespace: '%s', release name: '%s'", client.Namespace, client.ReleaseName)
	helmRelease, err := client.Run(chartRequested, vals)
	if err != nil {
		return nil, nil, []string{}, err
	}

	contextLogger.Debug().Msgf("Successfully rendered helm chart '%s', manifest length: %d bytes",
		chartRequested.Metadata.Name, len(helmRelease.Manifest))
	return helmRelease, chartRequested, excluded, nil
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

// setID will add auxiliary lines for each template as well as its dependencies
func setID(chartReq *chart.Chart) *chart.Chart {
	for _, temp := range chartReq.Templates {
		addHelmInvocationMarkers(addID(temp))
	}
	// Stamp YAML CRDs for line mapping; JSON CRDs are skipped (YAML comments corrupt JSON).
	for _, f := range localCRDFiles(chartReq) {
		if isYAMLCRD(f.Name) {
			addID(f)
		}
	}
	for _, dep := range chartReq.Dependencies() {
		setID(dep)
	}
	return chartReq
}

// addHelmInvocationMarkers instruments manifest templates so the rendered
// output retains the source position of the invocation that actually ran, which
// is what lets a finding in output produced by a named template point back to
// the file that invoked it. The marker action is inserted immediately before
// include/template/tpl, which keeps it under the same Helm control flow as the
// invocation.
//
// Two kinds of invocation are instrumented, and nothing else:
//   - any top-level invocation of an action-only wrapper template, whose whole
//     output is the output of its invocations;
//   - in other manifest templates, an invocation that stands alone on its line
//     and is not left-trimmed, which can only emit a block of YAML. Inline
//     uses (`name: {{ include ... }}`) and trimmed ones (`{{- include ... }}`)
//     produce values glued to the surrounding text and are left alone.
//
// The body of a define or block is never instrumented: it is a named partial
// whose result is used by its callers, often as a scalar (a label value, a
// name), so anything added there would corrupt every value the partial returns.
// Files that only hold partials (a leading underscore) are skipped for the same
// reason.
func addHelmInvocationMarkers(file *chart.File) *chart.File {
	source := string(file.Data)
	if strings.Contains(source, kicsHelmInvocation) {
		return file
	}
	wrapper := isHelmInvocationWrapper(source)
	if !wrapper && strings.HasPrefix(filepath.Base(file.Name), "_") {
		return file
	}

	var markers []replacement
	var blocks helmBlockStack
	for _, span := range balancedTemplateActionSpans(source) {
		actionText := strings.Trim(source[span[0]+len("{{"):span[1]-len("}}")], "- \t\r\n")
		fields := strings.Fields(actionText)
		if len(fields) == 0 {
			continue
		}
		if blocks.track(fields[0]) || blocks.inPartial() || !isHelmOutputInvocation(fields[0]) {
			continue
		}

		line := strings.Count(source[:span[0]], "\n") + 1
		lineStart := strings.LastIndexByte(source[:span[0]], '\n') + 1
		col := span[0] - lineStart
		marker := invocationMarker(line, col)
		if r, ok := invocationReplacement(source, span, actionText, marker, wrapper); ok {
			markers = append(markers, r)
		}
	}

	sort.Slice(markers, func(i, j int) bool {
		return markers[i].start > markers[j].start
	})
	for _, marker := range markers {
		source = source[:marker.start] + marker.text + source[marker.end:]
	}
	file.Data = []byte(source)
	return file
}

// invocationMarker is the comment line recording the source position of an
// include-like action in its rendered output.
func invocationMarker(line, col int) string {
	return fmt.Sprintf("%s%d_%d:\n", kicsHelmInvocation, line, col)
}

// invocationReplacement builds the marker edit for one include-like action.
func invocationReplacement(source string, span [2]int, actionText, marker string, wrapper bool) (replacement, bool) {
	prefix := fmt.Sprintf("{{ print %q }}", marker)
	plain := replacement{start: span[0], end: span[0], text: prefix}
	if !wrapper {
		// Emitted before the line's indentation so the include output keeps it.
		lineStart := strings.LastIndexByte(source[:span[0]], '\n') + 1
		plain.start, plain.end = lineStart, lineStart
		return plain, standaloneUntrimmedAction(source, span)
	}
	// markEveryDocument rewrites the action, and the rewrite is later
	// stripped/restored with the lazy templateActionRE, which stops at the
	// first "}}" — including one inside a quoted argument. Only rewrite
	// actions the lazy regex spans identically; a quoted "}}" falls back to
	// the self-contained prefix marker, which the lazy regex strips whole.
	lazy := templateActionRE.FindStringIndex(source[span[0]:])
	if strings.HasPrefix(actionText, helmInclude) && !strings.Contains(actionText, "|") &&
		lazy != nil && span[0]+lazy[1] == span[1] {
		return replacement{
			start: span[0],
			end:   span[1],
			text:  prefix + markEveryDocument(source[span[0]:span[1]], marker),
		}, true
	}
	return plain, true
}

// standaloneUntrimmedAction reports whether the action at span is alone on its
// line and does not trim the whitespace before it.
func standaloneUntrimmedAction(source string, span [2]int) bool {
	if strings.HasPrefix(source[span[0]:], "{{-") {
		return false
	}
	lineStart := strings.LastIndexByte(source[:span[0]], '\n') + 1
	lineEnd := len(source)
	if i := strings.IndexByte(source[span[1]:], '\n'); i >= 0 {
		lineEnd = span[1] + i
	}
	return strings.TrimSpace(source[lineStart:span[0]]) == "" &&
		strings.TrimSpace(source[span[1]:lineEnd]) == "" &&
		!insideBlockScalar(source[:lineStart])
}

var blockScalarHeader = regexp.MustCompile(`[|>][+-]?\d?[+-]?\s*$`)

// insideBlockScalar reports whether the text before an action may belong to a
// YAML block scalar: walking back over indented lines reaches a "|" or ">"
// header. A column-0 marker line would terminate such a scalar, so these
// actions are left uninstrumented.
func insideBlockScalar(before string) bool {
	lines := strings.Split(before, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimRight(removeBalancedActions(lines[i]), " \t\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if blockScalarHeader.MatchString(line) {
			return true
		}
		if line[0] != ' ' && line[0] != '\t' {
			return false
		}
	}
	return false
}

// helmBlockStack follows the control-flow blocks opened by template actions so
// an action can be told apart as top-level output or part of a define body.
type helmBlockStack []bool

// track updates the stack for an action starting with keyword and reports
// whether the action only opens or closes a block.
func (b *helmBlockStack) track(keyword string) bool {
	switch keyword {
	case "define", "block":
		*b = append(*b, true)
	case "if", "range", "with":
		*b = append(*b, false)
	case "end":
		if len(*b) > 0 {
			*b = (*b)[:len(*b)-1]
		}
	default:
		return false
	}
	return true
}

// inPartial reports whether the current action sits inside a define or block.
func (b helmBlockStack) inPartial() bool {
	for _, partial := range b {
		if partial {
			return true
		}
	}
	return false
}

// markedIncludeRE matches an include rewritten by markEveryDocument and
// captures what restoreMarkedInclude needs to give back the original action.
var markedIncludeRE = regexp.MustCompile(
	`(?s)^\{\{(-?) print "\\n" \((.*)\) \| replace "\\n---\\n" "\\n---\\n` +
		regexp.QuoteMeta(kicsHelmInvocation) + `\d+_\d+:\\n" (-?)\}\}$`)

// markEveryDocument makes an include repeat marker after each document
// separator it emits. Helm splits and sorts every template's documents before
// the resolver sees them, so a marker printed only ahead of the include never
// reaches documents after the first separator.
func markEveryDocument(templateAction, marker string) string {
	inner := templateAction[len("{{") : len(templateAction)-len("}}")]
	left, right := "", ""
	if strings.HasPrefix(inner, "-") {
		left, inner = "-", inner[1:]
	}
	if strings.HasSuffix(inner, "-") {
		right, inner = "-", inner[:len(inner)-1]
	}
	return fmt.Sprintf(`{{%s print "\n" (%s) | replace "\n---\n" %q %s}}`, left, inner, "\n---\n"+marker, right)
}

func restoreMarkedInclude(templateAction []byte) ([]byte, bool) {
	m := markedIncludeRE.FindSubmatch(templateAction)
	if m == nil {
		return nil, false
	}
	return []byte("{{" + string(m[1]) + string(m[2]) + string(m[3]) + "}}"), true
}

func isHelmInvocationWrapper(source string) bool {
	// Balanced action removal: the lazy regex would leave a quoted "}}" as
	// residue and disqualify a wrapper template that is in fact action-only.
	withoutActions := removeBalancedActions(source)
	for _, line := range strings.Split(withoutActions, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !isYAMLDocumentBoundary(trimmed) {
			return false
		}
	}
	return true
}

const helmInclude = "include"

func isHelmOutputInvocation(name string) bool {
	return name == helmInclude || name == "template" || name == "tpl"
}

// addID will add auxiliary lines used to detect line
// one for each top-level "apiVersion:" where the id is the source line index.
func addID(file *chart.File) *chart.File {
	split := strings.Split(string(file.Data), "\n")
	apiVersionLines := topLevelAPIVersionLines(split, isYAMLCRD(file.Name))

	stamped := make([]byte, 0, len(file.Data)+len(apiVersionLines)*24)
	nextAPIVersion := 0
	for i, line := range split {
		if nextAPIVersion < len(apiVersionLines) && apiVersionLines[nextAPIVersion] == i {
			stamped = append(stamped, "# KICS_HELM_ID_"...)
			stamped = strconv.AppendInt(stamped, int64(i), helmIDNumberBase)
			stamped = append(stamped, ':', '\n')
			nextAPIVersion++
		}
		stamped = append(stamped, line...)
		if i+1 < len(split) {
			stamped = append(stamped, '\n')
		}
	}
	file.Data = stamped
	return file
}

func topLevelAPIVersionLines(lines []string, exhaustive bool) []int {
	var result []int
	for documentStart := 0; documentStart < len(lines); {
		documentEnd := documentStart
		for documentEnd < len(lines) && !isYAMLDocumentBoundary(lines[documentEnd]) {
			documentEnd++
		}
		result = appendDocumentAPIVersionLine(result, lines, documentStart, documentEnd, exhaustive)

		documentStart = documentEnd + 1
		if documentEnd == len(lines) {
			break
		}
	}
	return result
}

func appendDocumentAPIVersionLine(
	result []int, lines []string, documentStart, documentEnd int, exhaustive bool,
) []int {
	minIndent := -1
	for lineNumber := documentStart; lineNumber < documentEnd; lineNumber++ {
		line := lines[lineNumber]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "%") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if minIndent < 0 || indent < minIndent {
			minIndent = indent
		}
	}

	resultStart := len(result)
	mayNeedFallback := false
	for lineNumber := documentStart; lineNumber < documentEnd; lineNumber++ {
		line := lines[lineNumber]
		mayNeedFallback = mayNeedFallback || strings.Contains(line, "apiVersion")
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == minIndent && isAPIVersionKey(line[indent:]) {
			result = append(result, lineNumber)
		}
	}
	if len(result) == resultStart && (exhaustive || mayNeedFallback) {
		if lineNumber, ok := parsedAPIVersionLine(lines[documentStart:documentEnd]); ok {
			result = append(result, documentStart+lineNumber)
		}
	}
	return result
}

func parsedAPIVersionLine(lines []string) (int, bool) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(strings.Join(lines, "\n")), &document); err != nil ||
		len(document.Content) == 0 {
		return 0, false
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return 0, false
	}
	for index := 0; index+1 < len(root.Content); index += 2 {
		key := root.Content[index]
		if key.Value == "apiVersion" {
			return key.Line - 1, true
		}
	}
	return 0, false
}

func isYAMLDocumentBoundary(line string) bool {
	line = strings.TrimRight(line, " \t\r")
	if len(line) < 3 || (line[:3] != "---" && line[:3] != "...") {
		return false
	}
	return len(line) == 3 || strings.HasPrefix(strings.TrimSpace(line[3:]), "#")
}

func isAPIVersionKey(line string) bool {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "{") {
		line = strings.TrimSpace(line[1:])
	}
	explicitKey := strings.HasPrefix(line, "?")
	if explicitKey {
		line = strings.TrimSpace(line[1:])
	}

	var remainder string
	switch {
	case strings.HasPrefix(line, "'apiVersion'"):
		remainder = line[len("'apiVersion'"):]
	case strings.HasPrefix(line, `"apiVersion"`):
		remainder = line[len(`"apiVersion"`):]
	case strings.HasPrefix(line, "apiVersion"):
		remainder = line[len("apiVersion"):]
	default:
		return false
	}
	remainder = strings.TrimSpace(remainder)
	if explicitKey {
		return remainder == "" || strings.HasPrefix(remainder, "#")
	}
	return strings.HasPrefix(remainder, ":")
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
