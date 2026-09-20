package helm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
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
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/ignore"
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

func runInstall(ctx context.Context, chartPath string, fsys vfs.FS, client *action.Install,
	valueOpts *values.Options) (*release.Release, *chart.Chart, []string, error) {
	contextLogger := logger.FromContext(ctx)
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

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
	chartRequested, err := loadChart(fsys, chartPath)
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

// loadChart loads the chart at dir from the scan FS. The real disk keeps
// helm's own directory loader (symlink and .helmignore semantics unchanged
// from the CLI); any other FS (the server's in-memory one) is walked via the
// vfs and assembled with helm's in-memory loader.
func loadChart(fsys vfs.FS, dir string) (*chart.Chart, error) {
	if _, ok := fsys.(vfs.DiskFS); ok {
		return loader.LoadDir(dir)
	}
	return loadChartFromFS(fsys, dir)
}

// utf8bom mirrors loader's BOM handling for files read through the vfs.
var utf8bom = []byte{0xEF, 0xBB, 0xBF}

// loadChartFromFS mirrors loader.LoadDir over the scan FS: .helmignore rules,
// regular files only, each capped at helm's MaxDecompressedFileSize, then
// loader.LoadFiles (the same in-memory entry point LoadDir feeds).
func loadChartFromFS(fsys vfs.FS, dir string) (*chart.Chart, error) {
	rules := ignore.Empty()
	// Stat first so a missing .helmignore is not recorded as a missing file by
	// an in-memory FS (it would become a pointless escalation request).
	if _, err := fsys.Stat(filepath.Join(dir, ignore.HelmIgnore)); err == nil {
		data, err := fsys.ReadFile(filepath.Join(dir, ignore.HelmIgnore))
		if err != nil {
			return nil, errors.Wrapf(err, "error reading %s", ignore.HelmIgnore)
		}
		parsed, err := ignore.Parse(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		rules = parsed
	}
	rules.AddDefaults()

	files := make([]*loader.BufferedFile, 0)
	if err := walkChartFiles(fsys, rules, dir, "", &files); err != nil {
		return nil, err
	}
	return loader.LoadFiles(files)
}

// walkChartFiles recursively collects dir's files into out, keyed by their
// chart-root-relative slash path. A ReadDir miss is not an error: an absent
// optional subdirectory must not fail the whole render.
func walkChartFiles(fsys vfs.FS, rules *ignore.Rules, dir, rel string, out *[]*loader.BufferedFile) error {
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return errors.Wrapf(err, "error reading %s", rel)
	}
	for _, entry := range entries {
		entryRel := entry.Name()
		if rel != "" {
			entryRel = rel + "/" + entry.Name()
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return errors.Wrapf(infoErr, "error stating %s", entryRel)
		}
		if info.IsDir() {
			// Directory-based ignore rules skip the entire subtree.
			if rules.Ignore(entryRel, info) {
				continue
			}
			if err := walkChartFiles(fsys, rules, filepath.Join(dir, entry.Name()), entryRel, out); err != nil {
				return err
			}
			continue
		}
		if rules.Ignore(entryRel, info) {
			continue
		}
		if !info.Mode().IsRegular() {
			return errors.Errorf("cannot load irregular file %s as it has file mode type bits set", entryRel)
		}
		if info.Size() > loader.MaxDecompressedFileSize {
			return errors.Errorf("chart file %q is larger than the maximum file size %d", entry.Name(), loader.MaxDecompressedFileSize)
		}
		data, err := fsys.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return errors.Wrapf(err, "error reading %s", entryRel)
		}
		*out = append(*out, &loader.BufferedFile{
			Name: entryRel,
			Data: bytes.TrimPrefix(data, utf8bom),
		})
	}
	return nil
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

// templateActionRE matches Helm/Go template action delimiters including trim markers.
var templateActionRE = regexp.MustCompile(`(?s)\{\{-?.*?-?\}\}`)

// templateCommentRE matches Helm template comment blocks: {{/* ... */}} (with optional trim markers).
var templateCommentRE = regexp.MustCompile(`(?s)\{\{-?\s*/\*.*?\*/\s*-?\}\}`)

// templateActionSpans returns the [start, end) byte ranges of all {{ ... }} blocks in s,
// excluding comment blocks ({{/* ... */}}).
// The returned slice is sorted by start (FindAllStringIndex guarantees this).
func templateActionSpans(s string) [][2]int {
	allMatches := templateActionRE.FindAllStringIndex(s, -1)
	commentMatches := templateCommentRE.FindAllStringIndex(s, -1)
	commentSet := make(map[[2]int]bool, len(commentMatches))
	for _, m := range commentMatches {
		commentSet[[2]int{m[0], m[1]}] = true
	}
	spans := make([][2]int, 0, len(allMatches))
	for _, m := range allMatches {
		if !commentSet[[2]int{m[0], m[1]}] {
			spans = append(spans, [2]int{m[0], m[1]})
		}
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
// templateArgRE matches a Sprig function argument: a numeric literal, a .Values.foo
// field path, or a $variable reference.
const templateArgRE = `[\w$.]+`

var deterministicPatterns = []deterministicPattern{
	{
		re:      regexp.MustCompile(`\brandAlphaNum\s+` + templateArgRE),
		replace: func(lineNum int) string { return fmt.Sprintf(`"ddscan%04d"`, lineNum) },
		guard:   notPrecededByVarOrField,
	},
	{
		re:      regexp.MustCompile(`\brandAlpha\s+` + templateArgRE),
		replace: func(lineNum int) string { return fmt.Sprintf(`"ddscan%04d"`, lineNum) },
		guard:   notPrecededByVarOrField,
	},
	{
		re:      regexp.MustCompile(`\brandAscii\s+` + templateArgRE),
		replace: func(lineNum int) string { return fmt.Sprintf(`"ddscan%04d"`, lineNum) },
		guard:   notPrecededByVarOrField,
	},
	{
		re:      regexp.MustCompile(`\brandNumeric\s+` + templateArgRE),
		replace: func(lineNum int) string { return fmt.Sprintf(`"%08d"`, lineNum) },
		guard:   notPrecededByVarOrField,
	},
	{
		re:      regexp.MustCompile(`\brandBytes\s+` + templateArgRE),
		replace: func(lineNum int) string { return fmt.Sprintf(`"ddscan%04d"`, lineNum) },
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
		temp = addHelmInvocationMarkers(temp)
		if temp != nil {
			continue
		}
	}
	// Stamp YAML CRDs for line mapping; JSON CRDs are skipped (YAML comments corrupt JSON).
	for _, f := range localCRDFiles(chartReq) {
		if isYAMLCRD(f.Name) {
			addID(f)
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

// addHelmInvocationMarkers instruments action-only wrapper templates so the
// rendered output retains the source position of the invocation that actually
// ran. The marker action is inserted immediately before include/template/tpl,
// which keeps it under the same Helm control flow as the invocation.
func addHelmInvocationMarkers(file *chart.File) *chart.File {
	source := string(file.Data)
	if strings.Contains(source, kicsHelmInvocation) || !isHelmInvocationWrapper(source) {
		return file
	}

	var markers []replacement
	for _, span := range templateActionSpans(source) {
		actionText := strings.Trim(source[span[0]+len("{{"):span[1]-len("}}")], "- \t\r\n")
		fields := strings.Fields(actionText)
		if len(fields) == 0 || !isHelmOutputInvocation(fields[0]) {
			continue
		}

		line := strings.Count(source[:span[0]], "\n") + 1
		lineStart := strings.LastIndexByte(source[:span[0]], '\n') + 1
		col := span[0] - lineStart
		marker := fmt.Sprintf("%s%d_%d:\n", kicsHelmInvocation, line, col)
		markers = append(markers, replacement{
			start: span[0],
			end:   span[0],
			text:  fmt.Sprintf("{{ print %q }}", marker),
		})
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

func isHelmInvocationWrapper(source string) bool {
	withoutActions := templateActionRE.ReplaceAllString(source, "")
	for _, line := range strings.Split(withoutActions, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !isYAMLDocumentBoundary(trimmed) {
			return false
		}
	}
	return true
}

func isHelmOutputInvocation(name string) bool {
	return name == "include" || name == "template" || name == "tpl"
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
// The output keeps the chart path's separator style: a pushed (content-push)
// chart path is forward-slash, and its resolved files must be too so findings
// match the pushed path shape on every platform; a native disk chart path
// (the CLI on Windows) keeps its native separators.
func resolvedChartFilePath(chartPath, chartRelative string) string {
	subFolder := filepath.Base(chartPath)
	joined := filepath.Join(filepath.Dir(chartPath), subFolder, filepath.FromSlash(chartRelative))
	if !strings.Contains(chartPath, `\`) {
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
