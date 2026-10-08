package helm

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/helmmarker"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	masterUtils "github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/releaseutil"
)

// Resolver is an instance of the helm resolver. A nil fsys falls back to the
// real filesystem; the server passes the request's in-memory FS.
type Resolver struct {
	fsys vfs.FS
}

// NewResolver builds a helm resolver reading chart files from fsys.
func NewResolver(fsys vfs.FS) *Resolver {
	return &Resolver{fsys: fsys}
}

// splitManifest keeps the information of the manifest splitted by source
type splitManifest struct {
	path                string
	content             []byte
	original            []byte
	splitID             string
	sourceDocumentIndex int
	helmInvocations     model.HelmInvocations
	splitIDMap          map[int]interface{}
	isCRD               bool
}

// dependenciesDirName is the chart subdirectory Helm loads subcharts from.
const dependenciesDirName = "charts"

// Resolve will render the passed helm chart and return its content ready for parsing
func (r *Resolver) Resolve(ctx context.Context, filePath string) (resolved model.ResolvedFiles, err error) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("Resolving Helm files")
	// A panic is reported as an error: an empty result with no error would read
	// as a chart that rendered to nothing, and its raw templates would be withheld.
	defer func() {
		if p := recover(); p != nil {
			masterUtils.HandlePanic(ctx, p, "Recovered from panic during resolve of file "+filePath)
			resolved, err = model.ResolvedFiles{}, fmt.Errorf("panic during resolve of %s: %v", filePath, p)
		}
	}()
	fsys := r.filesystem()
	splits, excluded, err := renderHelm(ctx, fsys, filePath)
	if err != nil {
		return model.ResolvedFiles{}, errors.Wrap(err, "failed to render helm chart")
	}
	// Pushed charts are addressed with "/" on every OS, so their resolved files
	// must be too; disk charts keep the OS separator.
	slashPaths := !vfs.IsDisk(fsys)
	var rfiles = model.ResolvedFiles{
		Excluded: excluded,
	}
	contextLogger.Debug().Msgf("Processing %d helm manifest splits from chart '%s'", len(*splits), filePath)
	for i := range *splits {
		split := &(*splits)[i]
		sourceKey := chartSourceKey(split.path)
		chartRelative, ok := chartRelativeFromSource(sourceKey)
		if !ok {
			continue
		}
		origpath := resolvedChartFilePath(filePath, chartRelative, slashPaths)
		rfiles.File = append(rfiles.File, model.ResolvedHelm{
			FileName:            origpath,
			Content:             split.content,
			OriginalData:        split.original,
			SplitID:             split.splitID,
			SourceDocumentIndex: split.sourceDocumentIndex,
			HelmInvocations:     split.helmInvocations,
			IDInfo:              split.splitIDMap,
			IsCRD:               split.isCRD,
		})
	}
	contextLogger.Debug().Msgf("Successfully processed %d helm files from chart '%s'", len(rfiles.File), filePath)
	return rfiles, nil
}

// SupportedTypes returns the supported fileKinds for this resolver
func (r *Resolver) SupportedTypes() []model.FileKind {
	return []model.FileKind{model.KindHELM}
}

// GetType reports KindHELM when dir is the root of an application chart, read
// through the same filesystem the chart is rendered from. A library chart
// (type: library) renders no manifests, so it is KindCOMMON.
func (r *Resolver) GetType(dir string) model.FileKind {
	data, err := r.filesystem().ReadFile(filepath.Join(filepath.FromSlash(dir), "Chart.yaml"))
	if err != nil || chartYAMLDeclaresLibrary(data) {
		return model.KindCOMMON
	}
	return model.KindHELM
}

// chartYAMLDeclaresLibrary reports whether Chart.yaml content declares type: library.
func chartYAMLDeclaresLibrary(data []byte) bool {
	var meta struct {
		Type string `yaml:"type"`
	}
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return false
	}
	return meta.Type == "library"
}

// maxMarkerRetries bounds how many templates are rendered again without
// invocation markers before the whole chart is.
const maxMarkerRetries = 3

// yamlParseErrorRE matches Helm's report of a rendered manifest it cannot
// parse, which names the template that produced it.
var yamlParseErrorRE = regexp.MustCompile(`YAML parse error on (.+?): `)

// yamlParseErrorTemplate returns the template Helm could not parse the output
// of, when err says so.
func yamlParseErrorTemplate(err error) (template string, ok bool) {
	if err == nil {
		return "", false
	}
	m := yamlParseErrorRE.FindStringSubmatch(err.Error())
	if m == nil {
		return "", false
	}
	return m[1], true
}

// renderHelm will use helm library to render helm charts
func renderHelm(ctx context.Context, fsys vfs.FS, path string) (*[]splitManifest, []string, error) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("Running helm install")
	manifest, loadedChart, stamped, excluded, err := renderWithMarkers(ctx, fsys, path)
	if err != nil {
		return nil, []string{}, err
	}
	return splitManifestYAML(manifest, loadedChart, stamped), excluded, nil
}

// renderWithMarkers renders the chart with invocation markers. A marker is a
// comment line, which ends a plain multi-line value an include continues, so
// it can make a template's output unparseable. A marker must never cost a
// chart its render: each marked template Helm fails to parse is rendered again
// without markers, as it was before they existed, and the chart gives up all of
// them only when that does not settle it. A template that had no marker is
// broken by itself, and its error is returned at once.
func renderWithMarkers(ctx context.Context, fsys vfs.FS, path string) (
	*release.Release, *chart.Chart, stampedSources, []string, error,
) {
	contextLogger := logger.FromContext(ctx)
	unmarked := map[string]bool{}
	for attempt := 0; ; attempt++ {
		marks := newInvocationMarks()
		marks.unmarked = unmarked
		manifest, loadedChart, stamped, excluded, err := runInstall(
			ctx, path, fsys, newClient(ctx), &values.Options{}, marks)
		template, parseErr := yamlParseErrorTemplate(err)
		if !parseErr || (marks.seen[template] && !marks.marked[template]) {
			return manifest, loadedChart, stamped, excluded, err
		}
		// A template the stamping never saw, as when Helm names a subchart by an
		// alias, cannot be left unmarked on its own.
		if !marks.seen[template] || attempt >= maxMarkerRetries {
			break
		}
		unmarked[template] = true
		contextLogger.Debug().Msgf("Rendering chart '%s' again without invocation markers in template '%s'", path, template)
	}
	contextLogger.Debug().Msgf("Rendering chart '%s' again without any invocation marker", path)
	return runInstall(ctx, path, fsys, newClient(ctx), &values.Options{}, &invocationMarks{none: true})
}

// splitManifestYAML will split the rendered file and return its content by template as well as the template path.
// stamped gives the template sources from before invocation markers were added (see setID).
func splitManifestYAML(
	template *release.Release, loadedChart *chart.Chart, stamped stampedSources,
) *[]splitManifest {
	sourceChart := loadedChart
	if sourceChart == nil {
		sourceChart = template.Chart
	}
	sources := make([]*chart.File, 0)
	sources = updateName(sources, sourceChart, sourceChart.Name())
	var splitedManifest []splitManifest
	splitedSource := splitHelmManifest(template.Manifest)
	sourceData := indexSources(sources, stamped)
	sourceDocumentIndices := make(map[string]int)
	var lastSource string
	for _, splited := range splitedSource {
		splited = strings.ReplaceAll(splited, "\r", "")
		sourcePath, hasSource := parseManifestSource(splited)
		if hasSource {
			sourcePath = chartSourceKey(sourcePath)
			if sourceData[sourcePath] == nil {
				lastSource = ""
				continue
			}
		}
		if !hasSource {
			// Helm omits the Source header on later documents from a multi-document CRD.
			if lastSource != "" && looksLikeManifest(splited) {
				sourcePath = lastSource
			} else {
				continue
			}
		} else {
			lastSource = sourcePath
		}

		sourcePath = chartSourceKey(sourcePath)
		sourceKey := sourcePath
		source := sourceData[sourceKey]
		if source == nil {
			continue
		}
		invocations := parseHelmInvocations(splited)
		splited = removeInvocationMarkers(splited)
		source.ensureIDMap()
		splitID := helmmarker.FirstID(splited)
		sourceDocumentIndex := sourceDocumentIndices[sourceKey]
		if !source.isCRD || splitID != "" || strings.EqualFold(filepath.Ext(sourcePath), ".json") {
			sourceDocumentIndices[sourceKey]++
		}
		splitedManifest = append(splitedManifest, splitManifest{
			path:                sourcePath,
			content:             []byte(splited),
			original:            source.original,
			splitID:             splitID,
			sourceDocumentIndex: sourceDocumentIndex,
			helmInvocations:     invocations,
			splitIDMap:          source.idMap,
			isCRD:               source.isCRD,
		})
	}
	return &splitedManifest
}

func splitHelmManifest(manifest string) []string {
	manifests := releaseutil.SplitManifests(manifest)
	keys := make([]string, 0, len(manifests))
	for key := range manifests {
		keys = append(keys, key)
	}
	sort.Sort(releaseutil.BySplitManifestsOrder(keys))

	splits := make([]string, 0, len(keys))
	for _, key := range keys {
		splits = append(splits, "\n"+manifests[key]+"\n")
	}
	return splits
}

// parseManifestSource extracts the Helm # Source header from a manifest split.
func parseManifestSource(split string) (source string, ok bool) {
	for split != "" {
		lineEnd := strings.IndexByte(split, '\n')
		line := split
		if lineEnd >= 0 {
			line = split[:lineEnd]
			split = split[lineEnd+1:]
		} else {
			split = ""
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "# Source: ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# Source: ")), true
		}
		return "", false
	}
	return "", false
}

// parseHelmInvocations returns the invocation markers of a rendered document
// in order, each with the line it emits once the marker lines are removed and
// the position of its action in the source template as written.
func parseHelmInvocations(content string) model.HelmInvocations {
	if !hasInvocationMarker(content) {
		return nil
	}
	var invocations model.HelmInvocations
	kept := 0
	for _, line := range strings.Split(content, "\n") {
		marker, ok := parseInvocationMarker(line)
		if !ok {
			kept++
			continue
		}
		invocations = append(invocations, model.HelmInvocationAt{
			RenderedLine: kept + 1,
			Position:     model.ResourceLine{Line: marker.Line, Col: marker.Col},
		})
	}
	return invocations
}

func looksLikeManifest(split string) bool {
	return len(topLevelAPIVersionLines(strings.Split(split, "\n"), true)) > 0
}

// chartSourceKey normalizes Helm source paths for cross-platform lookup.
func chartSourceKey(path string) string {
	path = strings.ReplaceAll(path, `\`, `/`)
	return filepath.ToSlash(filepath.Clean(path))
}

// chartRelativeFromSource strips the leading chart name segment from a normalized
// Helm manifest source path (e.g. test_helm/crds/widget.yaml -> crds/widget.yaml).
func chartRelativeFromSource(sourceKey string) (string, bool) {
	parts := strings.Split(sourceKey, "/")
	if len(parts) < 2 {
		return "", false
	}
	return strings.Join(parts[1:], "/"), true
}

// helmChartPath joins Helm chart-relative segments with forward slashes.
func helmChartPath(parts ...string) string {
	elems := make([]string, 0, len(parts))
	for _, part := range parts {
		part = filepath.ToSlash(part)
		for _, segment := range strings.Split(part, "/") {
			if segment != "" && segment != "." {
				elems = append(elems, segment)
			}
		}
	}
	return strings.Join(elems, "/")
}

type sourceMetadata struct {
	original      []byte
	idMap         map[int]interface{}
	isCRD         bool
	idMapPrepared bool
}

func (s *sourceMetadata) ensureIDMap() {
	if s.idMapPrepared {
		return
	}
	s.idMap = getIDMap(s.original)
	s.idMapPrepared = true
}

func indexSources(files []*chart.File, stamped stampedSources) map[string]*sourceMetadata {
	sources := make(map[string]*sourceMetadata, len(files))
	for _, file := range files {
		original := stamped.of(file)
		if bytes.IndexByte(original, '\r') >= 0 {
			original = bytes.ReplaceAll(original, []byte{'\r'}, nil)
		}
		sources[chartSourceKey(file.Name)] = &sourceMetadata{
			original: original,
			isCRD:    isCRDSourcePath(file.Name),
		}
	}
	return sources
}

func isCRDSourcePath(name string) bool {
	parts := strings.Split(chartSourceKey(name), "/")
	if len(parts) == 0 {
		return false
	}
	index := 1
	for index < len(parts) {
		switch parts[index] {
		case crdDirName:
			return index+1 < len(parts)
		case dependenciesDirName:
			index += 2
		default:
			return false
		}
	}
	return false
}

// updateName will update the templates name as well as its dependencies
func updateName(template []*chart.File, charts *chart.Chart, name string) []*chart.File {
	name = helmChartPath(name)
	if name != charts.Name() {
		name = helmChartPath(name, charts.Name())
	}
	for _, temp := range charts.Templates {
		temp.Name = helmChartPath(name, temp.Name)
	}
	template = append(template, charts.Templates...)
	for _, f := range localCRDFiles(charts) {
		rel := crdChartRelativePath(f.Name)
		template = append(template, &chart.File{
			Name: helmChartPath(name, rel),
			Data: f.Data,
		})
	}
	for _, dep := range charts.Dependencies() {
		template = updateName(template, dep, helmChartPath(name, dependenciesDirName))
	}
	return template
}

// getIdMap will construct a map with ids with the corresponding lines as keys
// for use in detector
func getIDMap(originalData []byte) map[int]interface{} {
	ids := make(map[int]interface{})
	idHelm := -1
	lineRange := model.HelmIDLineRange{Start: 1, End: 0}
	for line, stringLine := range strings.Split(string(originalData), "\n") {
		if id, ok := helmmarker.ParseIDLine(stringLine); ok {
			if idHelm != -1 {
				lineRange.End = line - 1
				ids[idHelm] = lineRange
			}
			idHelm = id.Line
			lineRange = model.HelmIDLineRange{Start: line, End: line}
		} else if idHelm != -1 {
			lineRange.End = line
		}
	}
	ids[idHelm] = lineRange

	return ids
}
