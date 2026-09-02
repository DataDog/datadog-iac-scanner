package helm

import (
	"context"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	masterUtils "github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/pkg/errors"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/releaseutil"
)

// Resolver is an instance of the helm resolver
type Resolver struct {
}

// splitManifest keeps the information of the manifest splitted by source
type splitManifest struct {
	path       string
	content    []byte
	original   []byte
	splitID    string
	splitIDMap map[int]interface{}
}

const (
	kicsHelmID = "# KICS_HELM_ID_"
)

// Resolve will render the passed helm chart and return its content ready for parsing
func (r *Resolver) Resolve(ctx context.Context, filePath string) (model.ResolvedFiles, error) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("Resolving Helm files")
	// handle panic during resolve process
	defer func() {
		if r := recover(); r != nil {
			errMessage := "Recovered from panic during resolve of file " + filePath
			masterUtils.HandlePanic(ctx, r, errMessage)
		}
	}()
	splits, excluded, loadedChart, err := renderHelm(ctx, filePath)
	if err != nil {
		return model.ResolvedFiles{}, errors.Wrap(err, "failed to render helm chart")
	}
	var rfiles = model.ResolvedFiles{
		Excluded: excluded,
	}
	contextLogger.Debug().Msgf("Processing %d helm manifest splits from chart '%s'", len(*splits), filePath)
	seenCRDs := make(map[string]struct{}, len(*splits))
	for _, split := range *splits {
		sourceKey := chartSourceKey(split.path)
		seenCRDs[sourceKey] = struct{}{}
		chartRelative, ok := chartRelativeFromSource(sourceKey)
		if !ok {
			continue
		}
		origpath := resolvedChartFilePath(filePath, chartRelative)
		rfiles.File = append(rfiles.File, model.ResolvedHelm{
			FileName:     origpath,
			Content:      split.content,
			OriginalData: split.original,
			SplitID:      split.splitID,
			IDInfo:       split.splitIDMap,
		})
	}
	if err := appendDirectCRDFiles(&rfiles, filePath, loadedChart, seenCRDs); err != nil {
		return model.ResolvedFiles{}, err
	}
	contextLogger.Debug().Msgf("Successfully processed %d helm files from chart '%s'", len(rfiles.File), filePath)
	return rfiles, nil
}

// SupportedTypes returns the supported fileKinds for this resolver
func (r *Resolver) SupportedTypes() []model.FileKind {
	return []model.FileKind{model.KindHELM}
}

// renderHelm will use helm library to render helm charts
func renderHelm(ctx context.Context, path string) (*[]splitManifest, []string, *chart.Chart, error) {
	contextLogger := logger.FromContext(ctx)
	client := newClient(ctx)
	contextLogger.Debug().Msg("Running helm install")
	manifest, loadedChart, excluded, err := runInstall(ctx, []string{path}, client, &values.Options{})
	if err != nil {
		return nil, []string{}, nil, err
	}
	splitted, err := splitManifestYAML(manifest, loadedChart)
	if err != nil {
		return nil, []string{}, nil, err
	}
	return splitted, excluded, loadedChart, nil
}

// splitManifestYAML will split the rendered file and return its content by template as well as the template path
func splitManifestYAML(template *release.Release, loadedChart *chart.Chart) (*[]splitManifest, error) {
	sourceChart := loadedChart
	if sourceChart == nil {
		sourceChart = template.Chart
	}
	sources := make([]*chart.File, 0)
	sources = updateName(sources, sourceChart, sourceChart.Name())
	var splitedManifest []splitManifest
	splitedSource := splitHelmManifest(template.Manifest)
	origData := toMap(sources)
	// crdSplitCount and markersBySource support multi-document CRD files: Helm renders
	// each document as a separate split without repeating the Source header, and omits
	// KICS_HELM_ID markers. We attribute sourceless splits to lastSource and pick the
	// Nth cached marker for the Nth occurrence of a given source path.
	crdSplitCount := make(map[string]int)
	markersBySource := make(map[string][]string)
	var lastSource string
	for _, splited := range splitedSource {
		splited = strings.ReplaceAll(splited, "\r", "")
		var lineID string
		for _, line := range strings.Split(splited, "\n") {
			if strings.Contains(line, kicsHelmID) {
				lineID = line // get auxiliary line id
				break
			}
		}

		sourcePath, hasSource := parseManifestSource(splited)
		if hasSource {
			sourcePath = chartSourceKey(sourcePath)
			if origData[sourcePath] == nil {
				hasSource = false
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
		if origData[sourceKey] == nil {
			continue
		}
		original := origData[sourceKey]
		idMap, err := getIDMap(original)
		if err != nil {
			return nil, err
		}
		// CRDs have no inline markers in the rendered output; use the Nth stamped marker.
		if lineID == "" {
			markers, ok := markersBySource[sourcePath]
			if !ok {
				markers = extractHelmMarkers(original)
				markersBySource[sourcePath] = markers
			}
			n := crdSplitCount[sourcePath]
			if n < len(markers) {
				lineID = markers[n]
			}
			crdSplitCount[sourcePath]++
		}
		splitedManifest = append(splitedManifest, splitManifest{
			path:       sourcePath,
			content:    []byte(strings.ReplaceAll(splited, "\r", "")),
			original:   original,
			splitID:    lineID,
			splitIDMap: idMap,
		})
	}
	return &splitedManifest, nil
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
	for _, line := range strings.Split(split, "\n") {
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

func looksLikeManifest(split string) bool {
	apiVersionLines, parsed := topLevelAPIVersionLines([]byte(split))
	return parsed && len(apiVersionLines) > 0
}

// extractHelmMarkers returns all KICS_HELM_ID lines from content in order.
func extractHelmMarkers(data []byte) []string {
	var markers []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, kicsHelmID) {
			markers = append(markers, strings.TrimSpace(line))
		}
	}
	return markers
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

// toMap will convert to map original data having the path as it's key
func toMap(files []*chart.File) map[string][]byte {
	mapFiles := make(map[string][]byte)
	for _, file := range files {
		mapFiles[chartSourceKey(file.Name)] = []byte(strings.ReplaceAll(string(file.Data), "\r", ""))
	}
	return mapFiles
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
		template = updateName(template, dep, helmChartPath(name, "charts"))
	}
	return template
}

func crdDocuments(data []byte) [][]byte {
	text := strings.ReplaceAll(string(data), "\r", "")
	parts := splitHelmManifest(text)
	docs := make([][]byte, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		docs = append(docs, []byte(part))
	}
	return docs
}

func appendDirectCRDFiles(
	rfiles *model.ResolvedFiles, chartPath string, ch *chart.Chart, seen map[string]struct{},
) error {
	if ch == nil {
		return nil
	}
	rootKey := chartSourceKey(ch.Name())
	var walk func(prefix string, chart *chart.Chart) error
	walk = func(prefix string, chart *chart.Chart) error {
		chartPrefix := helmChartPath(prefix, chart.Name())
		for _, f := range localCRDFiles(chart) {
			rel := crdChartRelativePath(f.Name)
			sourceKey := chartSourceKey(helmChartPath(chartPrefix, rel))
			if _, ok := seen[sourceKey]; ok {
				continue
			}
			chartRelative := strings.TrimPrefix(sourceKey, rootKey+"/")
			if chartRelative == sourceKey {
				continue
			}
			origpath := resolvedChartFilePath(chartPath, chartRelative)
			original := append([]byte(nil), f.Data...)
			idMap, err := getIDMap(original)
			if err != nil {
				return err
			}
			markers := extractHelmMarkers(original)
			docs := crdDocuments(original)
			for i, doc := range docs {
				lineID := ""
				if i < len(markers) {
					lineID = markers[i]
				}
				rfiles.File = append(rfiles.File, model.ResolvedHelm{
					FileName:     origpath,
					Content:      append([]byte(nil), doc...),
					OriginalData: original,
					SplitID:      lineID,
					IDInfo:       idMap,
				})
			}
			seen[sourceKey] = struct{}{}
		}
		for _, dep := range chart.Dependencies() {
			if err := walk(helmChartPath(chartPrefix, "charts"), dep); err != nil {
				return err
			}
		}
		return nil
	}
	return walk("", ch)
}

// getIdMap will construct a map with ids with the corresponding lines as keys
// for use in detector
func getIDMap(originalData []byte) (map[int]interface{}, error) {
	ids := make(map[int]interface{})
	mapLines := make(map[int]int)
	idHelm := -1
	for line, stringLine := range strings.Split(string(originalData), "\n") {
		if strings.Contains(stringLine, kicsHelmID) {
			id, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(stringLine, kicsHelmID), ":"))
			if err != nil {
				return nil, err
			}
			if idHelm == -1 {
				idHelm = id
				mapLines[line] = line
			} else {
				ids[idHelm] = mapLines
				mapLines = make(map[int]int)
				idHelm = id
				mapLines[line] = line
			}
		} else if idHelm != -1 {
			mapLines[line] = line
		}
	}
	ids[idHelm] = mapLines

	return ids, nil
}
