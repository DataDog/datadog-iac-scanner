package helm

import (
	"bytes"
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
	path                string
	content             []byte
	original            []byte
	splitID             string
	sourceDocumentIndex int
	splitIDMap          map[int]interface{}
	isCRD               bool
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
	splits, excluded, err := renderHelm(ctx, filePath)
	if err != nil {
		return model.ResolvedFiles{}, errors.Wrap(err, "failed to render helm chart")
	}
	var rfiles = model.ResolvedFiles{
		Excluded: excluded,
	}
	contextLogger.Debug().Msgf("Processing %d helm manifest splits from chart '%s'", len(*splits), filePath)
	for _, split := range *splits {
		sourceKey := chartSourceKey(split.path)
		chartRelative, ok := chartRelativeFromSource(sourceKey)
		if !ok {
			continue
		}
		origpath := resolvedChartFilePath(filePath, chartRelative)
		rfiles.File = append(rfiles.File, model.ResolvedHelm{
			FileName:            origpath,
			Content:             split.content,
			OriginalData:        split.original,
			SplitID:             split.splitID,
			SourceDocumentIndex: split.sourceDocumentIndex,
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

// renderHelm will use helm library to render helm charts
func renderHelm(ctx context.Context, path string) (*[]splitManifest, []string, error) {
	contextLogger := logger.FromContext(ctx)
	client := newClient(ctx)
	contextLogger.Debug().Msg("Running helm install")
	manifest, loadedChart, excluded, err := runInstall(ctx, []string{path}, client, &values.Options{})
	if err != nil {
		return nil, []string{}, err
	}
	splitted, err := splitManifestYAML(manifest, loadedChart)
	if err != nil {
		return nil, []string{}, err
	}
	return splitted, excluded, nil
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
	sourceData := indexSources(sources)
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
		if err := source.ensureIDMap(); err != nil {
			return nil, err
		}
		splitID := firstHelmMarker(splited)
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
			splitIDMap:          source.idMap,
			isCRD:               source.isCRD,
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

func firstHelmMarker(content string) string {
	index := strings.Index(content, kicsHelmID)
	if index < 0 {
		return ""
	}
	lineStart := strings.LastIndexByte(content[:index], '\n') + 1
	lineEnd := strings.IndexByte(content[index:], '\n')
	if lineEnd < 0 {
		return content[lineStart:]
	}
	return content[lineStart : index+lineEnd]
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

func (s *sourceMetadata) ensureIDMap() error {
	if s.idMapPrepared {
		return nil
	}
	idMap, err := getIDMap(s.original)
	if err != nil {
		return err
	}
	s.idMap = idMap
	s.idMapPrepared = true
	return nil
}

func indexSources(files []*chart.File) map[string]*sourceMetadata {
	sources := make(map[string]*sourceMetadata, len(files))
	for _, file := range files {
		original := file.Data
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
		case "charts":
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
		template = updateName(template, dep, helmChartPath(name, "charts"))
	}
	return template
}

// getIdMap will construct a map with ids with the corresponding lines as keys
// for use in detector
func getIDMap(originalData []byte) (map[int]interface{}, error) {
	ids := make(map[int]interface{})
	idHelm := -1
	lineRange := model.HelmIDLineRange{Start: 1, End: 0}
	for line, stringLine := range strings.Split(string(originalData), "\n") {
		if strings.Contains(stringLine, kicsHelmID) {
			id, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(stringLine, kicsHelmID), ":"))
			if err != nil {
				return nil, err
			}
			if idHelm != -1 {
				lineRange.End = line - 1
				ids[idHelm] = lineRange
			}
			idHelm = id
			lineRange = model.HelmIDLineRange{Start: line, End: line}
		} else if idHelm != -1 {
			lineRange.End = line
		}
	}
	ids[idHelm] = lineRange

	return ids, nil
}
