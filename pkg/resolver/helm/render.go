package helm

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/pkg/errors"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/release"
	kyaml "sigs.k8s.io/kustomize/kyaml/yaml"
	"sigs.k8s.io/kustomize/kyaml/yaml/merge2"
)

const (
	kicsHelmID = "# KICS_HELM_ID_"

	valuesMergeMerge    = "merge"
	valuesMergeOverride = "override"
	valuesMergeReplace  = "replace"
)

// splitManifest holds one manifest slice split by source.
type splitManifest struct {
	path       string
	content    []byte
	original   []byte
	splitID    string
	splitIDMap map[int]interface{}
}

// RenderOptions configures Helm chart rendering (dry-run template).
type RenderOptions struct {
	ChartPath        string
	ChartRepo        string
	ReleaseName      string
	NameTemplate     string
	Namespace        string
	ValuesFiles      []string
	SetValues        []string
	ValuesInline     map[string]interface{}
	ValuesMerge      string
	IncludeCRDs      bool
	SkipHooks        bool
	SkipTests        bool
	APIVersions      []string
	KubeVersion      string
	Version          string
	Devel            bool
	RepositoryConfig string
	RepositoryCache  string
	RegistryConfig   string
}

// RenderedChart is the output of RenderChart.
type RenderedChart struct {
	Resources []RenderedResource
	Excluded  []string
}

// RenderedResource is one manifest document from a rendered chart.
type RenderedResource struct {
	SourceFile string
	Content    []byte
	Original   []byte
	SplitID    string
	IDInfo     map[int]interface{}
}

// RenderChart renders a chart at ChartPath using the Helm SDK (dry-run).
func RenderChart(ctx context.Context, opts *RenderOptions) (*RenderedChart, error) {
	if opts == nil {
		return nil, errors.New("helm RenderOptions is nil")
	}
	contextLogger := logger.FromContext(ctx)
	client := newClient(ctx, opts)
	valueOpts := &values.Options{
		ValueFiles: opts.ValuesFiles,
		Values:     opts.SetValues,
	}
	cleanup := func() {}
	if len(opts.ValuesInline) > 0 {
		var err error
		cleanup, err = applyValuesInline(ctx, valueOpts, opts)
		if err != nil {
			return nil, err
		}
	}
	defer cleanup()
	manifest, excluded, err := runInstall(ctx, []string{opts.ChartPath}, client, valueOpts, opts)
	if err != nil {
		contextLogger.Error().Msgf("failed to run helm install for '%s': %s", opts.ChartPath, err)
		return nil, errors.Wrap(err, "helm render")
	}
	splits, err := splitManifestYAML(manifest)
	if err != nil {
		return nil, err
	}
	out := &RenderedChart{Excluded: excluded}
	for _, sp := range *splits {
		if opts.SkipTests && isHelmTestTemplate(sp.path) {
			continue
		}
		out.Resources = append(out.Resources, RenderedResource{
			SourceFile: sp.path,
			Content:    sp.content,
			Original:   sp.original,
			SplitID:    sp.splitID,
			IDInfo:     sp.splitIDMap,
		})
	}
	return out, nil
}

func applyValuesInline(ctx context.Context, valueOpts *values.Options, opts *RenderOptions) (func(), error) {
	if opts == nil {
		return func() {}, errors.New("helm RenderOptions is nil")
	}
	contextLogger := logger.FromContext(ctx)
	inlineBytes, err := mergedValuesInlineBytes(opts)
	if err != nil {
		return func() {}, err
	}
	if len(inlineBytes) == 0 {
		return func() {}, nil
	}
	f, err := os.CreateTemp("", "iac-scanner-helm-values-*.yaml")
	if err != nil {
		return func() {}, errors.Wrap(err, "create helm values temp file")
	}
	if _, err := f.Write(inlineBytes); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return func() {}, errors.Wrap(err, "write merged inline helm values")
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return func() {}, errors.Wrap(err, "close merged inline helm values")
	}
	contextLogger.Debug().Msgf("wrote inline helm values to %s", f.Name())
	// Single temp file replaces ValueFiles so inline merge is not applied twice.
	valueOpts.ValueFiles = []string{f.Name()}
	return func() {
		_ = os.Remove(f.Name())
	}, nil
}

func mergedValuesInlineBytes(opts *RenderOptions) ([]byte, error) {
	if opts == nil {
		return nil, errors.New("helm RenderOptions is nil")
	}
	mergeMode := strings.TrimSpace(opts.ValuesMerge)
	if mergeMode == "" {
		mergeMode = valuesMergeOverride
	}
	switch mergeMode {
	case valuesMergeReplace:
		return kyaml.Marshal(opts.ValuesInline)
	case valuesMergeMerge, valuesMergeOverride:
	default:
		return nil, errors.Errorf("invalid helm valuesMerge %q", opts.ValuesMerge)
	}
	if len(opts.ValuesFiles) == 0 {
		return kyaml.Marshal(opts.ValuesInline)
	}
	baseNode, err := mergeHelmValueFilesToBaseNode(opts.ChartPath, opts.ValuesFiles)
	if err != nil {
		return nil, err
	}
	return mergeInlineYAMLWithBase(mergeMode, baseNode, opts.ValuesInline)
}

// mergeHelmValueFilesToBaseNode merges valueFiles in order (later wins), after constraining paths to the chart tree.
func mergeHelmValueFilesToBaseNode(chartPath string, valueFiles []string) (*kyaml.RNode, error) {
	var baseNode *kyaml.RNode
	for i, valuesFile := range valueFiles {
		safePath, err := valuesFilePathForRead(chartPath, valuesFile)
		if err != nil {
			return nil, err
		}
		baseBytes, err := readChartContainedValuesFile(safePath)
		if err != nil {
			return nil, errors.Wrap(err, "read helm base values file")
		}
		currentNode, err := kyaml.Parse(string(baseBytes))
		if err != nil {
			return nil, errors.Wrap(err, "parse helm base values file")
		}
		if i == 0 {
			baseNode = currentNode
			continue
		}
		// Later values files win over earlier ones (Helm precedence), then inline merges on top.
		baseNode, err = merge2.Merge(currentNode, baseNode.Copy(), kyaml.MergeOptions{})
		if err != nil {
			return nil, errors.Wrap(err, "merge helm base values files")
		}
	}
	return baseNode, nil
}

func mergeInlineYAMLWithBase(mergeMode string, baseNode *kyaml.RNode, inline map[string]interface{}) ([]byte, error) {
	inlineNode, err := kyaml.FromMap(inline)
	if err != nil {
		return nil, errors.Wrap(err, "parse inline helm values")
	}
	var outValues *kyaml.RNode
	switch mergeMode {
	case valuesMergeOverride:
		outValues, err = merge2.Merge(inlineNode, baseNode.Copy(), kyaml.MergeOptions{})
	case valuesMergeMerge:
		outValues, err = merge2.Merge(baseNode, inlineNode.Copy(), kyaml.MergeOptions{})
	}
	if err != nil {
		return nil, errors.Wrap(err, "merge helm inline values")
	}
	return []byte(outValues.MustString()), nil
}

// readChartContainedValuesFile reads bytes from absPath; absPath must come from valuesFilePathForRead.
func readChartContainedValuesFile(absPath string) ([]byte, error) {
	//nolint:gosec // G304: absPath is only ever valuesFilePathForRead output (under chart directory).
	return os.ReadFile(absPath)
}

// valuesFilePathForRead returns an absolute path to valuesFile only if it resolves under the chart directory.
// Both sides are evaluated through filepath.EvalSymlinks so a symlink inside the chart that points outside
// the chart tree is rejected; a lexical Rel/IsLocal check alone is unsafe because os.ReadFile follows symlinks.
func valuesFilePathForRead(chartPath, valuesFile string) (string, error) {
	chartAbs, err := filepath.Abs(chartPath)
	if err != nil {
		return "", errors.Wrap(err, "resolve chart path")
	}
	chartAbs = filepath.Clean(chartAbs)
	if ev, err := filepath.EvalSymlinks(chartAbs); err == nil {
		chartAbs = filepath.Clean(ev)
	}
	var p string
	if filepath.IsAbs(valuesFile) {
		p = filepath.Clean(valuesFile)
	} else {
		p = filepath.Clean(filepath.Join(chartAbs, valuesFile))
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", errors.Wrapf(err, "resolve values file %q", valuesFile)
	}
	resolved = filepath.Clean(resolved)
	rel, err := filepath.Rel(chartAbs, resolved)
	if err != nil || !filepath.IsLocal(rel) {
		return "", errors.Errorf("values file %q is outside chart directory", valuesFile)
	}
	return resolved, nil
}

func isHelmTestTemplate(path string) bool {
	path = filepath.ToSlash(path)
	return strings.Contains(path, "/tests/") || strings.HasPrefix(path, "tests/")
}

func splitManifestYAML(template *release.Release) (*[]splitManifest, error) {
	sources := make([]*chart.File, 0)
	sources = updateName(sources, template.Chart, template.Chart.Name())
	var splitedManifest []splitManifest
	splitedSource := strings.Split(template.Manifest, "---")
	origData := toMap(sources)
	for _, splited := range splitedSource {
		var lineID string
		for _, line := range strings.Split(splited, "\n") {
			if strings.Contains(line, kicsHelmID) {
				lineID = line
				break
			}
		}
		path := strings.Split(strings.TrimPrefix(splited, "\n# Source: "), "\n")
		if path[0] == "" {
			continue
		}
		if origData[filepath.FromSlash(path[0])] == nil {
			continue
		}
		idMap, err := getIDMap(origData[filepath.FromSlash(path[0])])
		if err != nil {
			return nil, err
		}
		splitedManifest = append(splitedManifest, splitManifest{
			path:       path[0],
			content:    []byte(strings.ReplaceAll(splited, "\r", "")),
			original:   origData[filepath.FromSlash(path[0])],
			splitID:    lineID,
			splitIDMap: idMap,
		})
	}
	return &splitedManifest, nil
}

func toMap(files []*chart.File) map[string][]byte {
	mapFiles := make(map[string][]byte)
	for _, file := range files {
		mapFiles[file.Name] = []byte(strings.ReplaceAll(string(file.Data), "\r", ""))
	}
	return mapFiles
}

func updateName(template []*chart.File, charts *chart.Chart, name string) []*chart.File {
	if name != charts.Name() {
		name = filepath.Join(name, charts.Name())
	}
	for _, temp := range charts.Templates {
		temp.Name = filepath.Join(name, temp.Name)
	}
	template = append(template, charts.Templates...)
	for _, dep := range charts.Dependencies() {
		template = updateName(template, dep, filepath.Join(name, "charts"))
	}
	return template
}

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
