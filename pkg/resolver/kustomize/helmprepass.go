package kustomize

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/resolver/helm"
	"github.com/DataDog/datadog-iac-scanner/pkg/rootfile"
	"gopkg.in/yaml.v3"
)

// ErrMaxStagingBytes is returned when copied helm staging exceeds MaxFetchBytes.
var ErrMaxStagingBytes = errors.New("kustomize staging exceeds max fetch bytes")

func subtreeDeclaresHelmCharts(kustomRoot, kf string) bool {
	var found bool
	_ = WalkLocalKustomizations(kustomRoot, func(kustPath string, raw []byte) error {
		if filepath.Clean(kustPath) == filepath.Join(kustomRoot, kf) {
			return nil
		}
		var childDoc map[string]interface{}
		if err := yaml.Unmarshal(raw, &childDoc); err != nil {
			return nil
		}
		if childHC, _ := childDoc["helmCharts"].([]interface{}); len(childHC) > 0 {
			found = true
		}
		return nil
	})
	return found
}

// PrepareHelmChartsIfNeeded returns the kustomize build dir and fs root; rewrites nested kustomizations with helmCharts.
// If inflation is off, strips helmCharts and emits diagnostics so the rest of the tree can still scan.
func PrepareHelmChartsIfNeeded(
	ctx context.Context,
	repoRoot,
	kustomRoot,
	scratchDir string,
	allowInflation,
	helmIncludeCRDs bool,
	maxStagingBytes int64,
) (buildRoot, fsRoot string, diags []model.ResolverDiagnostic, _ error) {
	repoRoot = filepath.Clean(repoRoot)
	kustomRoot = filepath.Clean(kustomRoot)
	kf := kustomizationEntryFile(kustomRoot)
	data, err := rootfile.ReadFile(filepath.Join(kustomRoot, kf))
	if err != nil {
		return kustomRoot, repoRoot, nil, err
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return kustomRoot, repoRoot, nil, err
	}
	hc, _ := doc["helmCharts"].([]interface{})
	if len(hc) == 0 && !subtreeDeclaresHelmCharts(kustomRoot, kf) {
		return kustomRoot, repoRoot, nil, nil
	}

	// Isolate staging per (scratch, kustom root) so same-named overlays do not collide.
	sum := sha256.Sum256([]byte(filepath.Clean(scratchDir) + "\x00" + filepath.Clean(kustomRoot)))
	stagedRepo := filepath.Join(scratchDir, "helm-prepass", hex.EncodeToString(sum[:16]))
	stageRels, err := StageRelPathsForKustomRoot(repoRoot, kustomRoot)
	if err != nil {
		return kustomRoot, repoRoot, []model.ResolverDiagnostic{{
			FilePath: filepath.Join(kustomRoot, kf),
			Message:  err.Error(),
			QueryID:  "kustomize-helm-prepass-failed",
			Line:     1,
		}}, nil
	}
	if err := CopyRepoRelativeFilesNoSymlinks(stagedRepo, repoRoot, stageRels); err != nil {
		return kustomRoot, repoRoot, []model.ResolverDiagnostic{{
			FilePath: filepath.Join(kustomRoot, kf),
			Message:  err.Error(),
			QueryID:  "kustomize-helm-prepass-failed",
			Line:     1,
		}}, nil
	}
	relFromRepo, err := filepath.Rel(repoRoot, kustomRoot)
	if err != nil || relFromRepo == relDotDot || strings.HasPrefix(relFromRepo, parentDirPrefix) {
		return kustomRoot, repoRoot, []model.ResolverDiagnostic{{
			FilePath: filepath.Join(kustomRoot, kf),
			Message:  "kustomization root is outside configured repo root",
			QueryID:  "kustomize-helm-prepass-failed",
			Line:     1,
		}}, nil
	}
	staging := filepath.Join(stagedRepo, relFromRepo)
	if maxStagingBytes > 0 {
		sz, err := DirTotalSize(stagedRepo)
		if err == nil && sz > maxStagingBytes {
			return kustomRoot, stagedRepo, []model.ResolverDiagnostic{{
				FilePath: filepath.Join(kustomRoot, kf),
				Message:  "helm prepass copy exceeds configured Kustomize max fetch bytes",
				QueryID:  "kustomize-max-fetch-exceeded",
				Line:     1,
			}}, ErrMaxStagingBytes
		}
	}

	configHome := filepath.Join(scratchDir, "helm-config")
	repoConfig := filepath.Join(configHome, "repositories.yaml")
	repoCache := filepath.Join(configHome, ".cache")
	registryConfig := filepath.Join(configHome, "registry", "config.json")
	_ = os.MkdirAll(filepath.Dir(repoConfig), dirPermCopyTree)
	_ = os.MkdirAll(repoCache, dirPermCopyTree)
	_ = os.MkdirAll(filepath.Dir(registryConfig), dirPermCopyTree)

	if err := WalkLocalKustomizations(staging, func(kustPath string, raw []byte) error {
		var err error
		diags, err = rewriteHelmChartsInKustomization(
			ctx, kustPath, raw, stagedRepo,
			helmIncludeCRDs, allowInflation,
			repoConfig, repoCache, registryConfig, diags,
		)
		return err
	}); err != nil {
		return kustomRoot, stagedRepo, diags, err
	}
	return staging, stagedRepo, diags, nil
}

func renderHelmChartEntries(
	ctx context.Context,
	hc []interface{},
	kustPath, kustDir, stagedRepo, genDir, chartHome string,
	helmIncludeCRDs bool,
	repoConfig, repoCache, registryConfig string,
	diags []model.ResolverDiagnostic,
) ([]string, []model.ResolverDiagnostic) {
	var newResources []string
	for i, item := range hc {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := entry["name"].(string)
		if name == "" {
			continue
		}
		repo, _ := entry["repo"].(string)
		version, _ := entry["version"].(string)

		chartPath, chartDiags, ok := resolveHelmChartPath(ctx, kustPath, stagedRepo, kustDir, chartHome, name, repo)
		diags = append(diags, chartDiags...)
		if !ok {
			continue
		}

		valuesFiles, err := helmValueFilesForEntry(stagedRepo, kustDir, entry)
		if err != nil {
			diags = append(diags, model.ResolverDiagnostic{
				FilePath: kustPath,
				Message:  err.Error(),
				QueryID:  "kustomize-helm-values-invalid",
				Line:     1,
			})
			continue
		}

		releaseName, _ := entry["releaseName"].(string)
		nameTemplate, _ := entry["nameTemplate"].(string)
		namespace, _ := entry["namespace"].(string)
		valuesInline := mapStringAny(entry["valuesInline"])
		valuesMerge, _ := entry["valuesMerge"].(string)
		apiVersions := stringSlice(entry["apiVersions"])
		kubeVersion, _ := entry["kubeVersion"].(string)
		devel, _ := entry["devel"].(bool)

		includeCRDs := helmIncludeCRDs
		if v, ok := entry["includeCRDs"].(bool); ok {
			includeCRDs = v
		}
		skipHooks := false
		if v, ok := entry["skipHooks"].(bool); ok && v {
			skipHooks = true
		}
		skipTests := false
		if v, ok := entry["skipTests"].(bool); ok && v {
			skipTests = true
		}

		rc, err := helm.RenderChart(ctx, &helm.RenderOptions{
			ChartPath:        chartPath,
			ChartRepo:        strings.TrimSpace(repo),
			ReleaseName:      strings.TrimSpace(releaseName),
			NameTemplate:     strings.TrimSpace(nameTemplate),
			Namespace:        strings.TrimSpace(namespace),
			ValuesFiles:      valuesFiles,
			ValuesInline:     valuesInline,
			ValuesMerge:      strings.TrimSpace(valuesMerge),
			IncludeCRDs:      includeCRDs,
			SkipHooks:        skipHooks,
			SkipTests:        skipTests,
			APIVersions:      apiVersions,
			KubeVersion:      strings.TrimSpace(kubeVersion),
			Version:          strings.TrimSpace(version),
			Devel:            devel,
			RepositoryConfig: repoConfig,
			RepositoryCache:  repoCache,
			RegistryConfig:   registryConfig,
		})
		if err != nil {
			diags = append(diags, model.ResolverDiagnostic{
				FilePath: kustPath,
				Message:  err.Error(),
				QueryID:  "kustomize-helm-render-failed",
				Line:     1,
			})
			continue
		}
		outPath := filepath.Join(genDir, filepath.Base(name)+"-"+strconv.Itoa(i)+".yaml")
		var blobs [][]byte
		for _, res := range rc.Resources {
			blobs = append(blobs, res.Content)
		}
		if err := os.WriteFile(outPath, joinYAML(blobs), filePermCopyTree); err != nil {
			diags = append(diags, model.ResolverDiagnostic{
				FilePath: outPath,
				Message:  err.Error(),
				QueryID:  "kustomize-helm-write-failed",
				Line:     1,
			})
			continue
		}
		rel, _ := filepath.Rel(kustDir, outPath)
		newResources = append(newResources, rel)
	}
	return newResources, diags
}

func rewriteHelmChartsInKustomization(
	ctx context.Context,
	kustPath string,
	raw []byte,
	stagedRepo string,
	helmIncludeCRDs, allowInflation bool,
	repoConfig, repoCache, registryConfig string,
	diags []model.ResolverDiagnostic,
) ([]model.ResolverDiagnostic, error) {
	var doc map[string]interface{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return diags, err
	}
	hc, _ := doc["helmCharts"].([]interface{})
	if len(hc) == 0 {
		return diags, nil
	}
	kustDir := filepath.Dir(kustPath)
	if !allowInflation {
		delete(doc, "helmCharts")
		delete(doc, "helmGlobals")
		outK, err := yaml.Marshal(doc)
		if err != nil {
			return diags, err
		}
		if err := os.WriteFile(kustPath, outK, filePermCopyTree); err != nil {
			return diags, err
		}
		return append(diags, model.ResolverDiagnostic{
			FilePath: kustPath,
			Message:  "kustomization declares helmCharts but Kustomize Helm inflation is disabled",
			QueryID:  "kustomize-helm-inflation-disabled",
			Line:     1,
		}), nil
	}

	chartHome := defaultHelmChartHome
	if g, ok := doc["helmGlobals"].(map[string]interface{}); ok {
		if ch, ok := g["chartHome"].(string); ok && ch != "" {
			chartHome = ch
		}
	}
	genDir := filepath.Join(kustDir, ".iac-scanner-helm-out")
	_ = os.MkdirAll(genDir, dirPermCopyTree)

	newResources, diags := renderHelmChartEntries(
		ctx, hc, kustPath, kustDir, stagedRepo, genDir, chartHome,
		helmIncludeCRDs, repoConfig, repoCache, registryConfig, diags,
	)

	delete(doc, "helmCharts")
	delete(doc, "helmGlobals")
	existing, _ := doc["resources"].([]interface{})
	resList := append([]interface{}(nil), existing...)
	for _, r := range newResources {
		resList = append(resList, r)
	}
	doc["resources"] = resList
	outK, err := yaml.Marshal(doc)
	if err != nil {
		return diags, err
	}
	if err := os.WriteFile(kustPath, outK, filePermCopyTree); err != nil {
		return diags, err
	}
	return diags, nil
}

func helmValueFilesForEntry(repoRoot, staging string, entry map[string]interface{}) ([]string, error) {
	var files []string
	if vf, ok := entry["valuesFile"].(string); ok && vf != "" {
		p, err := stagedHelmValuePath(repoRoot, staging, vf)
		if err != nil {
			return nil, err
		}
		files = append(files, p)
	}
	if av, ok := entry["additionalValuesFiles"].([]interface{}); ok {
		for _, x := range av {
			if s, ok := x.(string); ok && s != "" {
				p, err := stagedHelmValuePath(repoRoot, staging, s)
				if err != nil {
					return nil, err
				}
				files = append(files, p)
			}
		}
	}
	// Inline values go through RenderOptions.ValuesInline in helm.RenderChart, not ValueFiles here.
	return files, validateValuesMerge(entry)
}

func stagedHelmValuePath(stagedRepoRoot, staging, rel string) (string, error) {
	stagedRepoRoot = filepath.Clean(stagedRepoRoot)
	staging = filepath.Clean(staging)
	p := filepath.Clean(filepath.Join(staging, rel))
	if !isUnderRoot(p, stagedRepoRoot) {
		return "", fmt.Errorf("helm values file %q escapes the staged repo root", rel)
	}
	return p, nil
}

// stagedHelmChartPath resolves a local helmCharts entry to a path under
// stagedRepoRoot, rejecting "../" escapes via chartHome or name.
func stagedHelmChartPath(stagedRepoRoot, kustDir, chartHome, name string) (string, error) {
	stagedRepoRoot = filepath.Clean(stagedRepoRoot)
	kustDir = filepath.Clean(kustDir)
	p := filepath.Clean(filepath.Join(kustDir, chartHome, name))
	if !isUnderRoot(p, stagedRepoRoot) {
		return "", fmt.Errorf("helm chart %q (chartHome %q) escapes the staged repo root", name, chartHome)
	}
	return p, nil
}

// resolveHelmChartPath returns the chart locator for a helmCharts entry. For
// remote charts (repo != "") it is the chart name; for local charts it is the
// staged path. ok is false when the entry must be skipped.
func resolveHelmChartPath(
	ctx context.Context,
	kustPath, stagedRepo, kustDir, chartHome, name, repo string,
) (string, []model.ResolverDiagnostic, bool) {
	if strings.TrimSpace(repo) != "" {
		return name, nil, true
	}
	contextLogger := logger.FromContext(ctx)
	localPath, err := stagedHelmChartPath(stagedRepo, kustDir, chartHome, name)
	if err != nil {
		return "", []model.ResolverDiagnostic{{
			FilePath: kustPath,
			Message:  err.Error(),
			QueryID:  "kustomize-helm-chart-escape",
			Line:     1,
		}}, false
	}
	if _, err := os.Stat(localPath); err != nil {
		contextLogger.Warn().Msgf("kustomize helm chart not found at %s", localPath)
		return "", []model.ResolverDiagnostic{{
			FilePath: kustPath,
			Message:  "helm chart not found: " + localPath,
			QueryID:  "kustomize-helm-chart-missing",
			Line:     1,
		}}, false
	}
	return localPath, nil, true
}

func validateValuesMerge(entry map[string]interface{}) error {
	mode, _ := entry["valuesMerge"].(string)
	mode = strings.TrimSpace(mode)
	switch mode {
	case "", "merge", "override", "replace":
		return nil
	default:
		return fmt.Errorf("invalid valuesMerge %q (expected merge, override, or replace)", mode)
	}
}

func mapStringAny(v interface{}) map[string]interface{} {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return m
}

func stringSlice(v interface{}) []string {
	list, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func joinYAML(parts [][]byte) []byte {
	var b []byte
	for i, p := range parts {
		if i > 0 {
			b = append(b, "---\n"...)
		}
		b = append(b, p...)
		if len(p) > 0 && p[len(p)-1] != '\n' {
			b = append(b, '\n')
		}
	}
	return b
}
