package kustomize

import (
	"errors"
	"strings"

	"sigs.k8s.io/kustomize/api/provider"
	"sigs.k8s.io/kustomize/api/types"
)

// errRefused is returned for a kustomization that cannot be rendered safely.
// It never carries the offending value.
var errRefused = errors.New("kustomization refused")

// KustomizationFileNames are the file names Kustomize recognizes.
var KustomizationFileNames = []string{"kustomization.yaml", "kustomization.yml", "Kustomization"}

// IsKustomizationFile reports whether base is a name Kustomize loads.
func IsKustomizationFile(base string) bool {
	for _, n := range KustomizationFileNames {
		if base == n {
			return true
		}
	}
	return false
}

// decodeKustomization decodes and normalizes a kustomization, then refuses it
// when it could reach the network, run git or a plugin, read a path that is not
// plain and local, or change global OpenAPI state.
func decodeKustomization(content []byte) (*types.Kustomization, error) {
	var k types.Kustomization
	if err := k.Unmarshal(content); err != nil {
		return nil, errRefused
	}
	k.FixKustomization()
	if err := validateKustomization(&k); err != nil {
		return nil, err
	}
	return &k, nil
}

func validateKustomization(k *types.Kustomization) error {
	if len(k.OpenAPI) > 0 || len(k.Generators) > 0 || len(k.Transformers) > 0 || len(k.Validators) > 0 ||
		len(k.HelmCharts) > 0 || len(k.HelmChartInflationGenerator) > 0 || k.HelmGlobals != nil {
		return errRefused
	}
	return validatePaths(k)
}

// validatePaths checks every path-bearing entry of the kustomization is a
// plain local path.
func validatePaths(k *types.Kustomization) error {
	for _, p := range kustomizationPaths(k) {
		if p != "" && !isPlainLocalPath(p) {
			return errRefused
		}
	}
	return nil
}

// kustomizationPaths lists every path-bearing entry of the kustomization, as
// written: resources, bases, components, CRDs, configurations, patch,
// replacement and generator files.
func kustomizationPaths(k *types.Kustomization) []string {
	paths := make([]string, 0, len(k.Resources)+len(k.Components))
	paths = append(paths, k.Resources...)
	paths = append(paths, k.Bases...) //nolint:staticcheck // legacy kustomizations still declare bases
	paths = append(paths, k.Components...)
	paths = append(paths, k.Crds...)
	paths = append(paths, k.Configurations...)
	for _, p := range k.PatchesStrategicMerge { //nolint:staticcheck // legacy kustomizations still declare patchesStrategicMerge
		if !IsInlinePatch(string(p)) {
			paths = append(paths, string(p))
		}
	}
	for _, p := range k.Patches {
		paths = append(paths, p.Path)
	}
	for _, p := range k.PatchesJson6902 { //nolint:staticcheck // legacy kustomizations still declare patchesJson6902
		paths = append(paths, p.Path)
	}
	for _, r := range k.Replacements {
		paths = append(paths, r.Path)
	}
	for i := range k.ConfigMapGenerator {
		paths = appendGeneratorPaths(paths, &k.ConfigMapGenerator[i].GeneratorArgs)
	}
	for i := range k.SecretGenerator {
		paths = appendGeneratorPaths(paths, &k.SecretGenerator[i].GeneratorArgs)
	}
	return paths
}

var resourceFactory = provider.NewDefaultDepProvider().GetResourceFactory()

// IsInlinePatch reports whether Kustomize treats a patchesStrategicMerge entry
// as patch content: like PatchStrategicMergeTransformer, it first decodes the
// entry as resources and only loads it as a path when that fails.
func IsInlinePatch(entry string) bool {
	_, err := resourceFactory.SliceFromBytes([]byte(entry))
	return err == nil
}

func appendGeneratorPaths(paths []string, g *types.GeneratorArgs) []string {
	for _, f := range g.FileSources {
		if i := strings.Index(f, "="); i >= 0 {
			f = f[i+1:]
		}
		paths = append(paths, f)
	}
	paths = append(paths, g.EnvSources...)
	if g.EnvSource != "" {
		paths = append(paths, g.EnvSource)
	}
	return paths
}

// isPlainLocalPath accepts only relative paths that neither the HTTP loader nor
// the git repo-spec parser of Kustomize would treat as remote.
func isPlainLocalPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") {
		return false
	}
	if len(p) >= 2 && p[1] == ':' { // drive letter
		return false
	}
	if strings.ContainsAny(p, "@:?\\") || strings.Contains(p, "://") {
		return false
	}
	lower := strings.ToLower(p)
	if strings.HasPrefix(lower, "git::") {
		return false
	}
	first, _, _ := strings.Cut(lower, "/")
	return first != "github.com" && first != "gitlab.com" && first != "bitbucket.org"
}
