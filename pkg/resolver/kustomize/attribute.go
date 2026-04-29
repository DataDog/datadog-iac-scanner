package kustomize

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"sigs.k8s.io/kustomize/api/konfig"
	"sigs.k8s.io/kustomize/api/resource"
)

// TransformerAnnotationKey is the alpha transformation-chain annotation (must match upstream; see konfig_constants_test).
const TransformerAnnotationKey = "alpha.config.kubernetes.io/transformations"

func helmInflatedOrigin(res *resource.Resource, kustAbs string) *model.KustomizeOrigin {
	ann := res.GetAnnotations()
	if ann == nil {
		return nil
	}
	if _, ok := ann[konfig.HelmGeneratedAnnotation]; !ok {
		return nil
	}
	return &model.KustomizeOrigin{
		OriginKind:          model.KustomizeOriginHelmInflated,
		GeneratorConfigFile: kustAbs,
		ResourceGVK:         res.GetGvk().String(),
		ResourceName:        res.GetName(),
	}
}

func appendTransformationFromOrigin(
	chain []model.KustomizeTransformation,
	t *resource.Origin,
	kustomizationDir, origSourceRepo string,
) []model.KustomizeTransformation {
	if t == nil {
		return chain
	}
	configuredIn := ""
	if t.ConfiguredIn != "" {
		configuredIn = t.ConfiguredIn
		if origSourceRepo != "" {
			configuredIn = joinRepoURL(origSourceRepo, configuredIn)
		} else if !filepath.IsAbs(configuredIn) {
			configuredIn = filepath.Join(kustomizationDir, filepath.Clean(configuredIn))
		}
	}
	transformerPath := resolveOriginPath(kustomizationDir, origSourceRepo, t.Path)
	if configuredIn != "" && t.Path != "" && !looksLikeRemotePath(configuredIn) {
		transformerPath = filepath.Join(filepath.Dir(configuredIn), filepath.Clean(t.Path))
	} else if configuredIn != "" && t.Path != "" && looksLikeRemotePath(configuredIn) {
		transformerPath = joinRepoURL(dirURL(configuredIn), t.Path)
	}
	return append(chain, model.KustomizeTransformation{
		TransformerPath: cleanLocalPath(transformerPath),
		ConfiguredIn:    configuredIn,
		FieldPath:       t.Path,
	})
}

func transformerOrigin(res *resource.Resource, kustomizationDir, kustAbs string) *model.KustomizeOrigin {
	trans, err := res.GetTransformations()
	if err != nil || len(trans) == 0 {
		return nil
	}
	origSourceFile, origSourceRepo, origSourceRef := "", "", ""
	if origin, originErr := res.GetOrigin(); originErr == nil && origin != nil && origin.Path != "" {
		origSourceFile = resolveOriginPath(kustomizationDir, origin.Repo, origin.Path)
		origSourceRepo = origin.Repo
		origSourceRef = origin.Ref
	}
	var chain []model.KustomizeTransformation
	for _, t := range trans {
		chain = appendTransformationFromOrigin(chain, t, kustomizationDir, origSourceRepo)
	}
	return &model.KustomizeOrigin{
		OriginKind:          model.KustomizeOriginTransformer,
		GeneratorConfigFile: kustAbs,
		Transformations:     chain,
		OriginalSourceFile:  origSourceFile,
		OriginalSourceRepo:  origSourceRepo,
		OriginalSourceRef:   origSourceRef,
		ResourceGVK:         res.GetGvk().String(),
		ResourceName:        res.GetName(),
	}
}

// OriginFromResource builds KustomizeOrigin from kustomize API resource metadata.
func OriginFromResource(res *resource.Resource, kustomizationDir string) *model.KustomizeOrigin {
	if res == nil {
		return nil
	}
	kustFile := kustomizationEntryFile(kustomizationDir)
	kustAbs := filepath.Join(kustomizationDir, kustFile)

	if o := helmInflatedOrigin(res, kustAbs); o != nil {
		return o
	}
	if o := transformerOrigin(res, kustomizationDir, kustAbs); o != nil {
		return o
	}

	origin, err := res.GetOrigin()
	if err != nil || origin == nil {
		return &model.KustomizeOrigin{
			OriginKind:          model.KustomizeOriginDirect,
			GeneratorConfigFile: kustAbs,
			ResourceGVK:         res.GetGvk().String(),
			ResourceName:        res.GetName(),
		}
	}

	cbKind := origin.ConfiguredBy.GetKind()
	cbName := origin.ConfiguredBy.GetName()
	if origin.ConfiguredIn != "" && isGeneratorConfiguredKind(cbKind) {
		cfg := origin.ConfiguredIn
		if !filepath.IsAbs(cfg) {
			cfg = filepath.Join(kustomizationDir, cfg)
		}
		return &model.KustomizeOrigin{
			OriginKind:          model.KustomizeOriginGenerator,
			GeneratorKind:       cbKind,
			ConfiguredByKind:    cbKind,
			ConfiguredByName:    cbName,
			GeneratorConfigFile: cfg,
			ResourceGVK:         res.GetGvk().String(),
			ResourceName:        generatorResourceName(res),
		}
	}

	if origin.Path != "" {
		sf := resolveOriginPath(kustomizationDir, origin.Repo, origin.Path)
		return &model.KustomizeOrigin{
			OriginKind:          model.KustomizeOriginDirect,
			SourceFile:          sf,
			SourceRepo:          origin.Repo,
			SourceRef:           origin.Ref,
			ResourceGVK:         res.GetGvk().String(),
			ResourceName:        res.GetName(),
			GeneratorConfigFile: kustAbs,
		}
	}

	return &model.KustomizeOrigin{
		OriginKind:          model.KustomizeOriginDirect,
		GeneratorConfigFile: kustAbs,
		ResourceGVK:         res.GetGvk().String(),
		ResourceName:        res.GetName(),
	}
}

func resolveOriginPath(kustomizationDir, repo, path string) string {
	if path == "" {
		return ""
	}
	if repo != "" {
		return joinRepoURL(repo, path)
	}
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(kustomizationDir, path)
}

func looksLikeRemotePath(path string) bool {
	return strings.Contains(path, "://")
}

func joinRepoURL(base, rel string) string {
	if base == "" {
		return rel
	}
	if rel == "" {
		return base
	}
	if looksLikeRemotePath(rel) {
		return rel
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(filepath.ToSlash(rel), "/")
}

func dirURL(path string) string {
	if !looksLikeRemotePath(path) {
		return filepath.Dir(path)
	}
	path = strings.TrimRight(path, "/")
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return path
	}
	return path[:idx]
}

func cleanLocalPath(path string) string {
	if looksLikeRemotePath(path) {
		return path
	}
	return filepath.Clean(path)
}

func isGeneratorConfiguredKind(kind string) bool {
	k := strings.ToLower(kind)
	if k == "" {
		return false
	}
	return strings.Contains(k, "generator")
}

func kustomizationEntryFile(dir string) string {
	for _, n := range kustomizationNames {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			return n
		}
	}
	return "kustomization.yaml"
}
