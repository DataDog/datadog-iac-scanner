package kustomize

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	resolverkustomize "github.com/DataDog/datadog-iac-scanner/pkg/resolver/kustomize"
	"github.com/stretchr/testify/require"
)

func TestDetectKindLine_Delegates(t *testing.T) {
	ctx := context.Background()
	lines := []string{"a: 1", "b: 2"}
	f := &model.FileMetadata{
		Kind:              model.KindKUSTOMIZE,
		FilePath:          "x.yaml",
		LinesOriginalData: &lines,
		LineInfoDocument:  map[string]interface{}{"a": map[string]interface{}{"_kics_line": float64(1)}},
		Document:          map[string]interface{}{"a": 1},
	}
	v := DetectKindLine{}.DetectLine(ctx, f, "a", 1)
	require.Equal(t, "x.yaml", v.ResolvedFile)
	require.NotEqual(t, -1, v.Line)
}

func TestTransformerLineForOrigin_prefersPatchPathLine(t *testing.T) {
	dir := t.TempDir()
	kust := filepath.Join(dir, "kustomization.yaml")
	content := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\npatches:\n- path: p.yaml\n"
	require.NoError(t, os.WriteFile(kust, []byte(content), 0o600))
	patchPath := filepath.Join(dir, "p.yaml")
	o := &model.KustomizeOrigin{
		OriginKind:          model.KustomizeOriginTransformer,
		GeneratorConfigFile: kust,
		Transformations:     []model.KustomizeTransformation{{TransformerPath: patchPath}},
	}
	line, p := transformerLineForOrigin(o)
	require.Equal(t, kust, p)
	require.Equal(t, 4, line, "should point at the list entry referencing the patch file")
}

func TestDirectSourceDetectLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "d.yaml")
	require.NoError(t, os.WriteFile(p, []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: n\nspec:\n  replicas: 1\n"), 0o600))
	v := directSourceDetectLine(p, "metadata.name", 1)
	require.Equal(t, 4, v.Line)
	require.Equal(t, p, v.ResolvedFile)
}

func TestDirectSourceDetectLine_ASTNestedSequence(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "d.yaml")
	require.NoError(t, os.WriteFile(p, []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: n\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx:1.0\n"), 0o600))
	v := directSourceDetectLine(p, "spec.template.spec.containers[0].image", 3)
	require.Equal(t, 10, v.Line)
	require.Equal(t, "image: nginx:1.0", v.LineWithVulnerability)
	require.Equal(t, p, v.ResolvedFile)
}

func TestTransformerPatchFileLine_nestedContainersUsesAST(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	kust := filepath.Join(dir, "kustomization.yaml")
	patchPath := filepath.Join(dir, "patch.yaml")
	require.NoError(t, os.WriteFile(kust, []byte("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\npatches:\n- path: patch.yaml\n"), 0o600))
	patchYAML := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
      - name: sidecar
        image: alpine:3
      - name: app
        image: nginx:bad
`
	require.NoError(t, os.WriteFile(patchPath, []byte(patchYAML), 0o600))
	v := transformerPatchFileLine(ctx, &model.KustomizeOrigin{
		OriginKind:          model.KustomizeOriginTransformer,
		GeneratorConfigFile: kust,
		Transformations: []model.KustomizeTransformation{
			{TransformerPath: patchPath},
		},
	}, "spec.template.spec.containers[1].image", 3)
	require.Equal(t, 12, v.Line)
	require.Equal(t, patchPath, v.ResolvedFile)
	require.Contains(t, v.LineWithVulnerability, "nginx:bad")
}

func TestTransformerPatchFileLine_prefersPatchFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	kust := filepath.Join(dir, "kustomization.yaml")
	patchPath := filepath.Join(dir, "patch.yaml")
	require.NoError(t, os.WriteFile(kust, []byte("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\npatches:\n- path: patch.yaml\n"), 0o600))
	require.NoError(t, os.WriteFile(patchPath, []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  replicas: 3\n"), 0o600))
	v := transformerPatchFileLine(ctx, &model.KustomizeOrigin{
		OriginKind:          model.KustomizeOriginTransformer,
		GeneratorConfigFile: kust,
		Transformations: []model.KustomizeTransformation{
			{TransformerPath: patchPath},
		},
	}, "spec.replicas", 3)
	require.Equal(t, 6, v.Line)
	require.Equal(t, patchPath, v.ResolvedFile)
	require.Equal(t, "replicas: 3", v.LineWithVulnerability)
}

func TestTransformerPatchFileLine_usesConfiguredInBaseKustomization(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	base := filepath.Join(repo, "base")
	overlay := filepath.Join(repo, "overlay")
	require.NoError(t, os.MkdirAll(base, 0o700))
	require.NoError(t, os.MkdirAll(overlay, 0o700))

	baseKust := filepath.Join(base, "kustomization.yaml")
	basePatch := filepath.Join(base, "patch.yaml")
	require.NoError(t, os.WriteFile(baseKust, []byte("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\npatches:\n- path: patch.yaml\n"), 0o600))
	require.NoError(t, os.WriteFile(basePatch, []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  replicas: 7\n"), 0o600))

	v := transformerPatchFileLine(ctx, &model.KustomizeOrigin{
		OriginKind:          model.KustomizeOriginTransformer,
		GeneratorConfigFile: filepath.Join(overlay, "kustomization.yaml"),
		Transformations: []model.KustomizeTransformation{
			{
				TransformerPath: filepath.Join(overlay, "patch.yaml"),
				ConfiguredIn:    baseKust,
				FieldPath:       "patch.yaml",
			},
		},
	}, "spec.replicas", 3)
	require.Equal(t, 6, v.Line)
	require.Equal(t, basePatch, v.ResolvedFile)
	require.Equal(t, "replicas: 7", v.LineWithVulnerability)
}

func TestTransformerPatchFileLine_DoesNotProbeUnrelatedPatchFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	kust := filepath.Join(dir, "kustomization.yaml")
	patchA := filepath.Join(dir, "patch-a.yaml")
	patchB := filepath.Join(dir, "patch-b.yaml")
	require.NoError(t, os.WriteFile(kust, []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
patches:
- path: patch-a.yaml
- path: patch-b.yaml
`), 0o600))
	require.NoError(t, os.WriteFile(patchA, []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 3
`), 0o600))
	require.NoError(t, os.WriteFile(patchB, []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 9
`), 0o600))

	v := transformerPatchFileLine(ctx, &model.KustomizeOrigin{
		OriginKind:          model.KustomizeOriginTransformer,
		GeneratorConfigFile: kust,
		Transformations: []model.KustomizeTransformation{
			{TransformerPath: patchA, FieldPath: "patch-a.yaml"},
		},
	}, "spec.replicas", 3)
	require.Equal(t, patchA, v.ResolvedFile)
	require.Equal(t, "replicas: 3", v.LineWithVulnerability)
}

func TestDetectKindLine_GeneratorOrigin(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	kust := filepath.Join(dir, "kustomization.yaml")
	content := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nconfigMapGenerator:\n- name: my-map\n  literals:\n  - k=v\n"
	require.NoError(t, os.WriteFile(kust, []byte(content), 0o600))

	lines := []string{"apiVersion: v1", "kind: ConfigMap", "metadata:", "  name: my-map"}
	f := &model.FileMetadata{
		Kind:              model.KindKUSTOMIZE,
		FilePath:          filepath.Join(dir, "generated.yaml"),
		LinesOriginalData: &lines,
		Document: map[string]interface{}{
			"metadata": map[string]interface{}{"name": "my-map"},
		},
		KustomizeOrigin: &model.KustomizeOrigin{
			OriginKind:          model.KustomizeOriginGenerator,
			GeneratorConfigFile: kust,
			ResourceName:        "my-map",
		},
	}
	v := DetectKindLine{}.DetectLine(ctx, f, "data.k", 1)
	require.Equal(t, kust, v.ResolvedFile)
	require.Equal(t, 4, v.Line, "line should point at the list item declaring the generator name")
}

func TestDetectKindLine_DirectRemoteOrigin_DoesNotTreatURLAsLocalPath(t *testing.T) {
	ctx := context.Background()
	lines := []string{"apiVersion: apps/v1", "kind: Deployment"}
	f := &model.FileMetadata{
		Kind:              model.KindKUSTOMIZE,
		FilePath:          "rendered.yaml",
		LinesOriginalData: &lines,
		Document:          map[string]interface{}{"kind": "Deployment"},
		KustomizeOrigin: &model.KustomizeOrigin{
			OriginKind: model.KustomizeOriginDirect,
			SourceFile: "https://github.com/org/repo/base/deployment.yaml",
			SourceRepo: "https://github.com/org/repo",
		},
	}
	v := DetectKindLine{}.DetectLine(ctx, f, "kind", 1)
	require.Equal(t, "rendered.yaml", v.ResolvedFile)
}

func TestDetectKindLine_TransformerBaseOwnedPatchResolvesIntoBasePatchFile(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	base := filepath.Join(repo, "base")
	overlay := filepath.Join(repo, "overlay")
	require.NoError(t, os.MkdirAll(base, 0o700))
	require.NoError(t, os.MkdirAll(overlay, 0o700))

	require.NoError(t, os.WriteFile(filepath.Join(base, "deployment.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      containers:
      - name: app
        image: nginx
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(base, "patch.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 9
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(base, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- deployment.yaml
patches:
- path: patch.yaml
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(overlay, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base
`), 0o600))

	r := resolverkustomize.NewResolver(resolverkustomize.Options{
		RepoRoot:           repo,
		AllowHelmInflation: false,
		HelmIncludeCRDs:    true,
	})
	out, err := r.Resolve(ctx, overlay)
	require.NoError(t, err)
	require.Empty(t, out.Diagnostics, "%+v", out.Diagnostics)
	require.Len(t, out.File, 1)
	require.NotNil(t, out.File[0].Origin)

	lines := strings.Split(string(out.File[0].Content), "\n")
	f := &model.FileMetadata{
		Kind:              model.KindKUSTOMIZE,
		FilePath:          out.File[0].FileName,
		LinesOriginalData: &lines,
		Document: map[string]interface{}{
			"spec": map[string]interface{}{
				"replicas": 9,
			},
		},
		KustomizeOrigin: out.File[0].Origin,
	}
	v := DetectKindLine{}.DetectLine(ctx, f, "spec.replicas", 1)
	require.Equal(t, filepath.Join(base, "patch.yaml"), v.ResolvedFile)
	require.Equal(t, 6, v.Line)
	require.Equal(t, "replicas: 9", v.LineWithVulnerability)
}

func TestDetectKindLine_TransformerFallsBackToOriginalSourceForUntouchedField(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	base := filepath.Join(repo, "base")
	overlay := filepath.Join(repo, "overlay")
	require.NoError(t, os.MkdirAll(base, 0o700))
	require.NoError(t, os.MkdirAll(overlay, 0o700))

	baseDeployment := filepath.Join(base, "deployment.yaml")
	require.NoError(t, os.WriteFile(baseDeployment, []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      containers:
      - name: app
        image: nginx
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(base, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- deployment.yaml
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(overlay, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base
namespace: prod
`), 0o600))

	r := resolverkustomize.NewResolver(resolverkustomize.Options{
		RepoRoot:           repo,
		AllowHelmInflation: false,
		HelmIncludeCRDs:    true,
	})
	out, err := r.Resolve(ctx, overlay)
	require.NoError(t, err)
	require.Empty(t, out.Diagnostics, "%+v", out.Diagnostics)
	require.Len(t, out.File, 1)
	require.NotNil(t, out.File[0].Origin)
	require.Equal(t, model.KustomizeOriginTransformer, out.File[0].Origin.OriginKind)

	lines := strings.Split(string(out.File[0].Content), "\n")
	f := &model.FileMetadata{
		Kind:              model.KindKUSTOMIZE,
		FilePath:          out.File[0].FileName,
		LinesOriginalData: &lines,
		Document: map[string]interface{}{
			"spec": map[string]interface{}{
				"replicas": 3,
			},
		},
		KustomizeOrigin: out.File[0].Origin,
	}
	v := DetectKindLine{}.DetectLine(ctx, f, "spec.replicas", 1)
	require.Equal(t, baseDeployment, v.ResolvedFile)
	require.Equal(t, 6, v.Line)
	require.Equal(t, "replicas: 3", v.LineWithVulnerability)
}
