package kustomize

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestResolver_KRMInlineEmitsDiagnostic(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	require.NoError(t, writeFile(filepath.Join(dir, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
generators:
- apiVersion: builtin
  kind: ConfigMapGenerator
  name: gen
resources: []
`))
	r := NewResolver(Options{RepoRoot: dir})
	out, err := r.Resolve(ctx, dir)
	require.NoError(t, err)
	var found bool
	for _, d := range out.Diagnostics {
		if d.QueryID == "kustomize-exec-plugin-disabled" {
			found = true
			break
		}
	}
	require.True(t, found, "expected kustomize-exec-plugin-disabled diagnostic")
}

func TestResolver_RemoteRefsDisallowed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	require.NoError(t, writeFile(filepath.Join(dir, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- https://example.com/some/base
`))
	r := NewResolver(Options{RepoRoot: dir})
	out, err := r.Resolve(ctx, dir)
	require.NoError(t, err)
	require.Empty(t, out.File)
	require.Len(t, out.Diagnostics, 1)
	require.Equal(t, "kustomize-remote-disallowed", out.Diagnostics[0].QueryID)
	require.Contains(t, out.Excluded, filepath.Join(dir, "kustomization.yaml"))
}

func TestResolver_RejectsLocalPathsOutsideRepoRoot(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, writeFile(filepath.Join(repo, "kustomization.yaml"), "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- "+filepath.Join(outside, "deployment.yaml")+"\n"))

	r := NewResolver(Options{RepoRoot: repo})
	out, err := r.Resolve(ctx, repo)
	require.NoError(t, err)
	require.Empty(t, out.File)
	require.NotEmpty(t, out.Diagnostics)
	require.Equal(t, "kustomize-render-failed", out.Diagnostics[len(out.Diagnostics)-1].QueryID)
}

func TestResolver_RemoteRefsDisallowedInNestedLocalBase(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	base := filepath.Join(repo, "base")
	root := filepath.Join(repo, "root")
	require.NoError(t, os.MkdirAll(base, 0o700))
	require.NoError(t, os.MkdirAll(root, 0o700))
	require.NoError(t, writeFile(filepath.Join(base, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- https://example.com/nested/remote
`))
	require.NoError(t, writeFile(filepath.Join(root, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base
`))

	r := NewResolver(Options{RepoRoot: repo})
	out, err := r.Resolve(ctx, root)
	require.NoError(t, err)
	require.Empty(t, out.File)
	require.Len(t, out.Diagnostics, 1)
	require.Equal(t, "kustomize-remote-disallowed", out.Diagnostics[0].QueryID)
	require.Equal(t, filepath.Join(base, "kustomization.yaml"), out.Diagnostics[0].FilePath)
}

func TestResolver_NamespaceFromOverlay(t *testing.T) {
	ctx := context.Background()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "test", "fixtures", "test_kustomize", "regressions", "namespace_overlay", "overlay"))
	require.NoError(t, err)
	repo, err := filepath.Abs(filepath.Join("..", "..", "..", "test", "fixtures", "test_kustomize", "regressions", "namespace_overlay"))
	require.NoError(t, err)

	r := NewResolver(Options{
		RepoRoot:           repo,
		AllowHelmInflation: false,
		RenderTimeout:      0,
		HelmIncludeCRDs:    true,
	})
	out, err := r.Resolve(ctx, root)
	require.NoError(t, err)
	require.Empty(t, out.Diagnostics, "%+v", out.Diagnostics)
	require.NotEmpty(t, out.File)

	var joined strings.Builder
	for _, f := range out.File {
		joined.Write(f.Content)
	}
	combined := joined.String()
	require.Contains(t, combined, "namespace: production")
}

func TestResolver_TransformerConfiguredInTracksBaseKustomization(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	base := filepath.Join(repo, "base")
	overlay := filepath.Join(repo, "overlay")
	require.NoError(t, os.MkdirAll(base, 0o700))
	require.NoError(t, os.MkdirAll(overlay, 0o700))

	require.NoError(t, writeFile(filepath.Join(base, "deployment.yaml"), `apiVersion: apps/v1
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
`))
	require.NoError(t, writeFile(filepath.Join(base, "patch.yaml"), `apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 5
`))
	require.NoError(t, writeFile(filepath.Join(base, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- deployment.yaml
patches:
- path: patch.yaml
`))
	require.NoError(t, writeFile(filepath.Join(overlay, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base
`))

	r := NewResolver(Options{
		RepoRoot:           repo,
		AllowHelmInflation: false,
		HelmIncludeCRDs:    true,
	})
	out, err := r.Resolve(ctx, overlay)
	require.NoError(t, err)
	require.Empty(t, out.Diagnostics, "%+v", out.Diagnostics)
	require.NotEmpty(t, out.File)

	found := false
	for _, f := range out.File {
		if f.Origin == nil || f.Origin.OriginKind != model.KustomizeOriginTransformer {
			continue
		}
		require.NotEmpty(t, f.Origin.Transformations)
		require.Equal(t, filepath.Join(base, "kustomization.yaml"), f.Origin.Transformations[0].ConfiguredIn)
		found = true
	}
	require.True(t, found, "expected transformed resource with base-owned configuredIn path")
}

func TestResolver_DirectOriginPreservesSourceBytes(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	root := filepath.Join(repo, "root")
	require.NoError(t, os.MkdirAll(root, 0o700))
	sourcePath := filepath.Join(root, "deployment.yaml")
	source := `# dd-iac-scan ignore-block
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 1
`
	require.NoError(t, writeFile(sourcePath, source))
	require.NoError(t, writeFile(filepath.Join(root, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- deployment.yaml
`))

	r := NewResolver(Options{RepoRoot: repo})
	out, err := r.Resolve(ctx, root)
	require.NoError(t, err)
	require.NotEmpty(t, out.File)
	require.Equal(t, sourcePath, out.File[0].FileName)
	require.Equal(t, source, string(out.File[0].OriginalData))
}

func TestResolver_TransformerOriginPreservesOriginalSourceBytes(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	base := filepath.Join(repo, "base")
	overlay := filepath.Join(repo, "overlay")
	require.NoError(t, os.MkdirAll(base, 0o700))
	require.NoError(t, os.MkdirAll(overlay, 0o700))
	source := `# dd-iac-scan ignore-block
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 1
`
	require.NoError(t, writeFile(filepath.Join(base, "deployment.yaml"), source))
	require.NoError(t, writeFile(filepath.Join(overlay, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base/deployment.yaml
namespace: prod
`))

	r := NewResolver(Options{RepoRoot: repo})
	out, err := r.Resolve(ctx, overlay)
	require.NoError(t, err)
	require.NotEmpty(t, out.File)
	require.Equal(t, source, string(out.File[0].OriginalData))
	require.NotNil(t, out.File[0].Origin)
	require.Equal(t, model.KustomizeOriginTransformer, out.File[0].Origin.OriginKind)
}

func TestRenderWithTimeout_KillsHelperProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	t.Setenv("KUSTOMIZE_HELPER_SLEEP_MS", "200")
	_, err := renderWithTimeout(ctx, t.TempDir(), t.TempDir(), false)
	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestResolver_ExcludedIncludesKustomizationAndUpwardBaseRefs(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	base := filepath.Join(repo, "base")
	overlay := filepath.Join(repo, "overlay")
	require.NoError(t, os.MkdirAll(base, 0o700))
	require.NoError(t, os.MkdirAll(overlay, 0o700))
	require.NoError(t, writeFile(filepath.Join(base, "deployment.yaml"), `apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 1
`))
	require.NoError(t, writeFile(filepath.Join(base, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- deployment.yaml
`))
	require.NoError(t, writeFile(filepath.Join(overlay, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base
`))

	r := NewResolver(Options{RepoRoot: repo})
	out, err := r.Resolve(ctx, overlay)
	require.NoError(t, err)
	require.Contains(t, out.Excluded, filepath.Join(overlay, "kustomization.yaml"))
	require.Contains(t, out.Excluded, filepath.Join(base))
}

func TestSourcePathForOutput_PreservesRemoteOriginPath(t *testing.T) {
	origin := &model.KustomizeOrigin{
		OriginKind: model.KustomizeOriginDirect,
		SourceFile: "https://github.com/org/repo/base/deployment.yaml",
		SourceRepo: "https://github.com/org/repo",
	}
	got := sourcePathForOutput(origin, "/tmp/local-root", nil)
	require.Equal(t, "https://github.com/org/repo/base/deployment.yaml", got)
}

func TestCleanLocalPath_PreservesRemoteTransformerURL(t *testing.T) {
	got := cleanLocalPath("https://github.com/org/repo/base/patch.yaml")
	require.Equal(t, "https://github.com/org/repo/base/patch.yaml", got)
}

func TestResolver_EffectiveRepoRoot_StaysWithinNeededSubtreeInsideGitRepo(t *testing.T) {
	repo := t.TempDir()
	overlay := filepath.Join(repo, "services", "app", "overlay")
	base := filepath.Join(repo, "services", "base")
	other := filepath.Join(repo, "other")
	require.NoError(t, os.MkdirAll(filepath.Join(repo, ".git"), 0o700))
	require.NoError(t, os.MkdirAll(overlay, 0o700))
	require.NoError(t, os.MkdirAll(base, 0o700))
	require.NoError(t, os.MkdirAll(other, 0o700))
	require.NoError(t, writeFile(filepath.Join(overlay, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../../base
`))

	r := NewResolver(Options{RepoRoot: repo})
	got := r.effectiveRepoRoot(overlay)
	require.Equal(t, filepath.Join(repo, "services"), got)
}

func TestResolver_EffectiveRepoRoot_DoesNotBroadenAcrossDistinctGitRepos(t *testing.T) {
	parent := t.TempDir()
	repoA := filepath.Join(parent, "repo-a")
	repoB := filepath.Join(parent, "repo-b")
	overlayA := filepath.Join(repoA, "overlay")
	require.NoError(t, os.MkdirAll(filepath.Join(repoA, ".git"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(repoB, ".git"), 0o700))
	require.NoError(t, os.MkdirAll(overlayA, 0o700))
	require.NoError(t, writeFile(filepath.Join(overlayA, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: []
`))

	r := NewResolver(Options{RepoRoot: parent})
	got := r.effectiveRepoRoot(overlayA)
	require.Equal(t, overlayA, got)
	require.NotEqual(t, parent, got)
}

func TestDetect(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeFile(filepath.Join(dir, "kustomization.yaml"), "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"))
	k, ok := Detect(dir)
	require.True(t, ok)
	require.Equal(t, string(model.KindKUSTOMIZE), string(k))
}

func writeFile(p, content string) error {
	return os.WriteFile(p, []byte(content), 0o600)
}
