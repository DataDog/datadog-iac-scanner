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

func TestResolver_KRMInlineDoesNotFailScanPrep(t *testing.T) {
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
	require.Empty(t, out.File)
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
	require.Contains(t, out.Excluded, filepath.Join(dir, "kustomization.yaml"))
}

func TestResolver_LegacyHostStyleRemoteRefDisallowed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	require.NoError(t, writeFile(filepath.Join(dir, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- github.com/Liujingfang1/mysql?ref=test
`))
	r := NewResolver(Options{RepoRoot: dir})
	out, err := r.Resolve(ctx, dir)
	require.NoError(t, err)
	require.Empty(t, out.File)
	require.Contains(t, out.Excluded, filepath.Join(dir, "kustomization.yaml"))
}

func TestResolver_HelmChartsRemoteRepoNotPreRejectedWhenInflationDisabled(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	require.NoError(t, writeFile(filepath.Join(repo, "local.yaml"), `apiVersion: v1
kind: ConfigMap
metadata:
  name: keep-me
data:
  k: v
`))
	require.NoError(t, writeFile(filepath.Join(repo, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- local.yaml
helmCharts:
- name: mini
  repo: https://charts.example.com
  releaseName: rel
`))

	r := NewResolver(Options{RepoRoot: repo, AllowHelmInflation: false})
	out, err := r.Resolve(ctx, repo)
	require.NoError(t, err)

	var sawLocal bool
	for _, f := range out.File {
		if strings.Contains(f.FileName, "local.yaml") {
			sawLocal = true
		}
	}
	require.True(t, sawLocal, "%+v", out.File)
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
	require.Contains(t, out.Excluded, filepath.Join(base, "kustomization.yaml"))
}

func TestResolver_NamespaceFromOverlay(t *testing.T) {
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
	require.NoError(t, writeFile(filepath.Join(base, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- deployment.yaml
`))
	require.NoError(t, writeFile(filepath.Join(overlay, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base
namespace: production
`))

	r := NewResolver(Options{
		RepoRoot:           repo,
		AllowHelmInflation: false,
		RenderTimeout:      0,
		HelmIncludeCRDs:    true,
	})
	out, err := r.Resolve(ctx, overlay)
	require.NoError(t, err)
	require.NotEmpty(t, out.File)

	var joined strings.Builder
	for _, f := range out.File {
		joined.Write(f.Content)
	}
	combined := joined.String()
	require.Contains(t, combined, "namespace: production")
}

func TestResolver_NamespaceFromOverlay_FileInputPath(t *testing.T) {
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
	require.NoError(t, writeFile(filepath.Join(base, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- deployment.yaml
`))
	require.NoError(t, writeFile(filepath.Join(overlay, "kustomization.yaml"), `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../base
namespace: production
`))

	r := NewResolver(Options{
		RepoRoot:           repo,
		AllowHelmInflation: false,
		RenderTimeout:      0,
		HelmIncludeCRDs:    true,
	})
	out, err := r.Resolve(ctx, filepath.Join(overlay, "kustomization.yaml"))
	require.NoError(t, err)
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

func TestIsResolvedFileSafe(t *testing.T) {
	repo := t.TempDir()
	scratch := t.TempDir()
	other := t.TempDir()

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"empty", "", false},
		{"relative", "patch.yaml", false},
		{"remote URL", "https://example.com/patch.yaml", false},
		{"absolute outside roots", filepath.Join(other, "patch.yaml"), false},
		{"absolute under repo", filepath.Join(repo, "base", "patch.yaml"), true},
		{"absolute under scratch", filepath.Join(scratch, "kustomize-build", "x.yaml"), true},
		{"escapes via dotdot back into repo", filepath.Join(repo, "..", filepath.Base(repo), "x.yaml"), true},
		{"escapes via dotdot to host", filepath.Join(repo, "..", "..", "..", "etc", "passwd"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isResolvedFileSafe(tc.path, repo, scratch)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestSafeReadResolvedFile_RejectsOutOfRoot(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "secret")
	require.NoError(t, os.WriteFile(target, []byte("topsecret"), 0o600))

	_, ok := safeReadResolvedFile(target, repo)
	require.False(t, ok, "must not read host files outside configured roots")
}

func TestSafeReadResolvedFile_AllowsInRoot(t *testing.T) {
	repo := t.TempDir()
	target := filepath.Join(repo, "patch.yaml")
	require.NoError(t, os.WriteFile(target, []byte("payload"), 0o600))

	raw, ok := safeReadResolvedFile(target, repo, "")
	require.True(t, ok)
	require.Equal(t, "payload", string(raw))
}

func TestOriginalDataForResolvedResource_DropsOutOfRootSourceFile(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir()
	hostFile := filepath.Join(outside, "passwd")
	require.NoError(t, os.WriteFile(hostFile, []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o600))

	origin := &model.KustomizeOrigin{
		OriginKind: model.KustomizeOriginDirect,
		SourceFile: hostFile,
	}
	rendered := "kind: ConfigMap\n"
	got := originalDataForResolvedResource(origin, rendered, repo, "")
	require.Equal(t, rendered, string(got), "must not surface host file bytes as OriginalData")
}

func TestOriginalDataForResolvedResource_DropsOutOfRootOriginalSourceFile(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir()
	hostFile := filepath.Join(outside, "shadow")
	require.NoError(t, os.WriteFile(hostFile, []byte("hash"), 0o600))

	origin := &model.KustomizeOrigin{
		OriginKind:         model.KustomizeOriginTransformer,
		OriginalSourceFile: hostFile,
	}
	rendered := "kind: Deployment\n"
	got := originalDataForResolvedResource(origin, rendered, repo, "")
	require.Equal(t, rendered, string(got))
}

func TestAppendMissingTransformerPathDiags_SkipsOutOfRoot(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir()
	missingHostPath := filepath.Join(outside, "does-not-exist", "patch.yaml")

	origin := &model.KustomizeOrigin{
		OriginKind:          model.KustomizeOriginTransformer,
		GeneratorConfigFile: filepath.Join(repo, "kustomization.yaml"),
		Transformations: []model.KustomizeTransformation{
			{TransformerPath: missingHostPath, FieldPath: "patches[0].path"},
		},
	}
	got := appendMissingTransformerPathDiags(origin, repo, "", map[string]struct{}{}, nil)
	require.Empty(t, got, "must not emit diagnostics that surface attacker-controlled host paths")
}

func TestOriginalDataForResolvedResource_ReadsInRootSourceFile(t *testing.T) {
	repo := t.TempDir()
	srcPath := filepath.Join(repo, "deployment.yaml")
	src := "kind: Deployment\nmetadata:\n  name: app\n"
	require.NoError(t, os.WriteFile(srcPath, []byte(src), 0o600))

	origin := &model.KustomizeOrigin{
		OriginKind: model.KustomizeOriginDirect,
		SourceFile: srcPath,
	}
	got := originalDataForResolvedResource(origin, "rendered", repo, "")
	require.Equal(t, src, string(got))
}

func writeFile(p, content string) error {
	return os.WriteFile(p, []byte(content), 0o600)
}
