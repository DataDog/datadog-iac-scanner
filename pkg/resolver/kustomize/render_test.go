package kustomize

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"sigs.k8s.io/kustomize/api/resmap"
	"sigs.k8s.io/kustomize/api/resource"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	for p, c := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const deployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          image: nginx
---
apiVersion: v1
kind: Service
metadata:
  name: web
`

func baseTree() map[string]string {
	return map[string]string{
		"base/kustomization.yaml":         "resources:\n  - deployment.yaml\n",
		"base/deployment.yaml":            deployment,
		"overlays/dev/kustomization.yaml": "namePrefix: dev-\nnamespace: dev\nresources:\n  - ../../base\n",
		"overlays/prod/kustomization.yaml": `nameSuffix: -prod
resources:
  - ../../base
components:
  - ../../components/extra
configMapGenerator:
  - name: settings
    literals:
      - SECRET=canary-literal-value
`,
		"components/extra/kustomization.yaml": "apiVersion: kustomize.config.k8s.io/v1alpha1\nkind: Component\nresources:\n  - cm.yaml\n",
		"components/extra/cm.yaml":            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: extra\n",
	}
}

func render(t *testing.T, dir, root string) (*Result, error) {
	t.Helper()
	return NewRenderer(vfs.Default(), dir, 5<<20).Render(context.Background(), filepath.Join(dir, root))
}

func TestRenderAttributesSources(t *testing.T) {
	dir := writeTree(t, baseTree())
	res, err := render(t, dir, "overlays/prod")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range res.Documents {
		a := d.Kustomize
		rel, _ := filepath.Rel(dir, d.FileName)
		got[a.Kind+"/"+a.RenderedName] = filepath.ToSlash(rel) + "#" + a.SourceName
		if strings.Contains(string(d.Content), originAnnotation) {
			t.Errorf("origin annotation left in %s", a.RenderedName)
		}
		if a.Generator == nil && d.SourceDocumentIndex < 0 {
			t.Errorf("%s: no source document", a.RenderedName)
		}
	}
	want := map[string]string{
		"Deployment/web-prod":  "base/deployment.yaml#web",
		"Service/web-prod":     "base/deployment.yaml#web",
		"ConfigMap/extra-prod": "components/extra/cm.yaml#extra",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	var gen bool
	for k, v := range got {
		if strings.HasPrefix(k, "ConfigMap/settings-prod-") {
			gen = v == "overlays/prod/kustomization.yaml#settings"
		}
	}
	if !gen {
		t.Errorf("generated config map not attributed to its kustomization: %v", got)
	}
	if res.MappingFailures != 0 {
		t.Errorf("mapping failures: %d", res.MappingFailures)
	}
}

func TestRenderReadSetAndCacheKeepOriginal(t *testing.T) {
	dir := writeTree(t, baseTree())
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	res, err := r.Render(context.Background(), filepath.Join(dir, "overlays/dev"))
	if err != nil {
		t.Fatal(err)
	}
	var rels []string
	for _, p := range res.Reads {
		rel, _ := filepath.Rel(dir, p)
		rels = append(rels, filepath.ToSlash(rel))
	}
	want := "base/deployment.yaml,base/kustomization.yaml,overlays/dev/kustomization.yaml"
	if strings.Join(rels, ",") != want {
		t.Errorf("reads: %v", rels)
	}
	b, _ := r.Source(filepath.Join(dir, "overlays/dev/kustomization.yaml"))
	if strings.Contains(string(b), "originAnnotations") {
		t.Error("cache holds the annotated copy")
	}
	for _, d := range res.Documents {
		if d.Kustomize.RenderedNamespace != "dev" || !strings.HasPrefix(d.Kustomize.RenderedName, "dev-") {
			t.Errorf("unexpected %+v", d.Kustomize)
		}
	}
}

func TestRenderRefusals(t *testing.T) {
	cases := map[string]struct {
		files  map[string]string
		reason string
	}{
		"remote resource in nested base": {map[string]string{
			"o/kustomization.yaml": "resources:\n  - ../b\n",
			"b/kustomization.yaml": "resources:\n  - https://example.invalid/x.yaml\n",
		}, ReasonValidation},
		"openapi":  {map[string]string{"o/kustomization.yaml": "openapi:\n  path: schema.json\n"}, ReasonValidation},
		"helm":     {map[string]string{"o/kustomization.yaml": "helmCharts:\n  - name: x\n"}, ReasonValidation},
		"plugin":   {map[string]string{"o/kustomization.yaml": "generators:\n  - gen.yaml\n"}, ReasonValidation},
		"absolute": {map[string]string{"o/kustomization.yaml": "resources:\n  - /etc/passwd\n"}, ReasonValidation},
		"escape": {map[string]string{"o/kustomization.yaml": "resources:\n  - ../../../../../../../../etc/hosts\n"},
			ReasonValidation},
		"oversized": {map[string]string{
			"o/kustomization.yaml": "resources:\n  - big.yaml\n",
			"o/big.yaml":           "a: " + strings.Repeat("x", 2<<20) + "\n",
		}, ReasonSizeLimit},
		"no kustomization": {map[string]string{"o/x.yaml": "a: b\n"}, ReasonMissingFile},
		"broken":           {map[string]string{"o/kustomization.yaml": "resources:\n  - missing.yaml\n"}, ReasonRenderError},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, c.files)
			_, err := NewRenderer(vfs.Default(), dir, 1<<20).Render(context.Background(), filepath.Join(dir, "o"))
			var re *RenderError
			if !errors.As(err, &re) || re.Reason != c.reason {
				t.Fatalf("got %v, want %s", err, c.reason)
			}
		})
	}
}

func TestRenderSymlinkEscapeRefused(t *testing.T) {
	outside := writeTree(t, map[string]string{"secret.yaml": deployment})
	dir := writeTree(t, map[string]string{"o/kustomization.yaml": "resources:\n  - link.yaml\n"})
	if err := os.Symlink(filepath.Join(outside, "secret.yaml"), filepath.Join(dir, "o/link.yaml")); err != nil {
		t.Skip(err)
	}
	for _, fsys := range []vfs.FS{vfs.DiskFS{}, &vfs.DiskFS{}} {
		if _, err := NewRenderer(fsys, dir, 5<<20).Render(context.Background(), filepath.Join(dir, "o")); err == nil {
			t.Fatalf("%T: symlink outside the root was followed", fsys)
		}
	}
}

func TestRenderBudget(t *testing.T) {
	dir := writeTree(t, baseTree())
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	r.cache.served = maxServedBytes - 10
	_, err := r.Render(context.Background(), filepath.Join(dir, "overlays/dev"))
	var re *RenderError
	if !errors.As(err, &re) || re.Reason != ReasonBudget {
		t.Fatalf("got %v", err)
	}
}

// TestRenderNoEgress points every proxy at a listener and PATH at a failing
// git: no remote reference may reach either.
func TestRenderNoEgress(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake git helper requires a POSIX shell")
	}
	var hits atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	bin := t.TempDir()
	marker := filepath.Join(bin, "git-ran")
	// Shell builtins only: PATH holds the fake git alone, so `touch` may not
	// exist and the marker must not depend on it.
	if err := os.WriteFile(filepath.Join(bin, "git"),
		[]byte("#!/bin/sh\necho ran > "+marker+"\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Prove the trap works: the fake git, actually invoked, leaves its marker
	// (it exits 1 on purpose, so the exit status proves nothing).
	if out, err := exec.Command(filepath.Join(bin, "git")).CombinedOutput(); err == nil {
		t.Fatalf("fake git exited 0: %s", out)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("fake git marker missing after direct invocation: %v", err)
	}
	_ = os.Remove(marker)
	t.Setenv("HTTP_PROXY", "http://"+ln.Addr().String())
	t.Setenv("HTTPS_PROXY", "http://"+ln.Addr().String())
	t.Setenv("PATH", bin)
	refs := []string{
		"resources:\n  - https://example.com/x.yaml\n",
		"resources:\n  - github.com/org/repo//base?ref=v1\n",
		"resources:\n  - git::https://example.com/repo\n",
		"components:\n  - git@github.com:org/repo\n",
		"crds:\n  - http://example.com/crd.yaml\n",
		"configurations:\n  - http://example.com/c.yaml\n",
		"patches:\n  - path: https://example.com/p.yaml\n",
		"patchesStrategicMerge:\n  - https://example.com/p.yaml\n",
		"patchesJson6902:\n  - path: https://example.com/p.yaml\n    target: {kind: X, name: y}\n",
		"replacements:\n  - path: https://example.com/r.yaml\n",
		"configMapGenerator:\n  - name: c\n    files:\n      - k=https://example.com/f\n",
		"secretGenerator:\n  - name: c\n    envs:\n      - https://example.com/e\n",
		"bases:\n  - https://example.com/base\n",
	}
	for _, ref := range refs {
		dir := writeTree(t, map[string]string{"o/kustomization.yaml": ref})
		if _, err := render(t, dir, "o"); err == nil {
			t.Errorf("rendered %q", ref)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("%d requests reached the proxy", hits.Load())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("git ran")
	}
}

// TestRenderSymlinkRoleValidation refuses a kustomization reached through a
// symlink to an ordinary file: the requested role, not the target's name,
// decides validation, so a remote reference inside it never loads.
func TestRenderSymlinkRoleValidation(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
		"o/plain.txt":       "resources:\n  - https://example.com/x.yaml\n",
	})
	if err := os.Symlink(filepath.Join(dir, "o/plain.txt"), filepath.Join(dir, "o/kustomization.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := render(t, dir, "o"); err == nil {
		t.Fatal("rendered a symlinked kustomization without validation")
	}
}

// TestRenderNestedSymlinkNoEgress refuses a kustomization reached through
// nested symlinks that end outside the confinement root, with live HTTP and
// git traps: the escaped file is never read and no remote is contacted.
func TestRenderNestedSymlinkNoEgress(t *testing.T) {
	var hits atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	bin := t.TempDir()
	marker := filepath.Join(bin, "git-ran")
	if err := os.WriteFile(filepath.Join(bin, "git"),
		[]byte("#!/bin/sh\necho ran > "+marker+"\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HTTP_PROXY", "http://"+ln.Addr().String())
	t.Setenv("HTTPS_PROXY", "http://"+ln.Addr().String())
	t.Setenv("PATH", bin)

	outside := t.TempDir()
	escaped := filepath.Join(outside, "escape.yaml")
	// The escaped file orders a remote fetch: reading it would mean egress.
	if err := os.WriteFile(escaped, []byte("resources:\n  - https://example.invalid/x.yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := writeTree(t, map[string]string{
		"o/dep.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
	})
	// o/link2 -> outside/escape.yaml, o/link1 -> link2, resource -> link1:
	// two symlink hops ending outside the root.
	if err := os.Symlink(escaped, filepath.Join(dir, "o/link2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "o/link2"), filepath.Join(dir, "o/link1")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "o/kustomization.yaml"),
		[]byte("resources:\n  - dep.yaml\n  - link1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := render(t, dir, "o"); err == nil {
		t.Fatal("rendered a resource outside the confinement root")
	}
	if hits.Load() != 0 {
		t.Errorf("%d requests reached the proxy", hits.Load())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("git ran")
	}
	// The root kustomization itself must not be reachable through an outside
	// symlink either: preparation probes through the confined resolve.
	dir2 := writeTree(t, map[string]string{
		"o/dep.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
	})
	if err := os.Symlink(filepath.Join(dir, "o/link2"), filepath.Join(dir2, "o/kustomization.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := render(t, dir2, "o"); err == nil {
		t.Fatal("prepared a root kustomization outside the confinement root")
	}
}

// TestRenderRemainingBudgetDeadline caps a root by what is left of the phase
// deadline, not by its own timeout: with an expired phase deadline the render
// fails at once even though its own timeout has not started to matter.
func TestRenderRemainingBudgetDeadline(t *testing.T) {
	dir := writeTree(t, baseTree())
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	r.timeout = time.Minute
	r.deadline = time.Now().Add(time.Nanosecond)
	_, err := r.Render(context.Background(), filepath.Join(dir, "overlays/dev"))
	var re *RenderError
	if !errors.As(err, &re) || re.Reason != ReasonTimeout {
		t.Fatalf("got %v", err)
	}
}

// TestRenderPreparationDeadline abandons a root whose preparation starts past
// the deadline: the root kustomization is never read.
func TestRenderPreparationDeadline(t *testing.T) {
	dir := writeTree(t, baseTree())
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	a := &adapter{fsys: r.fsys, root: r.confine, cache: r.cache, reads: map[string]struct{}{}}
	_, err := r.prepareRoot(a, filepath.Join(dir, "overlays/dev"), time.Now().Add(-time.Second))
	var re *RenderError
	if !errors.As(err, &re) || re.Reason != ReasonTimeout {
		t.Fatalf("got %v", err)
	}
	if len(a.reads) != 0 {
		t.Fatalf("read %d files past the deadline", len(a.reads))
	}
}

// TestRenderMappingRootDeadline abandons a root whose mapping runs past its
// own root deadline even when the phase deadline is still far away.
func TestRenderMappingRootDeadline(t *testing.T) {
	r := NewRenderer(vfs.Default(), t.TempDir(), 5<<20)
	rm := resmap.New()
	rs, err := resource.NewFactory(nil).FromMap(map[string]interface{}{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]interface{}{"name": "x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rm.Append(rs); err != nil {
		t.Fatal(err)
	}
	if r.mapResources(&Result{}, rm, "", time.Now().Add(-time.Second)) {
		t.Fatal("mapping past the root deadline must fail the root")
	}
}

// TestRenderMappingLastResourceDeadline abandons a root whose deadline passes
// while its last resource is mapped.
func TestRenderMappingLastResourceDeadline(t *testing.T) {
	dir := t.TempDir()
	r := NewRenderer(hookFS{onAbs: func(string) { time.Sleep(200 * time.Millisecond) }}, dir, 5<<20)
	rm := resmap.New()
	rs, err := resource.NewFactory(nil).FromMap(map[string]interface{}{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]interface{}{"name": "x", "annotations": map[string]interface{}{originAnnotation: "path: x.yaml\n"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rm.Append(rs); err != nil {
		t.Fatal(err)
	}
	if r.mapResources(&Result{Root: dir}, rm, "", time.Now().Add(100*time.Millisecond)) {
		t.Fatal("a root whose deadline passed while mapping must fail")
	}
}

// TestRenderContextCanceled abandons a render when the scan is canceled.
func TestRenderContextCanceled(t *testing.T) {
	dir := writeTree(t, baseTree())
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := r.Render(ctx, filepath.Join(dir, "overlays/dev"))
	var re *RenderError
	if !errors.As(err, &re) || re.Reason != ReasonTimeout {
		t.Fatalf("got %v", err)
	}
}

// TestRenderMappingDeadline abandons a root whose mapping runs past the phase
// deadline instead of returning a partial result.
func TestRenderMappingDeadline(t *testing.T) {
	r := NewRenderer(vfs.Default(), t.TempDir(), 5<<20)
	rm := resmap.New()
	rs, err := resource.NewFactory(nil).FromMap(map[string]interface{}{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]interface{}{"name": "x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rm.Append(rs); err != nil {
		t.Fatal(err)
	}
	r.deadline = time.Now().Add(-time.Second)
	if r.mapResources(&Result{}, rm, "", time.Now().Add(time.Hour)) {
		t.Fatal("mapping past the phase deadline must fail the root")
	}
}

func TestRenderConcurrent(t *testing.T) {
	dir := writeTree(t, baseTree())
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			root := []string{"overlays/dev", "overlays/prod"}[i%2]
			if _, err := r.Render(context.Background(), filepath.Join(dir, root)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
}

func TestRenderErrorHidesInput(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "secretGenerator:\n  - name: s\n    literals:\n      - canary-no-equals-sign\n",
	})
	_, err := render(t, dir, "o")
	if err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatalf("got %v", err)
	}
}

func BenchmarkRender(b *testing.B) {
	files := baseTree()
	dir := b.TempDir()
	for p, c := range files {
		full := filepath.Join(dir, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(c), 0o600)
	}
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	for i := 0; i < b.N; i++ {
		if _, err := r.Render(context.Background(), filepath.Join(dir, "overlays/prod")); err != nil {
			b.Fatal(err)
		}
	}
}

// TestRenderMemFS renders an in-memory tree: its directories exist only as
// the parents of pushed files.
func TestRenderMemFS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("MemFS keys are forward-slash paths")
	}
	fsys := vfs.NewMemFS(map[string][]byte{
		"/repo/o/kustomization.yaml": []byte("resources:\n  - cm.yaml\n"),
		"/repo/o/cm.yaml":            []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n"),
	})
	res, err := NewRenderer(fsys, "/repo", 5<<20).Render(context.Background(), "/repo/o")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Documents) != 1 || res.Documents[0].SourceDocumentIndex != 0 {
		t.Fatalf("documents: %+v", res.Documents)
	}
}

// TestRenderRemoteShapedRootRefused refuses a relative root Kustomize would
// parse as a git URL and clone before reading through the adapter.
func TestRenderRemoteShapedRootRefused(t *testing.T) {
	fsys := vfs.NewMemFS(map[string][]byte{
		"github.com/org/repo/kustomization.yaml": []byte("resources: []\n"),
	})
	_, err := NewRenderer(fsys, "github.com", 5<<20).Render(context.Background(), "github.com/org/repo")
	var re *RenderError
	if !errors.As(err, &re) || re.Reason != ReasonValidation {
		t.Fatalf("got %v", err)
	}
}

// hookFS is the disk with hooks on Stat and ReadFile, to hold a render at a
// chosen point.
type hookFS struct {
	vfs.DiskFS
	onStat, onRead, onAbs func(string)
}

func (h hookFS) Abs(p string) (string, error) {
	if h.onAbs != nil {
		h.onAbs(p)
	}
	return h.DiskFS.Abs(p)
}

func (h hookFS) Stat(p string) (fs.FileInfo, error) {
	if h.onStat != nil {
		h.onStat(p)
	}
	return h.DiskFS.Stat(p)
}

func (h hookFS) ReadFile(p string) ([]byte, error) {
	if h.onRead != nil {
		h.onRead(p)
	}
	return h.DiskFS.ReadFile(p)
}

// TestRenderStdLogSharedWithHelm keeps the standard logger silenced while a
// render runs even when a Helm render that started first ends meanwhile.
func TestRenderStdLogSharedWithHelm(t *testing.T) {
	var out bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(prev)
	dir := writeTree(t, baseTree())
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	fsys := hookFS{onRead: func(p string) {
		if filepath.Base(p) == "deployment.yaml" {
			once.Do(func() { close(reached); <-release })
		}
	}}
	endHelm := logger.SilenceStdLog()
	done := make(chan error, 1)
	go func() {
		_, err := NewRenderer(fsys, dir, 5<<20).Render(context.Background(), filepath.Join(dir, "base"))
		done <- err
	}()
	<-reached
	endHelm()
	log.Print("leaked while Kustomize runs")
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("standard logger restored during the render: %q", out.String())
	}
	log.Print("after")
	if out.Len() == 0 {
		t.Fatal("standard logger not restored")
	}
}

// TestRenderWatchdogRemainingBudget stops the run at the root deadline:
// the time preparation took is not granted again to execution.
func TestRenderWatchdogRemainingBudget(t *testing.T) {
	dir := writeTree(t, baseTree())
	release := make(chan struct{})
	defer close(release)
	var once sync.Once
	fsys := hookFS{
		onStat: func(p string) {
			if filepath.Base(p) == "kustomization.yaml" && filepath.Base(filepath.Dir(p)) == "base" {
				once.Do(func() { time.Sleep(1500 * time.Millisecond) })
			}
		},
		onRead: func(p string) {
			if filepath.Base(p) == "deployment.yaml" {
				<-release
			}
		},
	}
	r := NewRenderer(fsys, dir, 5<<20)
	r.timeout = 2 * time.Second
	start := time.Now()
	_, err := r.Render(context.Background(), filepath.Join(dir, "base"))
	var re *RenderError
	if !errors.As(err, &re) || re.Reason != ReasonTimeout {
		t.Fatalf("got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("watchdog fired after %v, past the 2s root budget", elapsed)
	}
}

// TestRenderWatchdogBoundsPreparation stops a render whose root preparation
// blocks at the root deadline.
func TestRenderWatchdogBoundsPreparation(t *testing.T) {
	dir := writeTree(t, baseTree())
	release := make(chan struct{})
	defer close(release)
	fsys := hookFS{onStat: func(p string) {
		if filepath.Base(p) == "kustomization.yaml" {
			<-release
		}
	}}
	r := NewRenderer(fsys, dir, 5<<20)
	r.timeout = 200 * time.Millisecond
	start := time.Now()
	_, err := r.Render(context.Background(), filepath.Join(dir, "base"))
	var re *RenderError
	if !errors.As(err, &re) || re.Reason != ReasonTimeout {
		t.Fatalf("got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("returned after %v, past the 200ms root budget", elapsed)
	}
}

// TestRenderSymlinkedSourceAttributed attributes a resource listed through an
// in-repo symlink to the file it resolves to, the one the cache holds.
func TestRenderSymlinkedSourceAttributed(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "resources:\n  - link.yaml\n",
		"o/real.yaml":          "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n",
	})
	if err := os.Symlink("real.yaml", filepath.Join(dir, "o/link.yaml")); err != nil {
		t.Skip(err)
	}
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	d := res.Documents[0]
	if d.FileName != filepath.Join(dir, "o/real.yaml") || d.SourceDocumentIndex != 0 || res.MappingFailures != 0 {
		t.Fatalf("got %s #%d, %d failures", d.FileName, d.SourceDocumentIndex, res.MappingFailures)
	}
}

// TestRenderSameNameNamespaces maps two documents of one file sharing a name
// in different namespaces each to its own document.
func TestRenderSameNameNamespaces(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "resources:\n  - cm.yaml\n",
		"o/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n  namespace: a\n---\n" +
			"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n  namespace: b\n",
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, d := range res.Documents {
		got[d.Kustomize.RenderedNamespace] = d.SourceDocumentIndex
	}
	if got["a"] != 0 || got["b"] != 1 || res.MappingFailures != 0 {
		t.Fatalf("got %v, %d failures", got, res.MappingFailures)
	}
}

// TestRenderGeneratorKind attributes a generated object to a generator of its
// own kind: a longer Secret generator name it contains does not claim it.
func TestRenderGeneratorKind(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "namePrefix: dev-\nconfigMapGenerator:\n  - name: app\n    literals:\n      - A=b\n" +
			"secretGenerator:\n  - name: dev-app\n    literals:\n      - A=b\n",
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range res.Documents {
		got[d.Kustomize.Kind] = d.Kustomize.Generator.Name
	}
	if got["ConfigMap"] != "app" || got["Secret"] != "dev-app" {
		t.Fatalf("got %v", got)
	}
}

// TestRenderGeneratorTieFails counts generated objects whose generator entry
// is ambiguous (one name in two namespaces) as mapping failures.
func TestRenderGeneratorTieFails(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "configMapGenerator:\n  - name: app\n    namespace: a\n    literals:\n      - A=b\n" +
			"  - name: app\n    namespace: b\n    literals:\n      - A=b\n",
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Documents) != 2 || res.MappingFailures != 2 {
		t.Fatalf("got %d documents, %d failures", len(res.Documents), res.MappingFailures)
	}
}

// TestRenderAffixCollisionFails counts as mapping failures the objects a
// name prefix makes indistinguishable: app rendered as dev-app and dev-app
// itself, as source documents and as generator entries.
func TestRenderAffixCollisionFails(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "namePrefix: dev-\nresources:\n  - cm.yaml\n" +
			"configMapGenerator:\n  - name: gen\n    literals:\n      - A=b\n  - name: dev-gen\n    literals:\n      - A=b\n",
		"o/cm.yaml": "apiVersion: v1\nkind: Service\nmetadata:\n  name: app\n---\n" +
			"apiVersion: v1\nkind: Service\nmetadata:\n  name: dev-app\n",
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if d.SourceDocumentIndex >= 0 || (d.Kustomize.Generator != nil && d.Kustomize.Generator.Name != "") {
			t.Errorf("%s attributed despite the collision", d.Kustomize.RenderedName)
		}
	}
	if len(res.Documents) != 4 || res.MappingFailures != 4 {
		t.Fatalf("got %d documents, %d failures", len(res.Documents), res.MappingFailures)
	}
}

// TestRenderAffixCollisionOtherNamespaceFails rejects affix collisions the
// rendered output alone cannot reveal: counterparts in other namespaces.
func TestRenderAffixCollisionOtherNamespaceFails(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "namePrefix: dev-\nresources:\n  - svc.yaml\n" +
			"configMapGenerator:\n  - name: gen\n    namespace: a\n    literals:\n      - A=b\n" +
			"  - name: dev-gen\n    namespace: b\n    literals:\n      - A=b\n",
		"o/svc.yaml": "apiVersion: v1\nkind: Service\nmetadata:\n  name: app\n  namespace: a\n---\n" +
			"apiVersion: v1\nkind: Service\nmetadata:\n  name: dev-app\n  namespace: b\n",
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Documents) != 4 || res.MappingFailures != 4 {
		t.Fatalf("got %d documents, %d failures", len(res.Documents), res.MappingFailures)
	}
}

// TestRenderAffixCollisionDeletedFails rejects a match whose counterpart a
// patch deleted from the render: dev-app may be app under the prefix.
func TestRenderAffixCollisionDeletedFails(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "namePrefix: dev-\nresources:\n  - svc.yaml\npatches:\n" +
			"  - patch: |-\n      apiVersion: v1\n      kind: Service\n      metadata:\n        name: dev-app\n      $patch: delete\n",
		"o/svc.yaml": "apiVersion: v1\nkind: Service\nmetadata:\n  name: app\n---\n" +
			"apiVersion: v1\nkind: Service\nmetadata:\n  name: dev-app\n",
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Documents) != 1 || res.Documents[0].SourceDocumentIndex >= 0 || res.MappingFailures != 1 {
		t.Fatalf("got %d documents, %d failures", len(res.Documents), res.MappingFailures)
	}
}

// TestRenderChainIntermediate records every kustomization between the root
// and the source file, not only the two ends.
func TestRenderChainIntermediate(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"top/kustomization.yaml":  "resources:\n  - ../mid\n",
		"mid/kustomization.yaml":  "namePrefix: mid-\nresources:\n  - ../base\n",
		"base/kustomization.yaml": "resources:\n  - cm.yaml\n",
		"base/cm.yaml":            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n",
	})
	res, err := render(t, dir, "top")
	if err != nil {
		t.Fatal(err)
	}
	var rels []string
	for _, k := range res.Documents[0].Kustomize.Chain {
		rel, _ := filepath.Rel(dir, k)
		rels = append(rels, filepath.ToSlash(rel))
	}
	if want := "top/kustomization.yaml,mid/kustomization.yaml,base/kustomization.yaml"; strings.Join(rels, ",") != want {
		t.Fatalf("chain %v, want %s", rels, want)
	}
}
