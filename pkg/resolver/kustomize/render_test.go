package kustomize

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	yamlparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"sigs.k8s.io/kustomize/api/resmap"
	"sigs.k8s.io/kustomize/api/resource"
	"sigs.k8s.io/kustomize/api/types"
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

// idle waits until no render holds the lock, abandoned or not.
func (l *renderLock) idle() {
	for {
		l.mu.Lock()
		owner, changed := l.owner, l.changed
		l.mu.Unlock()
		if owner == nil {
			return
		}
		<-changed
	}
}

// waitRunLock waits for an abandoned run to release the render lock.
func waitRunLock() { runLock.idle() }

func render(t *testing.T, dir, root string) (*Result, error) {
	t.Helper()
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	res, err := r.Render(context.Background(), filepath.Join(dir, root), nil)
	if err == nil {
		checkDocumentCounts(t, r, res)
	}
	return res, err
}

// checkDocumentCounts checks that the mapping indexes the documents of every
// source manifest a render read as the YAML parser does.
func checkDocumentCounts(t *testing.T, r *Renderer, res *Result) {
	t.Helper()
	for _, p := range res.Reads {
		content, ok := r.Source(p)
		if !ok || IsKustomizationFile(filepath.Base(p)) {
			continue
		}
		parsed, _, _ := yamlparser.ParseWithNodeTransformNoResolve(context.Background(), content, p, nil)
		if got := len(r.sourceDocuments(p)); got != len(parsed) {
			t.Errorf("%s: mapping counts %d documents, the parser %d", p, got, len(parsed))
		}
	}
}

// TestRenderEmptyDocumentIndex indexes source documents past empty and
// comment-only ones as the YAML parser does.
func TestRenderEmptyDocumentIndex(t *testing.T) {
	svc := func(n string) string { return "apiVersion: v1\nkind: Service\nmetadata:\n  name: " + n + "\n" }
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "resources:\n  - a.yaml\n  - b.yaml\n",
		"o/a.yaml":             svc("a1") + "---\n---\n" + svc("a2"),
		"o/b.yaml":             svc("b1") + "---\n# only a comment\n---\n" + svc("b2"),
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, d := range res.Documents {
		got[d.Kustomize.RenderedName] = d.SourceDocumentIndex
	}
	if got["a1"] != 0 || got["a2"] != 1 || got["b1"] != 0 || got["b2"] != 1 || res.MappingFailures != 0 {
		t.Fatalf("got %v, %d failures", got, res.MappingFailures)
	}
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
	res, err := r.Render(context.Background(), filepath.Join(dir, "overlays/dev"), nil)
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
			_, err := NewRenderer(vfs.Default(), dir, 1<<20).Render(context.Background(), filepath.Join(dir, "o"), nil)
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
		if _, err := NewRenderer(fsys, dir, 5<<20).Render(context.Background(), filepath.Join(dir, "o"), nil); err == nil {
			t.Fatalf("%T: symlink outside the root was followed", fsys)
		}
	}
}

func TestRenderBudget(t *testing.T) {
	dir := writeTree(t, baseTree())
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	r.cache.served = maxServedBytes - 10
	_, err := r.Render(context.Background(), filepath.Join(dir, "overlays/dev"), nil)
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

// TestRenderSymlinkRoleValidation decides the role by the requested name, not
// the symlink target's: a remote reference inside an in-workspace alias is
// validated and refused, a valid alias renders, and the escaped file is
// never read.
func TestRenderSymlinkRoleValidation(t *testing.T) {
	outside := t.TempDir()
	escaped := filepath.Join(outside, "escape.txt")
	if err := os.WriteFile(escaped, []byte("resources:\n  - https://example.com/x.yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := writeTree(t, map[string]string{
		"o/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
		// An in-workspace alias holding a valid kustomization renders fine.
		"o/plain.yaml": "resources:\n  - deployment.yaml\n",
	})
	if err := os.Symlink(filepath.Join(dir, "o/plain.yaml"), filepath.Join(dir, "o/kustomization.yaml")); err != nil {
		t.Fatal(err)
	}
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	res, err := r.Render(context.Background(), filepath.Join(dir, "o"), nil)
	if err != nil {
		t.Fatalf("valid in-workspace alias: %v", err)
	}
	if len(res.Documents) != 1 {
		t.Fatalf("aliased kustomization rendered %d documents", len(res.Documents))
	}

	// An alias to a file outside the root is refused and never read.
	dir2 := writeTree(t, map[string]string{
		"o/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
	})
	if err := os.Symlink(escaped, filepath.Join(dir2, "o/kustomization.yaml")); err != nil {
		t.Fatal(err)
	}
	r2 := NewRenderer(vfs.Default(), dir2, 5<<20)
	if _, err := r2.Render(context.Background(), filepath.Join(dir2, "o"), nil); err == nil {
		t.Fatal("rendered a kustomization alias pointing outside the root")
	}
	if b, ok := r2.Source(escaped); ok {
		t.Fatalf("the escaped file was read: %d bytes", len(b))
	}

	// An in-workspace alias whose content is not a kustomization is
	// validated as one and refused.
	dir3 := writeTree(t, map[string]string{
		"o/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
		"o/plain.txt":       "resources:\n  - https://example.com/x.yaml\n",
	})
	if err := os.Symlink(filepath.Join(dir3, "o/plain.txt"), filepath.Join(dir3, "o/kustomization.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := render(t, dir3, "o"); err == nil {
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
	r.deadline = time.Now().Add(-time.Second)
	_, err := r.Render(context.Background(), filepath.Join(dir, "overlays/dev"), nil)
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
	if r.mapResources(context.Background(), &Result{}, rm, "", nil, time.Now().Add(-time.Second)) == nil {
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
	if r.mapResources(context.Background(), &Result{Root: dir}, rm, "", nil, time.Now().Add(100*time.Millisecond)) == nil {
		t.Fatal("a root whose deadline passed while mapping must fail")
	}
}

// TestRenderMappingDeadlineMidWork expires the deadline while mapping real
// documents: the root is abandoned rather than partially mapped.
func TestRenderMappingDeadlineMidWork(t *testing.T) {
	dir := writeTree(t, baseTree())
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	if _, err := r.Render(context.Background(), filepath.Join(dir, "overlays/dev"), nil); err != nil {
		t.Fatal(err)
	}
	// Re-map a ResMap-shaped result past a deadline that has already expired:
	// check() runs before the graph and per resource.
	r.deadline = time.Now().Add(-time.Second)
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
	if r.mapResources(context.Background(), &Result{Root: dir}, rm, "", nil, time.Now().Add(100*time.Millisecond)) == nil {
	}
}

// TestRenderContextCanceled abandons a render when the scan is canceled.
func TestRenderContextCanceled(t *testing.T) {
	dir := writeTree(t, baseTree())
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := r.Render(ctx, filepath.Join(dir, "overlays/dev"), nil)
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
	if r.mapResources(context.Background(), &Result{}, rm, "", nil, time.Now().Add(time.Hour)) == nil {
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
			if _, err := r.Render(context.Background(), filepath.Join(dir, root), nil); err != nil {
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
		if _, err := r.Render(context.Background(), filepath.Join(dir, "overlays/prod"), nil); err != nil {
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
	res, err := NewRenderer(fsys, "/repo", 5<<20).Render(context.Background(), "/repo/o", nil)
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
	_, err := NewRenderer(fsys, "github.com", 5<<20).Render(context.Background(), "github.com/org/repo", nil)
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
		_, err := NewRenderer(fsys, dir, 5<<20).Render(context.Background(), filepath.Join(dir, "base"), nil)
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
	t.Cleanup(waitRunLock)
	r := NewRenderer(fsys, dir, 5<<20)
	r.timeout = 2 * time.Second
	start := time.Now()
	_, err := r.Render(context.Background(), filepath.Join(dir, "base"), nil)
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
	t.Cleanup(waitRunLock)
	r := NewRenderer(fsys, dir, 5<<20)
	r.timeout = 200 * time.Millisecond
	start := time.Now()
	_, err := r.Render(context.Background(), filepath.Join(dir, "base"), nil)
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

// TestRenderSerializationFailureFailsRoot fails the whole root when a
// rendered resource cannot be serialized (a replacement writing a string
// into an integer field), rather than dropping that resource.
func TestRenderSerializationFailureFailsRoot(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "resources:\n  - a.yaml\nreplacements:\n  - source:\n      kind: ConfigMap\n" +
			"      fieldPath: data.x\n    targets:\n      - select:\n          kind: Deployment\n        fieldPaths:\n" +
			"          - spec.replicas\n",
		"o/a.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\ndata:\n  x: abc\n---\n" +
			"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\nspec:\n  replicas: 1\n",
		"b/kustomization.yaml": "resources:\n  - deployment.yaml\n",
		"b/deployment.yaml":    deployment,
	})
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	res, err := r.Render(context.Background(), filepath.Join(dir, "o"), nil)
	var re *RenderError
	if res != nil || !errors.As(err, &re) || re.Reason != ReasonRenderError {
		t.Fatalf("got a result: %t, error %v", res != nil, err)
	}
	// Not a timeout: the next root still renders.
	if _, err := r.Render(context.Background(), filepath.Join(dir, "b"), nil); err != nil {
		t.Fatal(err)
	}
}

// TestRenderLoadGraphUnprovenStaysLocal keeps a proven paths count when an
// unrelated kustomization is unproven: the root's own generator maps under its
// prefix though a child kustomization is linked from another directory, whose
// resources do not.
func TestRenderLoadGraphUnprovenStaysLocal(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "namePrefix: dev-\nresources:\n  - ../c\n" +
			"configMapGenerator:\n  - name: gen\n    literals:\n      - A=b\n",
		"real/kustomization.yaml": "resources:\n  - svc.yaml\n",
		"c/svc.yaml":              "apiVersion: v1\nkind: Service\nmetadata:\n  name: app\n",
	})
	if err := os.Symlink(filepath.Join("..", "real", "kustomization.yaml"), filepath.Join(dir, "c", "kustomization.yaml")); err != nil {
		t.Skip(err)
	}
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, d := range res.Documents {
		got[d.Kustomize.Kind] = d.SourceDocumentIndex >= 0 || d.Kustomize.Generator != nil && d.Kustomize.Generator.Name == "gen"
	}
	if len(got) != 2 || !got["ConfigMap"] || got["Service"] || res.MappingFailures != 1 {
		t.Fatalf("mapped %v, %d failures", got, res.MappingFailures)
	}
}

// TestRenderLoadGraphBoundedUnproven bounds the walk, every step counted, when
// an unproven branch comes first and many generator-only branches follow: the
// generators' paths counts are not a root walk each. The root reaches the
// unproven branch past none of them, so, as before, none maps.
func TestRenderLoadGraphBoundedUnproven(t *testing.T) {
	const gens = 300
	files := map[string]string{
		"u/kustomization.yaml":    "resources:\n  - ../w\n",
		"real/kustomization.yaml": "resources:\n  - svc.yaml\n",
		"w/svc.yaml":              "apiVersion: v1\nkind: Service\nmetadata:\n  name: app\n",
	}
	var root strings.Builder
	root.WriteString("namePrefix: p-\nresources:\n  - ../u\n")
	for i := range gens {
		fmt.Fprintf(&root, "  - ../g%d\n", i)
		files[fmt.Sprintf("g%d/kustomization.yaml", i)] = fmt.Sprintf("configMapGenerator:\n  - name: cm%d\n    literals:\n      - A=b\n", i)
	}
	files["o/kustomization.yaml"] = root.String()
	dir := writeTree(t, files)
	if err := os.Symlink(filepath.Join("..", "real", "kustomization.yaml"), filepath.Join(dir, "w", "kustomization.yaml")); err != nil {
		t.Skip(err)
	}
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Documents) != gens+1 || res.MappingFailures != gens+1 {
		t.Fatalf("got %d documents, %d failures", len(res.Documents), res.MappingFailures)
	}
	entries, nodes := 2+gens, 3+gens
	if limit := 4 * (entries*(1+len(KustomizationFileNames)) + nodes); res.graphSteps > limit {
		t.Fatalf("load graph walks took %d steps, want at most %d", res.graphSteps, limit)
	}
}

// TestRenderLoadGraphBounded walks the load graph once per root: the steps
// are bounded by the graph's entries, not by resources times the graph.
func TestRenderLoadGraphBounded(t *testing.T) {
	const bases, docs = 40, 50
	files := map[string]string{}
	var root strings.Builder
	root.WriteString("namePrefix: p-\nresources:\n")
	for b := range bases {
		fmt.Fprintf(&root, "  - ../b%d\n", b)
		var k strings.Builder
		k.WriteString("resources:\n")
		for d := range docs {
			fmt.Fprintf(&k, "  - d%d.yaml\n", d)
			files[fmt.Sprintf("b%d/d%d.yaml", b, d)] = fmt.Sprintf("apiVersion: v1\nkind: Service\nmetadata:\n  name: s%d-%d\n", b, d)
		}
		files[fmt.Sprintf("b%d/kustomization.yaml", b)] = k.String()
	}
	files["o/kustomization.yaml"] = root.String()
	res, err := render(t, writeTree(t, files), "o")
	if err != nil {
		t.Fatal(err)
	}
	entries := bases + bases*docs
	if len(res.Documents) != bases*docs || res.MappingFailures != 0 {
		t.Fatalf("got %d documents, %d failures", len(res.Documents), res.MappingFailures)
	}
	if limit := entries * (1 + len(KustomizationFileNames)); res.graphSteps == 0 || res.graphSteps > limit {
		t.Fatalf("load graph walk took %d steps, want at most %d", res.graphSteps, limit)
	}
}

// TestRenderAbandonedLockFailsFast fails a root fast while an abandoned run
// holds the render lock, without stopping the renderer, waits for a live one,
// and renders the roots after it once the lock is free.
func TestRenderAbandonedLockFailsFast(t *testing.T) {
	dir := writeTree(t, baseTree())
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	o := runLock.acquire(context.Background(), time.Now().Add(time.Hour))
	runLock.abandon(o)
	start := time.Now()
	_, err := r.Render(context.Background(), filepath.Join(dir, "base"), nil)
	var re *RenderError
	if !errors.As(err, &re) || re.Reason != ReasonTimeout || time.Since(start) > rootTimeout/2 {
		t.Fatalf("got %v after %v", err, time.Since(start))
	}
	runLock.release(o)
	live := runLock.acquire(context.Background(), time.Now().Add(time.Hour))
	go func() {
		time.Sleep(100 * time.Millisecond)
		runLock.release(live)
	}()
	for _, root := range []string{"base", "overlays/dev"} {
		if _, err := r.Render(context.Background(), filepath.Join(dir, root), nil); err != nil {
			t.Fatalf("%s: %v", root, err)
		}
	}
}

// TestRenderLockWaiterSeesAbandonment fails a waiter that started while the
// owner was live as soon as the owner is abandoned, not at its deadline.
func TestRenderLockWaiterSeesAbandonment(t *testing.T) {
	l := &renderLock{changed: make(chan struct{})}
	o := l.acquire(context.Background(), time.Now().Add(time.Hour))
	got := make(chan *lockOwner)
	go func() { got <- l.acquire(context.Background(), time.Now().Add(time.Hour)) }()
	time.Sleep(50 * time.Millisecond)
	l.abandon(o)
	select {
	case w := <-got:
		if w != nil {
			t.Fatal("the waiter took a lock its abandoned owner still holds")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the waiter kept waiting after the owner was abandoned")
	}
}

// TestRenderLockEndedWait refuses the lock to an acquisition whose context
// ended or whose deadline passed, even free or released while it waited, and
// leaves the lock usable by the roots after it.
func TestRenderLockEndedWait(t *testing.T) {
	l := &renderLock{changed: make(chan struct{})}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if l.acquire(canceled, time.Now().Add(time.Hour)) != nil {
		t.Fatal("a canceled acquisition took the free lock")
	}
	if l.acquire(context.Background(), time.Now().Add(-time.Second)) != nil {
		t.Fatal("an expired acquisition took the free lock")
	}
	o := l.acquire(context.Background(), time.Now().Add(time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan *lockOwner)
	go func() { got <- l.acquire(ctx, time.Now().Add(time.Hour)) }()
	cancel()
	l.release(o)
	if <-got != nil {
		t.Fatal("a canceled waiter took the released lock")
	}
	if l.acquire(context.Background(), time.Now().Add(time.Hour)) == nil {
		t.Fatal("the lock is not usable after the canceled waiter")
	}
}

// TestRenderLockIdleWaitsForAbandoned waits for an abandoned owner to finish
// before cleanup returns, though acquisitions fail fast meanwhile.
func TestRenderLockIdleWaitsForAbandoned(t *testing.T) {
	l := &renderLock{changed: make(chan struct{})}
	o := l.acquire(context.Background(), time.Now().Add(time.Hour))
	l.abandon(o)
	idle := make(chan struct{})
	go func() { l.idle(); close(idle) }()
	select {
	case <-idle:
		t.Fatal("idle returned while the abandoned owner holds the lock")
	case <-time.After(100 * time.Millisecond):
	}
	l.release(o)
	<-idle
}

// TestRenderLockLateAbandonment ignores an abandonment that comes after its
// owner released the lock: the next owner stays live and its waiters wait.
func TestRenderLockLateAbandonment(t *testing.T) {
	l := &renderLock{changed: make(chan struct{})}
	o := l.acquire(context.Background(), time.Now().Add(time.Hour))
	l.release(o)
	next := l.acquire(context.Background(), time.Now().Add(time.Hour))
	l.abandon(o)
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan *lockOwner)
	go func() { got <- l.acquire(ctx, time.Now().Add(time.Hour)) }()
	select {
	case <-got:
		t.Fatal("a waiter failed fast on a live owner")
	case <-time.After(100 * time.Millisecond):
	}
	l.release(next)
	if w := <-got; w == nil {
		t.Fatal("the waiter did not take the released lock")
	}
	cancel()
}

// TestRenderGeneratorNamespace reports a generated object's source namespace
// from its generator entry, empty when the entry sets none.
func TestRenderGeneratorNamespace(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "configMapGenerator:\n  - name: a\n    namespace: x\n    literals:\n      - A=b\n" +
			"  - name: b\n    literals:\n      - A=b\n",
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range res.Documents {
		got[d.Kustomize.SourceName] = d.Kustomize.SourceNamespace
	}
	if ns, ok := got["a"]; !ok || ns != "x" || got["b"] != "" || len(got) != 2 {
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

// TestRenderAffixSameKind maps every document of a file holding several of
// one kind under a namespace-only or a prefix-only overlay.
func TestRenderAffixSameKind(t *testing.T) {
	deploy := func(n string) string {
		return "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: " + n + "\n---\n"
	}
	for name, affix := range map[string]string{"namespace": "namespace: dev\n", "prefix": "namePrefix: dev-\n"} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"o/kustomization.yaml": affix + "resources:\n  - app.yaml\n",
				"o/app.yaml":           deploy("api") + deploy("worker") + "apiVersion: v1\nkind: Service\nmetadata:\n  name: api\n",
			})
			res, err := render(t, dir, "o")
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]int{}
			for _, d := range res.Documents {
				got[d.Kustomize.Kind+"/"+d.Kustomize.SourceName] = d.SourceDocumentIndex
			}
			if len(got) != 3 || got["Deployment/api"] != 0 || got["Deployment/worker"] != 1 || got["Service/api"] != 2 ||
				res.MappingFailures != 0 {
				t.Fatalf("got %v, %d failures", got, res.MappingFailures)
			}
		})
	}
	// The prefix transformer skips CustomResourceDefinitions and APIServices:
	// under a prefix dev-app is not app, so neither maps; a namespace alone
	// renames neither, so both map by name.
	obj := func(kind, n string) string {
		return "apiVersion: v1\nkind: " + kind + "\nmetadata:\n  name: " + n + "\n---\n"
	}
	for _, kind := range []string{"CustomResourceDefinition", "APIService"} {
		for affix, want := range map[string]int{"namePrefix: dev-\n": -1, "namespace: dev\n": 0} {
			res, err := render(t, writeTree(t, map[string]string{
				"o/kustomization.yaml": affix + "resources:\n  - crd.yaml\n",
				"o/crd.yaml":           obj(kind, "app") + obj(kind, "dev-app"),
			}), "o")
			if err != nil {
				t.Fatal(err)
			}
			failures := 0
			for _, d := range res.Documents {
				switch {
				case want < 0 && d.SourceDocumentIndex >= 0:
					t.Errorf("%s %s %s attributed to %s", affix, kind, d.Kustomize.RenderedName, d.Kustomize.SourceName)
				case want >= 0 && (d.SourceDocumentIndex < 0 || d.Kustomize.SourceName != d.Kustomize.RenderedName):
					t.Errorf("%s %s %s not attributed by name", affix, kind, d.Kustomize.RenderedName)
				case d.SourceDocumentIndex < 0:
					failures++
				}
			}
			if len(res.Documents) != 2 || res.MappingFailures != failures {
				t.Errorf("%s %s: %d documents, %d failures", affix, kind, len(res.Documents), res.MappingFailures)
			}
		}
	}
}

// TestRenderAffixCollisionDisambiguates attributes the documents of a file
// holding several of their kind under a name prefix: the affix chain names
// one document per rendered name (app rendered as dev-app, dev-app as
// dev-dev-app), and generator entries the prefix explains exactly map.
func TestRenderAffixCollisionDisambiguates(t *testing.T) {
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
		a := d.Kustomize
		switch {
		case a.Generator == nil && d.SourceDocumentIndex < 0:
			t.Errorf("%s not attributed: the affix chain names one document", a.RenderedName)
		case a.Generator != nil && !generatedAs(a.RenderedName, "dev-"+a.Generator.Name, false):
			t.Errorf("%s attributed to generator %q", a.RenderedName, a.Generator.Name)
		}
	}
	if len(res.Documents) != 4 || res.MappingFailures != 0 {
		t.Fatalf("got %d documents, %d failures", len(res.Documents), res.MappingFailures)
	}
}

// TestRenderAffixCollisionOtherNamespaceDisambiguates attributes counterparts
// in other namespaces the rendered output alone cannot tell apart: the affix
// chain names one document per rendered name, the generator entries map.
func TestRenderAffixCollisionOtherNamespaceDisambiguates(t *testing.T) {
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
	if len(res.Documents) != 4 || res.MappingFailures != 0 {
		t.Fatalf("got %d documents, %d failures", len(res.Documents), res.MappingFailures)
	}
}

// TestRenderAffixCollisionDeletedDisambiguates attributes the survivor of a
// patch that deleted its counterpart: dev-app is app under the prefix, the
// deleted source document rendered nothing.
func TestRenderAffixCollisionDeletedDisambiguates(t *testing.T) {
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
	if len(res.Documents) != 1 || res.Documents[0].SourceDocumentIndex != 0 || res.MappingFailures != 0 {
		t.Fatalf("got %d documents, %d failures", len(res.Documents), res.MappingFailures)
	}
}

// TestRenderNestedNamesWithoutRenaming maps nested names exactly when no
// kustomization in the graph can rename, and rejects them once one level adds
// an affix.
func TestRenderNestedNamesWithoutRenaming(t *testing.T) {
	files := map[string]string{
		"top/kustomization.yaml": "resources:\n  - ../o\n",
		"o/kustomization.yaml": "resources:\n  - svc.yaml\n" +
			"configMapGenerator:\n  - name: gen\n    literals:\n      - A=b\n  - name: gen-x\n    literals:\n      - A=b\n",
		"o/svc.yaml": "apiVersion: v1\nkind: Service\nmetadata:\n  name: app\n---\n" +
			"apiVersion: v1\nkind: Service\nmetadata:\n  name: app-config\n",
	}
	res, err := render(t, writeTree(t, files), "top")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range res.Documents {
		a := d.Kustomize
		got[a.RenderedName] = a.SourceName
		if a.Generator != nil {
			got[a.RenderedName] = a.Generator.Name
		}
	}
	if got["app"] != "app" || got["app-config"] != "app-config" || res.MappingFailures != 0 || len(got) != 4 {
		t.Fatalf("got %v, %d failures", got, res.MappingFailures)
	}
	for _, n := range []string{"gen", "gen-x"} {
		var ok bool
		for k, v := range got {
			ok = ok || (strings.HasPrefix(k, n+"-") && v == n)
		}
		if !ok {
			t.Errorf("generator %s not attributed: %v", n, got)
		}
	}
	files["top/kustomization.yaml"] = "nameSuffix: -s\nresources:\n  - ../o\n"
	res, err = render(t, writeTree(t, files), "top")
	if err != nil {
		t.Fatal(err)
	}
	// The suffix names one document per rendered Service, and each generator
	// entry it explains exactly maps.
	for _, d := range res.Documents {
		a := d.Kustomize
		if (a.Generator == nil && d.SourceDocumentIndex < 0) || (a.Generator != nil && !generatedAs(a.RenderedName, a.Generator.Name+"-s", false)) {
			t.Errorf("%s not attributed: the suffix names one document", a.RenderedName)
		}
	}
	if res.MappingFailures != 0 {
		t.Fatalf("affix in the graph: %d failures, want 0", res.MappingFailures)
	}
}

// TestRenderNoRenamingProof keeps the conservative matching when renaming
// is not proven absent: transformer configurations, or a symlinked
// kustomization whose target name is not a kustomization's.
func TestRenderNoRenamingProof(t *testing.T) {
	svc := "apiVersion: v1\nkind: Service\nmetadata:\n  name: app\n---\n" +
		"apiVersion: v1\nkind: Service\nmetadata:\n  name: app-config\n"
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "resources:\n  - svc.yaml\nconfigurations:\n  - conf.yaml\n",
		"o/conf.yaml":          "namePrefix:\n  - path: metadata/name\n",
		"o/svc.yaml":           svc,
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	if res.MappingFailures != 2 {
		t.Fatalf("configurations: %d failures, want 2", res.MappingFailures)
	}
	rn := NewRenderer(vfs.Default(), t.TempDir(), 5<<20)
	if !rn.beyondAffixes(&types.Kustomization{Labels: []types.Label{{Pairs: map[string]string{"a": "b"}, FieldSpecs: []types.FieldSpec{{Path: "metadata/name"}}}}}, "") {
		t.Fatal("labels with their own field specs proved no renaming")
	}
	gen := func(name, behavior string, off bool) types.ConfigMapArgs {
		return types.ConfigMapArgs{GeneratorArgs: types.GeneratorArgs{Name: name, Behavior: behavior,
			Options: &types.GeneratorOptions{DisableNameSuffixHash: off}}}
	}
	for name, ks := range map[string][]types.Kustomization{
		"merge":         {{ConfigMapGenerator: []types.ConfigMapArgs{gen("g", "merge", false)}}},
		"repeated name": {{ConfigMapGenerator: []types.ConfigMapArgs{gen("g", "", false)}}, {SecretGenerator: []types.SecretArgs{{GeneratorArgs: gen("g", "", false).GeneratorArgs}}}},
	} {
		var g generatorEntries
		ok := true
		for i := range ks {
			ok = g.add(&ks[i]) && ok
		}
		if ok {
			t.Errorf("%s: generator entries proved unambiguous", name)
		}
	}
	var mixed generatorEntries
	if !mixed.add(&types.Kustomization{ConfigMapGenerator: []types.ConfigMapArgs{gen("g", "", false)}}) ||
		!mixed.add(&types.Kustomization{ConfigMapGenerator: []types.ConfigMapArgs{gen("h", "create", true)}}) {
		t.Error("entries hashing differently are matched by their own hashing")
	}
	var g generatorEntries
	if !g.add(&types.Kustomization{ConfigMapGenerator: []types.ConfigMapArgs{gen("g", "create", false), gen("g-x", "", false)}}) {
		t.Error("distinct created entries hashing alike must keep the shortcut")
	}
	dir = writeTree(t, map[string]string{
		"top/kustomization.yaml": "resources:\n  - ../o\nconfigMapGenerator:\n  - name: gen\n    behavior: merge\n    literals:\n      - C=d\n",
		"o/kustomization.yaml":   "configMapGenerator:\n  - name: gen\n    literals:\n      - A=b\n  - name: gen-x\n    literals:\n      - A=b\n",
	})
	r0 := NewRenderer(vfs.Default(), dir, 5<<20)
	res, err = r0.Render(context.Background(), filepath.Join(dir, "top"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r0.renameMode(res.Reads) == renameNone {
		t.Fatal("a merging generator proved no renaming")
	}
	if !rn.beyondAffixes(&types.Kustomization{OpenAPI: map[string]string{"path": "s.json"}}, "") ||
		!setsAffixes(&types.Kustomization{Namespace: "n", Resources: []string{"a"}}) || rn.beyondAffixes(&types.Kustomization{Resources: []string{"a"}}, "") {
		t.Fatal("only identity-safe fields prove no renaming")
	}
	dir = writeTree(t, map[string]string{
		"o/real.yml": "namePrefix: dev-\nresources:\n  - svc.yaml\n",
		"o/svc.yaml": "apiVersion: v1\nkind: Service\nmetadata:\n  name: app\n---\n" +
			"apiVersion: v1\nkind: Service\nmetadata:\n  name: dev-app\n",
	})
	if err := os.Symlink("real.yml", filepath.Join(dir, "o", "kustomization.yaml")); err != nil {
		t.Skip(err)
	}
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	if _, err := r.Render(context.Background(), filepath.Join(dir, "o"), nil); err != nil {
		t.Fatal(err)
	}
	if r.renameMode([]string{filepath.Join(dir, "o", "real.yml")}) == renameNone {
		t.Fatal("a symlinked kustomization with an affix proved no renaming")
	}
}

// TestRenderGeneratorHashOption matches generator entries by exact name when
// the hash is disabled, and nested entry names stay unambiguous either way.
func TestRenderGeneratorHashOption(t *testing.T) {
	for _, opts := range []string{"", "generatorOptions:\n  disableNameSuffixHash: true\n"} {
		dir := writeTree(t, map[string]string{
			"o/kustomization.yaml": opts + "configMapGenerator:\n  - name: gen\n    literals:\n      - A=b\n" +
				"  - name: gen-x\n    literals:\n      - A=b\n",
		})
		res, err := render(t, dir, "o")
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, d := range res.Documents {
			got[d.Kustomize.RenderedName] = d.Kustomize.Generator.Name
		}
		if res.MappingFailures != 0 || len(got) != 2 {
			t.Fatalf("%q: got %v, %d failures", opts, got, res.MappingFailures)
		}
		if opts != "" && (got["gen"] != "gen" || got["gen-x"] != "gen-x") {
			t.Fatalf("hash disabled: got %v", got)
		}
	}
}

// TestRenderPatchRenaming keeps the conservative refusal when a patch opts
// into renaming, writes the whole document, or is a component renaming.
func TestRenderPatchRenaming(t *testing.T) {
	cases := map[string]string{
		"allowNameChange": "patches:\n  - target: {kind: Deployment, name: web}\n    options: {allowNameChange: true}\n" +
			"    patch: |-\n      apiVersion: apps/v1\n      kind: Deployment\n      metadata:\n        name: web\n",
		"allowKindChange": "patches:\n  - target: {kind: Deployment, name: web}\n    options: {allowKindChange: true}\n" +
			"    patch: |-\n      apiVersion: apps/v1\n      kind: Deployment\n      metadata:\n        name: web\n",
		"whole document pointer": "patches:\n  - target: {kind: Deployment, name: web}\n" +
			"    patch: '[{\"op\":\"replace\",\"path\":\"/\",\"value\":{}}]'\n",
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"o/kustomization.yaml": "resources:\n  - dep.yaml\n" + extra,
				"o/dep.yaml":           "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
			})
			res, err := render(t, dir, "o")
			if err != nil {
				t.Fatal(err)
			}
			if res.MappingFailures == 0 {
				t.Fatal("the renaming patch proved the names attributable")
			}
			for _, d := range res.Documents {
				if d.SourceDocumentIndex >= 0 {
					t.Errorf("%s attributed despite the renaming patch", d.Kustomize.RenderedName)
				}
			}
		})
	}
	dir := writeTree(t, map[string]string{
		"top/kustomization.yaml":      "components:\n  - comp\n",
		"top/comp/kustomization.yaml": "apiVersion: kustomize.config.k8s.io/v1alpha1\nkind: Component\nnamespace: prod\nresources:\n  - dep.yaml\n",
		"top/comp/dep.yaml":           "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
	})
	res, err := render(t, dir, "top")
	if err != nil {
		t.Fatal(err)
	}
	if res.MappingFailures == 0 {
		t.Fatal("a component renaming proved the names attributable")
	}
}

// TestPatchesRenameUnreadable treats a patch the renderer cannot read, a JSON
// 6902 patch that does not decode, an op writing the whole object or the
// metadata object, and a move out of metadata as ones that may rename; a
// strategic-merge patch proves it cannot rename.
func TestPatchesRenameUnreadable(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "resources:\n  - dep.yaml\n",
		"o/dep.yaml":           "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
	})
	r := NewRenderer(vfs.Default(), dir, 5<<20)
	kust := filepath.Join(dir, "o", "kustomization.yaml")
	if !r.patchMayRename(kust, "missing.yaml", "") {
		t.Fatal("an unreadable patch file proved it cannot rename")
	}
	for name, patch := range map[string]string{
		"undecodable ops":         "- just a string",
		"metadata object pointer": "[{\"op\":\"replace\",\"path\":\"/metadata\",\"value\":{}}]",
		"move out of metadata":    "[{\"op\":\"move\",\"from\":\"/metadata/labels/app\",\"path\":\"/spec/label\"}]",
		"empty op path":           "[{\"op\":\"replace\",\"path\":\"\",\"value\":{}}]",
	} {
		if !r.patchMayRename("", "", patch) {
			t.Errorf("%s proved it cannot rename", name)
		}
	}
	if r.patchMayRename("", "", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n") {
		t.Error("a strategic-merge patch proved it can rename")
	}
}

// TestRenderJSONPatchRenameFails counts as a mapping failure an object a JSON
// patch renamed and moved to another namespace, even when the name it took is
// a source document's own.
func TestRenderJSONPatchRenameFails(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "resources:\n  - svc.yaml\npatches:\n  - target:\n      kind: Service\n      name: app\n    patch: |-\n" +
			"      - op: replace\n        path: /metadata/name\n        value: other\n" +
			"      - op: add\n        path: /metadata/namespace\n        value: b\n",
		"o/svc.yaml": "apiVersion: v1\nkind: Service\nmetadata:\n  name: app\n  namespace: a\n---\n" +
			"apiVersion: v1\nkind: Service\nmetadata:\n  name: other\n  namespace: b2\n",
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if d.SourceDocumentIndex >= 0 {
			t.Errorf("%s/%s attributed despite the patch", d.Kustomize.RenderedNamespace, d.Kustomize.RenderedName)
		}
	}
	if len(res.Documents) != 2 || res.MappingFailures != 2 {
		t.Fatalf("got %d documents, %d failures", len(res.Documents), res.MappingFailures)
	}
}

// TestRenderSharedBaseTwoChainsFails counts as failures the objects of a base
// two overlays reach with different affixes: one chain cannot explain them.
func TestRenderSharedBaseTwoChainsFails(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"top/kustomization.yaml": "resources:\n  - ../a\n  - ../b\n",
		"a/kustomization.yaml":   "namePrefix: dev-\nnamespace: a\nresources:\n  - ../base\n",
		"b/kustomization.yaml":   "namespace: b\nresources:\n  - ../base\n",
		"base/kustomization.yaml": "configMapGenerator:\n  - name: gen\n    options:\n      annotations:\n" +
			"        config.kubernetes.io/local-config: \"true\"\n    literals:\n      - A=b\n" +
			"  - name: dev-gen\n    literals:\n      - A=b\n",
	})
	res, err := render(t, dir, "top")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if g := d.Kustomize.Generator; g != nil && g.Name != "" {
			t.Errorf("%s/%s attributed to %s", d.Kustomize.RenderedNamespace, d.Kustomize.RenderedName, g.Name)
		}
	}
	if len(res.Documents) != 2 || res.MappingFailures != 2 {
		t.Fatalf("got %d documents, %d failures", len(res.Documents), res.MappingFailures)
	}
}

// TestRenderSharedBaseSymlinkChainsFails counts both chains to a base one
// overlay reaches through a symlinked kustomization.
func TestRenderSharedBaseSymlinkChainsFails(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"top/kustomization.yaml": "resources:\n  - ../a\n  - ../b\n",
		"a/kustomization.yaml":   "namePrefix: dev-\nnamespace: a\nresources:\n  - ../base\n",
		"b/kustomization.yaml":   "namespace: b\nresources:\n  - ../alias\n",
		"base/kustomization.yaml": "configMapGenerator:\n  - name: gen\n    options:\n      annotations:\n" +
			"        config.kubernetes.io/local-config: \"true\"\n    literals:\n      - A=b\n" +
			"  - name: dev-gen\n    literals:\n      - A=b\n",
	})
	if err := os.MkdirAll(filepath.Join(dir, "alias"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "base", "kustomization.yaml"), filepath.Join(dir, "alias", "kustomization.yaml")); err != nil {
		t.Skip(err)
	}
	res, err := render(t, dir, "top")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if g := d.Kustomize.Generator; g != nil && g.Name != "" {
			t.Errorf("%s/%s attributed to %s", d.Kustomize.RenderedNamespace, d.Kustomize.RenderedName, g.Name)
		}
	}
	if res.MappingFailures != len(res.Documents) {
		t.Fatalf("got %d documents, %d failures", len(res.Documents), res.MappingFailures)
	}
}

// TestRenderSymlinkedKustomizationOtherDirFails fails closed on a base an
// overlay reaches through a kustomization symlinked from another directory:
// Kustomize resolves its entries from the link's directory.
func TestRenderSymlinkedKustomizationOtherDirFails(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"top/kustomization.yaml": "resources:\n  - ../a\n  - ../b\n",
		"a/kustomization.yaml":   "namePrefix: dev-\nnamespace: a\nresources:\n  - ../base\n",
		"templates/deep/b.yml":   "namespace: b\nresources:\n  - ../base\n",
		"b/placeholder.txt":      "",
		"base/kustomization.yaml": "configMapGenerator:\n  - name: gen\n    options:\n      annotations:\n" +
			"        config.kubernetes.io/local-config: \"true\"\n    literals:\n      - A=b\n" +
			"  - name: dev-gen\n    literals:\n      - A=b\n",
	})
	if err := os.Symlink(filepath.Join("..", "templates", "deep", "b.yml"), filepath.Join(dir, "b", "kustomization.yaml")); err != nil {
		t.Skip(err)
	}
	res, err := render(t, dir, "top")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if g := d.Kustomize.Generator; g != nil && g.Name != "" {
			t.Errorf("%s/%s attributed to %s", d.Kustomize.RenderedNamespace, d.Kustomize.RenderedName, g.Name)
		}
	}
	if len(res.Documents) != 2 || res.MappingFailures != 2 {
		t.Fatalf("got %d documents, %d failures", len(res.Documents), res.MappingFailures)
	}
}

// TestRenderSymlinkedRootKustomizationFails fails closed when the root
// kustomization is linked from another directory, even when the chain walk
// from the target's directory happens to reach the source file.
func TestRenderSymlinkedRootKustomizationFails(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"t/k.yml":       "namePrefix: dev-\nresources:\n  - cm.yaml\n",
		"o/cm.yaml":     "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n",
		"o/placeholder": "",
	})
	if err := os.Symlink(filepath.Join("..", "t", "k.yml"), filepath.Join(dir, "o", "kustomization.yaml")); err != nil {
		t.Skip(err)
	}
	// The chain walk from t then reaches o/cm.yaml through t/cm.yaml.
	if err := os.Symlink(filepath.Join("..", "o", "cm.yaml"), filepath.Join(dir, "t", "cm.yaml")); err != nil {
		t.Skip(err)
	}
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Documents) != 1 || res.MappingFailures != 1 {
		t.Fatalf("got %d documents, %d failures", len(res.Documents), res.MappingFailures)
	}
}

// TestRenderIdentityNameHashDisabled keeps a generated name that only looks
// hashed when its generator disabled the content-hash suffix, by its own
// options or the kustomization's generatorOptions.
func TestRenderIdentityNameHashDisabled(t *testing.T) {
	const kust = "configMapGenerator:\n  - name: settings-bcdfgh2m4k\n    literals:\n      - TOKEN=1\n"
	for name, option := range map[string]string{
		"global generatorOptions": "generatorOptions:\n  disableNameSuffixHash: true\n" + kust,
		"generator options":       kust + "    options:\n      disableNameSuffixHash: true\n",
	} {
		t.Run(name, func(t *testing.T) {
			res, err := render(t, writeTree(t, map[string]string{"o/kustomization.yaml": option}), "o")
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range res.Documents {
				a := d.Kustomize
				if a.Kind != "ConfigMap" {
					continue
				}
				if a.RenderedName != "settings-bcdfgh2m4k" {
					t.Errorf("precondition: rendered name %q, want the generator name whole", a.RenderedName)
				}
				if a.IdentityName != a.RenderedName {
					t.Errorf("identity name %q lost a suffix that was never a hash", a.IdentityName)
				}
			}
		})
	}
}

// TestRenderIdentityOverlappingGenerators keeps the stripped identity of a
// hash-enabled generator whose name contains a disableNameSuffixHash sibling's
// name, and keeps it when the generated data changes the content hash.
func TestRenderIdentityOverlappingGenerators(t *testing.T) {
	tree := func(value string) map[string]string {
		return map[string]string{"o/kustomization.yaml": "configMapGenerator:\n" +
			"  - name: app\n    options:\n      disableNameSuffixHash: true\n    literals:\n      - A=1\n" +
			"  - name: app-config\n    literals:\n      - A=" + value + "\n"}
	}
	config := func(t *testing.T, tree map[string]string) (rendered, identity string) {
		t.Helper()
		res, err := render(t, writeTree(t, tree), "o")
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range res.Documents {
			if a := d.Kustomize; a.Kind == "ConfigMap" && strings.HasPrefix(a.RenderedName, "app-config") {
				return a.RenderedName, a.IdentityName
			}
		}
		t.Fatal("no app-config ConfigMap rendered")
		return "", ""
	}
	rendered, identity := config(t, tree("1"))
	if rendered == "app-config" {
		t.Fatal("precondition: the hash-enabled generator rendered no content hash")
	}
	if identity != "app-config" {
		t.Errorf("identity name %q kept the content hash", identity)
	}
	if editedRendered, editedIdentity := config(t, tree("2")); editedIdentity != identity {
		t.Errorf("data edit moved the identity from %q to %q", identity, editedIdentity)
	} else if editedRendered == rendered {
		t.Error("precondition: the data edit did not change the content hash")
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

func planTree(t *testing.T, files map[string]string, charts ...string) (string, []PlannedRoot) {
	t.Helper()
	dir := writeTree(t, files)
	var dirs []string
	for p := range files {
		if IsKustomizationFile(filepath.Base(p)) {
			dirs = append(dirs, filepath.Join(dir, filepath.Dir(p)))
		}
	}
	var chartDirs []string
	for _, c := range charts {
		chartDirs = append(chartDirs, filepath.Join(dir, c))
	}
	return dir, Plan(dirs, chartDirs, os.ReadFile)
}

func TestPlan(t *testing.T) {
	files := baseTree()
	files["overlays/staging/kustomization.yaml"] = "namePrefix: stg-\nresources:\n  - ../dev\n"
	files["lone/kustomization.yaml"] = "resources: []\n"
	files["chart/kustomization.yaml"] = "resources: []\n"
	files["remote/kustomization.yaml"] = "resources:\n  - ../nested\n"
	files["nested/kustomization.yaml"] = "resources:\n  - https://example.invalid/x\n"
	files["cycle-a/kustomization.yaml"] = "resources:\n  - ../cycle-b\n"
	files["cycle-b/kustomization.yaml"] = "resources:\n  - ../cycle-a\n"
	files["selfcycle/kustomization.yaml"] = "resources:\n  - ../selfcycle-x\n"
	files["selfcycle-x/kustomization.yaml"] = "resources:\n  - ../selfcycle-x\n"
	dir, roots := planTree(t, files, "chart")
	got := map[string]string{}
	for _, r := range roots {
		rel, _ := filepath.Rel(dir, r.Dir)
		got[filepath.ToSlash(rel)] = r.Skip
	}
	want := map[string]string{
		"overlays/staging": "", "overlays/prod": "", "lone": "", "remote": ReasonPlanSkip, "selfcycle": ReasonPlanSkip,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	for _, r := range roots {
		if strings.HasSuffix(r.Dir, "staging") {
			if a := r.Closure[filepath.Join(dir, "base")]; a.Prefix != "stg-dev-" {
				t.Errorf("affixes %+v", a)
			}
		}
	}
}

func BenchmarkPlan(b *testing.B) {
	files := map[string]string{}
	var dirs []string
	for i := 0; i < 1000; i++ {
		d := "k" + strconv.Itoa(i)
		files[d+"/kustomization.yaml"] = "namePrefix: p-\nresources:\n  - ../k" + strconv.Itoa(i/2) + "\n"
		dirs = append(dirs, d)
	}
	content := func(p string) ([]byte, error) {
		rel := filepath.Base(filepath.Dir(p)) + "/" + filepath.Base(p)
		if c, ok := files[rel]; ok {
			return []byte(c), nil
		}
		return nil, os.ErrNotExist
	}
	abs := make([]string, len(dirs))
	for i, d := range dirs {
		abs[i] = "/r/" + d
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Plan(abs, nil, content)
	}
}

// TestRenderMapsByAffixChain maps a rendered name to the source document the
// verified affix chain selects: dev- prefixed, "web" and "dev-web" in one
// file must not be confused, and an unresolvable name is a mapping failure.
func TestRenderMapsByAffixChain(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"base/kustomization.yaml": "namePrefix: dev-\nresources:\n  - dep.yaml\n",
		"base/dep.yaml":           "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: dev-web\n",
	})
	res, err := render(t, dir, "base")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]int{}
	for _, d := range res.Documents {
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		// The rendered name keeps its source name plus the affix.
		found[d.Kustomize.SourceName] = d.SourceDocumentIndex
	}
	want := map[string]int{"web": 0, "dev-web": 1}
	if !reflect.DeepEqual(found, want) {
		t.Fatalf("affix mapping: got %v, want %v", found, want)
	}
	if res.MappingFailures != 0 {
		t.Fatalf("mapping failures: %d, want 0", res.MappingFailures)
	}
}

// TestRenderTargetsMatchSelectorSemantics drops patches whose namespace,
// apiVersion or label selector does not select the resource.
func TestRenderTargetsMatchSelectorSemantics(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": `resources:
  - dep.yaml
patches:
  - path: wrong-ns.yaml
    target: {kind: Deployment, name: web, namespace: other}
  - path: wrong-group.yaml
    target: {group: batch, version: v1, kind: Job, name: web}
  - path: right-label.yaml
    target: {kind: Deployment, name: web, labelSelector: "app=web"}
  - path: wrong-label.yaml
    target: {kind: Deployment, name: web, labelSelector: "app=backend"}
  - path: right-set.yaml
    target: {kind: Deployment, name: web, labelSelector: "app in (web, api)"}
  - path: right-existence.yaml
    target: {kind: Deployment, name: web, labelSelector: "app"}
  - path: wrong-inequality.yaml
    target: {kind: Deployment, name: web, labelSelector: "app!=web"}
`,
		"o/dep.yaml":              "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  labels:\n    app: web\n",
		"o/wrong-ns.yaml":         "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 1\n",
		"o/wrong-group.yaml":      "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: web\n",
		"o/right-label.yaml":      "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 2\n",
		"o/wrong-label.yaml":      "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 3\n",
		"o/right-set.yaml":        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 4\n",
		"o/right-existence.yaml":  "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 5\n",
		"o/wrong-inequality.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 6\n",
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		files := map[string]bool{}
		for _, w := range d.Kustomize.Writers {
			files[filepath.Base(w.File)] = true
		}
		if files["wrong-ns.yaml"] || files["wrong-group.yaml"] || files["wrong-label.yaml"] || files["wrong-inequality.yaml"] {
			t.Fatalf("non-selecting patch attributed: %v", files)
		}
		if !files["right-label.yaml"] || !files["right-set.yaml"] || !files["right-existence.yaml"] {
			t.Fatalf("selecting patch missing: %v", files)
		}
		return
	}
	t.Fatal("no deployment rendered")
}

// TestRenderWritersPatchOnlyComponentAndOrder attributes a patch-only
// component and orders overlapping writes by Kustomize's application order:
// the overlay's patch beats the component's, which beats the base's.
func TestRenderWritersPatchOnlyComponentAndOrder(t *testing.T) {
	files := map[string]string{
		"base/kustomization.yaml":         "resources:\n  - dep.yaml\npatches:\n  - path: base-patch.yaml\n",
		"base/dep.yaml":                   "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 1\n",
		"base/base-patch.yaml":            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 2\n",
		"comp/kustomization.yaml":         "apiVersion: kustomize.config.k8s.io/v1alpha1\nkind: Component\npatches:\n  - path: comp-patch.yaml\n",
		"comp/comp-patch.yaml":            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 3\n",
		"overlays/dev/kustomization.yaml": "resources:\n  - ../../base\ncomponents:\n  - ../../comp\npatches:\n  - path: dev-patch.yaml\n",
		"overlays/dev/dev-patch.yaml":     "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 4\n",
	}
	dir := writeTree(t, files)
	res, err := render(t, dir, "overlays/dev")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		var got []string
		for _, w := range d.Kustomize.Writers {
			rel, _ := filepath.Rel(dir, w.File)
			got = append(got, filepath.ToSlash(rel))
		}
		// Last applied first: overlay, then component (patch-only, hoisted),
		// then the base's own patch.
		want := []string{"overlays/dev/dev-patch.yaml", "comp/comp-patch.yaml", "base/base-patch.yaml"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("writer order: %v", got)
		}
		return
	}
	t.Fatal("no deployment rendered")
}

// TestRenderWritersSiblingAndNestedComponents orders sibling components
// last-listed first, resolves nested components relative to their loader, and
// asserts the nested component's patch is applied and attributed.
func TestRenderWritersSiblingAndNestedComponents(t *testing.T) {
	files := map[string]string{
		"base/kustomization.yaml":         "resources:\n  - dep.yaml\n",
		"base/dep.yaml":                   "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 1\n",
		"comp1/kustomization.yaml":        "apiVersion: kustomize.config.k8s.io/v1alpha1\nkind: Component\ncomponents:\n  - nested\npatches:\n  - path: c1-patch.yaml\n",
		"comp1/c1-patch.yaml":             "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 2\n",
		"comp1/nested/kustomization.yaml": "apiVersion: kustomize.config.k8s.io/v1alpha1\nkind: Component\npatches:\n  - path: n-patch.yaml\n",
		"comp1/nested/n-patch.yaml":       "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 3\n",
		"comp2/kustomization.yaml":        "apiVersion: kustomize.config.k8s.io/v1alpha1\nkind: Component\npatches:\n  - path: c2-patch.yaml\n",
		"comp2/c2-patch.yaml":             "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 4\n",
		"overlays/dev/kustomization.yaml": "resources:\n  - ../../base\ncomponents:\n  - ../../comp1\n  - ../../comp2\n",
	}
	dir := writeTree(t, files)
	res, err := render(t, dir, "overlays/dev")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		// The nested component's patch applied: the last writer set the
		// replicas it carries.
		if !strings.Contains(string(d.Content), "replicas: 4") {
			t.Fatalf("expected comp2's patch last, got: %s", d.Content)
		}
		var got []string
		for _, w := range d.Kustomize.Writers {
			rel, _ := filepath.Rel(dir, w.File)
			got = append(got, filepath.ToSlash(rel))
		}
		// Last applied first: comp2 (listed last), comp1, then comp1's nested
		// component (its step runs inside comp1's).
		want := []string{"comp2/c2-patch.yaml", "comp1/c1-patch.yaml", "comp1/nested/n-patch.yaml"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("component writer order: %v", got)
		}
		return
	}
	t.Fatal("no deployment rendered")
}

// TestRenderWritersSelectorBeforeLabelTransform keeps a patch attributed when
// a later commonLabels entry overwrites the label its selector matched.
func TestRenderWritersSelectorBeforeLabelTransform(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": `resources:
  - dep.yaml
patches:
  - path: sel.yaml
    target: {kind: Deployment, name: web, labelSelector: "app in (web)"}
commonLabels:
  app: prod
`,
		"o/dep.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  labels:\n    app: web\n",
		"o/sel.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 2\n",
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		found := false
		for _, w := range d.Kustomize.Writers {
			if w.Kind == model.KustomizeStrategicMerge && filepath.Base(w.File) == "sel.yaml" {
				found = true
			}
		}
		if !found {
			t.Fatalf("patch selected before the label transform lost: %+v", d.Kustomize.Writers)
		}
		return
	}
	t.Fatal("no deployment rendered")
}

// TestRenderWritersSelectorStateAtPatchLevel evaluates patch selectors
// against the label state at the patch's application point: a mid-level label
// is visible to the outer patch, an outer-only label is not visible to the
// mid patch.
func TestRenderWritersSelectorStateAtPatchLevel(t *testing.T) {
	// (a) The mid overlay adds commonLabels; the outer patch selects on it.
	files := map[string]string{
		"base/kustomization.yaml":  "resources:\n  - dep.yaml\n",
		"base/dep.yaml":            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 1\n",
		"mid/kustomization.yaml":   "resources:\n  - ../base\ncommonLabels:\n  tier: mid\n",
		"outer/kustomization.yaml": "resources:\n  - ../mid\npatches:\n  - path: sel.yaml\n    target: {kind: Deployment, name: web, labelSelector: \"tier in (mid)\"}\n",
		"outer/sel.yaml":           "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 2\n",
	}
	dir := writeTree(t, files)
	res, err := render(t, dir, "outer")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		if !slices.ContainsFunc(d.Kustomize.Writers, func(w model.KustomizeWriter) bool {
			return w.Kind == model.KustomizeStrategicMerge && filepath.Base(w.File) == "sel.yaml"
		}) {
			t.Fatalf("outer patch selecting a mid-level label lost: %+v", d.Kustomize.Writers)
		}
	}
	// (b) The mid patch selects a label only the outer level adds: krusty
	// never applies it, and attribution must not claim it.
	files2 := map[string]string{
		"base/kustomization.yaml":  "resources:\n  - dep.yaml\n",
		"base/dep.yaml":            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 1\n",
		"mid/kustomization.yaml":   "resources:\n  - ../base\npatches:\n  - path: sel.yaml\n    target: {kind: Deployment, name: web, labelSelector: \"app in (prod)\"}\n",
		"mid/sel.yaml":             "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 2\n",
		"outer/kustomization.yaml": "resources:\n  - ../mid\ncommonLabels:\n  app: prod\n",
	}
	dir2 := writeTree(t, files2)
	res2, err := render(t, dir2, "outer")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res2.Documents {
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		if slices.ContainsFunc(d.Kustomize.Writers, func(w model.KustomizeWriter) bool {
			return w.Kind == model.KustomizeStrategicMerge && filepath.Base(w.File) == "sel.yaml"
		}) {
			t.Fatalf("mid patch selecting an outer-only label attributed: %+v", d.Kustomize.Writers)
		}
	}
}

// TestRenderWritersJSON6902AfterLabels attributes a JSON 6902 patch whose
// selector matches a label the same kustomization's labels set: JSON 6902
// applies after the label transformer.
func TestRenderWritersJSON6902AfterLabels(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": `resources:
  - dep.yaml
labels:
  - pairs:
      tier: mid
patchesJson6902:
  - path: p.json
    target: {kind: Deployment, name: web, labelSelector: "tier in (mid)"}
`,
		"o/dep.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  paused: false\n",
		"o/p.json":   `[{"op": "replace", "path": "/spec/paused", "value": true}]`,
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		if !slices.ContainsFunc(d.Kustomize.Writers, func(w model.KustomizeWriter) bool {
			return w.Kind == model.KustomizeJSON6902 && filepath.Base(w.File) == "p.json"
		}) {
			t.Fatalf("JSON 6902 patch selected by the same kustomization's labels lost: %+v", d.Kustomize.Writers)
		}
		return
	}
	t.Fatal("no deployment rendered")
}

// TestRenderWritersLabelsAndAnnotations attributes a field a label or
// annotation transformer set to its entry, and leaves replacements
// unattributed rather than guessed.
func TestRenderWritersLabelsAndAnnotations(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": `resources:
  - dep.yaml
  - cm.yaml
labels:
  - pairs:
      app: web
commonAnnotations:
  owner: team
replacements:
  - source: {kind: ConfigMap, name: x, fieldPath: data.k}
    targets:
      - select: {kind: Deployment}
        fieldPaths:
          - metadata.annotations.note
`,
		"o/dep.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  annotations:\n    note: old\n",
		"o/cm.yaml":  "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata:\n  k: fresh\n",
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		var labels, annotations, replacements bool
		for _, w := range d.Kustomize.Writers {
			switch w.Kind {
			case model.KustomizeLabels:
				labels = w.Name == "app" && w.Line == 5
			case model.KustomizeAnnotations:
				annotations = w.Name == "owner" && w.Line == 8
			case model.KustomizeReplacement:
				replacements = true
			}
		}
		if !labels || !annotations {
			t.Fatalf("label/annotation writers missing (labels=%v annotations=%v)", labels, annotations)
		}
		if replacements {
			t.Fatal("replacement must not be attributed")
		}
		return
	}
	t.Fatal("no deployment rendered")
}

// TestRenderInlineOffsetsDistinct keeps two inline patches with the same
// first line apart: each writer points at its own entry line.
func TestRenderInlineOffsetsDistinct(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": `resources:
  - dep.yaml
patches:
  - patch: |-
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: web
      spec:
        replicas: 1
  - patch: |-
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: web
      spec:
        replicas: 2
`,
		"o/dep.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		var offsets []int
		for _, w := range d.Kustomize.Writers {
			offsets = append(offsets, w.LineOffset+w.Line)
		}
		if len(offsets) != 2 || offsets[0] == offsets[1] {
			t.Fatalf("inline patches collide: %v", offsets)
		}
		return
	}
	t.Fatal("no deployment rendered")
}

// TestRenderWritersSingleLineSMP attributes a single-line flow-style inline
// patchesStrategicMerge entry to its patch line, as Kustomize classifies it.
func TestRenderWritersSingleLineSMP(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": "resources:\n  - dep.yaml\npatchesStrategicMerge:\n" +
			"  - '{apiVersion: apps/v1, kind: Deployment, metadata: {name: web}, spec: {replicas: 3}}'\n",
		"o/dep.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 1\n",
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		ws := d.Kustomize.Writers
		if len(ws) != 1 || ws[0].Kind != model.KustomizeStrategicMerge || filepath.Base(ws[0].File) != "kustomization.yaml" ||
			ws[0].LineOffset != 3 { // content starts on line 4
			t.Fatalf("inline patch writer missing: %+v", ws)
		}
		return
	}
	t.Fatal("no deployment rendered")
}

// TestRenderJSON6902FileDetectsOps reads a JSON-format JSON 6902 patch file.
func TestRenderJSON6902FileDetectsOps(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"o/kustomization.yaml": `resources:
  - dep.yaml
patchesJson6902:
  - path: patch.json
    target: {kind: Deployment, name: web}
`,
		"o/dep.yaml":   "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  paused: false\n",
		"o/patch.json": `[{"op": "replace", "path": "/spec/paused", "value": true}]`,
	})
	res, err := render(t, dir, "o")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		if len(d.Kustomize.Writers) != 1 || d.Kustomize.Writers[0].Kind != model.KustomizeJSON6902 {
			t.Fatalf("JSON 6902 writer missing: %+v", d.Kustomize.Writers)
		}
		return
	}
	t.Fatal("no deployment rendered")
}

func TestRenderWriters(t *testing.T) {
	files := baseTree()
	files["overlays/dev/kustomization.yaml"] = `namePrefix: dev-
namespace: dev
resources:
  - ../../base
images:
  - name: nginx
    newTag: latest
patches:
  - path: smp.yaml
  - target:
      kind: Deployment
      name: web
    path: ops.yaml
  - patch: |-
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: web
      spec:
        replicas: 3
`
	files["overlays/dev/smp.yaml"] = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"
	files["overlays/dev/ops.yaml"] = "- op: add\n  path: /spec/paused\n  value: true\n"
	dir := writeTree(t, files)
	res, err := render(t, dir, "overlays/dev")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Documents {
		if d.Kustomize.Kind != "Deployment" {
			continue
		}
		var got []string
		for _, w := range d.Kustomize.Writers {
			rel, _ := filepath.Rel(dir, w.File)
			got = append(got, w.Kind+":"+filepath.ToSlash(rel)+":"+strconv.Itoa(w.LineOffset+w.Line))
		}
		// Kustomize applies images after namespace after patches, so the last
		// writer to touch a field is found first.
		want := []string{
			"images:overlays/dev/kustomization.yaml:6", "namespace:overlays/dev/kustomization.yaml:2",
			"smp:overlays/dev/kustomization.yaml:14", "json6902:overlays/dev/ops.yaml:0",
			"smp:overlays/dev/smp.yaml:0",
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("writers: %v", got)
		}
		return
	}
	t.Fatal("no deployment rendered")
}

// identities renders root in tree and returns the resource IDs of the
// rendered objects.
func identities(t *testing.T, tree map[string]string, root string) []string {
	t.Helper()
	res, err := render(t, writeTree(t, tree), root)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, d := range res.Documents {
		ids = append(ids, d.Kustomize.ResourceID("web"))
	}
	sort.Strings(ids)
	return ids
}

// TestRenderIdentity identifies a rendered object by its rendered group, kind,
// namespace and name: where its manifest lives and what a generator holds do
// not matter, the affixes and namespace an overlay sets do.
func TestRenderIdentity(t *testing.T) {
	tree := func(file, prefix, ns, value string) map[string]string {
		return map[string]string{
			"base/kustomization.yaml": "resources:\n  - " + file + "\n",
			"base/" + file:            deployment,
			"o/kustomization.yaml": "namePrefix: " + prefix + "\nnamespace: " + ns + "\nresources:\n  - ../base\n" +
				"configMapGenerator:\n  - name: settings\n    literals:\n      - A=" + value + "\n",
		}
	}
	got := identities(t, tree("deployment.yaml", "dev-", "dev", "1"), "o")
	want := []string{"/ConfigMap|dev|dev-settings", "/Service|dev|dev-web", "apps/Deployment|dev|dev-web"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for name, other := range map[string]map[string]string{
		"moved manifest":      tree("moved.yaml", "dev-", "dev", "1"),
		"generated data edit": tree("deployment.yaml", "dev-", "dev", "2"),
	} {
		if ids := identities(t, other, "o"); !reflect.DeepEqual(ids, got) {
			t.Errorf("%s: got %v, want %v", name, ids, got)
		}
	}
	for name, other := range map[string]map[string]string{
		"namePrefix": tree("deployment.yaml", "qa-", "dev", "1"),
		"namespace":  tree("deployment.yaml", "dev-", "qa", "1"),
	} {
		for i, id := range identities(t, other, "o") {
			if id == got[i] {
				t.Errorf("%s: %s kept its identity", name, id)
			}
		}
	}
}

// TestRenderIdentityReplacementCanary never identifies an object by a name a
// replacement copied from generated data, whether the target names the field
// or leaves it out: an omitted target fieldPaths defaults to metadata.name.
func TestRenderIdentityReplacementCanary(t *testing.T) {
	for name, targets := range map[string]string{
		"named field":   "        fieldPaths:\n          - metadata.name\n",
		"omitted field": "",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"o/deployment.yaml": deployment,
				"o/kustomization.yaml": "resources:\n  - deployment.yaml\n" +
					"configMapGenerator:\n  - name: settings\n    literals:\n      - TOKEN=canaryvalue\n" +
					"replacements:\n  - source:\n      kind: ConfigMap\n      name: settings\n      fieldPath: data.TOKEN\n" +
					"    targets:\n      - select:\n          kind: Deployment\n" + targets,
			})
			res, err := render(t, dir, "o")
			if err != nil {
				t.Fatal(err)
			}
			var copied bool
			for _, d := range res.Documents {
				a := d.Kustomize
				copied = copied || a.RenderedName == "canaryvalue"
				if id := a.ResourceID("web"); strings.Contains(id, "canary") {
					t.Errorf("identity %q carries generated data", id)
				}
			}
			if !copied {
				t.Fatal("precondition: the replacement did not copy the value into a name")
			}
		})
	}
}
