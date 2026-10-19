/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2025 Datadog, Inc.
 */
package kustomize

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"sigs.k8s.io/kustomize/api/provider"
	"sigs.k8s.io/kustomize/api/resmap"
	"sigs.k8s.io/kustomize/kyaml/openapi"
)

const baseDeployment = `apiVersion: apps/v1

kind: Deployment

metadata:

  name: app

spec:

  template:

    spec:

      containers:

        - name: app

          image: nginx

`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func writeBaseAndOverlays(t *testing.T, root string) {
	t.Helper()
	writeFile(t, filepath.Join(root, "base", "kustomization.yaml"), "resources:\n  - deployment.yaml\n")
	writeFile(t, filepath.Join(root, "base", "deployment.yaml"), baseDeployment)
	writeFile(t, filepath.Join(root, "overlays", "dev", "kustomization.yaml"),
		"resources:\n  - ../../base\nnamePrefix: dev-\n")
	writeFile(t, filepath.Join(root, "overlays", "prod", "kustomization.yaml"),
		"resources:\n  - ../../base\nnamePrefix: prod-\n")
}

func TestRender_BaseAndOverlays(t *testing.T) {
	root := t.TempDir()
	writeBaseAndOverlays(t, root)
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	result, err := renderer.Render(t.Context(), filepath.Join("overlays", "dev"))
	if err != nil {
		t.Fatalf("Render(dev) = %v, want nil", err)
	}
	// Disk paths keep the OS separator, as the Helm resolver does, so the
	// expectations are built with filepath.Join rather than hardcoded slashes.
	if want := filepath.Join("overlays", "dev"); result.Root != want {
		t.Errorf("Root = %q, want %q", result.Root, want)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(result.Entries))
	}
	e := result.Entries[0]
	if want := filepath.Join("base", "deployment.yaml"); e.FileName != want {
		t.Errorf("FileName = %q, want %q", e.FileName, want)
	}
	if want := filepath.Join("overlays", "dev"); e.RenderRoot != want {
		t.Errorf("RenderRoot = %q, want %q", e.RenderRoot, want)
	}
	if e.SourceResourceName != "app" {
		t.Errorf("SourceResourceName = %q, want app (name as written in the source)", e.SourceResourceName)
	}
	if e.SourceDocumentIndex != 0 {
		t.Errorf("SourceDocumentIndex = %d, want 0", e.SourceDocumentIndex)
	}
	if !strings.Contains(string(e.Content), "name: dev-app") {
		t.Errorf("Content missing rendered name: %s", e.Content)
	}
	if strings.Contains(string(e.Content), "config.kubernetes.io/origin") {
		t.Error("Content still carries the origin annotation")
	}
	if !strings.Contains(string(e.OriginalData), "name: app") {
		t.Error("OriginalData is not the source bytes")
	}
	if len(result.ReadFiles) == 0 {
		t.Error("ReadFiles is empty")
	}
	if result.MappingFailures != 0 {
		t.Errorf("MappingFailures = %d, want 0", result.MappingFailures)
	}
}

func TestRender_BothOverlaysShareSource(t *testing.T) {
	root := t.TempDir()
	writeBaseAndOverlays(t, root)
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	dev, err := renderer.Render(t.Context(), filepath.Join("overlays", "dev"))
	if err != nil {
		t.Fatal(err)
	}
	prod, err := renderer.Render(t.Context(), filepath.Join("overlays", "prod"))
	if err != nil {
		t.Fatal(err)
	}
	if dev.Entries[0].FileName != prod.Entries[0].FileName {
		t.Errorf("overlays disagree on source file: %q vs %q", dev.Entries[0].FileName, prod.Entries[0].FileName)
	}
	if dev.Entries[0].RenderRoot == prod.Entries[0].RenderRoot {
		t.Error("both renders report the same render root")
	}
	if string(dev.Entries[0].OriginalData) != string(prod.Entries[0].OriginalData) {
		t.Error("OriginalData differs between overlays of the same base")
	}
}

func TestRender_MultiDocSource(t *testing.T) {
	root := t.TempDir()
	multi := baseDeployment + "---\napiVersion: v1\nkind: Service\nmetadata:\n  name: svc\nspec: {}\n"
	writeFile(t, filepath.Join(root, "base", "kustomization.yaml"), "resources:\n  - sources.yaml\n")
	writeFile(t, filepath.Join(root, "base", "sources.yaml"), multi)
	writeFile(t, filepath.Join(root, "overlays", "dev", "kustomization.yaml"),
		"resources:\n  - ../../base\nnamePrefix: dev-\n")
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	result, err := renderer.Render(t.Context(), filepath.Join("overlays", "dev"))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]int{}
	for _, e := range result.Entries {
		byName[e.SourceResourceName] = e.SourceDocumentIndex
	}
	if byName["app"] != 0 || byName["svc"] != 1 {
		t.Errorf("document indexes = %v, want app:0 svc:1", byName)
	}
	if result.MappingFailures != 0 {
		t.Errorf("MappingFailures = %d, want 0", result.MappingFailures)
	}
}

func TestRender_GeneratorsMapToKustomization(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "kustomization.yaml"),
		"secretGenerator:\n  - name: creds\n    literals:\n      - user=admin\n")
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	result, err := renderer.Render(t.Context(), ".")
	if err != nil {
		t.Fatal(err)
	}
	// The render root is the confinement root here, which must report as "."
	if result.Root != "." {
		t.Errorf("Root = %q, want \".\" (an absolute path would leak the host layout)", result.Root)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(result.Entries))
	}
	e := result.Entries[0]
	if e.FileName != "kustomization.yaml" {
		t.Errorf("FileName = %q, want kustomization.yaml", e.FileName)
	}
	if e.RenderRoot != "." {
		t.Errorf("RenderRoot = %q, want \".\"", e.RenderRoot)
	}
	if !strings.Contains(string(e.Content), "kind: Secret") {
		t.Errorf("Content is not a generated Secret: %s", e.Content)
	}
	if strings.Contains(string(e.OriginalData), "originAnnotations") {
		t.Error("OriginalData carries the injected build metadata; findings there would lose their line numbers")
	}
}

func TestRender_Component(t *testing.T) {
	root := t.TempDir()
	compDeployment := strings.Replace(baseDeployment, "name: app", "name: comp-app", 1)
	writeFile(t, filepath.Join(root, "component", "kustomization.yaml"), "apiVersion: kustomize.config.k8s.io/v1alpha1\nkind: Component\nresources:\n  - deployment.yaml\n")
	writeFile(t, filepath.Join(root, "component", "deployment.yaml"), compDeployment)
	writeFile(t, filepath.Join(root, "kustomization.yaml"), "resources:\n  - deployment.yaml\ncomponents:\n  - component\n")
	writeFile(t, filepath.Join(root, "deployment.yaml"), baseDeployment)
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	result, err := renderer.Render(t.Context(), ".")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range result.Entries {
		if strings.Contains(filepath.ToSlash(e.FileName), "component/deployment.yaml") && e.SourceResourceName == "comp-app" {
			found = true
		}
	}
	if !found {
		t.Errorf("component resources not mapped: %+v", result.Entries)
	}
}

func TestRender_LoadRestrictionsNoneAllowsParentReferences(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "base", "kustomization.yaml"), "resources:\n  - deployment.yaml\n")
	writeFile(t, filepath.Join(root, "base", "deployment.yaml"), baseDeployment)
	writeFile(t, filepath.Join(root, "overlay", "kustomization.yaml"), "resources:\n  - ../base/deployment.yaml\n")
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	if _, err := renderer.Render(t.Context(), "overlay"); err != nil {
		t.Fatalf("Render(overlay with parent reference) = %v, want nil", err)
	}
}

func TestRender_MissingKustomization(t *testing.T) {
	root := t.TempDir()
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	_, err := renderer.Render(t.Context(), ".")
	if err == nil {
		t.Fatal("Render without kustomization = nil error, want missing_file")
	}
	if re, ok := err.(*RenderError); !ok || re.Reason != ReasonMissingFile {
		t.Errorf("reason = %v, want missing_file", err)
	}
}

func TestRender_MappingFailureCounted(t *testing.T) {
	root := t.TempDir()
	// The base renames its resources with a suffix the root knows nothing
	// about. One rendered name resolves through containment; the other is
	// ambiguous (its name contains both source names) and must fail with the
	// content still present for line-1 scanning.
	second := strings.Replace(baseDeployment, "name: app", "name: xapp", 1)
	writeFile(t, filepath.Join(root, "base", "kustomization.yaml"), "resources:\n  - deployments.yaml\nnameSuffix: -s\n")
	writeFile(t, filepath.Join(root, "base", "deployments.yaml"), baseDeployment+"---\n"+second)
	writeFile(t, filepath.Join(root, "overlay", "kustomization.yaml"), "resources:\n  - ../base\n")
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	result, err := renderer.Render(t.Context(), "overlay")
	if err != nil {
		t.Fatal(err)
	}
	if result.MappingFailures != 1 {
		t.Errorf("MappingFailures = %d, want 1", result.MappingFailures)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("got %d entries, want 2 (unmapped content is still scanned)", len(result.Entries))
	}
	for _, e := range result.Entries {
		if len(e.Content) == 0 {
			t.Error("entry has no content")
		}
	}
}

// cleanSchemaVersion isolates a test from the process-global Kustomize OpenAPI
// state and returns the version a render must restore. Without it a test that
// starts from a leaked custom schema would compare a dirty value to itself and
// pass whatever the renderer does.
func cleanSchemaVersion(t *testing.T) string {
	t.Helper()
	openapi.ResetOpenAPI()
	t.Cleanup(openapi.ResetOpenAPI)
	return openapi.GetSchemaVersion()
}

func TestRender_OpenAPIRootDoesNotBreakLaterRenders(t *testing.T) {
	root := t.TempDir()
	writeBaseAndOverlays(t, root)
	writeFile(t, filepath.Join(root, "withopenapi", "kustomization.yaml"),
		"resources:\n  - ../base\nopenapi:\n  path: schema.json\n")
	writeFile(t, filepath.Join(root, "withopenapi", "schema.json"), "{}")
	before := cleanSchemaVersion(t)
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	if _, err := renderer.Render(t.Context(), "withopenapi"); err != nil {
		t.Fatalf("Render(openapi root) = %v, want nil", err)
	}
	if got := openapi.GetSchemaVersion(); got != before {
		t.Errorf("schema version after render = %q, want %q restored", got, before)
	}
	if _, err := renderer.Render(t.Context(), filepath.Join("overlays", "dev")); err != nil {
		t.Fatalf("Render after openapi root = %v, want nil", err)
	}
}

func TestRender_OpenAPIInBaseIsResetToo(t *testing.T) {
	root := t.TempDir()
	// Only the base sets openapi, so keying the reset on the render root's own
	// openapi field would miss it and leave the custom schema installed for
	// every later render in the process.
	writeFile(t, filepath.Join(root, "base", "kustomization.yaml"),
		"resources:\n  - deployment.yaml\nopenapi:\n  path: schema.json\n")
	writeFile(t, filepath.Join(root, "base", "deployment.yaml"), baseDeployment)
	writeFile(t, filepath.Join(root, "base", "schema.json"), "{}")
	writeFile(t, filepath.Join(root, "overlay", "kustomization.yaml"), "resources:\n  - ../base\n")
	before := cleanSchemaVersion(t)
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	if _, err := renderer.Render(t.Context(), "overlay"); err != nil {
		t.Fatalf("Render(base sets openapi) = %v, want nil", err)
	}
	if got := openapi.GetSchemaVersion(); got != before {
		t.Errorf("schema version after render = %q, want %q restored", got, before)
	}
}

func TestRender_OpenAPIResetOnRenderError(t *testing.T) {
	root := t.TempDir()
	// krusty installs the custom schema before the work that can fail, so a
	// render that errors afterwards must still restore the global state.
	writeFile(t, filepath.Join(root, "kustomization.yaml"),
		"resources:\n  - deployment.yaml\nopenapi:\n  path: schema.json\npatches:\n  - path: patch.yaml\n")
	writeFile(t, filepath.Join(root, "deployment.yaml"), baseDeployment)
	writeFile(t, filepath.Join(root, "schema.json"), "{}")
	// A patch whose target does not exist makes the build fail after SetSchema.
	writeFile(t, filepath.Join(root, "patch.yaml"),
		"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: nonexistent\nspec:\n  replicas: 2\n")
	before := cleanSchemaVersion(t)
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	if _, err := renderer.Render(t.Context(), "."); err == nil {
		t.Fatal("Render(patch with no target) = nil error, want render error")
	}
	if got := openapi.GetSchemaVersion(); got != before {
		t.Errorf("schema version after failed render = %q, want %q restored", got, before)
	}
}

func TestMapResources_DropsResourcesWithNoSourceFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "kustomization.yaml"), "resources:\n  - deployment.yaml\n")
	writeFile(t, filepath.Join(root, "deployment.yaml"), baseDeployment)
	cfs, err := newConstrainedFS(vfs.DiskFS{}, root, ".", DefaultMaxFileBytes, &atomic.Int64{}, &byteCache{files: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	// A resource with no origin annotation cannot be traced to a source file,
	// so there is nowhere to report its findings. It must count as a mapping
	// failure and be dropped, never emitted with an empty FileName and a
	// document index of 0 that reads as a real position.
	res, err := provider.NewDefaultDepProvider().GetResourceFactory().FromBytes([]byte(baseDeployment))
	if err != nil {
		t.Fatal(err)
	}
	rm := resmap.New()
	if err := rm.Append(res); err != nil {
		t.Fatal(err)
	}
	entries, failures := mapResources(vfs.DiskFS{}, cfs, rm, "", "")
	if failures != 1 {
		t.Errorf("failures = %d, want 1", failures)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %+v, want none: an entry with no source file has nowhere to report", entries)
	}
}

func TestRender_ConcurrentRenders(t *testing.T) {
	root := t.TempDir()
	writeBaseAndOverlays(t, root)
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	overlays := []string{"dev", "prod"}
	results := make(chan error, len(overlays))
	for _, overlay := range overlays {
		go func(overlay string) {
			_, err := renderer.Render(t.Context(), filepath.Join("overlays", overlay))
			results <- err
		}(overlay)
	}
	for range overlays {
		if err := <-results; err != nil {
			t.Errorf("concurrent render = %v, want nil", err)
		}
	}
}

func TestRender_MemFS(t *testing.T) {
	files := map[string][]byte{
		"/repo/base/kustomization.yaml":         []byte("resources:\n  - deployment.yaml\n"),
		"/repo/base/deployment.yaml":            []byte(baseDeployment),
		"/repo/overlays/dev/kustomization.yaml": []byte("resources:\n  - ../../base\nnamePrefix: dev-\n"),
	}
	renderer := NewRenderer(vfs.NewMemFS(files), "/repo", 0)
	result, err := renderer.Render(t.Context(), "overlays/dev")
	if err != nil {
		t.Fatalf("Render(memfs) = %v, want nil", err)
	}
	if len(result.Entries) != 1 || result.Entries[0].SourceResourceName != "app" {
		t.Errorf("entries = %+v, want one mapped to source app", result.Entries)
	}
	// Pushed files are addressed with "/" on every OS, so a MemFS render
	// reports forward slashes whatever the host separator is.
	if result.Root != "overlays/dev" {
		t.Errorf("Root = %q, want overlays/dev", result.Root)
	}
	if got := result.Entries[0].FileName; got != "base/deployment.yaml" {
		t.Errorf("FileName = %q, want base/deployment.yaml", got)
	}
}

func TestRender_SymlinkedKustomizationKeepsAttribution(t *testing.T) {
	root := t.TempDir()
	// A render root whose kustomization.yaml is a symlink to another file in
	// the workspace is a legitimate layout. The top-level file is recognized
	// by its resolved path, so it still gets the origin annotations every
	// resource needs to be attributed back to its source document.
	writeFile(t, filepath.Join(root, "base", "kustomization.yaml"), "resources:\n  - deployment.yaml\n")
	writeFile(t, filepath.Join(root, "base", "deployment.yaml"), baseDeployment)
	writeFile(t, filepath.Join(root, "shared", "kustomization-shared.yaml"),
		"resources:\n  - ../base\nnamePrefix: dev-\n")
	writeFile(t, filepath.Join(root, "overlay", ".keep"), "")
	link := filepath.Join(root, "overlay", "kustomization.yaml")
	if err := os.Symlink(filepath.Join(root, "shared", "kustomization-shared.yaml"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	result, err := renderer.Render(t.Context(), "overlay")
	if err != nil {
		t.Fatalf("Render(symlinked kustomization) = %v, want nil", err)
	}
	if result.MappingFailures != 0 {
		t.Errorf("MappingFailures = %d, want 0", result.MappingFailures)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(result.Entries))
	}
	e := result.Entries[0]
	if want := filepath.Join("base", "deployment.yaml"); e.FileName != want {
		t.Errorf("FileName = %q, want %q", e.FileName, want)
	}
	if e.SourceResourceName != "app" {
		t.Errorf("SourceResourceName = %q, want app", e.SourceResourceName)
	}
	if e.SourceDocumentIndex != 0 {
		t.Errorf("SourceDocumentIndex = %d, want 0", e.SourceDocumentIndex)
	}
}

func TestRender_NamespaceOverrideKeepsAttribution(t *testing.T) {
	root := t.TempDir()
	// The rendered namespace is the transformed one, so it differs from the
	// namespace the source document writes. Attribution must still work: this
	// is the standard base-plus-overlay layout.
	namespaced := strings.Replace(baseDeployment, "  name: app\n", "  name: app\n  namespace: dev\n", 1)
	writeFile(t, filepath.Join(root, "base", "kustomization.yaml"), "resources:\n  - deployment.yaml\n")
	writeFile(t, filepath.Join(root, "base", "deployment.yaml"), namespaced)
	writeFile(t, filepath.Join(root, "overlay", "kustomization.yaml"),
		"resources:\n  - ../base\nnamespace: prod\n")
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	result, err := renderer.Render(t.Context(), "overlay")
	if err != nil {
		t.Fatal(err)
	}
	if result.MappingFailures != 0 {
		t.Errorf("MappingFailures = %d, want 0 (namespace is a tiebreaker, not a requirement)", result.MappingFailures)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(result.Entries))
	}
	e := result.Entries[0]
	if e.SourceDocumentIndex != 0 {
		t.Errorf("SourceDocumentIndex = %d, want 0", e.SourceDocumentIndex)
	}
	if !strings.Contains(string(e.Content), "namespace: prod") {
		t.Errorf("Content was not renamespaced: %s", e.Content)
	}
}

func TestRender_NamespaceDisambiguatesSameKindAndName(t *testing.T) {
	root := t.TempDir()
	// Two documents share kind and name and differ only by namespace, so the
	// namespace is what singles one out.
	devDoc := strings.Replace(baseDeployment, "  name: app\n", "  name: app\n  namespace: dev\n", 1)
	prodDoc := strings.Replace(baseDeployment, "  name: app\n", "  name: app\n  namespace: prod\n", 1)
	writeFile(t, filepath.Join(root, "kustomization.yaml"), "resources:\n  - deployments.yaml\n")
	writeFile(t, filepath.Join(root, "deployments.yaml"), devDoc+"---\n"+prodDoc)
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	result, err := renderer.Render(t.Context(), ".")
	if err != nil {
		t.Fatal(err)
	}
	if result.MappingFailures != 0 {
		t.Errorf("MappingFailures = %d, want 0", result.MappingFailures)
	}
	byNamespace := map[string]int{}
	for _, e := range result.Entries {
		if strings.Contains(string(e.Content), "namespace: dev") {
			byNamespace["dev"] = e.SourceDocumentIndex
		}
		if strings.Contains(string(e.Content), "namespace: prod") {
			byNamespace["prod"] = e.SourceDocumentIndex
		}
	}
	if byNamespace["dev"] != 0 || byNamespace["prod"] != 1 {
		t.Errorf("document indexes = %v, want dev:0 prod:1", byNamespace)
	}
}

func TestMemFS_ProbesRecordNothing(t *testing.T) {
	files := map[string][]byte{
		"/repo/base/kustomization.yaml": []byte("resources:\n  - deployment.yaml\n"),
		"/repo/base/deployment.yaml":    []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n"),
	}
	mem := vfs.NewMemFS(files)
	renderer := NewRenderer(mem, "/repo", 0)
	if _, err := renderer.Render(t.Context(), "base"); err != nil {
		t.Fatalf("Render(memfs base) = %v, want nil", err)
	}
	if missing := mem.MissingFiles(); len(missing) != 0 {
		t.Errorf("MissingFiles() = %v, want empty: kustomization probes must not escalate", missing)
	}
}

// canaryListener fails the test if anything connects to it.
func canaryListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var hits atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() {
		if hits.Load() != 0 {
			t.Errorf("renderer made %d network connections", hits.Load())
		}
	})
	return ln.Addr().String()
}

func fakeGitOnPath(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	old := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", old) })
	_ = os.Setenv("PATH", dir+string(os.PathListSeparator)+old)
}

func proxyToCanary(t *testing.T, addr string) {
	t.Helper()
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		old := os.Getenv(key)
		t.Cleanup(func() { _ = os.Setenv(key, old) })
		_ = os.Setenv(key, "http://"+addr)
	}
}

func TestRender_RefusesRemoteReferenceWithoutEgress(t *testing.T) {
	addr := canaryListener(t)
	proxyToCanary(t, addr)
	fakeGitOnPath(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "kustomization.yaml"),
		[]byte("resources:\n  - https://example.com/x.yaml\n"), 0600); err != nil {
		t.Fatal(err)
	}
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	_, err := renderer.Render(t.Context(), ".")
	if err == nil {
		t.Fatal("Render(remote ref) = nil error, want validation error")
	}
	if re, ok := err.(*RenderError); !ok || re.Reason != ReasonValidation {
		t.Errorf("reason = %v, want validation", err)
	}
}

func TestRender_RefusesGitReferenceWithoutEgress(t *testing.T) {
	addr := canaryListener(t)
	proxyToCanary(t, addr)
	fakeGitOnPath(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "kustomization.yaml"),
		[]byte("resources:\n  - github.com/org/repo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	_, err := renderer.Render(t.Context(), ".")
	if err == nil {
		t.Fatal("Render(github ref) = nil error, want validation error")
	}
}

func TestRender_RefusesCapitalizedRemoteReferenceWithoutEgress(t *testing.T) {
	addr := canaryListener(t)
	proxyToCanary(t, addr)
	fakeGitOnPath(t)
	root := t.TempDir()
	// "Resources" binds for Kustomize because it decodes through encoding/json,
	// which is case-insensitive. A case-sensitive validator sees nothing here.
	if err := os.WriteFile(filepath.Join(root, "kustomization.yaml"),
		[]byte("Resources:\n  - https://example.com/x.yaml\n"), 0600); err != nil {
		t.Fatal(err)
	}
	renderer := NewRenderer(vfs.DiskFS{}, root, 0)
	_, err := renderer.Render(t.Context(), ".")
	if err == nil {
		t.Fatal("Render(capitalized remote ref) = nil error, want validation error")
	}
	if re, ok := err.(*RenderError); !ok || re.Reason != ReasonValidation {
		t.Errorf("reason = %v, want validation", err)
	}
}
