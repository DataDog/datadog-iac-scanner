/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2025 Datadog, Inc.
 */
package kustomize

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"sigs.k8s.io/kustomize/api/types"
)

func TestPlainLocalPath(t *testing.T) {
	allowed := []string{
		"deployment.yaml",
		"./deployment.yaml",
		"../base/deployment.yaml",
		"base/deployment.yaml",
		"key=deployment.yaml",
	}
	refused := []string{
		"",
		".",
		"..",
		"/etc/passwd",
		"C:\\x.yaml",
		"https://example.com/x.yaml",
		"ssh://git@host/org/repo",
		"git@host:org/repo",
		"github.com:org/repo",
		"GitHub.com/org/repo",
		"HTTPS://example.com/x.yaml",
		"git::https://example.com/x.yaml",
		"key=https://example.com/x.yaml",
		"user@example.com:org/repo",
		"..\\base\\x.yaml",
		"a?b=x.yaml",
	}
	for _, p := range allowed {
		if !plainLocalPath(p) {
			t.Errorf("plainLocalPath(%q) = false, want true", p)
		}
	}
	for _, p := range refused {
		if plainLocalPath(p) {
			t.Errorf("plainLocalPath(%q) = true, want false", p)
		}
	}
}

func TestValidateKustomization(t *testing.T) {
	valid := []byte(`resources:
  - deployment.yaml
  - ../base
configMapGenerator:
  - name: cfg
    files:
      - app.properties
`)
	if _, err := validateKustomization(valid); err != nil {
		t.Fatalf("validateKustomization(valid) = %v, want nil", err)
	}
	invalid := map[string]string{
		"remote resource":  "resources:\n  - https://example.com/x.yaml\n",
		"remote patch":     "patches:\n  - path: https://example.com/p.yaml\n",
		"scp resource":     "resources:\n  - git@host:org/repo\n",
		"generators":       "generators:\n  - gen.yaml\n",
		"transformers":     "transformers:\n  - tr.yaml\n",
		"validators":       "validators:\n  - v.yaml\n",
		"helmCharts":       "helmCharts:\n  - name: foo\n",
		"helm generator":   "helmChartInflationGenerator:\n  - name: foo\n",
		"generator remote": "configMapGenerator:\n  - name: cfg\n    envs:\n      - https://x/.env\n",
		"openapi remote":   "openapi:\n  path: https://x/schema.json\n",
		// Kustomize decodes kustomization fields case-insensitively, so a
		// capitalized key binds for the renderer and must not slip past
		// validation.
		"capitalized remote resource": "Resources:\n  - https://example.com/x.yaml\n",
		"upper remote resource":       "RESOURCES:\n  - https://example.com/x.yaml\n",
		"capitalized git resource":    "Resources:\n  - github.com/org/repo\n",
		"capitalized generators":      "Generators:\n  - gen.yaml\n",
		"capitalized helmCharts":      "HelmCharts:\n  - name: foo\n",
		"capitalized remote patch":    "Patches:\n  - path: https://example.com/p.yaml\n",
		// An undecodable kustomization fails closed: Kustomize would refuse
		// it too, so the files are scanned raw instead.
		"unknown field":  "bogusUnknownField: 1\n",
		"duplicate keys": "resources:\n  - ok.yaml\nresources:\n  - https://example.com/x.yaml\n",
	}
	for name, content := range invalid {
		if _, err := validateKustomization([]byte(content)); err == nil {
			t.Errorf("validateKustomization(%s) = nil, want error", name)
		} else if re, ok := err.(*RenderError); !ok || re.Reason != ReasonValidation {
			t.Errorf("validateKustomization(%s) reason = %v, want validation", name, err)
		}
	}
}

func TestKustomizationFieldClassification(t *testing.T) {
	classified := make(map[string]bool)
	for _, list := range [][]string{kustomizationPathFields, kustomizationNoPathFields, kustomizationForbiddenFields} {
		for _, f := range list {
			if classified[f] {
				t.Errorf("field %s classified twice", f)
			}
			classified[f] = true
		}
	}
	typ := reflect.TypeOf(types.Kustomization{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !classified[name] {
			t.Errorf("field %s of types.Kustomization is unclassified; add it to the right list so its paths are validated", name)
		}
	}
}

func TestConstrainedFS_RelativeFollowsFilesystemSeparator(t *testing.T) {
	// Disk files keep the OS separator and pushed files are addressed with
	// "/" on every OS, matching the Helm resolver; the render root itself is
	// ".", never the absolute path it resolves to.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "overlays", "dev"), 0700); err != nil {
		t.Fatal(err)
	}
	disk, err := newConstrainedFS(vfs.DiskFS{}, root, ".", DefaultMaxFileBytes, &atomic.Int64{}, &byteCache{files: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := disk.relative(disk.confinementRoot); got != "." {
		t.Errorf("disk relative(root) = %q, want \".\"", got)
	}
	// Built from the resolved root, which is what every caller holds.
	nested := filepath.Join(disk.confinementRoot, "overlays", "dev")
	if want, got := filepath.Join("overlays", "dev"), disk.relative(nested); got != want {
		t.Errorf("disk relative(overlays/dev) = %q, want %q", got, want)
	}
	if got := disk.relative(filepath.Join("overlays", "dev")); got != filepath.Join("overlays", "dev") {
		t.Errorf("disk relative(relative input) = %q, want %q", got, filepath.Join("overlays", "dev"))
	}

	mem, err := newConstrainedFS(
		vfs.NewMemFS(map[string][]byte{"/repo/overlays/dev/kustomization.yaml": []byte("resources: []\n")}),
		"/repo", ".", DefaultMaxFileBytes, &atomic.Int64{}, &byteCache{files: map[string][]byte{}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := mem.relative(mem.confinementRoot); got != "." {
		t.Errorf("mem relative(root) = %q, want \".\"", got)
	}
	if got := mem.relative("/repo/overlays/dev"); got != "overlays/dev" {
		t.Errorf("mem relative(overlays/dev) = %q, want overlays/dev", got)
	}
	if got := mem.relative("overlays/dev"); got != "overlays/dev" {
		t.Errorf("mem relative(relative input) = %q, want overlays/dev", got)
	}
}

func TestIsRooted(t *testing.T) {
	// A leading "/" counts as rooted on every OS, volume name or not: the
	// in-memory filesystem addresses files that way, and Windows would treat
	// such a path as relative.
	rooted := []string{"/", "/repo", "/repo/overlays/dev", string(filepath.Separator) + "repo"}
	for _, p := range rooted {
		if !isRooted(p) {
			t.Errorf("isRooted(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"", ".", "repo", "overlays/dev", filepath.Join("overlays", "dev")} {
		if isRooted(p) {
			t.Errorf("isRooted(%q) = true, want false", p)
		}
	}
}

func TestAbsUnderRoot(t *testing.T) {
	// Expectations come from filepath primitives, so the table asserts the
	// same contract whatever the host separator is.
	root := filepath.Clean("/repo")
	tests := []struct {
		name string
		p    string
		want string
	}{
		// The case that regressed on Windows: a slash-rooted path already
		// under the root must be taken as it is, never re-joined onto it.
		{name: "slash rooted under root", p: "/repo/overlays/dev", want: filepath.Clean("/repo/overlays/dev")},
		{name: "root itself", p: "/repo", want: root},
		{name: "relative", p: "overlays/dev", want: filepath.Join(root, "overlays", "dev")},
		{name: "dot", p: ".", want: root},
		{name: "rooted outside root", p: "/elsewhere", want: filepath.Clean("/elsewhere")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := absUnderRoot(root, tc.p); got != tc.want {
				t.Errorf("absUnderRoot(%q, %q) = %q, want %q", root, tc.p, got, tc.want)
			}
		})
	}
}

func TestConstrainedFS_RefusesOutsideConfinement(t *testing.T) {
	outside := t.TempDir()
	root := t.TempDir()
	fs, err := newConstrainedFS(vfs.DiskFS{}, root, outside, DefaultMaxFileBytes, &atomic.Int64{}, &byteCache{files: map[string][]byte{}})
	if err == nil {
		t.Fatal("newConstrainedFS outside root = nil error, want error")
	}
	_ = fs
}

func TestConstrainedFS_RefusesSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	secret := t.TempDir()
	if err := os.WriteFile(filepath.Join(secret, "s.yaml"), []byte("x: 1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	fs, err := newConstrainedFS(vfs.DiskFS{}, root, ".", DefaultMaxFileBytes, &atomic.Int64{}, &byteCache{files: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadFile(filepath.Join(root, "escape", "s.yaml")); err == nil {
		t.Fatal("ReadFile through symlink escape = nil error, want error")
	} else if re, ok := err.(*RenderError); ok && re.Reason != ReasonValidation && re.Reason != ReasonMissingFile {
		t.Errorf("reason = %s, want validation or missing_file", re.Reason)
	}
}

func TestConstrainedFS_SizeLimitBeforeRead(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "big.yaml")
	if err := os.WriteFile(path, []byte("x: 1"), 0600); err != nil {
		t.Fatal(err)
	}
	budget := &atomic.Int64{}
	budget.Store(MaxTotalBytes)
	fs, err := newConstrainedFS(vfs.DiskFS{}, root, ".", 2, budget, &byteCache{files: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadFile(path); err == nil {
		t.Fatal("ReadFile oversized = nil error, want size limit")
	} else if re, ok := err.(*RenderError); !ok || re.Reason != ReasonSizeLimit {
		t.Errorf("reason = %v, want size_limit", err)
	}
	if got := budget.Load(); got != MaxTotalBytes {
		t.Errorf("budget = %d, want unchanged %d (file refused before reading)", got, MaxTotalBytes)
	}
}

func TestConstrainedFS_CumulativeBudget(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.yaml"), []byte("a: 1"), 0600); err != nil {
		t.Fatal(err)
	}
	budget := &atomic.Int64{}
	budget.Store(1)
	fs, err := newConstrainedFS(vfs.DiskFS{}, root, ".", DefaultMaxFileBytes, budget, &byteCache{files: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadFile(filepath.Join(root, "a.yaml")); err == nil {
		t.Fatal("ReadFile with exhausted budget = nil error, want size limit")
	}
}

func TestInjectOriginAnnotations(t *testing.T) {
	in := []byte("resources:\n  - deployment.yaml\n")
	out, err := injectOriginAnnotations(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "originAnnotations") {
		t.Error("injected copy missing originAnnotations")
	}
	if strings.Contains(string(in), "originAnnotations") {
		t.Error("injectOriginAnnotations mutated its input")
	}
	with := []byte("buildMetadata:\n  - transformerAnnotations\nresources: []\n")
	out, err = injectOriginAnnotations(with)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "originAnnotations") || !strings.Contains(string(out), "transformerAnnotations") {
		t.Errorf("existing buildMetadata not preserved: %s", out)
	}
}

// TestConstrainedFS_RefusesAllMutations pins the read-only half of the
// filesystem contract: every mutator of the kustomize FileSystem interface,
// plus the write path of the served file handle, must refuse. The build path
// never calls these, so without this table nothing executes them.
func TestConstrainedFS_RefusesAllMutations(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a.yaml")
	if err := os.WriteFile(path, []byte("a: 1"), 0600); err != nil {
		t.Fatal(err)
	}
	fs, err := newConstrainedFS(vfs.DiskFS{}, root, ".", DefaultMaxFileBytes,
		budgetWithRoom(DefaultMaxFileBytes), &byteCache{files: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func() error{
		"Create":    func() error { _, err := fs.Create(path); return err },
		"Mkdir":     func() error { return fs.Mkdir(filepath.Join(root, "d")) },
		"MkdirAll":  func() error { return fs.MkdirAll(filepath.Join(root, "d")) },
		"RemoveAll": func() error { return fs.RemoveAll(path) },
		"WriteFile": func() error { return fs.WriteFile(path, []byte("x")) },
		"Walk":      func() error { return fs.Walk(root, func(string, os.FileInfo, error) error { return nil }) },
	}
	for name, mutate := range mutations {
		if err := mutate(); err == nil {
			t.Errorf("%s = nil error, want refusal", name)
		}
	}
	// The handle Open serves must refuse writes too: Kustomize holds it as a
	// filesys.File, and a writable handle would defeat the read-only contract
	// even with every top-level mutator refusing.
	f, err := fs.Open(path)
	if err != nil {
		t.Fatalf("Open = %v, want nil", err)
	}
	if n, err := f.Write([]byte("x")); err == nil || n != 0 {
		t.Errorf("File.Write = (%d, %v), want (0, error)", n, err)
	}
	// And the mutations must actually not have happened.
	if _, err := os.Stat(filepath.Join(root, "d")); !os.IsNotExist(err) {
		t.Error("a directory was created despite the refusals")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "a: 1" {
		t.Errorf("file changed despite the refusals: %q, %v", data, err)
	}
}

// budgetWithRoom returns a cumulative budget that can absorb n bytes, so a
// test that is not about the budget never trips it by accident.
func budgetWithRoom(n int64) *atomic.Int64 {
	b := &atomic.Int64{}
	b.Store(n)
	return b
}
