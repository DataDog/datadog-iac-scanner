package kustomize

import (
	"reflect"
	"strings"
	"testing"

	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

func TestIsPlainLocalPath(t *testing.T) {
	for p, want := range map[string]bool{
		"deployment.yaml": true, "../base": true, "../common/patch.yaml": true, "a/b/c": true,
		"": false, "/etc/passwd": false, "~/x": false, "C:/x": false, `a\b`: false,
		"https://x": false, "HTTPS://x": false, "git::https://x": false, "GIT::x": false,
		"github.com/org/repo": false, "GitHub.com/x": false, "github.com:org/repo": false,
		"alice@host:org/repo": false, "git@github.com:org/repo.git": false, "ssh://git@host/repo": false,
		"gitlab.com/org/repo": false, "x?ref=main": false, "file://x": false,
	} {
		if got := isPlainLocalPath(p); got != want {
			t.Errorf("%q: got %v", p, got)
		}
	}
}

// TestKustomizationFieldsClassified fails when Kustomize adds a field, so that
// it is classified as path-bearing, refused or path-free before it is trusted.
func TestKustomizationFieldsClassified(t *testing.T) {
	known := map[string]bool{}
	for _, f := range strings.Fields(`TypeMeta MetaData OpenAPI NamePrefix NameSuffix Namespace CommonLabels Labels
		CommonAnnotations PatchesStrategicMerge PatchesJson6902 Patches Images ImageTags Replacements Replicas Vars
		SortOptions Resources Components Crds Bases ConfigMapGenerator SecretGenerator HelmGlobals HelmCharts
		HelmChartInflationGenerator GeneratorOptions Configurations Generators Transformers Validators BuildMetadata`) {
		known[f] = true
	}
	typ := reflect.TypeOf(types.Kustomization{})
	for i := 0; i < typ.NumField(); i++ {
		if !known[typ.Field(i).Name] {
			t.Errorf("unclassified kustomization field %s", typ.Field(i).Name)
		}
	}
}

func TestValidatePatchesStrategicMerge(t *testing.T) {
	for entry, want := range map[string]bool{
		"{apiVersion: apps/v1, kind: Deployment, metadata: {name: web}, spec: {replicas: 3}}":   true,
		"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 3\n": true,
		"patch.yaml":                    true,
		"../base/patch.yaml":            true,
		"/etc/passwd":                   false,
		"https://example.invalid/p.yml": false,
		"github.com/org/repo/p.yaml":    false,
	} {
		k := &types.Kustomization{PatchesStrategicMerge: []types.PatchStrategicMerge{types.PatchStrategicMerge(entry)}} //nolint:staticcheck // legacy field under test
		if got := validatePaths(k) == nil; got != want {
			t.Errorf("%q: accepted %v", entry, got)
		}
	}
}

func TestSingleLineInlinePatchRenders(t *testing.T) {
	fs := filesys.MakeFsInMemory()
	k := "resources: [deploy.yaml]\npatchesStrategicMerge:\n- '{apiVersion: apps/v1, kind: Deployment, metadata: {name: web}, spec: {replicas: 3}}'\n"
	if err := fs.WriteFile("/app/kustomization.yaml", []byte(k)); err != nil {
		t.Fatal(err)
	}
	if err := fs.WriteFile("/app/deploy.yaml", []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 1\n")); err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeKustomization([]byte(k))
	if err != nil || validateKustomization(decoded) != nil {
		t.Fatalf("refused: %v", err)
	}
	m, err := krusty.MakeKustomizer(krusty.MakeDefaultOptions()).Run(fs, "/app")
	if err != nil {
		t.Fatal(err)
	}
	out, err := m.AsYaml()
	if err != nil || !strings.Contains(string(out), "replicas: 3") {
		t.Fatalf("patch not applied: %v\n%s", err, out)
	}
}
