package kustomize

import (
	"reflect"
	"strings"
	"testing"

	"sigs.k8s.io/kustomize/api/types"
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
