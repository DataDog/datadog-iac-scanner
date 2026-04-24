package kustomize

import "testing"

func TestTransformerAnnotationKey_AlignsWithKustomizeAPI(t *testing.T) {
	// Must match the annotation key used by sigs.k8s.io/kustomize/api/resource.Resource.GetTransformations
	// (sigs.k8s.io/kustomize/api/internal/utils.TransformerAnnotationKey).
	const expected = "alpha.config.kubernetes.io/transformations"
	if TransformerAnnotationKey != expected {
		t.Fatalf("TransformerAnnotationKey = %q, want %q", TransformerAnnotationKey, expected)
	}
}
