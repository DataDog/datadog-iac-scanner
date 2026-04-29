package kustomize

import (
	"os"
	"testing"

	resolverkustomize "github.com/DataDog/datadog-iac-scanner/pkg/resolver/kustomize"
)

// TestMain ensures kustomize subprocess render (re-exec of this test binary) works during detector tests.
func TestMain(m *testing.M) {
	resolverkustomize.MaybeRunAsKustomizeRenderHelper()
	os.Exit(m.Run())
}
