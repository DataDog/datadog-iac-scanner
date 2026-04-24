package kustomize

import (
	"os"
	"testing"
)

// TestMain mirrors cmd/scanner main: subprocess kustomize render re-execs this test binary with
// GO_WANT_KUSTOMIZE_RENDER_HELPER=1 and must handle stdin before tests run.
func TestMain(m *testing.M) {
	MaybeRunAsKustomizeRenderHelper()
	os.Exit(m.Run())
}
