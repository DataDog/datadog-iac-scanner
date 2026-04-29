package kustomize

import (
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

var kustomizationNames = []string{"kustomization.yaml", "kustomization.yml", "Kustomization"}

// IsKustomizationEntryFile reports whether path is a kustomization entry filename.
func IsKustomizationEntryFile(path string) bool {
	base := filepath.Base(path)
	for _, n := range kustomizationNames {
		if base == n {
			return true
		}
	}
	return false
}

// Detect returns KindKUSTOMIZE when the directory contains a kustomization entry file.
func Detect(dir string) (model.FileKind, bool) {
	for _, n := range kustomizationNames {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			return model.KindKUSTOMIZE, true
		}
	}
	return model.KindCOMMON, false
}
