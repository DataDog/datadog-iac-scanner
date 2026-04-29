package kustomize

import (
	"path/filepath"
	"strings"
)

// isUnderRoot reports whether path is root itself or strictly under root.
// Used to confine reads/writes to the configured repo or scratch trees.
func isUnderRoot(path, root string) bool {
	cp := filepath.Clean(path)
	cr := filepath.Clean(root)
	return cp == cr || strings.HasPrefix(cp, cr+string(filepath.Separator))
}
