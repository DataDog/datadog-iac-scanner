package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsConfigFile(t *testing.T) {
	dir := t.TempDir()
	lockFile := filepath.Join(dir, "pnpm-lock.yaml")
	if err := os.WriteFile(lockFile, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "pnpm lock file", path: lockFile, want: true},
		{name: "non-matching file", path: filepath.Join(dir, "main.tf"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isConfigFile(tt.path, defaultConfigSuffixes); got != tt.want {
				t.Errorf("isConfigFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
