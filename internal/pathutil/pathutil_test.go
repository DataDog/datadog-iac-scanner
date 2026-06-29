package pathutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchesPath(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		file    string
		want    bool
	}{
		{"exact match", "/repo/src/main.tf", "/repo/src/main.tf", true},
		{"directory prefix", "/repo/src", "/repo/src/main.tf", true},
		{"directory prefix no trailing sep", "/repo/src", "/repo/src/nested/main.tf", true},
		{"no match different dir", "/repo/test", "/repo/src/main.tf", false},
		{"no partial prefix match", "/repo/s", "/repo/src/main.tf", false},
		{"glob star", "/repo/src/*.tf", "/repo/src/main.tf", true},
		{"glob star no match", "/repo/src/*.tf", "/repo/src/main.go", false},
		{"glob question mark", "/repo/src/mai?.tf", "/repo/src/main.tf", true},
		// double-star (**) glob
		{"doublestar all tf files", "/repo/**/*.tf", "/repo/src/main.tf", true},
		{"doublestar nested", "/repo/**/*.tf", "/repo/src/nested/deep/main.tf", true},
		{"doublestar no match ext", "/repo/**/*.tf", "/repo/src/main.go", false},
		{"doublestar prefix any subdir", "**/terraform/**", "infra/terraform/main.tf", true},
		{"doublestar prefix no match", "**/terraform/**", "infra/k8s/main.yaml", false},
		{"doublestar matches zero segments", "a/**/b.tf", "a/b.tf", true},
		{"doublestar matches one segment", "a/**/b.tf", "a/x/b.tf", true},
		{"doublestar matches many segments", "a/**/b.tf", "a/x/y/z/b.tf", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MatchesPath(tt.pattern, tt.file))
		})
	}
}

func TestExcluded(t *testing.T) {
	tests := []struct {
		name        string
		file        string
		ignorePaths []string
		onlyPaths   []string
		want        bool
	}{
		{"no filters", "infra/main.tf", nil, nil, false},
		{"ignored by glob", "infra/main.tf", []string{"infra/**"}, nil, true},
		{"not ignored", "src/main.tf", []string{"infra/**"}, nil, false},
		{"only-paths match", "src/main.tf", nil, []string{"src/**"}, false},
		{"only-paths excludes others", "infra/main.tf", nil, []string{"src/**"}, true},
		{"ignore wins over only", "src/main.tf", []string{"src/**"}, []string{"src/**"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Excluded(tt.file, tt.ignorePaths, tt.onlyPaths))
		})
	}
}
