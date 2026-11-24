package pathutil

import (
	"fmt"
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
		{"dot-slash ignore names the directory", "app/main.tf", []string{"./app"}, nil, true},
		{"trailing slash ignore names the directory", "app/main.tf", []string{"app/"}, nil, true},
		{"dot-slash only path keeps the file", "app/main.tf", nil, []string{"./app"}, false},
		{"dot-slash ignore leaves siblings", "apps/main.tf", []string{"./app"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Excluded(tt.file, tt.ignorePaths, tt.onlyPaths))
		})
	}
}

func TestMatcher(t *testing.T) {
	m := NewMatcher([]string{"/repo/.git", "/repo/vendor/**", "/repo/src/*.generated.tf", "./ignored", ""})
	m.AddExactFile("/repo/foo/bar.tf")
	m.AddLiteral("/repo/build")
	// AddExactFile followed by AddLiteral on the same path must still match descendants.
	m.AddExactFile("/repo/promoted")
	m.AddLiteral("/repo/promoted")

	cases := []struct {
		path string
		want bool
	}{
		{"", false},
		{"/repo/.git", true},
		{"/repo/.git/config", true},
		{"/repo/.gitignore", false},
		{"/repo/vendor/a/b/main.tf", true},
		{"/repo/src/x.generated.tf", true},
		{"/repo/src/main.tf", false},
		{"ignored/sub/a.tf", true},
		{"ignored_other/a.tf", false},
		{"/repo/foo/bar.tf", true},
		{"/repo/foo/bar.tf/child", false},
		{"/repo/build/out.tf", true},
		{"/repo/promoted", true},
		{"/repo/promoted/sub/file.tf", true},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, m.Match(tc.path), tc.path)
	}

	var nilMatcher *Matcher
	assert.False(t, nilMatcher.Match("/repo/main.tf"))

	rootMatcher := NewMatcher([]string{"/"})
	assert.True(t, rootMatcher.Match("/"))
	assert.True(t, rootMatcher.Match("/repo/main.tf"))
	assert.False(t, rootMatcher.Match("relative/main.tf"))
}

func TestMatcherParityWithMatchesPath(t *testing.T) {
	patterns := []string{
		"/repo/src",
		"/repo/src/",
		"./app",
		"app/",
		"/",
		"/repo/src/*.tf",
		"/repo/src/mai?.tf",
		"/repo/src/[a-z]*.tf",
		"/repo/**/*.tf",
		"**/terraform/**",
		"a/**/b.tf",
		"/repo/literal[dir]",
	}
	paths := []string{
		"/repo/src",
		"/repo/src/main.tf",
		"/repo/src/nested/main.tf",
		"/repo/src/main.go",
		"/repo/src_other/main.tf",
		"app",
		"app/main.tf",
		"apps/main.tf",
		"/",
		"/x",
		"infra/terraform/main.tf",
		"infra/k8s/main.yaml",
		"a/b.tf",
		"a/x/y/b.tf",
		"/repo/literal[dir]/child.tf",
	}
	for _, p := range patterns {
		m := NewMatcher([]string{p})
		for _, f := range paths {
			assert.Equal(t, MatchesPath(p, f), m.Match(f), "pattern=%q file=%q", p, f)
		}
	}
}

func BenchmarkMatcherVsLinearMatchesPath(b *testing.B) {
	const numIgnoredDirs = 500
	const numIgnoredFiles = 2000

	patterns := make([]string, 0, numIgnoredDirs+numIgnoredFiles)
	m := NewMatcher(nil)
	for i := range numIgnoredDirs {
		dir := fmt.Sprintf("/repo/services/svc-%04d/.terraform", i)
		patterns = append(patterns, dir)
		m.AddLiteral(dir)
	}
	for i := range numIgnoredFiles {
		file := fmt.Sprintf("/repo/services/svc-%04d/generated-%04d.tf", i%numIgnoredDirs, i)
		patterns = append(patterns, file)
		m.AddExactFile(file)
	}

	candidate := "/repo/services/svc-0499/prod/main.tf"

	b.Run("Matcher", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if m.Match(candidate) {
				b.Fatal("unexpected match")
			}
		}
	})

	b.Run("LinearMatchesPath", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			for _, p := range patterns {
				if MatchesPath(p, candidate) {
					b.Fatal("unexpected match")
				}
			}
		}
	})
}
