package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The expectations below mirror `git check-ignore` for the same patterns.
func TestGitIgnoreMatcher_MatchesPath(t *testing.T) {
	gitIgnore := []byte(`# comment

.vscode/*
!.vscode/extensions.json
build/
*.log
!important.log
/root-only.txt
docs/**/tmp/
node_modules
a/b*.txt
ignored/
!ignored/reincluded.tf
reopened/
!reopened/
!reopened/reincluded.tf
`)

	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	require.NoError(t, os.WriteFile(path, gitIgnore, 0o600))

	matcher, err := compileGitIgnoreFile(path)
	require.NoError(t, err)
	require.NotNil(t, matcher)

	tests := []struct {
		path string
		want bool
	}{
		// A pattern containing a slash is anchored to the repository root.
		{path: ".vscode/settings.json", want: true},
		{path: "sub/.vscode/settings.json", want: false},
		{path: ".vscode/extensions.json", want: false},
		{path: "root-only.txt", want: true},
		{path: "sub/root-only.txt", want: false},
		// A pattern without a slash matches at any depth.
		{path: "app.log", want: true},
		{path: "sub/app.log", want: true},
		{path: "important.log", want: false},
		{path: "sub/important.log", want: false},
		// Files are ignored through an ignored parent directory.
		{path: "build/out.txt", want: true},
		{path: "sub/build/out.txt", want: true},
		{path: "node_modules/pkg/index.js", want: true},
		{path: "docs/a/tmp/x.txt", want: true},
		{path: "docs/tmp/x.txt", want: true},
		{path: "a/b1.txt", want: true},
		{path: "a/c/b1.txt", want: false},
		// A file cannot be re-included while its parent remains ignored.
		{path: "ignored/reincluded.tf", want: true},
		{path: "reopened/reincluded.tf", want: false},
		{path: "keep/me.txt", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			require.Equal(t, tt.want, matcher.MatchesPath(tt.path))
			require.Equal(t, tt.want, matcher.MatchesPath(filepath.FromSlash(tt.path)))
		})
	}
}

func TestGitIgnoreMatcher_NoUsablePattern(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	require.NoError(t, os.WriteFile(path, []byte("# only a comment\n\n"), 0o600))

	matcher, err := compileGitIgnoreFile(path)
	require.NoError(t, err)
	require.Nil(t, matcher)
	require.False(t, matcher.MatchesPath("anything.tf"))
}

func TestGitIgnoreMatcher_MissingFile(t *testing.T) {
	matcher, err := compileGitIgnoreFile(filepath.Join(t.TempDir(), ".gitignore"))
	require.Error(t, err)
	require.Nil(t, matcher)
}
