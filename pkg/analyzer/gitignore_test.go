package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// ignoredDuringWalk reproduces how file discovery applies the matcher: each
// directory is tested on the way down and its subtree is pruned when ignored,
// then the file itself is tested. Exclusion inherited from a parent comes from
// the pruning, so it can only be observed through the walk.
func ignoredDuringWalk(m *gitIgnoreMatcher, relPath string) bool {
	relPath = filepath.ToSlash(relPath)
	parts := strings.Split(relPath, "/")
	for i := 1; i < len(parts); i++ {
		if m.MatchesDir(strings.Join(parts[:i], "/")) {
			return true
		}
	}
	return m.MatchesPath(relPath)
}

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
abc/**
!abc/def/
!abc/def/keep.tf
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
		// A trailing /** ignores contents, not the parent directory.
		{path: "abc/other.tf", want: true},
		{path: "abc/def/drop.tf", want: true},
		{path: "abc/def/keep.tf", want: false},
		{path: "keep/me.txt", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			require.Equal(t, tt.want, ignoredDuringWalk(matcher, tt.path))
			require.Equal(t, tt.want, ignoredDuringWalk(matcher, filepath.FromSlash(tt.path)))
		})
	}
}

// A negated pattern deeper in the tree wins last-match-wins precedence when the
// file is tested on its own, so honoring git requires pruning the directory
// rather than asking MatchesPath about inherited exclusions.
func TestGitIgnoreMatcher_ReincludeUnderIgnoredParentNeedsPruning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	require.NoError(t, os.WriteFile(path, []byte("ignored/\n!ignored/keep.tf\n"), 0o600))

	matcher, err := compileGitIgnoreFile(path)
	require.NoError(t, err)
	require.NotNil(t, matcher)

	require.False(t, matcher.MatchesPath("ignored/keep.tf"))
	require.True(t, matcher.MatchesDir("ignored"))
	require.True(t, ignoredDuringWalk(matcher, "ignored/keep.tf"))

	// The walk root resolves to an empty or dot-relative path and is never ignored.
	require.False(t, matcher.MatchesDir(""))
	require.False(t, matcher.MatchesDir("."))
}

func TestGitIgnoreMatcher_TrailingGlobstarDoesNotIgnoreParent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	require.NoError(t, os.WriteFile(path, []byte("abc/**\n!abc/def/\n!abc/def/keep.tf\n"), 0o600))

	matcher, err := compileGitIgnoreFile(path)
	require.NoError(t, err)
	require.NotNil(t, matcher)

	require.False(t, matcher.MatchesDir("abc"))
	require.False(t, matcher.MatchesDir("abc/def"))
	require.True(t, ignoredDuringWalk(matcher, "abc/other.tf"))
	require.True(t, ignoredDuringWalk(matcher, "abc/def/drop.tf"))
	require.False(t, ignoredDuringWalk(matcher, "abc/def/keep.tf"))
}

func TestGitIgnoreMatcher_RecursiveWildcardAfterReincludedDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	require.NoError(t, os.WriteFile(path, []byte("foo/**/*\n!foo/bar/\n!foo/bar/keep.tf\n"), 0o600))

	matcher, err := compileGitIgnoreFile(path)
	require.NoError(t, err)
	require.NotNil(t, matcher)

	require.False(t, matcher.MatchesDir("foo"))
	require.False(t, matcher.MatchesDir("foo/bar"))
	require.True(t, ignoredDuringWalk(matcher, "foo/bar/a.tf"))
	require.True(t, ignoredDuringWalk(matcher, "foo/bar/nested/a.tf"))
	require.False(t, ignoredDuringWalk(matcher, "foo/bar/keep.tf"))
}

func TestGitIgnoreMatcher_ExplicitFileChecksIgnoredParents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	require.NoError(t, os.WriteFile(path, []byte("build/\n"), 0o600))

	matcher, err := compileGitIgnoreFile(path)
	require.NoError(t, err)
	require.NotNil(t, matcher)

	require.False(t, matcher.MatchesPath("build/main.tf"))
	require.True(t, matcher.MatchesParentDir("build/main.tf"))
}

func TestGitIgnoreMatcher_ReincludedWildcardDirectoryKeepsDescendants(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	require.NoError(t, os.WriteFile(path, []byte("foo/*\n!foo/bar/\n"), 0o600))

	matcher, err := compileGitIgnoreFile(path)
	require.NoError(t, err)
	require.NotNil(t, matcher)

	require.True(t, ignoredDuringWalk(matcher, "foo/other.tf"))
	require.False(t, matcher.MatchesDir("foo/bar"))
	require.False(t, ignoredDuringWalk(matcher, "foo/bar/main.tf"))
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
