package analyzer

import (
	"os"
	"path/filepath"
	"strings"

	gitignore "github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

// gitIgnoreMatcher matches repo-relative paths against the patterns of a single
// .gitignore file, with git's last-match-wins precedence.
type gitIgnoreMatcher struct {
	matcher    gitignore.Matcher
	dirMatcher gitignore.Matcher
}

// compileGitIgnoreFile parses the .gitignore at path. It returns nil when the
// file holds no usable pattern, so callers can skip matching entirely.
func compileGitIgnoreFile(path string) (*gitIgnoreMatcher, error) {
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	var filePatterns, dirPatterns []gitignore.Pattern
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		// A nil domain anchors the patterns at the repository root, which is
		// where the parsed file lives.
		if !isDirectoryOnlyPattern(line) {
			filePatterns = append(filePatterns, gitignore.ParsePattern(line, nil))
		}
		dirPatterns = append(dirPatterns, gitignore.ParsePattern(directoryPattern(line), nil))
	}
	if len(dirPatterns) == 0 {
		return nil, nil
	}
	return &gitIgnoreMatcher{
		matcher:    gitignore.NewMatcher(filePatterns),
		dirMatcher: gitignore.NewMatcher(dirPatterns),
	}, nil
}

func isDirectoryOnlyPattern(pattern string) bool {
	if !strings.HasSuffix(pattern, `\ `) {
		pattern = strings.TrimRight(pattern, " ")
	}
	return strings.HasSuffix(pattern, "/")
}

func directoryPattern(pattern string) string {
	// Git's trailing /** matches a directory's contents, not the directory itself.
	if strings.HasSuffix(pattern, "/**") {
		return strings.TrimSuffix(pattern, "**") + "*"
	}
	return pattern
}

// MatchesPath reports whether the given repo-relative file path is ignored by a
// pattern naming the file itself.
//
// Exclusions inherited from a parent directory are not reported here. Callers
// walk directories through MatchesDir and stop descending when it matches,
// which mirrors git never entering an ignored directory and keeps matching at
// one pass over the patterns per path instead of one per path component.
func (m *gitIgnoreMatcher) MatchesPath(relPath string) bool {
	if m == nil {
		return false
	}
	return m.matches(m.matcher, relPath, false)
}

// MatchesDir reports whether the given repo-relative directory is ignored.
//
// Callers must stop descending when this returns true. Pruning is what enforces
// git's rule that a file cannot be re-included once one of its parent
// directories is excluded: a negated pattern deeper in the tree would otherwise
// win the last-match-wins precedence and resurrect the file.
func (m *gitIgnoreMatcher) MatchesDir(relPath string) bool {
	if m == nil {
		return false
	}
	return m.matches(m.dirMatcher, relPath, true)
}

func (m *gitIgnoreMatcher) MatchesParentDir(relPath string) bool {
	if m == nil {
		return false
	}
	normalized := strings.Trim(filepath.ToSlash(relPath), "/")
	parts := strings.Split(normalized, "/")
	for i := 1; i < len(parts); i++ {
		if m.dirMatcher.Match(parts[:i], true) {
			return true
		}
	}
	return false
}

func (m *gitIgnoreMatcher) matches(matcher gitignore.Matcher, relPath string, isDir bool) bool {
	normalized := strings.Trim(filepath.ToSlash(relPath), "/")
	if normalized == "" || normalized == "." {
		return false
	}
	return matcher.Match(strings.Split(normalized, "/"), isDir)
}
