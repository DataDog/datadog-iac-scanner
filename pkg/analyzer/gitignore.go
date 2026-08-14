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
	matcher gitignore.Matcher
}

// compileGitIgnoreFile parses the .gitignore at path. It returns nil when the
// file holds no usable pattern, so callers can skip matching entirely.
func compileGitIgnoreFile(path string) (*gitIgnoreMatcher, error) {
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	var patterns []gitignore.Pattern
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		// A nil domain anchors the patterns at the repository root, which is
		// where the parsed file lives.
		patterns = append(patterns, gitignore.ParsePattern(line, nil))
	}
	if len(patterns) == 0 {
		return nil, nil
	}
	return &gitIgnoreMatcher{matcher: gitignore.NewMatcher(patterns)}, nil
}

// MatchesPath reports whether the given repo-relative path is ignored, either
// directly or through one of its parent directories.
func (m *gitIgnoreMatcher) MatchesPath(relPath string) bool {
	if m == nil {
		return false
	}
	normalized := strings.Trim(filepath.ToSlash(relPath), "/")
	if normalized == "" {
		return false
	}
	return m.matcher.Match(strings.Split(normalized, "/"), false)
}
