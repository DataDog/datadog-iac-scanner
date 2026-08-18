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
	patterns []gitIgnorePattern
}

type gitIgnorePattern struct {
	pattern       gitignore.Pattern
	exactPath     bool
	directoryOnly bool
}

// compileGitIgnoreFile parses the .gitignore at path. It returns nil when the
// file holds no usable pattern, so callers can skip matching entirely.
func compileGitIgnoreFile(path string) (*gitIgnoreMatcher, error) {
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	var patterns []gitIgnorePattern
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		patterns = append(patterns, compileGitIgnorePattern(line))
	}
	if len(patterns) == 0 {
		return nil, nil
	}
	return &gitIgnoreMatcher{patterns: patterns}, nil
}

func compileGitIgnorePattern(pattern string) gitIgnorePattern {
	if !strings.HasSuffix(pattern, `\ `) {
		pattern = strings.TrimRight(pattern, " ")
	}

	inclusion := ""
	body := pattern
	if strings.HasPrefix(body, "!") {
		inclusion = "!"
		body = body[1:]
	}
	directoryOnly := strings.HasSuffix(body, "/")
	body = strings.TrimSuffix(body, "/")
	exactPath := strings.Contains(body, "/")
	if !exactPath {
		return gitIgnorePattern{
			pattern:       gitignore.ParsePattern(pattern, nil),
			directoryOnly: directoryOnly,
		}
	}

	// These recursive suffixes require at least one component below the parent.
	if strings.HasSuffix(body, "/**/*") {
		body = strings.TrimSuffix(body, "/**/*") + "/*/**"
	} else if strings.HasSuffix(body, "/**") {
		body = strings.TrimSuffix(body, "/**") + "/*/**"
	}
	const pathEnd = "\x00"
	return gitIgnorePattern{
		pattern:       gitignore.ParsePattern(inclusion+body+"/"+pathEnd, nil),
		exactPath:     true,
		directoryOnly: directoryOnly,
	}
}

// MatchesPath reports whether the given repo-relative file path is ignored by a
// pattern naming the file itself.
//
// Exclusions inherited from a parent directory are not reported here. Callers
// walk directories through MatchesDir and stop descending when it matches,
// which mirrors git never entering an ignored directory and keeps matching at
// one pass over the patterns per path instead of one per path component.
func (m *gitIgnoreMatcher) MatchesPath(relPath string) bool {
	return m.matches(relPath, false)
}

// MatchesDir reports whether the given repo-relative directory is ignored.
//
// Callers must stop descending when this returns true. Pruning is what enforces
// git's rule that a file cannot be re-included once one of its parent
// directories is excluded: a negated pattern deeper in the tree would otherwise
// win the last-match-wins precedence and resurrect the file.
func (m *gitIgnoreMatcher) MatchesDir(relPath string) bool {
	return m.matches(relPath, true)
}

func (m *gitIgnoreMatcher) MatchesParentDir(relPath string) bool {
	if m == nil {
		return false
	}
	normalized := strings.Trim(filepath.ToSlash(relPath), "/")
	parts := strings.Split(normalized, "/")
	for i := 1; i < len(parts); i++ {
		if m.matchParts(parts[:i], true) {
			return true
		}
	}
	return false
}

func (m *gitIgnoreMatcher) matches(relPath string, isDir bool) bool {
	if m == nil {
		return false
	}
	normalized := strings.Trim(filepath.ToSlash(relPath), "/")
	if normalized == "" || normalized == "." {
		return false
	}
	return m.matchParts(strings.Split(normalized, "/"), isDir)
}

func (m *gitIgnoreMatcher) matchParts(parts []string, isDir bool) bool {
	const pathEnd = "\x00"
	exactParts := make([]string, len(parts)+1)
	copy(exactParts, parts)
	exactParts[len(parts)] = pathEnd
	basename := parts[len(parts)-1:]

	for i := len(m.patterns) - 1; i >= 0; i-- {
		pattern := m.patterns[i]
		if pattern.directoryOnly && !isDir {
			continue
		}
		matchPath := basename
		if pattern.exactPath {
			matchPath = exactParts
		}
		if result := pattern.pattern.Match(matchPath, isDir); result > gitignore.NoMatch {
			return result == gitignore.Exclude
		}
	}
	return false
}
