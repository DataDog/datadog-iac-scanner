package pathutil

import (
	"path"
	"path/filepath"
	"strings"
)

// MatchesPath reports whether filePath is covered by pattern.
// pattern may be a literal path, a directory prefix, a single-star glob (*, ?, [...]),
// or a double-star glob (**) where ** matches zero or more path segments.
// Both arguments are normalized to forward slashes for OS-independent behavior.
func MatchesPath(pattern, filePath string) bool {
	pattern = filepath.ToSlash(pattern)
	filePath = filepath.ToSlash(filePath)

	// Exact match.
	if pattern == filePath {
		return true
	}
	// Directory prefix: any file under pattern/ matches.
	if strings.HasPrefix(filePath, strings.TrimSuffix(pattern, "/")+"/") {
		return true
	}
	// Double-star glob (**): segment-aware recursive match.
	if strings.Contains(pattern, "**") {
		return matchDoublestar(strings.Split(pattern, "/"), strings.Split(filePath, "/"))
	}
	// Single-level glob (*, ?, [...]): use path.Match with forward-slash semantics.
	if matched, err := path.Match(pattern, filePath); err == nil && matched {
		return true
	}
	return false
}

// Excluded reports whether filePath should be dropped given ignore-paths and
// only-paths lists. A file is excluded if it matches any ignorePaths pattern;
// otherwise, when onlyPaths is non-empty, it is excluded unless it matches one
// of them. Patterns use MatchesPath semantics.
func Excluded(filePath string, ignorePaths, onlyPaths []string) bool {
	for _, pattern := range ignorePaths {
		if MatchesPath(pattern, filePath) {
			return true
		}
	}
	if len(onlyPaths) == 0 {
		return false
	}
	for _, pattern := range onlyPaths {
		if MatchesPath(pattern, filePath) {
			return false
		}
	}
	return true
}

// matchDoublestar matches a pre-split path against a pre-split pattern where
// "**" matches zero or more path segments.
func matchDoublestar(pat, filePath []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			// ** matches zero remaining segments → try skipping the **
			if matchDoublestar(pat[1:], filePath) {
				return true
			}
			// ** matches one or more segments → consume one path segment and retry
			if len(filePath) == 0 {
				return false
			}
			return matchDoublestar(pat, filePath[1:])
		}
		if len(filePath) == 0 {
			return false
		}
		ok, err := path.Match(pat[0], filePath[0])
		if err != nil || !ok {
			return false
		}
		pat = pat[1:]
		filePath = filePath[1:]
	}
	return len(filePath) == 0
}
