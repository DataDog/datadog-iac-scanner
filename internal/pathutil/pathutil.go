package pathutil

import (
	"path"
	"path/filepath"
	"strings"
)

// MatchesPath reports whether filePath is covered by pattern.
// pattern may be a literal path, a directory prefix, a single-star glob (*, ?, [...]),
// or a double-star glob (**) where ** matches zero or more path segments.
// Both arguments are normalized to forward slashes for OS-independent behavior,
// and cleaned, so "./app" and "app/" name the same directory as "app".
func MatchesPath(pattern, filePath string) bool {
	pattern = cleanSlash(pattern)
	filePath = cleanSlash(filePath)
	return matchCleanPattern(pattern, filePath)
}

func matchCleanPattern(pattern, filePath string) bool {
	// Exact match.
	if pattern == filePath {
		return true
	}
	// Directory prefix: any file under pattern/ matches.
	if hasDirPrefix(filePath, pattern) {
		return true
	}
	if !hasGlobMeta(pattern) {
		return false
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

func hasDirPrefix(filePath, dir string) bool {
	if dir == "" {
		return false
	}
	if dir == "/" {
		return strings.HasPrefix(filePath, "/")
	}
	if len(filePath) <= len(dir) || filePath[len(dir)] != '/' {
		return false
	}
	return strings.HasPrefix(filePath, dir)
}

func hasGlobMeta(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[\\")
}

// Matcher evaluates a set of MatchesPath patterns repeatedly without re-cleaning
// or re-splitting patterns on every candidate path. Literal paths and directory
// prefixes are checked in O(1) / O(path depth) without scanning the pattern list.
type Matcher struct {
	exact  map[string]struct{}
	dirSet map[string]struct{}
	globs  []compiledGlob
}

type compiledGlob struct {
	pattern  string
	segments []string // non-nil iff pattern contains "**"
}

// NewMatcher compiles patterns for repeated path matching.
func NewMatcher(patterns []string) *Matcher {
	m := &Matcher{}
	for _, p := range patterns {
		m.Add(p)
	}
	return m
}

// Add inserts one MatchesPath pattern into the matcher.
func (m *Matcher) Add(pattern string) {
	if pattern == "" {
		return
	}
	clean := cleanSlash(pattern)
	if clean == "" {
		return
	}
	if !hasGlobMeta(clean) {
		m.AddLiteral(clean)
		return
	}
	if m.exact == nil {
		m.exact = make(map[string]struct{})
	}
	m.exact[clean] = struct{}{}
	g := compiledGlob{pattern: clean}
	if strings.Contains(clean, "**") {
		g.segments = strings.Split(clean, "/")
	}
	m.globs = append(m.globs, g)
}

// AddLiteral inserts a literal file or directory path (no glob interpretation).
// It matches exact paths and any descendant path under clean/.
func (m *Matcher) AddLiteral(pathOrDir string) {
	if pathOrDir == "" {
		return
	}
	clean := cleanSlash(pathOrDir)
	if clean == "" {
		return
	}
	if m.exact == nil {
		m.exact = make(map[string]struct{})
	}
	m.exact[clean] = struct{}{}
	if m.dirSet == nil {
		m.dirSet = make(map[string]struct{})
	}
	m.dirSet[clean] = struct{}{}
}

// AddExactFile inserts a literal file path known not to be a directory prefix,
// avoiding ancestor-prefix matching on per-file exclusions such as gitignored files.
func (m *Matcher) AddExactFile(filePath string) {
	if filePath == "" {
		return
	}
	clean := cleanSlash(filePath)
	if clean == "" {
		return
	}
	if m.exact == nil {
		m.exact = make(map[string]struct{})
	}
	m.exact[clean] = struct{}{}
}

// Match reports whether filePath matches any pattern in m.
func (m *Matcher) Match(filePath string) bool {
	if m == nil || (len(m.exact) == 0 && len(m.dirSet) == 0 && len(m.globs) == 0) {
		return false
	}
	clean := cleanSlash(filePath)
	if clean == "" {
		return false
	}
	if _, ok := m.exact[clean]; ok {
		return true
	}
	if m.matchDirAncestor(clean) {
		return true
	}
	return m.matchGlobs(clean)
}

// matchDirAncestor checks whether any proper ancestor directory of clean is in dirSet.
// Because cleanSlash produces a cleaned slash-separated path, checking every '/'
// boundary (plus root "/") matches hasDirPrefix in O(path depth) with zero allocations.
func (m *Matcher) matchDirAncestor(clean string) bool {
	if len(m.dirSet) == 0 {
		return false
	}
	for i := len(clean) - 1; i > 0; i-- {
		if clean[i] == '/' {
			if _, ok := m.dirSet[clean[:i]]; ok {
				return true
			}
		}
	}
	if clean[0] == '/' {
		if _, ok := m.dirSet["/"]; ok {
			return true
		}
	}
	return false
}

func (m *Matcher) matchGlobs(clean string) bool {
	if len(m.globs) == 0 {
		return false
	}
	var pathSegs []string
	for _, g := range m.globs {
		if hasDirPrefix(clean, g.pattern) {
			return true
		}
		if g.segments != nil {
			if pathSegs == nil {
				pathSegs = strings.Split(clean, "/")
			}
			if matchDoublestar(g.segments, pathSegs) {
				return true
			}
			continue
		}
		if matched, err := path.Match(g.pattern, clean); err == nil && matched {
			return true
		}
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

// ExcludedAny reports whether ignore-paths or only-paths leave out a file known
// by several paths, such as a file inside a chart archive and the declaration it
// is reported at: a path matched by an ignore drops the file, and when
// restricted, a path in scope keeps it. ignored and inScope decide one path.
func ExcludedAny(paths []string, ignored, inScope func(string) bool, restricted bool) bool {
	kept := !restricted
	for _, p := range paths {
		if ignored(p) {
			return true
		}
		if !kept && inScope(p) {
			kept = true
		}
	}
	return !kept
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

// cleanSlash puts p in one spelling. An empty p is kept rather than letting
// path.Clean turn it into ".".
func cleanSlash(p string) string {
	if p == "" {
		return p
	}
	return path.Clean(filepath.ToSlash(p))
}
