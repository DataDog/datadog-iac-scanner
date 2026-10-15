/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package provider

import (
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/internal/pathutil"
)

// FileFilter reports whether a file is left out of the scan by its path
// filters. Rendered Helm files are checked against it because a chart renders
// the files of dependencies from anywhere in the scan.
type FileFilter interface {
	ExcludesAny(paths ...string) bool
}

// PathFilter applies a scan's ignore-paths and only-paths, to Helm charts and
// the files they render. It does no I/O and never changes, so it is safe for
// concurrent use. A nil PathFilter excludes nothing.
//
// A pattern with glob syntax matches the paths it names on disk and also the
// paths it matches as text, as the in-memory and rule filters do. A rendered
// file of a packaged dependency names no file on disk, so a glob over the disk
// alone would drop it.
type PathFilter struct {
	// ignored holds cleaned absolute paths; each covers everything below it.
	ignored map[string]struct{}
	// ignoredGlobs holds absolute glob patterns, matched as text.
	ignoredGlobs []string
	// only holds cleaned absolute paths; nil means no restriction, while
	// non-nil (even empty) keeps only the files below one of them.
	only []string
	// onlyGlobs holds absolute glob patterns, matched as text.
	onlyGlobs []string
}

// ExpandPathFilter builds a PathFilter from ignore-paths and only-paths
// patterns, expanding their globs on disk and keeping them to match as text.
func ExpandPathFilter(ignorePatterns, onlyPatterns []string) (*PathFilter, error) {
	ignored, ignoredGlobs, err := expandPatterns(ignorePatterns)
	if err != nil {
		return nil, err
	}
	var only, onlyGlobs []string
	if len(onlyPatterns) > 0 {
		if only, onlyGlobs, err = expandPatterns(onlyPatterns); err != nil {
			return nil, err
		}
	}
	f := NewPathFilter(ignored, only)
	f.ignoredGlobs = absPaths(ignoredGlobs)
	f.onlyGlobs = absPaths(onlyGlobs)
	return f, nil
}

// NewLexicalPathFilter builds a PathFilter that matches patterns as text only,
// for files that are not on disk, such as pushed ones. Every pattern is kept as
// a glob, which matches a literal path or directory the same way.
func NewLexicalPathFilter(ignorePatterns, onlyPatterns []string) *PathFilter {
	f := NewPathFilter(nil, nil)
	f.ignoredGlobs = absPaths(ignorePatterns)
	if len(onlyPatterns) > 0 {
		f.only = []string{}
		f.onlyGlobs = absPaths(onlyPatterns)
	}
	return f
}

// expandPatterns returns the paths the patterns name on disk, and the patterns
// that have glob syntax.
func expandPatterns(patterns []string) (paths, globs []string, err error) {
	paths = make([]string, 0, len(patterns))
	for _, p := range patterns {
		expanded, err := GetExcludePaths(p)
		if err != nil {
			return nil, nil, err
		}
		paths = append(paths, expanded...)
		if hasGlobSyntax(p) {
			globs = append(globs, p)
		}
	}
	return paths, globs, nil
}

// NewPathFilter builds a PathFilter from expanded ignore-paths and only-paths.
func NewPathFilter(ignorePaths, onlyPaths []string) *PathFilter {
	f := &PathFilter{ignored: make(map[string]struct{}, len(ignorePaths))}
	for _, p := range ignorePaths {
		if abs, ok := absPath(p); ok {
			f.ignored[abs] = struct{}{}
		}
	}
	if onlyPaths != nil {
		f.only = make([]string, 0, len(onlyPaths))
		for _, p := range onlyPaths {
			if abs, ok := absPath(p); ok {
				f.only = append(f.only, abs)
			}
		}
	}
	return f
}

// ExcludesAny reports whether the filters leave out a file known by paths, such
// as a file inside a chart archive and the declaration it is reported at: a
// path that is ignored, or one below an ignored directory, drops it, and with
// only-paths, a path within one of them keeps it. Paths need not exist.
func (f *PathFilter) ExcludesAny(paths ...string) bool {
	if f == nil {
		return false
	}
	abs := make([]string, 0, len(paths))
	for _, p := range paths {
		if a, ok := absPath(p); ok {
			abs = append(abs, a)
		}
	}
	if len(abs) == 0 && len(paths) > 0 {
		// Paths that cannot be resolved are not checked, so the file is kept.
		return false
	}
	return pathutil.ExcludedAny(abs, f.ignoredPath, f.withinOnly, f.only != nil)
}

func (f *PathFilter) withinOnly(abs string) bool {
	for _, op := range f.only {
		if pathWithinBase(op, abs) {
			return true
		}
	}
	for _, g := range f.onlyGlobs {
		if pathutil.MatchesPath(g, abs) {
			return true
		}
	}
	return false
}

// ChartInScope reports whether the chart at root is rendered: neither it nor
// its Chart.yaml is ignored, and with only-paths, the chart lies within one or
// contains one (only-paths naming a single template still renders its chart;
// the files outside are dropped from the output). A glob's literal leading
// directories stand in for the paths it may name, so a chart a glob could reach
// renders even when no file of it is on disk.
func (f *PathFilter) ChartInScope(root string) bool {
	if f == nil {
		return true
	}
	abs, ok := absPath(root)
	if !ok {
		return true
	}
	if f.ignoredPath(abs) || f.ignoredPath(filepath.Join(abs, "Chart.yaml")) {
		return false
	}
	if f.only == nil {
		return true
	}
	for _, op := range f.only {
		if pathWithinBase(op, abs) || pathWithinBase(abs, op) {
			return true
		}
	}
	for _, g := range f.onlyGlobs {
		prefix := globPrefix(g)
		if pathWithinBase(prefix, abs) || pathWithinBase(abs, prefix) || pathutil.MatchesPath(g, abs) {
			return true
		}
	}
	return false
}

// ignoredPath reports whether abs, or a directory above it, is ignored by a
// path or by a glob.
func (f *PathFilter) ignoredPath(abs string) bool {
	for p := abs; ; {
		if _, ok := f.ignored[p]; ok {
			return true
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	for _, g := range f.ignoredGlobs {
		if pathutil.MatchesPath(g, abs) {
			return true
		}
	}
	return false
}

func hasGlobSyntax(p string) bool {
	return strings.ContainsAny(p, "*?[")
}

// globPrefix is the leading part of an absolute glob that has no glob syntax:
// every path the glob matches lies below it.
func globPrefix(glob string) string {
	segs := strings.Split(filepath.ToSlash(glob), "/")
	for i, seg := range segs {
		if hasGlobSyntax(seg) {
			if i == 0 {
				return "/"
			}
			return filepath.FromSlash(strings.Join(segs[:i], "/"))
		}
	}
	return glob
}

func absPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if abs, ok := absPath(p); ok {
			out = append(out, abs)
		}
	}
	return out
}

func absPath(p string) (string, bool) {
	abs, err := filepath.Abs(filepath.FromSlash(p))
	return abs, err == nil
}
