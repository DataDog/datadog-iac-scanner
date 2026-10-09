/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package provider

import (
	"path/filepath"
)

// FileFilter reports whether a file is left out of the scan by its path
// filters. Rendered Helm files are checked against it because a chart renders
// the files of dependencies from anywhere in the scan.
type FileFilter interface {
	ExcludesFile(path string) bool
}

// PathFilter applies a scan's ignore-paths and only-paths, already expanded to
// paths, to Helm charts and the files they render. It does no I/O and never
// changes, so it is safe for concurrent use. A nil PathFilter excludes nothing.
type PathFilter struct {
	// ignored holds cleaned absolute paths; each covers everything below it.
	ignored map[string]struct{}
	// only holds cleaned absolute paths; nil means no restriction, while
	// non-nil (even empty) keeps only the files below one of them.
	only []string
}

// ExpandPathFilter builds a PathFilter from ignore-paths and only-paths
// patterns, expanding their globs.
func ExpandPathFilter(ignorePatterns, onlyPatterns []string) (*PathFilter, error) {
	expand := func(patterns []string) ([]string, error) {
		expanded := make([]string, 0, len(patterns))
		for _, p := range patterns {
			paths, err := GetExcludePaths(p)
			if err != nil {
				return nil, err
			}
			expanded = append(expanded, paths...)
		}
		return expanded, nil
	}
	ignored, err := expand(ignorePatterns)
	if err != nil {
		return nil, err
	}
	var only []string
	if len(onlyPatterns) > 0 {
		if only, err = expand(onlyPatterns); err != nil {
			return nil, err
		}
	}
	return NewPathFilter(ignored, only), nil
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

// ExcludesFile reports whether path, or a directory above it, is ignored, or
// whether only-paths leave it out. The path need not exist, as for a file
// inside a chart archive.
func (f *PathFilter) ExcludesFile(path string) bool {
	if f == nil {
		return false
	}
	abs, ok := absPath(path)
	if !ok {
		return false
	}
	if f.ignoredPath(abs) {
		return true
	}
	if f.only == nil {
		return false
	}
	for _, op := range f.only {
		if pathWithinBase(op, abs) {
			return false
		}
	}
	return true
}

// ChartInScope reports whether the chart at root is rendered: neither it nor
// its Chart.yaml is ignored, and with only-paths, the chart lies within one or
// contains one (only-paths naming a single template still renders its chart;
// the files outside are dropped from the output).
func (f *PathFilter) ChartInScope(root string) bool {
	if f == nil {
		return true
	}
	abs, ok := absPath(root)
	if !ok {
		return true
	}
	if f.ignoredPath(abs) {
		return false
	}
	if _, ok := f.ignored[filepath.Join(abs, "Chart.yaml")]; ok {
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
	return false
}

func (f *PathFilter) ignoredPath(abs string) bool {
	if len(f.ignored) == 0 {
		return false
	}
	for p := abs; ; {
		if _, ok := f.ignored[p]; ok {
			return true
		}
		parent := filepath.Dir(p)
		if parent == p {
			return false
		}
		p = parent
	}
}

func absPath(p string) (string, bool) {
	abs, err := filepath.Abs(filepath.FromSlash(p))
	return abs, err == nil
}
