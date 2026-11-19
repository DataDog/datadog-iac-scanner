/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"cmp"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Metadata is what the scan knows about itself when the inventory is built.
type Metadata struct {
	ScanID           string
	ScannerVersion   string
	ScannedAt        time.Time
	Repository       Repository
	PlatformsScanned []string
}

// Collector gathers the inventory while a scan runs. It is safe for
// concurrent use; Build returns the same document whatever order the parts
// were added in.
type Collector struct {
	repoRoot string

	mu               sync.Mutex
	files            map[string]*File
	resources        []Resource
	unresolved       []UnresolvedSource
	links            []FindingLink
	findings         []Finding
	findingsUnlinked int
	failure          string

	rootOnce     sync.Once
	resolvedRoot string

	// pathResolver names an absolute path of a resource; see SetPathResolver.
	pathResolver func(string) string
}

// SetPathResolver sets how an absolute path of a resource is named, for
// files outside the repository such as fetched modules. By default a path is
// made relative to the repository root.
func (c *Collector) SetPathResolver(resolve func(string) string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pathResolver = resolve
}

// resourcePath names a path of a resource row.
func (c *Collector) resourcePath(path string) string {
	if path == "" || !filepath.IsAbs(path) {
		return filepath.ToSlash(path)
	}
	if c.pathResolver != nil {
		return c.pathResolver(path)
	}
	if rel, ok := c.RelPath(path); ok {
		return rel
	}
	return filepath.ToSlash(path)
}

// finish names the paths of r and builds its reference.
func (c *Collector) finish(r *Resource) {
	r.File = c.resourcePath(r.File)
	r.CallSiteFile = c.resourcePath(r.CallSiteFile)
	r.OriginChartPath = c.resourcePath(r.OriginChartPath)
	scope := r.File
	if r.RootModule != "" {
		scope = c.resourcePath(r.RootModule)
	}
	if r.ResourceRef == "" {
		r.ResourceRef = scope + "|" + r.ResourcePath
	}
	r.RootModule = ""
}

// NewCollector returns a collector for a scan of the repository at repoRoot.
func NewCollector(repoRoot string) *Collector {
	return &Collector{
		repoRoot: filepath.Clean(repoRoot),
		files:    make(map[string]*File),
	}
}

// RelPath returns path relative to the repository root, with slash
// separators. It reports false for a path outside the repository.
func (c *Collector) RelPath(path string) (string, bool) {
	if rel, ok := relativeTo(c.repoRoot, path); ok {
		return rel, true
	}
	// The repository root may have been found through a symlink (on macOS,
	// /var is /private/var) while the path was not, or the reverse.
	c.rootOnce.Do(func() {
		c.resolvedRoot, _ = filepath.EvalSymlinks(c.repoRoot)
	})
	if c.resolvedRoot == "" {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	return relativeTo(c.resolvedRoot, resolved)
}

func relativeTo(root, path string) (string, bool) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// RecordFile records one attempt to parse a file. A file is scanned when any
// attempt succeeded; otherwise it is failed, with the first reason in sort
// order so the result does not depend on which attempt finished first.
func (c *Collector) RecordFile(path, platform, status, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, ok := c.files[path]
	if !ok {
		c.files[path] = &File{Path: path, Platform: platform, Status: status, Reason: reason}
		if status == FileScanned {
			c.files[path].Reason = ""
		}
		return
	}
	if platform != "" && (f.Platform == "" || platform < f.Platform) {
		f.Platform = platform
	}
	switch {
	case f.Status == FileScanned:
	case status == FileScanned:
		f.Status = FileScanned
		f.Reason = ""
	case reason != "" && (f.Reason == "" || reason < f.Reason):
		f.Reason = reason
	}
}

// AddResource adds an inventory row.
func (c *Collector) AddResource(r *Resource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resources = append(c.resources, *r)
}

// AddUnresolvedSource records a source the scan could not resolve.
func (c *Collector) AddUnresolvedSource(u UnresolvedSource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.unresolved = append(c.unresolved, u)
}

// AddFindingLink links a finding fingerprint to a resource.
func (c *Collector) AddFindingLink(l FindingLink) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.links = append(c.links, l)
}

// Fail marks the inventory as unusable, because some of its resources may be
// missing. The first reason is kept.
func (c *Collector) Fail(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failure == "" {
		c.failure = reason
	}
}

// Failure returns why the inventory is unusable, "" when it is not.
func (c *Collector) Failure() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failure
}

// AddFindingsUnlinked counts findings that map to no resource.
func (c *Collector) AddFindingsUnlinked(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.findingsUnlinked += n
}

// Build returns the inventory, with every list sorted and deduplicated.
func (c *Collector) Build(meta *Metadata) *Inventory {
	c.mu.Lock()
	defer c.mu.Unlock()

	files := make([]File, 0, len(c.files))
	failed := 0
	for _, f := range c.files {
		files = append(files, *f)
		if f.Status == FileFailed {
			failed++
		}
	}
	slices.SortFunc(files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })

	// The rows are finished in place, not copied: there can be many.
	resources := c.resources
	for i := range resources {
		c.finish(&resources[i])
	}
	sort.Slice(resources, func(i, j int) bool { return compareResources(&resources[i], &resources[j]) < 0 })
	repeats := uniqueRefs(resources)

	unresolved := slices.Clone(c.unresolved)
	slices.SortFunc(unresolved, func(a, b UnresolvedSource) int {
		return cmp.Or(
			strings.Compare(a.Platform, b.Platform),
			strings.Compare(a.Source, b.Source),
			strings.Compare(a.Reason, b.Reason),
		)
	})
	unresolved = slices.Compact(unresolved)

	found, unlinked := c.linkFindings(resources, repeats)
	links := append(slices.Clone(c.links), found...)
	slices.SortFunc(links, func(a, b FindingLink) int {
		return cmp.Or(
			strings.Compare(a.FindingFingerprint, b.FindingFingerprint),
			strings.Compare(a.ResourceRef, b.ResourceRef),
		)
	})
	links = slices.Compact(links)

	platforms := slices.Clone(meta.PlatformsScanned)
	slices.Sort(platforms)
	platforms = slices.Compact(platforms)

	status := StatusComplete
	if failed > 0 || len(unresolved) > 0 {
		status = StatusPartial
	}

	return &Inventory{
		SchemaVersion:    SchemaVersion,
		ScanID:           meta.ScanID,
		ScannerVersion:   meta.ScannerVersion,
		ScannedAt:        meta.ScannedAt.UTC(),
		Repository:       meta.Repository,
		Status:           status,
		PlatformsScanned: nonNil(platforms),
		Stats: Stats{
			Resources:        len(resources),
			FilesFailed:      failed,
			FindingsUnlinked: c.findingsUnlinked + unlinked,
		},
		Files:             files,
		UnresolvedSources: nonNil(unresolved),
		Resources:         nonNil(resources),
		FindingLinks:      nonNil(links),
	}
}

// compareResources orders rows by where they are defined, then by identity.
// Every written field takes part, so that the order does not depend on the
// order rows were added in.
func compareResources(a, b *Resource) int {
	return cmp.Or(
		strings.Compare(a.File, b.File),
		cmp.Compare(a.LineStart, b.LineStart),
		strings.Compare(a.ResourcePath, b.ResourcePath),
		strings.Compare(a.ResourceRef, b.ResourceRef),
		strings.Compare(a.ModuleCall, b.ModuleCall),
		strings.Compare(a.Platform, b.Platform),
		strings.Compare(a.ResourceType, b.ResourceType),
		strings.Compare(a.ResourceName, b.ResourceName),
		cmp.Compare(a.LineEnd, b.LineEnd),
		cmp.Compare(a.ColumnStart, b.ColumnStart),
		cmp.Compare(a.ColumnEnd, b.ColumnEnd),
		strings.Compare(a.CallSiteFile, b.CallSiteFile),
		cmp.Compare(a.CallSiteLineStart, b.CallSiteLineStart),
		cmp.Compare(a.CallSiteLineEnd, b.CallSiteLineEnd),
		strings.Compare(a.Provider, b.Provider),
		strings.Compare(a.Completeness, b.Completeness),
		strings.Compare(a.ModuleSource, b.ModuleSource),
		strings.Compare(a.ModuleSourceType, b.ModuleSourceType),
		strings.Compare(a.ModuleVersion, b.ModuleVersion),
		strings.Compare(a.ModuleDependencyType, b.ModuleDependencyType),
		strings.Compare(a.ModulePath, b.ModulePath),
		strings.Compare(a.OriginGenerator, b.OriginGenerator),
		strings.Compare(a.OriginChartPath, b.OriginChartPath),
		strings.Compare(a.OriginChartName, b.OriginChartName),
		strings.Compare(a.OriginChartVersion, b.OriginChartVersion),
		strings.Compare(a.OriginTemplate, b.OriginTemplate),
		cmp.Compare(a.documentIndex, b.documentIndex),
	)
}

// uniqueRefs gives every sorted row its own reference: a row with the
// reference of an earlier row gets the first free "#n" suffix, from #2. It
// maps each row that shared its reference to the rows that shared it, in
// list order.
func uniqueRefs(rows []Resource) map[int][]int {
	count := make(map[string]int, len(rows))
	for i := range rows {
		count[rows[i].ResourceRef]++
	}
	if len(count) == len(rows) {
		return nil
	}
	shared := make(map[string][]int)
	for i := range rows {
		if ref := rows[i].ResourceRef; count[ref] > 1 {
			shared[ref] = append(shared[ref], i)
		}
	}
	// A suffix starts after the last "#", so two references never get the
	// same one and the groups can be renamed in any order.
	repeats := make(map[int][]int)
	for ref, group := range shared {
		n := 1
		for _, i := range group[1:] {
			candidate := ""
			for taken := true; taken; {
				n++
				candidate = ref + "#" + strconv.Itoa(n)
				_, taken = count[candidate]
			}
			count[candidate] = 1
			rows[i].ResourceRef = candidate
		}
		for _, i := range group {
			repeats[i] = group
		}
	}
	return repeats
}

// nonNil keeps empty lists as [] rather than null in the JSON document.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
