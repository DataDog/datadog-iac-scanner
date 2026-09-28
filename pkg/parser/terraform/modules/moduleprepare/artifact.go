/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package moduleprepare

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/modulegraph"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"golang.org/x/sync/errgroup"
)

const (
	artifactDirectoryPermissions = 0o750
	artifactFileModeMask         = 0o750
)

type stagedPackage struct {
	originalRoot string
	digest       string
	relativeRoot string
}

type materializer struct {
	artifactRoot string
	packages     map[string]stagedPackage
	packageRoots []string
	referenced   map[string]bool
}

type manifestGroup struct {
	source           string
	requestedVersion string
	sourceType       string
	registryScope    string
	resolved         []modulegraph.ResolvedModule
	failures         []modulegraph.ResolutionFailure
	declarations     []resolver.ManifestDeclaration
}

// newMaterializer stages every package into the artifact in parallel, hashing
// each file as it is copied so a package is read once. Packages no manifest
// entry ends up referencing are removed by prune.
func newMaterializer(
	ctx context.Context,
	artifactRoot, repositoryRoot string,
	modules []modulegraph.ResolvedModule,
	failures []modulegraph.ResolutionFailure,
	linkFiles bool,
) (*materializer, error) {
	packagesDir := filepath.Join(artifactRoot, manifestRoot)
	if err := os.MkdirAll(packagesDir, artifactDirectoryPermissions); err != nil {
		return nil, fmt.Errorf("creating module artifact root: %w", err)
	}
	m := &materializer{
		artifactRoot: artifactRoot,
		packages:     make(map[string]stagedPackage),
		referenced:   make(map[string]bool),
	}
	seen := make(map[string]bool)
	addRoot := func(packageRoot string) {
		if packageRoot == "" {
			return
		}
		root := filepath.Clean(packageRoot)
		if !seen[root] {
			seen[root] = true
			m.packageRoots = append(m.packageRoots, root)
		}
	}
	for i := range modules {
		addRoot(modules[i].PackageRoot)
	}
	for i := range failures {
		addRoot(failures[i].CallerPackageRoot)
	}

	stager := &packageStager{packagesDir: packagesDir}
	staged := make([]stagedPackage, len(m.packageRoots))
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(max(1, runtime.GOMAXPROCS(0)))
	for i, root := range m.packageRoots {
		// Packages inside the scanned repository, such as .terraform/modules,
		// belong to the user and are never linked, so their modes never change.
		_, inRepository := relativeWithin(repositoryRoot, root)
		link := linkFiles && !inRepository
		g.Go(func() error {
			pkg, err := stager.stage(gCtx, root, link)
			if err != nil {
				return fmt.Errorf("staging module package %q: %w", root, err)
			}
			staged[i] = pkg
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	for _, pkg := range staged {
		m.packages[pkg.originalRoot] = pkg
	}
	sort.Slice(m.packageRoots, func(i, j int) bool {
		if len(m.packageRoots[i]) != len(m.packageRoots[j]) {
			return len(m.packageRoots[i]) > len(m.packageRoots[j])
		}
		return m.packageRoots[i] < m.packageRoots[j]
	})
	return m, nil
}

func buildManifestModules(
	ctx context.Context,
	repositoryRoot string,
	graphResult *modulegraph.Result,
	materializer *materializer,
) ([]resolver.ManifestModule, error) {
	groups := make(map[string]*manifestGroup)
	for i := range graphResult.Modules {
		module := graphResult.Modules[i]
		declaration, err := materializer.declaration(repositoryRoot, module.CallerFile, module.Name, module.CallerLine, module.CallerEndLine)
		if err != nil {
			return nil, err
		}
		group := manifestGroupFor(groups, module.Source, module.Version, declaration)
		group.resolved = append(group.resolved, module)
		if group.sourceType == "" {
			group.sourceType, group.registryScope = sourceIdentity(module.Source, module.ResolvedRef)
		}
		group.declarations = append(group.declarations, declaration)
	}
	for i := range graphResult.Failures {
		failure := graphResult.Failures[i]
		declaration, err := materializer.declaration(
			repositoryRoot,
			failure.CallerFile,
			failure.Name,
			failure.CallerLine,
			failure.CallerEndLine,
		)
		if err != nil {
			return nil, err
		}
		group := manifestGroupFor(groups, failure.Source, failure.Version, declaration)
		group.failures = append(group.failures, failure)
		if group.sourceType == "" {
			group.sourceType, group.registryScope = sourceIdentity(failure.Source, "")
		}
		group.declarations = append(group.declarations, declaration)
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	entries := make([]resolver.ManifestModule, 0, len(keys))
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entry, err := materializer.buildEntry(groups[key])
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func manifestGroupFor(
	groups map[string]*manifestGroup,
	source, version string,
	declaration resolver.ManifestDeclaration,
) *manifestGroup {
	source = strings.TrimSpace(model.RedactURLCredentials(source))
	version = strings.TrimSpace(version)
	key := strings.Join([]string{
		source,
		version,
		declaration.Filename,
		declaration.ModuleName,
		fmt.Sprintf("%d", declaration.LineStart),
	}, "\x00")
	if groups[key] == nil {
		groups[key] = &manifestGroup{
			source:           source,
			requestedVersion: version,
		}
	}
	return groups[key]
}

func (m *materializer) buildEntry(group *manifestGroup) (resolver.ManifestModule, error) {
	entry := resolver.ManifestModule{
		Source:           group.source,
		SourceType:       group.sourceType,
		RegistryScope:    group.registryScope,
		RequestedVersion: group.requestedVersion,
		Declarations:     uniqueDeclarations(group.declarations),
	}
	if len(group.failures) > 0 {
		entry.Status = resolver.ManifestStatusUnresolved
		entry.Failure = joinedFailureReasons(group.failures)
		return entry, nil
	}
	if len(group.resolved) == 0 {
		entry.Status = resolver.ManifestStatusUnresolved
		entry.Failure = "module was not resolved"
		return entry, nil
	}

	first := group.resolved[0]
	packageInfo := m.packages[filepath.Clean(first.PackageRoot)]
	selectedPath, err := relativeSelectedPath(&first)
	if err != nil {
		return resolver.ManifestModule{}, err
	}
	for i := 1; i < len(group.resolved); i++ {
		module := group.resolved[i]
		otherPackage := m.packages[filepath.Clean(module.PackageRoot)]
		otherSelected, relErr := relativeSelectedPath(&module)
		if relErr != nil {
			return resolver.ManifestModule{}, relErr
		}
		if packageInfo.digest != otherPackage.digest ||
			filepath.Clean(selectedPath) != filepath.Clean(otherSelected) ||
			first.ResolvedVersion != module.ResolvedVersion ||
			first.ResolvedRef != module.ResolvedRef {
			entry.Status = resolver.ManifestStatusUnresolved
			entry.Failure = "module resolved inconsistently across declarations"
			return entry, nil
		}
	}
	m.referenced[packageInfo.relativeRoot] = true

	entry.CanonicalSource = model.RedactURLCredentials(first.CanonicalSource)
	entry.ResolvedVersion = first.ResolvedVersion
	entry.ResolvedRef = first.ResolvedRef
	entry.ContentDigest = packageInfo.digest
	entry.PackageRoot = packageInfo.relativeRoot
	entry.LocalPath = filepath.ToSlash(filepath.Join(packageInfo.relativeRoot, selectedPath))
	entry.Status = resolver.ManifestStatusResolved
	return entry, nil
}

// prune removes staged packages that no resolved manifest entry references.
func (m *materializer) prune() error {
	for _, pkg := range m.packages {
		if m.referenced[pkg.relativeRoot] {
			continue
		}
		destination := filepath.Join(m.artifactRoot, manifestRoot, filepath.FromSlash(pkg.relativeRoot))
		if err := os.RemoveAll(destination); err != nil {
			return fmt.Errorf("removing unreferenced module package: %w", err)
		}
	}
	return nil
}

func (m *materializer) declaration(
	repositoryRoot, filename, moduleName string, lineStart, lineEnd int,
) (resolver.ManifestDeclaration, error) {
	filename = filepath.Clean(filename)
	if relative, ok := relativeWithin(repositoryRoot, filename); ok {
		return newDeclaration(relative, moduleName, lineStart, lineEnd), nil
	}
	for _, root := range m.packageRoots {
		pkg := m.packages[root]
		if relative, ok := relativeWithin(pkg.originalRoot, filename); ok {
			return newDeclaration(filepath.Join(pkg.relativeRoot, relative), moduleName, lineStart, lineEnd), nil
		}
	}
	return resolver.ManifestDeclaration{}, fmt.Errorf("module declaration %q is outside the repository and resolved packages", filename)
}

func newDeclaration(filename, moduleName string, lineStart, lineEnd int) resolver.ManifestDeclaration {
	return resolver.ManifestDeclaration{
		Filename:   filepath.ToSlash(filename),
		LineStart:  lineStart,
		LineEnd:    lineEnd,
		ModuleName: moduleName,
	}
}

func sourceIdentity(source, resolvedRef string) (sourceType, registryScope string) {
	sourceType, registryScope = tfmodules.DetectModuleSourceType(source)
	if sourceType == "unknown" && resolvedRef != "" {
		sourceType = "git"
	}
	return sourceType, registryScope
}

func relativeSelectedPath(module *modulegraph.ResolvedModule) (string, error) {
	relative, ok := relativeWithin(module.PackageRoot, module.LocalPath)
	if !ok {
		return "", fmt.Errorf("module path %q is outside package root %q", module.LocalPath, module.PackageRoot)
	}
	if relative == "." {
		return "", nil
	}
	return relative, nil
}

func relativeWithin(root, path string) (string, bool) {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return relative, err == nil && !pathEscapes(relative)
}

func uniqueDeclarations(declarations []resolver.ManifestDeclaration) []resolver.ManifestDeclaration {
	sort.Slice(declarations, func(i, j int) bool {
		left, right := declarations[i], declarations[j]
		if left.Filename != right.Filename {
			return left.Filename < right.Filename
		}
		if left.LineStart != right.LineStart {
			return left.LineStart < right.LineStart
		}
		return left.ModuleName < right.ModuleName
	})
	output := declarations[:0]
	for _, declaration := range declarations {
		if len(output) == 0 || output[len(output)-1] != declaration {
			output = append(output, declaration)
		}
	}
	return output
}

func joinedFailureReasons(failures []modulegraph.ResolutionFailure) string {
	reasons := make(map[string]struct{}, len(failures))
	for i := range failures {
		reason := strings.TrimSpace(model.RedactURLCredentials(failures[i].Reason))
		if reason != "" {
			reasons[reason] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(reasons))
	for reason := range reasons {
		ordered = append(ordered, reason)
	}
	sort.Strings(ordered)
	return strings.Join(ordered, "; ")
}

type packageStager struct {
	packagesDir string
	// linkFailed stops link attempts once one fails, as they fail alike when
	// the package cache and the artifact sit on different filesystems.
	linkFailed atomic.Bool
}

// stage writes root under a temporary name while digesting it, then renames it
// to its digest. Roots with identical content collapse onto one directory.
func (s *packageStager) stage(ctx context.Context, root string, link bool) (stagedPackage, error) {
	temp, err := os.MkdirTemp(s.packagesDir, ".package-")
	if err != nil {
		return stagedPackage{}, fmt.Errorf("creating temporary package directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(temp)
	}()
	digest, err := resolver.WalkPackageDigest(ctx, root, resolver.PackageVisitor{
		Dir: func(relative string) error {
			return os.MkdirAll(filepath.Join(temp, relative), artifactDirectoryPermissions)
		},
		File: func(relative, path string, info fs.FileInfo, content io.Reader) error {
			return s.stageFile(path, filepath.Join(temp, relative), info.Mode(), content, link)
		},
	})
	if err != nil {
		return stagedPackage{}, err
	}
	pkg := stagedPackage{
		originalRoot: root,
		digest:       digest,
		relativeRoot: strings.TrimPrefix(digest, "sha256:"),
	}
	destination := filepath.Join(s.packagesDir, filepath.FromSlash(pkg.relativeRoot))
	if err := os.Rename(temp, destination); err != nil {
		if _, statErr := os.Stat(destination); statErr == nil {
			return pkg, nil
		}
		return stagedPackage{}, fmt.Errorf("publishing module package: %w", err)
	}
	return pkg, nil
}

func (s *packageStager) stageFile(source, destination string, sourceMode fs.FileMode, content io.Reader, link bool) error {
	mode := sourceMode.Perm() & artifactFileModeMask
	if link && !s.linkFailed.Load() {
		if linkFile(source, destination, sourceMode.Perm(), mode) {
			return nil
		}
		s.linkFailed.Store(true)
	}
	// destination is derived from an owned artifact root and a walked relative path.
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, content)
	return errors.Join(copyErr, output.Close())
}

// linkFile hard-links source to destination with the artifact's permissions,
// which narrows the shared inode's mode for the source too.
func linkFile(source, destination string, current, mode fs.FileMode) bool {
	if os.Link(source, destination) != nil {
		return false
	}
	if current != mode && os.Chmod(destination, mode) != nil {
		_ = os.Remove(destination)
		return false
	}
	return true
}
