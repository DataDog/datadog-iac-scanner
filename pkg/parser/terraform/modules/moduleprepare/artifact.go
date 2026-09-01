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
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/modulegraph"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
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

func newMaterializer(
	ctx context.Context,
	artifactRoot string,
	modules []modulegraph.ResolvedModule,
	failures []modulegraph.ResolutionFailure,
) (*materializer, error) {
	if err := os.MkdirAll(filepath.Join(artifactRoot, manifestRoot), artifactDirectoryPermissions); err != nil {
		return nil, fmt.Errorf("creating module artifact root: %w", err)
	}
	m := &materializer{
		artifactRoot: artifactRoot,
		packages:     make(map[string]stagedPackage),
	}
	addPackage := func(packageRoot string) error {
		if packageRoot == "" {
			return nil
		}
		root := filepath.Clean(packageRoot)
		if _, ok := m.packages[root]; ok {
			return nil
		}
		digest, err := resolver.ComputePackageDigest(ctx, root)
		if err != nil {
			return fmt.Errorf("digesting module package %q: %w", root, err)
		}
		m.packages[root] = stagedPackage{
			originalRoot: root,
			digest:       digest,
			relativeRoot: strings.TrimPrefix(digest, "sha256:"),
		}
		m.packageRoots = append(m.packageRoots, root)
		return nil
	}
	for i := range modules {
		if err := addPackage(modules[i].PackageRoot); err != nil {
			return nil, err
		}
	}
	for i := range failures {
		if err := addPackage(failures[i].CallerPackageRoot); err != nil {
			return nil, err
		}
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
		entry, err := materializer.buildEntry(ctx, groups[key])
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

func (m *materializer) buildEntry(ctx context.Context, group *manifestGroup) (resolver.ManifestModule, error) {
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
	if err := m.stagePackage(ctx, packageInfo); err != nil {
		return resolver.ManifestModule{}, err
	}

	entry.CanonicalSource = model.RedactURLCredentials(first.CanonicalSource)
	entry.ResolvedVersion = first.ResolvedVersion
	entry.ResolvedRef = first.ResolvedRef
	entry.ContentDigest = packageInfo.digest
	entry.PackageRoot = packageInfo.relativeRoot
	entry.LocalPath = filepath.ToSlash(filepath.Join(packageInfo.relativeRoot, selectedPath))
	entry.Status = resolver.ManifestStatusResolved
	return entry, nil
}

func (m *materializer) stagePackage(ctx context.Context, pkg stagedPackage) error {
	destination := filepath.Join(m.artifactRoot, manifestRoot, filepath.FromSlash(pkg.relativeRoot))
	if _, err := os.Stat(destination); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("checking staged module package: %w", err)
	}
	temp, err := os.MkdirTemp(filepath.Join(m.artifactRoot, manifestRoot), ".package-")
	if err != nil {
		return fmt.Errorf("creating temporary package directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(temp)
	}()
	if err := copyPackage(ctx, pkg.originalRoot, temp); err != nil {
		return fmt.Errorf("staging module package: %w", err)
	}
	if err := os.Rename(temp, destination); err != nil {
		if _, statErr := os.Stat(destination); statErr == nil {
			return nil
		}
		return fmt.Errorf("publishing module package: %w", err)
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

func copyPackage(ctx context.Context, source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symlink %q is not allowed in a module package", path)
		}
		if entry.IsDir() {
			return os.MkdirAll(target, artifactDirectoryPermissions)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular file %q is not allowed in a module package", path)
		}
		return copyRegularFile(path, target, info.Mode().Perm())
	})
}

func copyRegularFile(source, destination string, mode fs.FileMode) error {
	input, err := os.Open(source) //nolint:gosec
	if err != nil {
		return err
	}
	// destination is derived from an owned artifact root and a walked relative path.
	output, err := os.OpenFile( //nolint:gosec
		destination,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		mode&artifactFileModeMask,
	)
	if err != nil {
		return errors.Join(err, input.Close())
	}
	_, copyErr := io.Copy(output, input)
	inputCloseErr := input.Close()
	closeErr := output.Close()
	return errors.Join(copyErr, inputCloseErr, closeErr)
}
