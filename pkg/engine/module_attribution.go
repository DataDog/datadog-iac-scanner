/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"net/url"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
)

const (
	moduleDependencyDirect     = "direct"
	moduleDependencyTransitive = "transitive"
	moduleSourceTypeGit        = "git"
	moduleSourceTypeLocal      = "local"
	moduleSourceTypeRegistry   = "registry"
	moduleSourceSchemeFile     = "file"
	parentDirectoryPath        = ".."
)

// RemoteModuleProvenance holds resolved identity for a remote module call site.
type RemoteModuleProvenance struct {
	Source          string
	ResolvedVersion string
	ResolvedRef     string
	CanonicalSource string
	SourceType      string
	ModuleRoot      string
}

type moduleProvenanceLookup func(callerRoot, source, version, moduleName string) (RemoteModuleProvenance, bool)

func buildModuleAttribution(
	r *tfeval.ResolvedResource,
	repoPath string,
	moduleRoot string,
	lookup moduleProvenanceLookup,
) *model.ModuleAttribution {
	if r == nil || len(r.CallChain) == 0 {
		return nil
	}

	path := buildModulePath(r.CallChain, repoPath, lookup)
	if len(path) == 0 {
		return nil
	}

	leaf := path[len(path)-1]
	dependencyType := moduleDependencyDirect
	if len(path) > 1 {
		dependencyType = moduleDependencyTransitive
	}

	bodyFile := moduleRelativePath(r.DefinedIn, moduleRoot, repoPath)
	bodyEnd := r.DefEndLine
	if bodyEnd < r.DefLine {
		bodyEnd = r.DefLine
	}

	var modulePath []model.ModulePathHop
	if len(path) > 1 {
		modulePath = path
	}
	return &model.ModuleAttribution{
		Name:           leaf.Name,
		Source:         leaf.Source,
		SourceType:     leaf.SourceType,
		Version:        leaf.Version,
		DependencyType: dependencyType,
		CodeLocation:   path[0].CodeLocation,
		ModuleCodeLocation: model.SourceLocation{
			Filename:    bodyFile,
			LineStart:   r.DefLine,
			LineEnd:     bodyEnd,
			ColumnStart: r.DefColumn,
			ColumnEnd:   r.DefEndColumn,
		},
		ModulePath:      modulePath,
		ModuleCodeOwned: leaf.SourceType == moduleSourceTypeLocal && pathWithinRoot(moduleRoot, repoPath),
	}
}

func buildModulePath(
	chain []tfeval.CallSite,
	repoPath string,
	lookup moduleProvenanceLookup,
) []model.ModulePathHop {
	path := make([]model.ModulePathHop, 0, len(chain))
	for i, site := range chain {
		location := declarationLocation(
			site.CalledFrom,
			site.CalledLine,
			site.CalledEndLine,
			site.CalledColumn,
			site.CalledEndColumn,
			repoPath,
		)
		if i > 0 {
			location.Filename = filepath.ToSlash(filepath.Base(site.CalledFrom))
		}
		hop := model.ModulePathHop{
			Name:         site.ModuleName,
			CodeLocation: location,
		}
		enrichModuleHop(&hop, moduleCallerRoot(site.CalledFrom, repoPath), repoPath, &site, lookup)
		path = append(path, hop)
	}
	return path
}

func enrichModuleHop(
	hop *model.ModulePathHop,
	callerRoot string,
	repoPath string,
	site *tfeval.CallSite,
	lookup moduleProvenanceLookup,
) {
	sourceType, _ := tfmodules.DetectModuleSourceType(site.Source)
	hop.SourceType = sourceType
	hop.Source = normalizedModuleSource(site.Source, sourceType, callerRoot, repoPath)

	if lookup != nil {
		if prov, ok := lookup(callerRoot, site.Source, site.Version, site.ModuleName); ok {
			if prov.SourceType != "" {
				hop.SourceType = prov.SourceType
			}
			source := firstNonEmpty(prov.CanonicalSource, prov.Source, site.Source)
			hop.Source = normalizedModuleSource(source, hop.SourceType, callerRoot, repoPath)
			switch hop.SourceType {
			case moduleSourceTypeRegistry:
				hop.Version = strings.TrimSpace(prov.ResolvedVersion)
			case moduleSourceTypeGit:
				hop.Version = strings.TrimSpace(prov.ResolvedRef)
			}
			return
		}
	}
}

func normalizedModuleSource(source, sourceType, callerRoot, repoPath string) string {
	source = strings.TrimSpace(source)
	if sourceType == moduleSourceTypeRegistry {
		source = strings.SplitN(source, "@", 2)[0]
		if addr, err := tfmodules.ParseRegistryModuleSource(source); err == nil {
			return addr.String()
		}
	}
	if sourceType == moduleSourceTypeLocal {
		localSource := strings.TrimPrefix(source, "git::")
		if parsed, err := url.Parse(localSource); err == nil && parsed.Scheme == moduleSourceSchemeFile {
			localSource = fileURLPath(parsed.Path)
		}
		if portablePathIsAbs(localSource) && !filepath.IsAbs(localSource) {
			return portablePathBase(localSource)
		}
		target := absPath(localSource, callerRoot)
		if pathWithinRoot(target, repoPath) {
			rel, _ := filepath.Rel(filepath.Clean(repoPath), target)
			return filepath.ToSlash(rel)
		}
		return filepath.Base(filepath.Clean(target))
	}
	source = strings.TrimPrefix(source, "git::")
	source = strings.SplitN(source, "?", 2)[0]
	if parsed, err := url.Parse(source); err == nil && parsed.Scheme != "" {
		if parsed.Scheme == moduleSourceSchemeFile {
			return normalizedFileModuleSource(parsed.Path)
		}
		parsed.User = nil
		source = parsed.String()
	} else if at := strings.Index(source, "@"); at > 0 && strings.Contains(source[at+1:], ":") {
		source = source[at+1:]
	}
	source = strings.Replace(source, ".git//", "//", 1)
	return strings.TrimSuffix(source, ".git")
}

func normalizedFileModuleSource(path string) string {
	path = filepath.ToSlash(filepath.Clean(path))
	if packageEnd := strings.Index(path, ".git/"); packageEnd >= 0 {
		subdir := strings.TrimPrefix(path[packageEnd+len(".git/"):], "/")
		name := filepath.Base(path[:packageEnd])
		if subdir != "" {
			return name + "//" + subdir
		}
		return name
	}
	return strings.TrimSuffix(filepath.Base(path), ".git")
}

func fileURLPath(value string) string {
	if len(value) >= 3 && value[0] == '/' && value[2] == ':' {
		value = value[1:]
	}
	return filepath.FromSlash(value)
}

func portablePathIsAbs(value string) bool {
	value = strings.ReplaceAll(value, `\`, "/")
	return strings.HasPrefix(value, "/") ||
		(len(value) >= 3 && value[1] == ':' && value[2] == '/')
}

func portablePathBase(value string) string {
	return pathpkg.Base(strings.ReplaceAll(value, `\`, "/"))
}

func declarationLocation(
	filePath string,
	startLine, endLine, startColumn, endColumn int,
	repoPath string,
) model.SourceLocation {
	if endLine < startLine {
		endLine = startLine
	}
	filename := repoRelativeFile(filePath, repoPath)
	return model.SourceLocation{
		Filename:    filename,
		LineStart:   startLine,
		LineEnd:     endLine,
		ColumnStart: startColumn,
		ColumnEnd:   endColumn,
	}
}

func pathWithinRoot(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && rel != parentDirectoryPath &&
		!strings.HasPrefix(rel, parentDirectoryPath+string(filepath.Separator))
}

func repoRelativeFile(filePath, repoPath string) string {
	abs := absPath(filePath, repoPath)
	rel, err := filepath.Rel(filepath.Clean(repoPath), abs)
	if err != nil {
		return filepath.ToSlash(filepath.Base(abs))
	}
	return filepath.ToSlash(rel)
}

func moduleCallerRoot(calledFrom, repoPath string) string {
	return filepath.Clean(filepath.Dir(absPath(calledFrom, repoPath)))
}

func moduleRelativePath(definedIn, moduleRoot, repoPath string) string {
	absDefined := absPath(definedIn, repoPath)
	if moduleRoot != "" {
		rel, err := filepath.Rel(filepath.Clean(moduleRoot), absDefined)
		if err == nil && pathWithinRoot(absDefined, moduleRoot) {
			return filepath.ToSlash(rel)
		}
	}
	return repoRelativeFile(absDefined, repoPath)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func cloneModuleAttribution(attr *model.ModuleAttribution) *model.ModuleAttribution {
	if attr == nil {
		return nil
	}
	clone := *attr
	if len(attr.ModulePath) > 0 {
		clone.ModulePath = append([]model.ModulePathHop(nil), attr.ModulePath...)
	}
	return &clone
}

func moduleAttributionKey(resourceType string, definitionLine, definitionColumn int) string {
	return resourceType + "." + strconv.Itoa(definitionLine) + "." + strconv.Itoa(definitionColumn)
}

func cloneModuleAttributions(attrs map[string]*model.ModuleAttribution) map[string]*model.ModuleAttribution {
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]*model.ModuleAttribution, len(attrs))
	for key, attr := range attrs {
		out[key] = cloneModuleAttribution(attr)
	}
	return out
}

func moduleAttributionForResource(
	attrs map[string]*model.ModuleAttribution,
	resourceType string,
	definitionLine, definitionColumn int,
) *model.ModuleAttribution {
	if len(attrs) > 0 {
		if attr, ok := attrs[moduleAttributionKey(resourceType, definitionLine, definitionColumn)]; ok {
			return cloneModuleAttribution(attr)
		}
	}
	return nil
}

func moduleRootForResource(r *tfeval.ResolvedResource, repoPath string, lookup moduleProvenanceLookup) string {
	if r == nil || len(r.CallChain) == 0 {
		return ""
	}
	leaf := r.CallChain[len(r.CallChain)-1]
	callerRoot := moduleCallerRoot(leaf.CalledFrom, repoPath)
	if lookup != nil {
		if prov, ok := lookup(callerRoot, leaf.Source, leaf.Version, leaf.ModuleName); ok && prov.ModuleRoot != "" {
			return prov.ModuleRoot
		}
	}
	if len(r.CallChain) > 0 &&
		tfmodules.LooksLikeLocalModuleSource(strings.TrimPrefix(leaf.Source, "git::")) {
		return filepath.Dir(absPath(r.DefinedIn, repoPath))
	}
	return ""
}
