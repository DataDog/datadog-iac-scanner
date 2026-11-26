/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"path/filepath"
	"strings"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

// ModuleDirectoryIdentity identifies a package version and the module selected within it.
type ModuleDirectoryIdentity struct {
	Package string `json:"package"`
	Subdir  string `json:"subdir"`
}

// RequestedModuleDirectory identifies the module named by a call, independently
// of the directory the resolver returned.
func RequestedModuleDirectory(mod *tfmodules.ParsedModule, res *Resolution) ModuleDirectoryIdentity {
	if res.RegistryGitDirectory.Package != "" {
		return res.RegistryGitDirectory
	}
	source := strings.TrimSpace(mod.Source)
	if identity, ok := gitModuleDirectory(source, res.ResolvedRef); ok {
		return identity
	}

	_, subdir := splitGetterSubdir(source)
	version := strings.TrimSpace(mod.Version)
	if addr, err := tfmodules.ParseRegistryModuleSource(source); err == nil {
		subdir = addr.Subdir
		if res.ResolvedVersion != "" {
			version = res.ResolvedVersion
		}
	}
	return ModuleDirectoryIdentity{
		Package: canonicalizeModuleCacheSource(source) + "\x00" + version,
		Subdir:  filepath.ToSlash(filepath.Clean(subdir)),
	}
}

func gitModuleDirectory(source, resolvedRef string) (ModuleDirectoryIdentity, bool) {
	repo, subdir, ref, ok := parseGitGetterSource(source)
	if !ok {
		return ModuleDirectoryIdentity{}, false
	}
	if resolvedRef != "" {
		ref = resolvedRef
	} else if ref == "" {
		ref = defaultGitRef
	}
	return ModuleDirectoryIdentity{
		Package: normalizeGitRepoURL(repo) + "\x00" + ref,
		Subdir:  filepath.ToSlash(filepath.Clean(subdir)),
	}, true
}
