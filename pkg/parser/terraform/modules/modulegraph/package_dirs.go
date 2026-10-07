/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package modulegraph

import (
	"path/filepath"
	"strings"
)

// packageAddress splits a mapped module source into the address of its
// package and the suffix (ref query or registry version) following it.
type packageAddress struct {
	address string
	suffix  string
}

// mapPackageDirectories names each scanned directory of a package that no
// source mapping covers after the package's source. These are the directories
// local calls inside a fetched package reach: without a mapping their files
// are reported under the directory the package was fetched to.
func mapPackageDirectories(snapshot *walkerSnapshot) {
	if len(snapshot.sourceMappings) == 0 {
		return
	}
	mapped := make(map[string]bool, len(snapshot.sourceMappings))
	for localPath := range snapshot.sourceMappings {
		mapped[filepath.Clean(localPath)] = true
	}
	packages := packageAddresses(snapshot)
	if len(packages) == 0 {
		return
	}
	for _, path := range snapshot.paths {
		dir := filepath.Dir(filepath.Clean(path))
		if mapped[dir] {
			continue
		}
		if source, ok := packageDirectorySource(dir, mapped, packages); ok {
			snapshot.sourceMappings[dir] = source
			mapped[dir] = true
		}
	}
}

// packageAddresses derives, per package root, the package's address from the
// source mapped to a module resolved inside it. The smallest source wins so
// the result does not depend on resolution order.
func packageAddresses(snapshot *walkerSnapshot) map[string]packageAddress {
	sources := make(map[string]string)
	packages := make(map[string]packageAddress)
	for i := range snapshot.modules {
		module := &snapshot.modules[i]
		if module.PackageRoot == "" {
			continue
		}
		source, ok := snapshot.sourceMappings[module.LocalPath]
		if !ok {
			continue
		}
		root := filepath.Clean(module.PackageRoot)
		if previous, seen := sources[root]; seen && previous <= source {
			continue
		}
		if !pathContainsDir(root, module.LocalPath) {
			continue
		}
		subdir, err := filepath.Rel(root, filepath.Clean(module.LocalPath))
		if err != nil {
			continue
		}
		if pkg, ok := splitPackageAddress(source, filepath.ToSlash(subdir)); ok {
			sources[root] = source
			packages[root] = pkg
		}
	}
	return packages
}

// packageDirectorySource returns the source naming dir, the innermost package
// holding it, unless a mapped directory between them already covers it.
func packageDirectorySource(dir string, mapped map[string]bool, packages map[string]packageAddress) (string, bool) {
	for current := dir; ; {
		if current != dir && mapped[current] {
			return "", false
		}
		if pkg, ok := packages[current]; ok {
			rel, err := filepath.Rel(current, dir)
			if err != nil {
				return "", false
			}
			if rel == "." {
				return pkg.address + pkg.suffix, true
			}
			return pkg.address + "//" + filepath.ToSlash(rel) + pkg.suffix, true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", false
		}
		current = parent
	}
}

// splitPackageAddress strips subdir, the module's directory inside its
// package, from source. It fails when source does not end with that subdir.
func splitPackageAddress(source, subdir string) (packageAddress, bool) {
	body, suffix := source, ""
	if i := strings.Index(source, "?"); i >= 0 {
		body, suffix = source[:i], source[i:]
	} else if i := strings.LastIndex(source, "@"); i > strings.LastIndex(source, "/") && strings.Contains(source[:i], "/") {
		body, suffix = source[:i], source[i:]
	}
	if subdir == "." {
		if hasModuleSubdir(body) {
			return packageAddress{}, false
		}
		return packageAddress{address: body, suffix: suffix}, true
	}
	address, ok := strings.CutSuffix(body, "//"+subdir)
	if !ok || address == "" {
		return packageAddress{}, false
	}
	return packageAddress{address: address, suffix: suffix}, true
}

func hasModuleSubdir(address string) bool {
	if i := strings.Index(address, "://"); i >= 0 {
		address = address[i+len("://"):]
	}
	return strings.Contains(address, "//")
}
