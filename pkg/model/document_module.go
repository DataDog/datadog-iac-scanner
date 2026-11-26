/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2026 Datadog, Inc.
 */
package model

import (
	"cmp"
	"encoding/binary"
	"slices"
)

// ModuleDocumentPackage describes a resolved package in logical coordinates.
type ModuleDocumentPackage struct {
	Address      string
	Version      string
	Ref          string
	ManifestPath string
}

// Compare orders package coordinates for the choice among callers sharing a directory.
func (p ModuleDocumentPackage) Compare(other ModuleDocumentPackage) int {
	return cmp.Or(cmp.Compare(p.Address, other.Address), cmp.Compare(p.Version, other.Version),
		cmp.Compare(p.Ref, other.Ref), cmp.Compare(p.ManifestPath, other.ManifestPath))
}

// ModuleDocumentCallPath is the chain of calls that identifies an installation.
// Each file is relative to the checkout or the calling package.
type ModuleDocumentCallPath struct {
	calls []moduleDocumentCall
}

type moduleDocumentCall struct {
	file string
	name string
}

// WithCall returns the extended chain without modifying its prefix.
func (p ModuleDocumentCallPath) WithCall(file, name string) ModuleDocumentCallPath {
	calls := make([]moduleDocumentCall, len(p.calls)+1)
	copy(calls, p.calls)
	calls[len(p.calls)] = moduleDocumentCall{file: file, name: name}
	return ModuleDocumentCallPath{calls: calls}
}

// Compare orders call chains lexically, starting at the checkout.
func (p ModuleDocumentCallPath) Compare(other ModuleDocumentCallPath) int {
	return slices.CompareFunc(p.calls, other.calls, func(a, b moduleDocumentCall) int {
		return cmp.Or(cmp.Compare(a.file, b.file), cmp.Compare(a.name, b.name))
	})
}

type moduleDocumentLocation struct {
	version           string
	ref               string
	manifestPath      string
	installation      ModuleDocumentCallPath
	selectedDirectory string
}

// WithDocumentLocation returns the source mapping with its logical package
// identity. Reporting still uses Path and LocalPath.
func (s ExtractedPathObject) WithDocumentLocation(
	pkg ModuleDocumentPackage, root, selectedDirectory string, installation ModuleDocumentCallPath,
) ExtractedPathObject {
	s.DocumentSource = pkg.Address
	s.DocumentPackageRoot = root
	s.documentLocation = &moduleDocumentLocation{
		version: pkg.Version, ref: pkg.Ref, manifestPath: pkg.ManifestPath,
		installation: installation, selectedDirectory: selectedDirectory,
	}
	return s
}

func compareModuleDocumentLocations(a, b *moduleDocumentLocation) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	return cmp.Or(cmp.Compare(a.version, b.version), cmp.Compare(a.ref, b.ref),
		cmp.Compare(a.manifestPath, b.manifestPath), a.installation.Compare(b.installation),
		cmp.Compare(a.selectedDirectory, b.selectedDirectory))
}

func (loc *moduleDocumentLocation) appendID(name []byte) []byte {
	if loc == nil {
		return append(name, 0)
	}
	name = append(name, 1)
	for _, part := range [...]string{loc.version, loc.ref, loc.manifestPath, loc.selectedDirectory} {
		name = appendDocumentKeyString(name, part)
	}
	name = binary.AppendUvarint(name, uint64(len(loc.installation.calls)))
	for _, call := range loc.installation.calls {
		name = appendDocumentKeyString(name, call.file)
		name = appendDocumentKeyString(name, call.name)
	}
	return name
}

// enclosingDocumentPackage chooses the innermost containing package. Several
// selected directories may belong to that package, so choose its lowest key.
func enclosingDocumentPackage(path string, extraction map[string]ExtractedPathObject) (string, ExtractedPathObject) {
	var root string
	var source ExtractedPathObject
	for _, candidate := range extraction {
		dir := candidate.DocumentPackageRoot
		if dir == "" || !pathWithinDir(path, dir) {
			continue
		}
		order := cmp.Or(cmp.Compare(candidate.DocumentSource, source.DocumentSource),
			compareModuleDocumentLocations(candidate.documentLocation, source.documentLocation))
		if len(dir) > len(root) || (dir == root && order < 0) {
			root, source = dir, candidate
		}
	}
	return root, source
}
