/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2026 Datadog, Inc.
 */
package model

import (
	"cmp"
	"encoding/binary"
	"path/filepath"
	"slices"

	"github.com/google/uuid"
)

var documentNamespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://github.com/DataDog/datadog-iac-scanner/document"))

// DocumentPath names a file in the scan root relative to that root. Fetched
// modules outside the root use their source address and ref. For other files,
// it uses the lexical path relative to the root when possible, and the supplied
// path otherwise. Content-push scans have no root and may supply absolute
// paths. The key preserves the caller's path coordinates and filesystem aliases.
func DocumentPath(path, root string, extraction map[string]ExtractedPathObject) string {
	if path == "" {
		return ""
	}
	path = filepath.FromSlash(path)
	rel, err := filepath.Rel(root, path)
	if root != "" && err == nil && filepath.IsLocal(rel) {
		return filepath.ToSlash(rel)
	}
	dir := extractedSourceDir(path, extraction)
	source := extraction[dir]
	if source.DocumentSource == "" && !source.LocalPath {
		if key := documentPackagePath(path, extraction); key != "" {
			return key
		}
	}
	if dir == "" {
		if err != nil {
			return filepath.ToSlash(path)
		}
		return filepath.ToSlash(rel)
	}
	name := cmp.Or(source.DocumentSource, RedactURLCredentials(source.Path))
	if source.LocalPath {
		name = filepath.ToSlash(getRelativePath(root, filepath.FromSlash(source.Path)))
	}
	return name + "\x00" + filepath.ToSlash(path[len(dir):])
}

// documentPackagePath uses the innermost containing package. A package can
// have several selected module directories, so choose its lowest source key.
func documentPackagePath(path string, extraction map[string]ExtractedPathObject) string {
	var root, source string
	for _, candidate := range extraction {
		dir := candidate.DocumentPackageRoot
		if dir == "" || !pathWithinDir(path, dir) {
			continue
		}
		if len(dir) > len(root) || (dir == root && candidate.DocumentSource < source) {
			root, source = dir, candidate.DocumentSource
		}
	}
	if root == "" {
		return ""
	}
	// Distinguish package-relative paths from selected module-relative paths.
	return source + "\x00package\x00" + filepath.ToSlash(path[len(root):])
}

// DocumentKey identifies a parsed document by its position in the scan input.
// Path and ResolverRoot use the path coordinates described by DocumentPath.
// RenderedPath is the path in the resolver output, and SplitPosition is the
// split's manifest order.
type DocumentKey struct {
	Path          string
	Kind          FileKind
	Platform      string
	ResolverRoot  string
	RenderedPath  string
	SplitPosition int
	DocumentIndex int
}

// ID gives rules a stable UUID for the document.
func (k *DocumentKey) ID() string {
	var name []byte
	for _, part := range [...]string{k.Path, string(k.Kind), k.Platform, k.ResolverRoot, k.RenderedPath} {
		name = binary.AppendUvarint(name, uint64(len(part)))
		name = append(name, part...)
	}
	name = binary.AppendUvarint(name, uint64(k.SplitPosition))
	name = binary.AppendUvarint(name, uint64(k.DocumentIndex))
	return uuid.NewSHA1(documentNamespace, name).String()
}

// SortByDocumentKey orders documents by source path and position.
func (m FileMetadatas) SortByDocumentKey() {
	slices.SortStableFunc(m, func(a, b *FileMetadata) int {
		ak, bk := a.DocumentKey, b.DocumentKey
		return cmp.Or(
			cmp.Compare(cmp.Or(ak.Path, a.FilePath), cmp.Or(bk.Path, b.FilePath)),
			cmp.Compare(ak.Kind, bk.Kind),
			cmp.Compare(ak.Platform, bk.Platform),
			cmp.Compare(ak.ResolverRoot, bk.ResolverRoot),
			cmp.Compare(ak.RenderedPath, bk.RenderedPath),
			cmp.Compare(ak.SplitPosition, bk.SplitPosition),
			cmp.Compare(ak.DocumentIndex, bk.DocumentIndex),
		)
	})
}
