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

type documentSourceScope uint8

const (
	documentPath documentSourceScope = iota
	documentExtractedFile
	documentModuleDirectory
	documentModulePackage
)

// DocumentSource identifies a scan input independently of its reporting path.
type DocumentSource struct {
	origin   string
	file     string
	scope    documentSourceScope
	location *moduleDocumentLocation
}

// LexicalDocumentPath preserves the supplied filesystem coordinates and
// aliases. It makes paths relative to the checkout or package when possible.
func LexicalDocumentPath(path, root string) string {
	lexical, _ := lexicalDocumentPath(path, root)
	return lexical
}

// DocumentPath identifies a checkout file by its relative path. A file
// outside the checkout can belong to a selected module directory, somewhere
// else in the same package, or another kind of extracted source.
func DocumentPath(path, root string, extraction map[string]ExtractedPathObject) DocumentSource {
	lexical, inRoot := lexicalDocumentPath(path, root)
	if path == "" || inRoot {
		return DocumentSource{origin: lexical}
	}
	path = filepath.FromSlash(path)
	dir := extractedSourceDir(path, extraction)
	source := extraction[dir]
	if source.DocumentSource == "" && !source.LocalPath {
		if packageRoot, pkg := enclosingDocumentPackage(path, extraction); packageRoot != "" {
			return DocumentSource{
				origin: pkg.DocumentSource, file: filepath.ToSlash(path[len(packageRoot):]),
				scope: documentModulePackage, location: pkg.documentLocation,
			}
		}
	}
	if dir == "" {
		return DocumentSource{origin: lexical}
	}
	file := filepath.ToSlash(path[len(dir):])
	if source.LocalPath {
		origin := filepath.ToSlash(getRelativePath(root, filepath.FromSlash(source.Path)))
		return DocumentSource{origin: origin, file: file, scope: documentExtractedFile}
	}
	if source.DocumentSource != "" {
		return DocumentSource{
			origin: source.DocumentSource, file: file,
			scope: documentModuleDirectory, location: source.documentLocation,
		}
	}
	return DocumentSource{origin: RedactURLCredentials(source.Path), file: file, scope: documentExtractedFile}
}

func lexicalDocumentPath(path, root string) (string, bool) {
	if path == "" {
		return "", false
	}
	rel, err := filepath.Rel(root, filepath.FromSlash(path))
	if err != nil {
		return filepath.ToSlash(path), false
	}
	return filepath.ToSlash(rel), root != "" && filepath.IsLocal(rel)
}

func (s DocumentSource) compare(other DocumentSource) int {
	return cmp.Or(
		cmp.Compare(s.origin, other.origin),
		compareModuleDocumentLocations(s.location, other.location),
		cmp.Compare(s.scope, other.scope),
		cmp.Compare(s.file, other.file),
	)
}

// DocumentKey identifies a parsed document by its position in the scan input.
// Path and ResolverRoot use the path coordinates described by DocumentPath.
// RenderedPath is the path in the resolver output, and SplitPosition is the
// split's manifest order.
type DocumentKey struct {
	Path          DocumentSource
	Kind          FileKind
	Platform      string
	ResolverRoot  DocumentSource
	RenderedPath  string
	SplitPosition int
	DocumentIndex int
}

// ID gives rules a stable UUID for the document.
func (k *DocumentKey) ID() string {
	var name []byte
	for _, part := range [...]string{k.Path.origin, string(k.Kind), k.Platform, k.ResolverRoot.origin, k.RenderedPath} {
		name = appendDocumentKeyString(name, part)
	}
	name = binary.AppendUvarint(name, uint64(k.SplitPosition))
	name = binary.AppendUvarint(name, uint64(k.DocumentIndex))
	// The fixed fields preserve the IDs of ordinary checkout documents. An
	// extracted source has additional coordinates, framed after those fields.
	if k.Path.scope != documentPath || k.ResolverRoot.scope != documentPath {
		name = k.Path.appendExtractionID(name)
		name = k.ResolverRoot.appendExtractionID(name)
	}
	return uuid.NewSHA1(documentNamespace, name).String()
}

func appendDocumentKeyString(name []byte, part string) []byte {
	name = binary.AppendUvarint(name, uint64(len(part)))
	return append(name, part...)
}

func (s DocumentSource) appendExtractionID(name []byte) []byte {
	name = append(name, byte(s.scope))
	name = appendDocumentKeyString(name, s.file)
	if s.scope == documentModuleDirectory || s.scope == documentModulePackage {
		name = s.location.appendID(name)
	}
	return name
}

// SortByDocumentKey orders documents by source path and position.
func (m FileMetadatas) SortByDocumentKey() {
	slices.SortStableFunc(m, func(a, b *FileMetadata) int {
		ak, bk := a.DocumentKey, b.DocumentKey
		as, bs := ak.Path, bk.Path
		if as.scope == documentPath && as.origin == "" {
			as.origin = a.FilePath
		}
		if bs.scope == documentPath && bs.origin == "" {
			bs.origin = b.FilePath
		}
		return cmp.Or(
			as.compare(bs),
			cmp.Compare(ak.Kind, bk.Kind),
			cmp.Compare(ak.Platform, bk.Platform),
			ak.ResolverRoot.compare(bk.ResolverRoot),
			cmp.Compare(ak.RenderedPath, bk.RenderedPath),
			cmp.Compare(ak.SplitPosition, bk.SplitPosition),
			cmp.Compare(ak.DocumentIndex, bk.DocumentIndex),
		)
	})
}
