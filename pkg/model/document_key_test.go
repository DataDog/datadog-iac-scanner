/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2026 Datadog, Inc.
 */
package model

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDocumentKeyIdentityAndOrdering(t *testing.T) {
	path := DocumentPath("a.yaml", "", nil)
	root := DocumentPath("chart", "", nil)
	base := DocumentKey{
		Path: path, Kind: "a", Platform: "a", ResolverRoot: root,
		RenderedPath: "template", SplitPosition: 1, DocumentIndex: 1,
	}
	// Changing a later component sorts before changing an earlier one.
	components := []struct {
		name   string
		change func(*DocumentKey)
	}{
		{"document index", func(k *DocumentKey) { k.DocumentIndex++ }},
		{"split position", func(k *DocumentKey) { k.SplitPosition++ }},
		{"rendered path", func(k *DocumentKey) { k.RenderedPath += "s" }},
		{"resolver root", func(k *DocumentKey) { k.ResolverRoot = DocumentPath("charts", "", nil) }},
		{"platform", func(k *DocumentKey) { k.Platform = "b" }},
		{"kind", func(k *DocumentKey) { k.Kind = "b" }},
		{"path", func(k *DocumentKey) { k.Path = DocumentPath("b.yaml", "", nil) }},
	}
	want := []string{base.ID()}
	seen := map[string]bool{base.ID(): true}
	files := FileMetadatas{{DocumentKey: base, ID: base.ID()}}
	for _, component := range components {
		key := base
		component.change(&key)
		id := key.ID()
		require.False(t, seen[id], "%s must change the ID", component.name)
		seen[id] = true
		want = append(want, id)
		files = append(files, &FileMetadata{DocumentKey: key, ID: id})
	}

	// The first group is one input's documents, the rest represent other
	// inputs. Vary both orders independently.
	for _, inputOrder := range [][]int{{0, 1}, {1, 0}} {
		for _, documentOrder := range [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
			groups := []FileMetadatas{{files[documentOrder[0]], files[documentOrder[1]], files[documentOrder[2]]}, files[3:]}
			got := slices.Concat(groups[inputOrder[0]], groups[inputOrder[1]])
			got.SortByDocumentKey()
			ids := make([]string, len(got))
			for i := range got {
				ids[i] = got[i].ID
			}
			require.Equal(t, want, ids, "input order %v, document order %v", inputOrder, documentOrder)
		}
	}
}

func TestDocumentKeyComponentBoundaries(t *testing.T) {
	path := func(s string) DocumentSource { return DocumentPath(s, "", nil) }
	for _, pair := range []struct {
		name string
		a, b DocumentKey
	}{
		{"path and kind", DocumentKey{Path: path("ab"), Kind: "c"}, DocumentKey{Path: path("a"), Kind: "bc"}},
		{"kind and platform", DocumentKey{Kind: "ab", Platform: "c"}, DocumentKey{Kind: "a", Platform: "bc"}},
		{"platform and root", DocumentKey{Platform: "ab", ResolverRoot: path("c")}, DocumentKey{Platform: "a", ResolverRoot: path("bc")}},
		{"root and rendered path", DocumentKey{ResolverRoot: path("ab"), RenderedPath: "c"}, DocumentKey{ResolverRoot: path("a"), RenderedPath: "bc"}},
		{"positions", DocumentKey{SplitPosition: 1, DocumentIndex: 23}, DocumentKey{SplitPosition: 12, DocumentIndex: 3}},
	} {
		t.Run(pair.name, func(t *testing.T) {
			require.NotEqual(t, pair.a.ID(), pair.b.ID())
		})
	}
}

func TestDocumentKeyModuleCoordinates(t *testing.T) {
	root, packageRoot := t.TempDir(), t.TempDir()
	selected := filepath.Join(packageRoot, "entry")
	key := func(pkg ModuleDocumentPackage, dir string, call ModuleDocumentCallPath, file string) string {
		t.Helper()
		mapping := ExtractedPathObject{Path: "reporting-source"}.WithDocumentLocation(pkg, packageRoot, dir, call)
		k := DocumentKey{Path: DocumentPath(file, root, map[string]ExtractedPathObject{selected: mapping})}
		return k.ID()
	}
	pkg := ModuleDocumentPackage{Address: "example.invalid/modules/net", Version: "v1", Ref: "main", ManifestPath: "net"}
	var chain ModuleDocumentCallPath
	call := chain.WithCall("first/main.tf", "net")
	file := filepath.Join(selected, "main.tf")
	want := key(pkg, "entry", call, file)

	for _, change := range []func(*ModuleDocumentPackage){
		func(p *ModuleDocumentPackage) { p.Address += "/other" },
		func(p *ModuleDocumentPackage) { p.Version = "v2" },
		func(p *ModuleDocumentPackage) { p.Ref = "tag" },
		func(p *ModuleDocumentPackage) { p.ManifestPath = "other" },
	} {
		other := pkg
		change(&other)
		require.NotEqual(t, want, key(other, "entry", call, file))
	}
	require.NotEqual(t, want, key(pkg, "entry", chain.WithCall("second/main.tf", "net"), file))
	require.NotEqual(t, want, key(pkg, "other", call, file))
	require.NotEqual(t, want, key(pkg, "entry", call, filepath.Join(selected, "other.tf")))
	require.NotEqual(t, want, key(pkg, "entry", call, filepath.Join(packageRoot, "main.tf")),
		"the same relative file in a selected directory and its package must have distinct IDs")
	a, b := pkg, pkg
	a.Version, a.Ref = "v1\x00main", "other"
	b.Version, b.Ref = "v1", "main\x00other"
	require.NotEqual(t, key(a, "entry", call, file), key(b, "entry", call, file))
}

func TestDocumentPathUsesSuppliedCoordinatesWithoutRepositoryLocation(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "workspace")
	external := filepath.Join(parent, "external", "main.tf")
	require.Equal(t, DocumentSource{origin: "infra/main.tf"}, DocumentPath("infra/main.tf", "", nil))
	require.Equal(t, DocumentSource{origin: filepath.ToSlash(external)}, DocumentPath(external, "", nil))
	require.Equal(t, DocumentSource{origin: "../external/main.tf"}, DocumentPath(external, root, nil))
}

func TestDocumentPathKeepsFetchedModuleRefs(t *testing.T) {
	root := t.TempDir()
	first, second, third := t.TempDir(), t.TempDir(), t.TempDir()
	extracted := map[string]ExtractedPathObject{
		first:  {Path: "git::https://example.invalid/module//network?ref=v1"},
		second: {Path: "git::https://example.invalid/module//network?ref=v2"},
		third:  {Path: "git::https://example.invalid/module//network?ref=v1"},
	}
	firstPath := DocumentPath(filepath.Join(first, "main.tf"), root, extracted)
	secondPath := DocumentPath(filepath.Join(second, "main.tf"), root, extracted)
	thirdPath := DocumentPath(filepath.Join(third, "main.tf"), root, extracted)
	require.NotEqual(t, firstPath, secondPath)
	require.Equal(t, firstPath, thirdPath)

	extracted[second] = ExtractedPathObject{Path: "git::https://example.invalid/module//storage?ref=v1"}
	require.NotEqual(t, firstPath, DocumentPath(filepath.Join(second, "main.tf"), root, extracted))
}

func TestDocumentPathRetainsLocalModuleInstallation(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first", ".terraform", "modules", "network")
	second := filepath.Join(root, "second", ".terraform", "modules", "network")
	extracted := map[string]ExtractedPathObject{
		first:  {Path: "registry.example.invalid/example/network/aws@1.0.0"},
		second: {Path: "registry.example.invalid/example/network/aws@1.0.0"},
	}
	require.Equal(t, DocumentSource{origin: "first/.terraform/modules/network/main.tf"}, DocumentPath(filepath.Join(first, "main.tf"), root, extracted))
	require.Equal(t, DocumentSource{origin: "second/.terraform/modules/network/main.tf"}, DocumentPath(filepath.Join(second, "main.tf"), root, extracted))

	local := t.TempDir()
	extracted[local] = ExtractedPathObject{Path: filepath.Join(root, "module"), LocalPath: true}
	require.Equal(t, DocumentSource{origin: "module", file: "/main.tf", scope: documentExtractedFile},
		DocumentPath(filepath.Join(local, "main.tf"), root, extracted))
}
