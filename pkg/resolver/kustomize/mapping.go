/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2025 Datadog, Inc.
 */
package kustomize

import (
	"path/filepath"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"sigs.k8s.io/kustomize/api/resmap"
	"sigs.k8s.io/kustomize/api/resource"
	kyamlyaml "sigs.k8s.io/kustomize/kyaml/yaml"
)

// sourceIndex maps (kind, name, namespace) to the YAML document index of the
// source file, built lazily once per file per scan.
type sourceIndex struct {
	fsys  vfs.FS
	cache *byteCache
	mu    sync.Mutex
	files map[string][]docRef
}

type docRef struct {
	kind      string
	name      string
	namespace string
	index     int
}

func newSourceIndex(fsys vfs.FS, cache *byteCache) *sourceIndex {
	return &sourceIndex{fsys: fsys, cache: cache, files: make(map[string][]docRef)}
}

// mapResources attributes every rendered resource to the source document a
// developer edits, using the origin annotation for the file and the resource
// id for the document. Generated resources map to the kustomization entry that
// created them. A resource that cannot be attributed still gets an entry, with
// SourceDocumentIndex -1 so findings fall back to line 1; those count as
// mapping failures. rootPrefix and rootSuffix are the render root's name
// transformations, used to reverse the most common rename before matching.
func mapResources(
	fsys vfs.FS, cfs *constrainedFS, resMap resmap.ResMap, rootPrefix, rootSuffix string,
) (entries []model.ResolvedHelm, failures int) {
	index := newSourceIndex(fsys, cfs.cache)
	for _, res := range resMap.Resources() {
		entry, matched := mapResource(cfs, index, res, rootPrefix, rootSuffix)
		if !matched {
			failures++
		}
		entries = append(entries, entry)
	}
	return entries, failures
}

func mapResource(cfs *constrainedFS, index *sourceIndex, res *resource.Resource, rootPrefix, rootSuffix string) (model.ResolvedHelm, bool) {
	org := res.OrgId()
	origin, err := res.GetOrigin()
	if err != nil || origin == nil {
		return model.ResolvedHelm{}, false
	}
	var sourceAbs string
	generated := false
	switch {
	case origin.Path != "":
		sourceAbs = filepath.Join(cfs.renderRoot, filepath.FromSlash(origin.Path))
	case origin.ConfiguredIn != "":
		sourceAbs = filepath.Join(cfs.renderRoot, filepath.FromSlash(origin.ConfiguredIn))
		generated = true
	default:
		return model.ResolvedHelm{}, false
	}
	sourceAbs = filepath.Clean(sourceAbs)
	if !underDir(sourceAbs, cfs.confinementRoot) {
		return model.ResolvedHelm{}, false
	}
	fileContent, err := cfs.cache.get(sourceAbs, func() ([]byte, error) { return cfs.fsys.ReadFile(sourceAbs) })
	if err != nil {
		return model.ResolvedHelm{}, false
	}
	// The origin annotation is scanner plumbing: strip it so the rendered
	// content that gets scanned looks like what a cluster would receive.
	_ = res.SetOrigin(nil)
	content, err := res.AsYAML()
	if err != nil {
		return model.ResolvedHelm{}, false
	}
	entry := model.ResolvedHelm{
		FileName:            cfs.relative(sourceAbs),
		Content:             content,
		OriginalData:        fileContent,
		RenderRoot:          cfs.relative(cfs.renderRoot),
		SourceResourceName:  org.Name,
		SourceDocumentIndex: -1,
	}
	// Generated resources map to the kustomization document itself, whose
	// generator entries carry the lines to report.
	if generated {
		entry.SourceDocumentIndex = 0
		return entry, true
	}
	// OrgId equals the transformed id once Run strips the previous-name build
	// annotations, so matching goes from most to least specific: the rendered
	// name with the root's own prefix and suffix removed, the rendered name,
	// then the one source document name the rendered name contains.
	var doc docRef
	matched := false
	for _, candidate := range untransformedNames(org.Name, rootPrefix, rootSuffix) {
		if doc, matched = index.exact(sourceAbs, org.Kind, candidate, org.Namespace); matched {
			break
		}
	}
	if !matched {
		doc, matched = index.uniqueContained(sourceAbs, org.Kind, org.Name, org.Namespace)
	}
	if matched {
		entry.SourceDocumentIndex = doc.index
		entry.SourceResourceName = doc.name
	}
	return entry, matched
}

// untransformedNames lists the plausible source names of a rendered name:
// the name with the root's prefix and suffix removed, then the name itself.
func untransformedNames(name, prefix, suffix string) []string {
	var out []string
	if prefix != "" || suffix != "" {
		stripped := name
		if prefix != "" {
			stripped = strings.TrimPrefix(stripped, prefix)
		}
		if suffix != "" {
			stripped = strings.TrimSuffix(stripped, suffix)
		}
		if stripped != "" && stripped != name {
			out = append(out, stripped)
		}
	}
	return append(out, name)
}

// exact returns the source document matching kind and name, and namespace
// only when the source document sets one.
func (s *sourceIndex) exact(sourceAbs, kind, name, namespace string) (docRef, bool) {
	docs, ok := s.docs(sourceAbs)
	if !ok {
		return docRef{}, false
	}
	for _, d := range docs {
		if d.kind == kind && d.name == name && (d.namespace == "" || d.namespace == namespace) {
			return d, true
		}
	}
	return docRef{}, false
}

// uniqueContained resolves a transformed name to its source document when
// exactly one same-kind document name is contained in the rendered name
// (nested name prefix, suffix, or hash suffix). Zero or several candidates
// mean the match is not determinate and the caller counts a mapping failure.
func (s *sourceIndex) uniqueContained(sourceAbs, kind, name, namespace string) (docRef, bool) {
	docs, ok := s.docs(sourceAbs)
	if !ok {
		return docRef{}, false
	}
	var found docRef
	matched := false
	for _, d := range docs {
		if d.kind != kind || (d.namespace != "" && d.namespace != namespace) {
			continue
		}
		if strings.Contains(name, d.name) {
			if matched {
				return docRef{}, false
			}
			found, matched = d, true
		}
	}
	return found, matched
}

func (s *sourceIndex) docs(sourceAbs string) ([]docRef, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if docs, ok := s.files[sourceAbs]; ok {
		return docs, true
	}
	data, err := s.cache.get(sourceAbs, func() ([]byte, error) { return s.fsys.ReadFile(sourceAbs) })
	if err != nil {
		s.files[sourceAbs] = nil
		return nil, false
	}
	docs := parseDocuments(data)
	s.files[sourceAbs] = docs
	return docs, true
}

type sourceDocument struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
}

// parseDocuments indexes the YAML documents of a source file. Unparsable
// files yield no matches, which counts as a mapping failure upstream.
func parseDocuments(data []byte) []docRef {
	var docs []docRef
	decoder := kyamlyaml.NewDecoder(strings.NewReader(string(data)))
	for i := 0; ; i++ {
		var doc sourceDocument
		if err := decoder.Decode(&doc); err != nil {
			break
		}
		if doc.Kind == "" || doc.Metadata.Name == "" {
			continue
		}
		docs = append(docs, docRef{kind: doc.Kind, name: doc.Metadata.Name, namespace: doc.Metadata.Namespace, index: i})
	}
	return docs
}
