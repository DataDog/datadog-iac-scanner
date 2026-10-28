package kustomize

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/kustomize/api/resmap"
	"sigs.k8s.io/kustomize/api/resource"
	"sigs.k8s.io/kustomize/api/types"
)

const originAnnotation = "config.kubernetes.io/origin"

type sourceDoc struct {
	kind, name, namespace string
}

// mapResources attributes every rendered resource to the file it came from:
// the source manifest, or the kustomization file of a generated object.
// Patches are not attributed: Kustomize keeps the origin of the patched
// resource, and its transformer annotations name the kustomization of every
// patch transformer that visited the object, whether it changed it or not,
// never the patch file or the fields changed. A field an overlay patch adds or
// changes is therefore attributed to the source document, where it may be
// absent.
func (r *Renderer) mapResources(res *Result, m resmap.ResMap, rootKust string, rootDeadline time.Time) bool {
	if time.Now().After(rootDeadline) || time.Now().After(r.deadline) {
		return false
	}
	for _, rs := range m.Resources() {
		if time.Now().After(rootDeadline) || time.Now().After(r.deadline) {
			return false
		}
		doc, ok := r.mapResource(res, rs, rootKust)
		if ok {
			res.Documents = append(res.Documents, doc)
		}
	}
	rejectCollisions(res)
	return !time.Now().After(rootDeadline) && !time.Now().After(r.deadline)
}

type mappingKey struct {
	file, generator, namespace string
	index                      int
}

// rejectCollisions turns into mapping failures the documents attributed to a
// source document or generator entry another document of the same rendered
// namespace is attributed to: name affix matching cannot tell app rendered as
// dev-app from dev-app itself.
// ponytail: also rejects one source included twice into a namespace under two
// affixes; the plan's name-transform chain replaces the affix matching.
func rejectCollisions(res *Result) {
	groups := map[mappingKey][]int{}
	for i := range res.Documents {
		d := &res.Documents[i]
		a := d.Kustomize
		k := mappingKey{file: d.FileName, namespace: a.RenderedNamespace, index: d.SourceDocumentIndex}
		switch {
		case a.Generator != nil && a.Generator.Name != "":
			k.generator = a.Generator.Kind + "/" + a.Generator.Name
		case d.SourceDocumentIndex < 0:
			continue
		}
		groups[k] = append(groups[k], i)
	}
	for _, idx := range groups {
		if len(idx) < 2 {
			continue
		}
		for _, i := range idx {
			d := &res.Documents[i]
			d.SourceDocumentIndex = -1
			d.Kustomize.SourceName, d.Kustomize.SourceNamespace = "", ""
			if d.Kustomize.Generator != nil {
				d.Kustomize.Generator.Name = ""
			}
			res.MappingFailures++
		}
	}
}

func (r *Renderer) mapResource(res *Result, rs *resource.Resource, rootKust string) (model.ResolvedHelm, bool) {
	origin, _ := rs.GetOrigin()
	ann := rs.GetAnnotations()
	delete(ann, originAnnotation)
	if err := rs.SetAnnotations(ann); err != nil {
		return model.ResolvedHelm{}, false
	}
	content, err := rs.AsYAML()
	if err != nil {
		return model.ResolvedHelm{}, false
	}
	attr := &model.KustomizeAttribution{
		RenderRoot:        res.Root,
		Kind:              rs.GetKind(),
		RenderedName:      rs.GetName(),
		RenderedNamespace: rs.GetNamespace(),
		Chain:             []string{rootKust},
	}
	doc := model.ResolvedHelm{Content: content, SourceDocumentIndex: -1, Kustomize: attr}
	switch {
	case origin != nil && origin.ConfiguredIn != "":
		doc.FileName = r.canonical(filepath.Join(res.Root, filepath.FromSlash(origin.ConfiguredIn)))
		name := r.generatorName(doc.FileName, origin.ConfiguredBy.Kind, attr.RenderedName)
		if name == "" {
			res.MappingFailures++
		}
		attr.Generator = &model.KustomizeGenerator{Kind: origin.ConfiguredBy.Kind, Name: name}
		attr.SourceName = name
		attr.SourceNamespace = origin.ConfiguredBy.Namespace
	case origin != nil && origin.Path != "" && origin.Repo == "":
		doc.FileName = r.canonical(filepath.Join(res.Root, filepath.FromSlash(origin.Path)))
		idx, src := r.findSourceDocument(doc.FileName, attr.Kind, attr.RenderedName, attr.RenderedNamespace)
		doc.SourceDocumentIndex = idx
		if idx >= 0 {
			attr.SourceName, attr.SourceNamespace = src.name, src.namespace
		}
	default:
		res.MappingFailures++
		doc.FileName = rootKust
	}
	if doc.SourceDocumentIndex < 0 && attr.Generator == nil && doc.FileName != rootKust {
		res.MappingFailures++
	}
	if chain := r.chainTo(rootKust, doc.FileName, map[string]bool{}); chain != nil {
		attr.Chain = chain
	}
	doc.OriginalData, _ = r.Source(doc.FileName)
	return doc, true
}

// chainTo returns the kustomizations from kust down to the one listing file
// as a resource, or to file itself when it is a kustomization (a generator's),
// through the resources and components each loads.
func (r *Renderer) chainTo(kust, file string, seen map[string]bool) []string {
	if kust == file {
		return []string{kust}
	}
	k, ok := r.Kustomization(kust)
	if !ok || seen[kust] {
		return nil
	}
	seen[kust] = true
	dir := filepath.Dir(kust)
	for _, e := range append(append([]string{}, k.Resources...), k.Components...) {
		p := r.canonical(filepath.Join(dir, filepath.FromSlash(e)))
		if p == file {
			return []string{kust}
		}
		for _, n := range KustomizationFileNames {
			if sub := r.chainTo(filepath.Join(p, n), file, seen); sub != nil {
				return append([]string{kust}, sub...)
			}
		}
	}
	return nil
}

// canonical returns p in the symlink-free form the source cache is keyed by:
// an origin keeps the name a kustomization listed, not the file it read.
func (r *Renderer) canonical(p string) string {
	a := &adapter{fsys: r.fsys, root: r.confine, cache: r.cache}
	if abs, ok := a.resolve(p); ok {
		return abs
	}
	return p
}

// findSourceDocument returns the index of the document of kind in path that
// rendered to name, -1 when the names of two documents of kind are both in it:
// exact name (the rendered namespace disambiguates, an
// unresolved tie is a mapping failure), else the unique longest name the
// rendered one contains (prefixes and suffixes added), else the only document
// of that kind.
// ponytail: affix matching ignores which kustomization added which affix; the
// plan's name-transform chain replaces it once roots are planned.
func (r *Renderer) findSourceDocument(path, kind, name, namespace string) (int, sourceDoc) {
	docs := r.sourceDocuments(path)
	if nestedNames(docs, kind, name) {
		return -1, sourceDoc{}
	}
	exact, contains, sameKind := -1, -1, -1
	ambiguousExact, ambiguousContains, ambiguousKind := false, false, false
	for i, d := range docs {
		if d.kind != kind {
			continue
		}
		if d.name == name {
			exact, ambiguousExact = pickExact(docs, exact, i, ambiguousExact, namespace)
			continue
		}
		if d.name != "" && strings.Contains(name, d.name) {
			contains, ambiguousContains = pickContains(docs, contains, i, ambiguousContains)
		}
		if sameKind >= 0 {
			ambiguousKind = true
		}
		sameKind = i
	}
	switch {
	case exact >= 0 && ambiguousExact:
		return -1, sourceDoc{}
	case exact >= 0:
		return exact, docs[exact]
	case contains >= 0 && !ambiguousContains:
		return contains, docs[contains]
	case sameKind >= 0 && !ambiguousKind:
		return sameKind, docs[sameKind]
	}
	return -1, sourceDoc{}
}

// nestedNames reports whether name contains the names of two documents of
// kind: either could have rendered to it under an affix, even one deleted from
// the render or in another namespace.
func nestedNames(docs []sourceDoc, kind, name string) bool {
	seen := ""
	for _, d := range docs {
		if d.kind != kind || d.name == "" || !strings.Contains(name, d.name) {
			continue
		}
		if seen != "" && seen != d.name {
			return true
		}
		seen = d.name
	}
	return false
}

// pickContains folds document i, whose name the rendered one contains, into
// the current one: the longest name wins, an equal length is ambiguous.
func pickContains(docs []sourceDoc, contains, i int, ambiguous bool) (int, bool) {
	switch {
	case contains < 0 || len(docs[i].name) > len(docs[contains].name):
		return i, false
	case len(docs[i].name) == len(docs[contains].name):
		return contains, true
	}
	return contains, ambiguous
}

// pickExact folds document i, an exact name match, into the current one:
// the document in the rendered namespace wins, any other tie is ambiguous.
func pickExact(docs []sourceDoc, exact, i int, ambiguous bool, namespace string) (int, bool) {
	inNs := docs[i].namespace == namespace
	switch {
	case exact < 0:
		return i, false
	case inNs && docs[exact].namespace != namespace:
		return i, false
	case inNs == (docs[exact].namespace == namespace):
		return exact, true
	}
	return exact, ambiguous
}

func (r *Renderer) sourceDocuments(path string) []sourceDoc {
	r.mu.Lock()
	defer r.mu.Unlock()
	if docs, ok := r.docs[path]; ok {
		return docs
	}
	content, _ := r.Source(path)
	var docs []sourceDoc
	dec := yaml.NewDecoder(bytes.NewReader(content))
	for {
		var d struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name      string `yaml:"name"`
				Namespace string `yaml:"namespace"`
			} `yaml:"metadata"`
		}
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			docs = append(docs, sourceDoc{})
			break
		}
		docs = append(docs, sourceDoc{kind: d.Kind, name: d.Metadata.Name, namespace: d.Metadata.Namespace})
	}
	r.docs[path] = docs
	return docs
}

// generatorName returns the name of the only generator entry of genKind
// (ConfigMapGenerator or SecretGenerator) in the kustomization at path that
// the rendered name contains (prefix, suffix and hash added); more than one is
// ambiguous and returns "".
func (r *Renderer) generatorName(path, genKind, rendered string) string {
	k, ok := r.Kustomization(path)
	if !ok {
		return ""
	}
	var args []types.GeneratorArgs
	switch genKind {
	case "ConfigMapGenerator":
		for i := range k.ConfigMapGenerator {
			args = append(args, k.ConfigMapGenerator[i].GeneratorArgs)
		}
	case "SecretGenerator":
		for i := range k.SecretGenerator {
			args = append(args, k.SecretGenerator[i].GeneratorArgs)
		}
	}
	best := ""
	for i := range args {
		n := args[i].Name
		switch {
		case n == "" || !strings.Contains(rendered, n):
		case best != "":
			// Two entries, or one name in two namespaces: either could have
			// rendered to this name under an affix.
			return ""
		default:
			best = n
		}
	}
	return best
}
