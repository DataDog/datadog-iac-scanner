package kustomize

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"slices"
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
	mode := r.renameMode(res.Reads)
	for _, rs := range m.Resources() {
		if time.Now().After(rootDeadline) || time.Now().After(r.deadline) {
			return false
		}
		doc, ok := r.mapResource(res, rs, rootKust, mode)
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
// namespace is attributed to.
// ponytail: also rejects one source included twice into a namespace through
// two chains; per-chain origins would tell them apart.
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

// renameMode is how far the render graph can rename an object.
type renameMode int

const (
	// renameAny: a kustomization may rename beyond affixes (patches,
	// replacements, transformers, ...); no rendered name is attributable.
	renameAny renameMode = iota
	// renameAffix: only namePrefix, nameSuffix and namespace rename.
	renameAffix
	// renameNone: a rendered name is its source name (a generator's plus its
	// hash).
	renameNone
)

// affixFields may rename only by the affixes along an object's chain, and
// namespace only Namespace objects.
var affixFields = map[string]bool{"NamePrefix": true, "NameSuffix": true, "Namespace": true}

// renameMode returns how far the kustomizations the render read can rename:
// every one must set only identity-safe fields for renameNone, add only affix
// fields for renameAffix (components excluded: they apply affixes to their
// parent's objects), and generator entries must be unambiguous
// (generatorEntries) for either. Reads are symlink-resolved: a kustomization
// is known by its decoded entry whatever the target file is named, and one
// named as a kustomization without an entry is unproven.
func (r *Renderer) renameMode(reads []string) renameMode {
	mode := renameNone
	var gens generatorEntries
	for _, p := range reads {
		r.cache.mu.Lock()
		_, decoded := r.cache.kusts[p]
		r.cache.mu.Unlock()
		if !decoded && !IsKustomizationFile(filepath.Base(p)) {
			continue
		}
		k, ok := r.Kustomization(p)
		switch {
		case !ok || !gens.add(k):
			return renameAny
		case !renames(k, nil):
		case !renames(k, affixFields) && k.Kind != types.ComponentKind:
			mode = renameAffix
		default:
			return renameAny
		}
	}
	return mode
}

// generatorEntries proves generated names unambiguous across the graph: every
// entry creates (merge and replace keep the base origin under another
// kustomization's options), no entry name repeats, in any namespace or level,
// and every entry hashes the same way.
type generatorEntries struct {
	names   map[string]bool
	hashOff *bool
}

func (g *generatorEntries) add(k *types.Kustomization) bool {
	if g.names == nil {
		g.names = map[string]bool{}
	}
	global := k.GeneratorOptions != nil && k.GeneratorOptions.DisableNameSuffixHash
	var args []types.GeneratorArgs
	for i := range k.ConfigMapGenerator {
		args = append(args, k.ConfigMapGenerator[i].GeneratorArgs)
	}
	for i := range k.SecretGenerator {
		args = append(args, k.SecretGenerator[i].GeneratorArgs)
	}
	for i := range args {
		a := &args[i]
		off := global || a.Options != nil && a.Options.DisableNameSuffixHash
		if (a.Behavior != "" && a.Behavior != "create") || g.names[a.Name] || (g.hashOff != nil && *g.hashOff != off) {
			return false
		}
		g.names[a.Name], g.hashOff = true, &off
	}
	return true
}

// identitySafe are the kustomization fields that cannot change an object's
// name: labels and annotations on their built-in field specs, images,
// replicas, inputs, generators with their options (the hash is matched apart),
// and metadata of the build itself. Any other field, including one added to
// the schema later, may rename: namespace renames Namespace objects.
var identitySafe = map[string]bool{
	"TypeMeta": true, "MetaData": true, "CommonLabels": true, "CommonAnnotations": true,
	"Labels": true, "Images": true, "ImageTags": true, "Replicas": true, "Resources": true, "Components": true,
	"Bases": true, "ConfigMapGenerator": true, "SecretGenerator": true, "GeneratorOptions": true,
	"SortOptions": true, "BuildMetadata": true,
}

// renames reports whether k sets a field that can rename an object: one
// outside identitySafe and also, labels with their own field specs, which can target
// metadata/name.
func renames(k *types.Kustomization, also map[string]bool) bool {
	v := reflect.ValueOf(k).Elem()
	for i := 0; i < v.NumField(); i++ {
		if n := v.Type().Field(i).Name; !v.Field(i).IsZero() && !identitySafe[n] && !also[n] {
			return true
		}
	}
	return slices.ContainsFunc(k.Labels, func(l types.Label) bool { return len(l.FieldSpecs) > 0 })
}

func (r *Renderer) mapResource(res *Result, rs *resource.Resource, rootKust string, mode renameMode) (model.ResolvedHelm, bool) {
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
	if mode == renameAffix && attr.Kind == "Namespace" {
		mode = renameAny
	}
	switch {
	case origin != nil && origin.ConfiguredIn != "":
		doc.FileName = r.canonical(filepath.Join(res.Root, filepath.FromSlash(origin.ConfiguredIn)))
		name := r.matchGenerator(attr, rootKust, doc.FileName, origin.ConfiguredBy.Kind, mode)
		if name == "" {
			res.MappingFailures++
		}
		attr.Generator = &model.KustomizeGenerator{Kind: origin.ConfiguredBy.Kind, Name: name}
		attr.SourceName = name
		attr.SourceNamespace = origin.ConfiguredBy.Namespace
	case origin != nil && origin.Path != "" && origin.Repo == "":
		doc.FileName = r.canonical(filepath.Join(res.Root, filepath.FromSlash(origin.Path)))
		idx, src := r.matchDocument(attr, rootKust, doc.FileName, mode)
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
	r.chain(attr, rootKust, doc.FileName)
	doc.OriginalData, _ = r.Source(doc.FileName)
	return doc, true
}

// matchGenerator returns the generator entry of genKind in file attr renders.
func (r *Renderer) matchGenerator(attr *model.KustomizeAttribution, rootKust, file, genKind string, mode renameMode) string {
	prefix, suffix, ok := r.affixes(r.chain(attr, rootKust, file), mode, r.rootPaths(attr.RenderRoot, rootKust, file))
	if !ok {
		return ""
	}
	return r.generatorName(file, genKind, attr.RenderedName, prefix, suffix)
}

// matchDocument returns the document of file attr renders: by exact identity
// when renaming is absent, by affixes alone when only they rename.
func (r *Renderer) matchDocument(attr *model.KustomizeAttribution, rootKust, file string, mode renameMode) (int, sourceDoc) {
	prefix, suffix, ok := r.affixes(r.chain(attr, rootKust, file), mode, r.rootPaths(attr.RenderRoot, rootKust, file))
	switch {
	case mode == renameNone:
		return exactDocument(r.sourceDocuments(file), attr.Kind, attr.RenderedName, attr.RenderedNamespace)
	case ok:
		return affixDocument(r.sourceDocuments(file), attr.Kind, attr.RenderedName, prefix, suffix)
	}
	return -1, sourceDoc{}
}

// chain records in attr and returns the kustomizations from rootKust to file,
// nil when none loads it.
func (r *Renderer) chain(attr *model.KustomizeAttribution, rootKust, file string) []string {
	c := r.chainTo(rootKust, file, map[string]bool{})
	if c != nil {
		attr.Chain = c
	}
	return c
}

// affixes returns the name prefix and suffix the kustomizations of chain add,
// outermost first, and whether they alone explain a rendered name under mode.
// With affixes, file must be reached by a single chain: two overlays sharing a
// base apply different transformations, and one chain explains neither.
func (r *Renderer) affixes(chain []string, mode renameMode, paths int) (prefix, suffix string, ok bool) {
	switch {
	case mode == renameNone:
		return "", "", true
	case mode == renameAny || chain == nil || paths != 1:
		return "", "", false
	}
	for _, p := range chain {
		k, found := r.Kustomization(p)
		if !found {
			return "", "", false
		}
		prefix, suffix = prefix+k.NamePrefix, k.NameSuffix+suffix
	}
	return prefix, suffix, true
}

// entries returns what k loads: resources, components and legacy bases.
func entries(k *types.Kustomization) []string {
	return slices.Concat(k.Resources, k.Components, k.Bases) //nolint:staticcheck // legacy kustomizations still declare bases
}

// rootPaths is paths from the root kustomization, 2 when it is linked from
// another directory than the render root Kustomize resolves its entries from.
// Remote entries never match a local file, missing ones load nothing, and a
// repeated entry counts twice.
func (r *Renderer) rootPaths(root, rootKust, file string) int {
	if filepath.Dir(rootKust) != root {
		return 2
	}
	return r.paths(rootKust, file, map[string]bool{})
}

// paths counts, up to 2, the chains from kust to file through the resources
// and components each kustomization loads, by symlink-resolved path like the
// cache; onPath breaks cycles, and an undecoded served kustomization counts 2.
func (r *Renderer) paths(kust, file string, onPath map[string]bool) int {
	if kust == file {
		return 1
	}
	k, ok := r.Kustomization(kust)
	if !ok {
		// Probed names that do not exist are no path; a served file whose
		// kustomization is unknown is unproven.
		if _, served := r.Source(kust); served {
			return 2
		}
		return 0
	}
	if onPath[kust] {
		return 0
	}
	onPath[kust] = true
	defer delete(onPath, kust)
	n := 0
	dir := filepath.Dir(kust)
	for _, e := range entries(k) {
		p := r.canonical(filepath.Join(dir, filepath.FromSlash(e)))
		if p == file {
			n++
		}
		for _, name := range KustomizationFileNames {
			child := r.canonical(filepath.Join(p, name))
			if _, ok := r.Kustomization(child); ok && filepath.Dir(child) != p {
				// Linked from another directory: Kustomize resolves its
				// entries from p, the chain walk from the target's.
				return 2
			}
			n += r.paths(child, file, onPath)
		}
		if n >= 2 {
			return 2
		}
	}
	return n
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
	for _, e := range entries(k) {
		p := r.canonical(filepath.Join(dir, filepath.FromSlash(e)))
		if p == file {
			return []string{kust}
		}
		for _, n := range KustomizationFileNames {
			if sub := r.chainTo(r.canonical(filepath.Join(p, n)), file, seen); sub != nil {
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

// affixDocument returns the only document of kind in docs, across every
// namespace, when prefix and suffix around its name give the rendered name;
// several documents of kind, or an unexplained name, are a mapping failure.
func affixDocument(docs []sourceDoc, kind, name, prefix, suffix string) (int, sourceDoc) {
	found := -1
	for i, d := range docs {
		if d.kind != kind {
			continue
		}
		if found >= 0 {
			return -1, sourceDoc{}
		}
		found = i
	}
	if found < 0 || prefix+docs[found].name+suffix != name {
		return -1, sourceDoc{}
	}
	return found, docs[found]
}

// exactDocument returns the document of kind named name, the one in namespace
// when several are; any other tie is a mapping failure.
func exactDocument(docs []sourceDoc, kind, name, namespace string) (int, sourceDoc) {
	exact, ambiguous := -1, false
	for i, d := range docs {
		if d.kind == kind && d.name == name {
			exact, ambiguous = pickExact(docs, exact, i, ambiguous, namespace)
		}
	}
	if exact < 0 || ambiguous {
		return -1, sourceDoc{}
	}
	return exact, docs[exact]
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

// generatedAs reports whether name is the output of generator entry name n:
// n itself with the hash disabled, else n and one hash segment.
func generatedAs(name, n string, hashOff bool) bool {
	if hashOff {
		return name == n
	}
	hash, ok := strings.CutPrefix(name, n+"-")
	return ok && hash != "" && !strings.Contains(hash, "-")
}

// generatorName returns the name of the only generator entry of genKind
// (ConfigMapGenerator or SecretGenerator) in the kustomization at path whose
// name between prefix and suffix, with its hash unless disabled, is the
// rendered name; none or several return "".
func (r *Renderer) generatorName(path, genKind, rendered, prefix, suffix string) string {
	k, ok := r.Kustomization(path)
	if !ok {
		return ""
	}
	hashOff := k.GeneratorOptions != nil && k.GeneratorOptions.DisableNameSuffixHash
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
		off := hashOff || args[i].Options != nil && args[i].Options.DisableNameSuffixHash
		switch {
		case n == "" || !generatedAs(rendered, prefix+n+suffix, off):
		case best != "":
			return ""
		default:
			best = n
		}
	}
	return best
}
