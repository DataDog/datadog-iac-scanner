package kustomize

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	yamlparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/kustomize/api/resmap"
	"sigs.k8s.io/kustomize/api/resource"
	"sigs.k8s.io/kustomize/api/types"
)

const originAnnotation = "config.kubernetes.io/origin"

type sourceDoc struct {
	kind, name, namespace string
	labels, annotations   map[string]string
}

// mapResources attributes every rendered resource to the file it came from:
// the source manifest, or the kustomization file of a generated object.
// Patches are not attributed: Kustomize keeps the origin of the patched
// resource, and its transformer annotations name the kustomization of every
// patch transformer that visited the object, whether it changed it or not,
// never the patch file or the fields changed. A field an overlay patch adds or
// changes is therefore attributed to the source document, where it may be
// absent.
// It fails with a timeout past a deadline or once the scan is canceled, and
// with a render error when a resource cannot be serialized: the whole root
// then falls back to the raw scan rather than losing that resource.
func (r *Renderer) mapResources(ctx context.Context, res *Result, m resmap.ResMap, rootKust string,
	closure map[string]Affixes, rootDeadline time.Time) error {
	expired := func() bool {
		return ctx.Err() != nil || time.Now().After(rootDeadline) || time.Now().After(r.deadline)
	}
	if expired() {
		return &RenderError{Reason: ReasonTimeout}
	}
	mode := r.renameMode(res.Reads)
	g := r.loadGraph(res.Root, rootKust)
	// Counted once mapping is done, every walk the graph took included.
	defer func() { res.graphSteps += g.steps }()
	asWritten := r.namesMaySetByReplacement(res.Reads)
	namesWritten := r.replacementsWriteNames(res.Reads)
	nodes := r.renderGraph(res, rootKust, closure)
	for _, rs := range m.Resources() {
		if expired() {
			return &RenderError{Reason: ReasonTimeout}
		}
		doc, ok := r.mapResource(res, rs, g, mode, nodes, namesWritten)
		if !ok {
			return &RenderError{Reason: ReasonRenderError}
		}
		r.setIdentity(doc.Kustomize, rs.GetGvk().Group, asWritten, doc.FileName)
		res.Documents = append(res.Documents, doc)
	}
	rejectCollisions(res)
	if expired() {
		return &RenderError{Reason: ReasonTimeout}
	}
	return nil
}

type mappingKey struct {
	file, generator, namespace string
	index                      int
}

// rejectCollisions turns into mapping failures the documents attributed to a
// source document or generator entry another document of the same rendered
// namespace is attributed to.
// This also rejects one source included twice into a namespace through two
// chains, since the key does not record the chain a document came through.
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
	// replacements, transformers, ...); a rendered name is attributable only
	// by an exact identity in the rendered namespace.
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

// affixSkipped are the kinds the prefix and suffix transformers leave unnamed:
// an affix match would misread their names.
var affixSkipped = map[string]bool{"CustomResourceDefinition": true, "APIService": true}

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
		case r.beyondAffixes(k, p):
			return renameAny
		case setsAffixes(k):
			mode = renameAffix
		}
	}
	return mode
}

// beyondAffixes reports whether k can rename beyond the affix fields: a field
// outside identitySafe that no proof clears. A strategic-merge patch selects
// its target by the name it keeps, so it cannot rename; a JSON 6902 patch is
// read to see whether its ops write a name or namespace, and so is a
// replacement's target list. Any other field, including transformers and
// configurations, is not inspected and may rename.
func (r *Renderer) beyondAffixes(k *types.Kustomization, kust string) bool {
	v := reflect.ValueOf(k).Elem()
	for i := 0; i < v.NumField(); i++ {
		n := v.Type().Field(i).Name
		if v.Field(i).IsZero() || identitySafe[n] || (affixFields[n] && k.Kind != types.ComponentKind) {
			continue
		}
		switch n {
		//nolint:staticcheck // legacy kustomizations still declare patchesStrategicMerge and patchesJson6902
		case "Patches", "PatchesStrategicMerge", "PatchesJson6902":
			if r.patchEntriesMayRename(k, kust) {
				return true
			}
		case "Replacements":
			// A replacement's targets are read: one that writes a name or
			// namespace makes matching fall back to the kind instead.
		default:
			return true
		}
	}
	return slices.ContainsFunc(k.Labels, func(l types.Label) bool { return len(l.FieldSpecs) > 0 })
}

// patchEntriesMayRename reports whether any patch entry of k can rename its
// target.
func (r *Renderer) patchEntriesMayRename(k *types.Kustomization, kust string) bool {
	for _, p := range k.Patches {
		if patchOptionsAllowRename(p.Options) || r.patchMayRename(kust, p.Path, p.Patch) {
			return true
		}
	}
	for _, p := range k.PatchesStrategicMerge { //nolint:staticcheck // legacy kustomizations still declare patchesStrategicMerge
		if entry := string(p); !IsInlinePatch(entry) && r.patchMayRename(kust, entry, "") {
			return true
		}
	}
	for _, p := range k.PatchesJson6902 { //nolint:staticcheck // legacy kustomizations still declare patchesJson6902
		if r.patchMayRename(kust, p.Path, p.Patch) {
			return true
		}
	}
	return false
}

// patchOptionsAllowRename reports whether a patch entry opts into changing
// its target's name or kind.
func patchOptionsAllowRename(o *types.PatchArgs) bool {
	return o != nil && (o.AllowNameChange || o.AllowKindChange)
}

// patchMayRename reports whether a patch entry can rename its target. The
// content is an inline patch, or read from path relative to the kustomization
// at kust; an unreadable patch may rename. A JSON 6902 patch renames when an
// op writes or moves a metadata name or namespace; a strategic-merge patch
// never renames, it selects by the name it keeps.
func (r *Renderer) patchMayRename(kust, path, inline string) bool {
	content := inline
	if path != "" {
		b, ok := r.Source(r.canonical(filepath.Join(filepath.Dir(kust), filepath.FromSlash(path))))
		if !ok {
			return true
		}
		content = string(b)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		// An undecodable patch may rename.
		return true
	}
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	if root.Kind != yaml.SequenceNode {
		// A strategic-merge patch: it selects by the name it keeps.
		return false
	}
	var ops []struct {
		Op   string `yaml:"op"`
		Path string `yaml:"path"`
		From string `yaml:"from"`
	}
	if err := root.Decode(&ops); err != nil || len(ops) == 0 {
		// An undecodable or empty op list may rename.
		return true
	}
	for _, op := range ops {
		if jsonPointerMayRename(op.Path) {
			return true
		}
		if (op.Op == "move" || op.Op == "copy") &&
			(jsonPointerMayRename(op.From) || strings.HasPrefix(op.From, "/metadata")) {
			return true
		}
	}
	return false
}

// jsonPointerMayRename reports whether a JSON 6902 pointer may rename its
// target: the whole document ("" or "/"), the whole metadata object, or the
// metadata name or namespace.
func jsonPointerMayRename(p string) bool {
	return p == "" || p == "/" || p == "/metadata" || p == "/metadata/name" || p == "/metadata/namespace"
}

// replacementWritesName reports whether a replacement may write a name: a
// source by path is not inspected, a target without fieldPaths writes the
// name Kustomize defaults to, and a fieldPath under metadata may be the name.
func replacementWritesName(reps []types.ReplacementField) bool {
	for i := range reps {
		if reps[i].Path != "" {
			return true
		}
		for _, t := range reps[i].Targets {
			if len(t.FieldPaths) == 0 {
				return true
			}
			for _, fp := range t.FieldPaths {
				if strings.HasPrefix(fp, "metadata") && (fp == "metadata" || strings.Contains(fp, "name")) {
					return true
				}
			}
		}
	}
	return false
}

// setsAffixes reports whether k adds name affixes or a namespace. Components
// apply their parent's affixes, so they never set their own.
func setsAffixes(k *types.Kustomization) bool {
	return k.Kind != types.ComponentKind &&
		(k.NamePrefix != "" || k.NameSuffix != "" || k.Namespace != "")
}

// generatorEntries proves generated names unambiguous across the graph: every
// entry creates (merge and replace keep the base origin under another
// kustomization's options), and no entry name repeats, in any namespace or
// level. Entries may hash differently: each is matched by its own hashing.
type generatorEntries struct {
	names map[string]bool
}

func (g *generatorEntries) add(k *types.Kustomization) bool {
	if g.names == nil {
		g.names = map[string]bool{}
	}
	var args []types.GeneratorArgs
	for i := range k.ConfigMapGenerator {
		args = append(args, k.ConfigMapGenerator[i].GeneratorArgs)
	}
	for i := range k.SecretGenerator {
		args = append(args, k.SecretGenerator[i].GeneratorArgs)
	}
	for i := range args {
		a := &args[i]
		if (a.Behavior != "" && a.Behavior != "create") || g.names[a.Name] {
			return false
		}
		g.names[a.Name] = true
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

// hashSuffix matches the "-" and 10 characters Kustomize appends to a
// generated name: a hex digest prefix with 0, 1, 3, a and e respelled.
var hashSuffix = regexp.MustCompile(`-[2456789bcdfghkmt]{10}$`)

// setIdentity fills the fields a finding on the object is identified by. A
// generated name loses its content hash, so editing generated data keeps the
// identity, unless the generator disabled that hash and its name ends like
// one; an unknown generator entry leaves no name. When a replacement may
// have set names, the names as written are used: the rendered ones may carry
// values copied from generated data.
func (r *Renderer) setIdentity(a *model.KustomizeAttribution, group string, asWritten bool, genKust string) {
	a.APIGroup = group
	switch {
	case asWritten:
		a.IdentityName, a.IdentityNamespace = a.SourceName, a.SourceNamespace
	case a.Generator != nil && a.Generator.Name == "":
		a.IdentityName, a.IdentityNamespace = "", a.RenderedNamespace
	case a.Generator != nil && !r.nameHashDisabled(genKust, a.Generator.Kind, a.Generator.Name):
		a.IdentityName, a.IdentityNamespace = hashSuffix.ReplaceAllString(a.RenderedName, ""), a.RenderedNamespace
	default:
		a.IdentityName, a.IdentityNamespace = a.RenderedName, a.RenderedNamespace
	}
}

// nameHashDisabled reports whether the generator that rendered the object in
// the kustomization at path had its content-hash suffix disabled, by its own
// options or the kustomization's generatorOptions: its name is then as
// written, even when it ends like a hash. The generator's own options apply
// only to the entry attributed by name, never to a sibling whose rendered
// name merely contains it.
func (r *Renderer) nameHashDisabled(path, genKind, attributed string) bool {
	k, ok := r.Kustomization(path)
	if !ok {
		return false
	}
	if k.GeneratorOptions != nil && k.GeneratorOptions.DisableNameSuffixHash {
		return true
	}
	args := generatorArgs(k, genKind)
	for i := range args {
		if args[i].Options != nil && args[i].Options.DisableNameSuffixHash && args[i].Name == attributed {
			return true
		}
	}
	return false
}

// namesMaySetByReplacement reports whether a kustomization the render read
// has a replacement that may write a name or namespace, or a transformer
// entry, whose configuration is not inspected.
func (r *Renderer) namesMaySetByReplacement(reads []string) bool {
	for _, p := range reads {
		k, ok := r.Kustomization(p)
		if !ok {
			continue
		}
		if len(k.Transformers) > 0 || replacementWritesName(k.Replacements) {
			return true
		}
	}
	return false
}

// replacementsWriteNames reports whether a kustomization the render read has
// a replacement that may write a name or namespace: the rendered names it
// touches prove nothing, and matching falls back to the kind.
func (r *Renderer) replacementsWriteNames(reads []string) bool {
	for _, p := range reads {
		if k, ok := r.Kustomization(p); ok && replacementWritesName(k.Replacements) {
			return true
		}
	}
	return false
}

func (r *Renderer) mapResource(res *Result, rs *resource.Resource, g *loadGraph, mode renameMode, nodes []*kustNode,
	namesWritten bool) (model.ResolvedHelm, bool) {
	rootKust := g.rootKust
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
		APIVersion:        rs.GetApiVersion(),
		RenderedName:      rs.GetName(),
		RenderedNamespace: rs.GetNamespace(),
		Chain:             []string{rootKust},
		Labels:            rs.GetLabels(),
		Annotations:       rs.GetAnnotations(),
	}
	doc := model.ResolvedHelm{Content: content, SourceDocumentIndex: -1, Kustomize: attr}
	if mode == renameAffix && attr.Kind == "Namespace" {
		mode = renameAny
	}
	for _, n := range nodes {
		if n.loads(doc.FileName) && len(n.k.Replacements) > 0 {
			res.Unsupported++
		}
	}

	r.attributeSource(res, origin, attr, &doc, g, mode, namesWritten)
	if doc.SourceDocumentIndex < 0 && attr.Generator == nil && doc.FileName != rootKust {
		res.MappingFailures++
	}
	g.record(attr, doc.FileName)
	if attr.Generator == nil && doc.SourceDocumentIndex >= 0 {
		r.attachChain(nodes, doc.FileName, attr)
		res.Unsupported += r.unsupportedReplacements(nodes, doc.FileName)
	}
	doc.OriginalData, _ = r.Source(doc.FileName)
	return doc, true
}

// unsupportedReplacements counts the replacement entries of the
// kustomizations that load the source file: their written fields are counted,
// not attributed.
func (r *Renderer) unsupportedReplacements(nodes []*kustNode, source string) int {
	n := 0
	for _, node := range nodes {
		if node.loads(source) && len(node.k.Replacements) > 0 {
			n++
		}
	}
	return n
}

// attributeSource maps a rendered resource to the file a developer edits: the
// generating kustomization entry, its source document, or the root
// kustomization when the origin is unusable.
func (r *Renderer) attributeSource(res *Result, origin *resource.Origin, attr *model.KustomizeAttribution,
	doc *model.ResolvedHelm, g *loadGraph, mode renameMode, namesWritten bool) {
	rootKust := g.rootKust
	switch {
	case origin != nil && origin.ConfiguredIn != "":
		doc.FileName = r.canonical(filepath.Join(res.Root, filepath.FromSlash(origin.ConfiguredIn)))
		// Built-in generators record only their kind in the origin: the
		// namespace comes from the matched entry.
		entry := r.matchGenerator(attr, g, doc.FileName, origin.ConfiguredBy.Kind, mode)
		if entry == nil {
			res.MappingFailures++
			entry = &types.GeneratorArgs{}
		}
		attr.Generator = &model.KustomizeGenerator{Kind: origin.ConfiguredBy.Kind, Name: entry.Name}
		attr.SourceName, attr.SourceNamespace = entry.Name, entry.Namespace
	case origin != nil && origin.Path != "" && origin.Repo == "":
		doc.FileName = r.canonical(filepath.Join(res.Root, filepath.FromSlash(origin.Path)))
		idx, src := r.matchDocument(attr, g, doc.FileName, mode, namesWritten)
		doc.SourceDocumentIndex = idx
		if idx >= 0 {
			attr.SourceName, attr.SourceNamespace = src.name, src.namespace
			// Patch-target selectors are evaluated against the labels and
			// annotations visible when the patch applied; the source
			// document's own are the best state we keep.
			attr.SourceLabels, attr.SourceAnnotations = src.labels, src.annotations
		}
	default:
		res.MappingFailures++
		doc.FileName = rootKust
	}
}

// matchGenerator returns the generator entry of genKind in file attr renders.
func (r *Renderer) matchGenerator(attr *model.KustomizeAttribution, g *loadGraph, file, genKind string,
	mode renameMode) *types.GeneratorArgs {
	prefix, suffix, ok := r.affixes(g.record(attr, file), mode, g.count(file))
	if !ok {
		return nil
	}
	return r.generatorName(file, genKind, attr.RenderedName, prefix, suffix)
}

// matchDocument returns the document of file attr renders: by exact identity
// when renaming is absent, by affixes alone when only they rename. A
// replacement may have written the name the rendered object carries, so a
// failed match falls back to the only document of that kind in the file.
func (r *Renderer) matchDocument(attr *model.KustomizeAttribution, g *loadGraph, file string, mode renameMode,
	namesWritten bool) (int, sourceDoc) {
	if namesWritten {
		// A replacement may have written the rendered name: an exact or
		// affix match could hit a sibling whose name the replacement copied,
		// so the kind alone identifies the document.
		return sameKindDocument(r.sourceDocuments(file), attr.Kind)
	}
	prefix, suffix, ok := r.affixes(g.record(attr, file), mode, g.count(file))
	switch {
	case mode == renameNone:
		return exactDocument(r.sourceDocuments(file), attr.Kind, attr.RenderedName, attr.RenderedNamespace)
	case ok && (prefix+suffix == "" || !affixSkipped[attr.Kind]):
		return affixDocument(r.sourceDocuments(file), attr.Kind, attr.RenderedName, prefix, suffix)
	}
	return -1, sourceDoc{}
}

// sameKindDocument returns the only document of kind in docs; none or several
// are a mapping failure, since a written name proves nothing and the kind is
// the only proof left.
func sameKindDocument(docs []sourceDoc, kind string) (int, sourceDoc) {
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
	if found < 0 {
		return -1, sourceDoc{}
	}
	return found, docs[found]
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

// loadGraph is what the kustomizations of one render load, walked once from
// its root kustomization: every file's first chain and its paths count.
type loadGraph struct {
	rootKust string
	// chains are the kustomizations from the root down to the one listing a
	// file as a resource, or to the file itself when it is a kustomization
	// (a generator's), first found through the resources and components
	// each loads in order.
	chains map[string][]string
	// paths counts, up to 2, the chains from the root to a file, by
	// symlink-resolved path like the cache; a repeated entry counts twice.
	paths map[string]int
	// rootLinked makes every count 2: the root kustomization is linked from
	// another directory than the render root Kustomize resolves its entries
	// from.
	rootLinked bool
	// unproven are the kustomizations whose loads are unproven: one they load
	// is linked from another directory than the one Kustomize resolves its
	// entries from, is served but undecoded, or cycles back. A file reached
	// from the root past one of them counts 2.
	unproven map[string]bool
	// kusts are the kustomizations the walk visited, children those each
	// loads, and past answers pastUnproven for a kustomization.
	kusts, past map[string]bool
	children    map[string][]string
	// steps counts the entries, kustomization probes and walks taken.
	steps int
}

// loadGraph walks the kustomizations rootKust loads once, depth first in
// entry order, then counts paths in topological order. Remote entries never
// match a local file, and missing ones load nothing.
func (r *Renderer) loadGraph(root, rootKust string) *loadGraph {
	g := &loadGraph{rootKust: rootKust, chains: map[string][]string{rootKust: {rootKust}}, paths: map[string]int{},
		rootLinked: filepath.Dir(rootKust) != root, unproven: map[string]bool{}, children: map[string][]string{},
		kusts: map[string]bool{}, past: map[string]bool{}}
	children, listed := g.children, map[string][]string{}
	const visiting, visited = 1, 2
	state := map[string]int{}
	var order []string
	var walk func(kust string)
	walk = func(kust string) {
		state[kust] = visiting
		g.kusts[kust] = true
		defer func() { state[kust] = visited; order = append(order, kust) }()
		k, ok := r.Kustomization(kust)
		if !ok {
			if _, served := r.Source(kust); served {
				g.unproven[kust] = true
			}
			return
		}
		dir := filepath.Dir(kust)
		for _, e := range entries(k) {
			g.steps++
			p := r.canonical(filepath.Join(dir, filepath.FromSlash(e)))
			listed[kust] = append(listed[kust], p)
			if _, ok := g.chains[p]; !ok {
				g.chains[p] = slices.Clone(g.chains[kust])
			}
			for _, name := range KustomizationFileNames {
				g.steps++
				child := r.canonical(filepath.Join(p, name))
				if _, ok := r.Kustomization(child); !ok {
					// Probed names that do not exist are no path; a served
					// file whose kustomization is unknown is unproven.
					if _, served := r.Source(child); served {
						g.unproven[kust] = true
					}
					continue
				}
				// Linked from another directory: Kustomize resolves its
				// entries from p, the chain walk from the target's.
				if filepath.Dir(child) != p {
					g.unproven[kust] = true
				}
				children[kust] = append(children[kust], child)
				if _, ok := g.chains[child]; !ok {
					g.chains[child] = append(slices.Clone(g.chains[kust]), child)
				}
				switch state[child] {
				case visiting:
					g.unproven[kust] = true
				case 0:
					walk(child)
				}
			}
		}
	}
	walk(rootKust)
	g.countPaths(order, children, listed)
	g.markPast(order)
	return g
}

// countPaths counts, in the topological order the reverse of order gives,
// the paths from the root to every kustomization and to every entry each
// lists.
func (g *loadGraph) countPaths(order []string, children, listed map[string][]string) {
	kusts := map[string]int{g.rootKust: 1}
	for i := len(order) - 1; i >= 0; i-- {
		kust := order[i]
		for _, c := range children[kust] {
			kusts[c] = min(kusts[c]+kusts[kust], 2)
		}
		for _, p := range listed[kust] {
			g.paths[p] = min(g.paths[p]+kusts[kust], 2)
		}
	}
	for kust, n := range kusts {
		g.paths[kust] = min(g.paths[kust]+n, 2)
	}
}

// record records in attr and returns the chain to file, nil when none loads
// it.
func (g *loadGraph) record(attr *model.KustomizeAttribution, file string) []string {
	c := g.chains[file]
	if c != nil {
		attr.Chain = c
	}
	return c
}

// count is the paths count to file: 2 when the walk from the root to it,
// stopping at file, passes an unproven kustomization.
func (g *loadGraph) count(file string) int {
	if g.rootLinked || g.pastUnproven(file) {
		return 2
	}
	return g.paths[file]
}

// pastUnproven reports whether the root reaches an unproven kustomization
// other than file without passing file. Only a kustomization stops the walk,
// so for any other file any unproven kustomization counts.
func (g *loadGraph) pastUnproven(file string) bool {
	if len(g.unproven) == 0 {
		return false
	}
	if !g.kusts[file] {
		return true
	}
	return g.past[file]
}

// markPast answers pastUnproven for every kustomization at once. The root
// reaches an unproven kustomization u avoiding f exactly when f does not
// dominate u, so f is past none only when it dominates the lowest common
// dominator of the unproven kustomizations other than itself.
func (g *loadGraph) markPast(order []string) {
	if len(g.unproven) == 0 {
		return
	}
	d := g.dominators(order)
	var unproven []string
	for _, k := range order {
		if g.unproven[k] {
			unproven = append(unproven, k)
		}
	}
	// Lowest common dominators of the unproven kustomizations before and after
	// each, to leave one out.
	n := len(unproven)
	before, after := make([]string, n+1), make([]string, n+1)
	for i, u := range unproven {
		before[i+1] = d.common(before[i], u)
	}
	for i := n - 1; i >= 0; i-- {
		after[i] = d.common(after[i+1], unproven[i])
	}
	for k := range g.kusts {
		g.steps++
		g.past[k] = !d.dominates(k, before[n])
	}
	for i, u := range unproven {
		rest := d.common(before[i], after[i+1])
		g.past[u] = rest != "" && !d.dominates(u, rest)
	}
}

// domTree is the dominator tree of a load graph, with intervals answering
// "a dominates b" in constant time.
type domTree struct {
	g       *loadGraph
	post    map[string]int
	idom    map[string]string
	in, out map[string]int
}

// dominators computes the dominator tree in one pass in topological order
// over the acyclic graph: a cycle is unproven, and Kustomize rejects it.
// ponytail: common walks the tree, so a pathological graph costs edges times
// depth; Lengauer-Tarjan is the upgrade if that ever shows.
func (g *loadGraph) dominators(order []string) *domTree {
	d := &domTree{g: g, post: make(map[string]int, len(order)), idom: map[string]string{g.rootKust: g.rootKust},
		in: map[string]int{}, out: map[string]int{}}
	for i, k := range order {
		d.post[k] = i
	}
	for i := len(order) - 1; i >= 0; i-- {
		k := order[i]
		for _, c := range g.children[k] {
			g.steps++
			// The root and back edges dominate nothing new.
			if c != g.rootKust && d.post[c] < d.post[k] {
				d.idom[c] = d.common(d.idom[c], k)
			}
		}
	}
	tree := map[string][]string{}
	for _, k := range order {
		if k != g.rootKust {
			tree[d.idom[k]] = append(tree[d.idom[k]], k)
		}
	}
	clock := 0
	stack := []string{g.rootKust}
	for len(stack) > 0 {
		k := stack[len(stack)-1]
		if _, seen := d.in[k]; !seen {
			d.in[k], clock = clock, clock+1
			stack = append(stack, tree[k]...)
			continue
		}
		stack = stack[:len(stack)-1]
		d.out[k], clock = clock, clock+1
		g.steps++
	}
	return d
}

// common returns the lowest common dominator of a and b, either one alone
// when the other is "".
func (d *domTree) common(a, b string) string {
	if a == "" || b == "" {
		return a + b
	}
	for a != b {
		for d.post[a] < d.post[b] {
			a = d.idom[a]
			d.g.steps++
		}
		for d.post[b] < d.post[a] {
			b = d.idom[b]
			d.g.steps++
		}
	}
	return a
}

func (d *domTree) dominates(a, b string) bool {
	return d.in[a] <= d.in[b] && d.out[b] <= d.out[a]
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
// namespace, whose name between prefix and suffix gives the rendered name;
// none or several are a mapping failure.
func affixDocument(docs []sourceDoc, kind, name, prefix, suffix string) (int, sourceDoc) {
	found := -1
	for i, d := range docs {
		if d.kind != kind || prefix+d.name+suffix != name {
			continue
		}
		if found >= 0 {
			return -1, sourceDoc{}
		}
		found = i
	}
	if found < 0 {
		return -1, sourceDoc{}
	}
	return found, docs[found]
}

// attachChain records the kustomizations from the root down to the source file
// and the patch and transformer entries applying to it, with the scanner
// directives of the files findings are reported on.
func (r *Renderer) attachChain(nodes []*kustNode, fileName string, attr *model.KustomizeAttribution) {
	attr.Chain = attr.Chain[:0]
	var loading []*kustNode
	for _, n := range nodes {
		if n.loads(fileName) {
			loading = append(loading, n)
		}
	}
	// Root first: shallower kustomizations precede the deeper ones on the
	// dependency path.
	sort.Slice(loading, func(i, j int) bool {
		if loading[i].depth != loading[j].depth {
			return loading[i].depth < loading[j].depth
		}
		return loading[i].file < loading[j].file
	})
	for _, n := range loading {
		attr.Chain = append(attr.Chain, n.file)
	}
	attr.Writers = r.writers(nodes, fileName, attr)
	if len(attr.Writers) > 0 {
		attr.Commands = map[string]model.CommentsCommands{}
	}
	seen := map[string]bool{}
	for _, w := range attr.Writers {
		if seen[w.File] {
			continue
		}
		seen[w.File] = true
		if b, ok := r.Source(w.File); ok {
			attr.Commands[w.File] = writerCommands(b)
		}
	}
}

// writerCommands parses the head-of-file scanner directives (`# dd-iac-scan: …`)
// of a patch or kustomization file a finding is reported on; suppression must
// follow the attributed file, not the source manifest.
func writerCommands(content []byte) model.CommentsCommands {
	out := model.CommentsCommands{}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "---") {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			break
		}
		fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#")))
		if len(fields) > 1 && fields[0] == "dd-iac-scan" {
			key, value, _ := strings.Cut(fields[1], "=")
			out[key] = value
		}
	}
	return out
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
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			docs = append(docs, sourceDoc{})
			break
		}
		// Index documents as the YAML parser does, which skips empty ones.
		if yamlparser.IsEmptyDocument(&node) {
			continue
		}
		var d struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name        string            `yaml:"name"`
				Namespace   string            `yaml:"namespace"`
				Labels      map[string]string `yaml:"labels"`
				Annotations map[string]string `yaml:"annotations"`
			} `yaml:"metadata"`
		}
		_ = node.Decode(&d)
		docs = append(docs, sourceDoc{kind: d.Kind, name: d.Metadata.Name, namespace: d.Metadata.Namespace,
			labels: d.Metadata.Labels, annotations: d.Metadata.Annotations})
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

// generatorArgs returns the ConfigMap and Secret generators of genKind
// declared in k.
func generatorArgs(k *types.Kustomization, genKind string) []types.GeneratorArgs {
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
	return args
}

// generatorName returns the only generator entry of genKind
// (ConfigMapGenerator or SecretGenerator) in the kustomization at path whose
// name between prefix and suffix, with its hash unless disabled, is the
// rendered name; none or several return nil.
func (r *Renderer) generatorName(path, genKind, rendered, prefix, suffix string) *types.GeneratorArgs {
	k, ok := r.Kustomization(path)
	if !ok {
		return nil
	}
	args := generatorArgs(k, genKind)
	hashOff := k.GeneratorOptions != nil && k.GeneratorOptions.DisableNameSuffixHash
	var best *types.GeneratorArgs
	for i := range args {
		n := args[i].Name
		off := hashOff || args[i].Options != nil && args[i].Options.DisableNameSuffixHash
		switch {
		case n == "" || !generatedAs(rendered, prefix+n+suffix, off):
		case best != nil:
			return nil
		default:
			best = &args[i]
		}
	}
	return best
}
