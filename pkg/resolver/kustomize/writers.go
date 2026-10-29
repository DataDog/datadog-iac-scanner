package kustomize

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/kustomize/api/types"
)

// kustNode is a kustomization of a render, with its distance from the root,
// the affixes it applies, and its place in Kustomize's application order.
type kustNode struct {
	file      string
	k         *types.Kustomization
	depth     int
	component bool
	reach     map[string]bool // directories reachable from this one, itself included
	// affixes are the name prefix and suffix applied to the resources this
	// kustomization loads, root first; parentAffixes exclude its own.
	affixes, parentAffixes Affixes
	// applyOrder ranks the transformer steps Kustomize runs: deeper
	// kustomizations apply first, and the root applies last.
	applyOrder int
	// beforeLabels and beforeAnnotations are the label and annotation
	// transforms of the steps that ran before this node's own patches: the
	// state its patch targets are evaluated against.
	beforeLabels, beforeAnnotations map[string]string
	// components are the kustomizations this one loads as components,
	// deepest first: their transformer steps run just before this node's own.
	components []*kustNode
}

// renderGraph indexes the kustomizations a render read, with the affixes the
// plan verified and Kustomize's application order.
func (r *Renderer) renderGraph(res *Result, rootKust string, closure map[string]Affixes) []*kustNode {
	byDir := r.collectKustNodes(res)
	rootDir := filepath.Dir(rootKust)
	if byDir[rootDir] == nil {
		return nil
	}
	assignDepthsAndAffixes(byDir, rootDir, closure)
	orderNodeSteps(byDir, rootDir)
	collectAppliedTransforms(byDir)
	return reachedNodes(byDir)
}

// collectKustNodes parses every kustomization the render read into a node.
func (r *Renderer) collectKustNodes(res *Result) map[string]*kustNode {
	byDir := map[string]*kustNode{}
	for _, p := range res.Reads {
		if !IsKustomizationFile(filepath.Base(p)) {
			continue
		}
		if k, ok := r.Kustomization(p); ok {
			byDir[filepath.Dir(p)] = &kustNode{file: p, k: k, depth: -1, component: k.Kind == types.ComponentKind}
		}
	}
	return byDir
}

// assignDepthsAndAffixes walks the graph breadth-first from the root, leaving
// the directories the root does not reach at depth -1. Affixes come from the
// plan's verified closure when it covers a directory, else they accumulate
// along the walk.
func assignDepthsAndAffixes(byDir map[string]*kustNode, rootDir string, closure map[string]Affixes) {
	type queued struct {
		dir   string
		depth int
		affix Affixes
	}
	byDir[rootDir].depth = 0
	rootAffix := closureAffix(closure, rootDir)
	if rootAffix == (Affixes{}) && closure == nil {
		rootAffix = Affixes{Prefix: byDir[rootDir].k.NamePrefix, Suffix: byDir[rootDir].k.NameSuffix}
	}
	byDir[rootDir].affixes = rootAffix
	queue := []queued{{dir: rootDir, affix: rootAffix}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range children(cur.dir, byDir[cur.dir].k) {
			n := byDir[c]
			if n == nil || n.depth >= 0 {
				continue
			}
			n.depth = cur.depth + 1
			n.parentAffixes = cur.affix
			n.affixes = closureAffix(closure, c)
			if n.affixes == (Affixes{}) {
				n.affixes = Affixes{
					Prefix: cur.affix.Prefix + n.k.NamePrefix,
					Suffix: n.k.NameSuffix + cur.affix.Suffix,
				}
			}
			queue = append(queue, queued{dir: c, depth: n.depth, affix: n.affixes})
		}
	}
}

// collectAppliedTransforms records, per node, the label and annotation
// transforms of every step that runs before the node's own patches: the
// resource subtrees its resources come from and its components, never the
// node's own or any later, outer level.
func collectAppliedTransforms(byDir map[string]*kustNode) {
	var walk func(d string, into map[string]bool)
	walk = func(d string, into map[string]bool) {
		if into[d] || byDir[d] == nil {
			return
		}
		into[d] = true
		for _, c := range children(d, byDir[d].k) {
			walk(c, into)
		}
		for _, e := range byDir[d].k.Components {
			walk(filepath.Join(d, filepath.FromSlash(e)), into)
		}
	}
	for _, n := range byDir {
		if n.depth < 0 {
			continue
		}
		n.beforeLabels, n.beforeAnnotations = map[string]string{}, map[string]string{}
		applied := map[string]bool{}
		root := filepath.Dir(n.file)
		for _, c := range children(root, n.k) {
			walk(c, applied)
		}
		for _, e := range n.k.Components {
			walk(filepath.Join(root, filepath.FromSlash(e)), applied)
		}
		for d := range applied {
			for key, v := range kustomizationLabels(byDir[d].k) {
				n.beforeLabels[key] = v
			}
			for key, v := range kustomizationAnnotations(byDir[d].k) {
				n.beforeAnnotations[key] = v
			}
		}
	}
}

func closureAffix(closure map[string]Affixes, dir string) Affixes {
	if closure == nil {
		return Affixes{}
	}
	return closure[dir]
}

// orderNodeSteps numbers the transformer steps in Kustomize's application
// order: a post-order walk from the root, children in listing order, the node
// itself last — so bases and components apply before their loader.
func orderNodeSteps(byDir map[string]*kustNode, rootDir string) {
	order := 0
	var visit func(d string)
	seen := map[string]bool{}
	visit = func(d string) {
		if seen[d] || byDir[d] == nil {
			return
		}
		seen[d] = true
		k := byDir[d].k
		for _, c := range children(d, k) {
			visit(c)
		}
		byDir[d].applyOrder = order
		order++
		// Components hoisted into this kustomization, deepest listing first:
		// their steps run just before this node's own transformers.
		for _, comp := range componentNodes(byDir, d) {
			comp.applyOrder = order
			order++
		}
		byDir[d].components = componentNodes(byDir, d)
	}
	visit(rootDir)
}

// componentNodes returns the components dir loads, directly or through other
// components, in application order: each component's sub-components run
// before it, siblings in listing order. Sub-component paths resolve relative
// to the component that lists them, not to the root.
func componentNodes(byDir map[string]*kustNode, dir string) []*kustNode {
	var out []*kustNode
	seen := map[string]bool{}
	var add func(d string)
	add = func(d string) {
		for _, e := range byDir[d].k.Components {
			c := byDir[filepath.Join(d, filepath.FromSlash(e))]
			if c == nil || seen[c.file] {
				continue
			}
			seen[c.file] = true
			add(filepath.Dir(c.file))
			out = append(out, c)
		}
	}
	add(dir)
	return out
}

// reachedNodes keeps the nodes the root reaches.
func reachedNodes(byDir map[string]*kustNode) []*kustNode {
	var reach func(d string, seen map[string]bool)
	reach = func(d string, seen map[string]bool) {
		if seen[d] || byDir[d] == nil {
			return
		}
		seen[d] = true
		for _, c := range children(d, byDir[d].k) {
			reach(c, seen)
		}
	}
	nodes := make([]*kustNode, 0, len(byDir))
	for _, n := range byDir {
		if n.depth < 0 {
			continue
		}
		n.reach = map[string]bool{}
		reach(filepath.Dir(n.file), n.reach)
		nodes = append(nodes, n)
	}
	return nodes
}

// writers lists the patches and transformer entries that apply to a resource
// from source, the last one Kustomize applies first. The order mirrors
// Kustomize: transformer steps run deepest kustomization first (bases, then
// components, then the loader), and within one kustomization the builtin
// order is patchesStrategicMerge, patches, namespace, prefix/suffix, labels,
// annotations, patchesJson6902, replicas, images, replacements — reversed
// here so the last writer to touch a field is found first.
func (r *Renderer) writers(nodes []*kustNode, source string, a *model.KustomizeAttribution) []model.KustomizeWriter {
	ordered := slices.Clone(nodes)
	slices.SortStableFunc(ordered, func(x, y *kustNode) int { return y.applyOrder - x.applyOrder })
	var out []model.KustomizeWriter
	for _, n := range ordered {
		if !n.loads(source) {
			continue
		}
		// The node's own step runs last: its writers come first, then its
		// components', last applied (last listed) first.
		out = append(out, r.ownWriters(n, a)...)
		for i := len(n.components) - 1; i >= 0; i-- {
			out = append(out, r.ownWriters(n.components[i], a)...)
		}
	}
	return out
}

// ownWriters lists one kustomization's own patches and transformer entries
// that apply to the resource, last applied first.
func (r *Renderer) ownWriters(n *kustNode, a *model.KustomizeAttribution) []model.KustomizeWriter {
	// Patch targets are evaluated against the labels and annotations visible
	// when the patch applied: the source document's own plus the transforms
	// of the steps before this node's patches, never later or outer levels.
	visible := *a
	visible.Labels = mergeKV(a.SourceLabels, n.beforeLabels)
	visible.Annotations = mergeKV(a.SourceAnnotations, n.beforeAnnotations)
	a = &visible
	kustText, _ := r.Source(n.file)
	node := r.KustNode(n.file, kustText)
	var out []model.KustomizeWriter
	// JSON 6902 patches apply after the node's own label and annotation
	// transformers: their selectors see those entries too.
	afterKV := *a
	afterKV.Labels = mergeKV(visible.Labels, kustomizationLabels(n.k))
	afterKV.Annotations = mergeKV(visible.Annotations, kustomizationAnnotations(n.k))
	for i := len(n.k.PatchesJson6902) - 1; i >= 0; i-- { //nolint:staticcheck // legacy kustomizations still declare patchesJson6902
		p := n.k.PatchesJson6902[i] //nolint:staticcheck // see above
		if w, ok := r.patchWriter(n, node, "patchesJson6902", i, p.Path, p.Patch, p.Target, &afterKV); ok {
			out = append(out, w)
		}
	}
	// Unified patches apply in listing order; reversed, the last one is
	// found first. The node index travels with the entry: offsets are
	// positional in the file, not in the reversed list.
	patches := make([]struct {
		p  types.Patch
		at int
	}, len(n.k.Patches))
	for i, p := range n.k.Patches {
		patches[len(patches)-1-i] = struct {
			p  types.Patch
			at int
		}{p, i}
	}
	for _, e := range patches {
		if w, ok := r.patchWriter(n, node, "patches", e.at, e.p.Path, e.p.Patch, e.p.Target, a); ok {
			out = append(out, w)
		}
	}
	// Legacy SMP entries apply in listing order; reversed, the last one is
	// found first, with the node index kept for the inline offsets.
	out = append(out, r.legacySMPWriters(n, node, a)...)
	return out
}

// legacySMPWriters lists the legacy patchesStrategicMerge entries that apply
// to the resource, last applied first, with the node index kept for the
// inline offsets.
func (r *Renderer) legacySMPWriters(n *kustNode, node *yaml.Node, a *model.KustomizeAttribution) []model.KustomizeWriter {
	entries := make([]struct {
		p  types.PatchStrategicMerge
		at int
	}, len(n.k.PatchesStrategicMerge)) //nolint:staticcheck // legacy kustomizations still declare patchesStrategicMerge
	for i, p := range n.k.PatchesStrategicMerge { //nolint:staticcheck // see above
		entries[len(entries)-1-i] = struct {
			p  types.PatchStrategicMerge
			at int
		}{p, i}
	}
	var out []model.KustomizeWriter
	for _, e := range entries {
		// An entry that decodes as resources is an inline patch, else a file
		// path, as PatchStrategicMergeTransformer decides.
		entry := string(e.p)
		path, patch := entry, ""
		if IsInlinePatch(entry) {
			path, patch = "", entry
		}
		if w, ok := r.patchWriter(n, node, "patchesStrategicMerge", e.at, path, patch, nil, a); ok {
			out = append(out, w)
		}
	}
	return out
}

// patchWriter builds the writer of a patch referenced by path or inline under
// one of the kustomization's patch fields, when its target matches.
func (r *Renderer) patchWriter(n *kustNode, node *yaml.Node, field string, index int,
	path, patch string, target *types.Selector, a *model.KustomizeAttribution) (model.KustomizeWriter, bool) {
	w := model.KustomizeWriter{File: n.file}
	if path != "" {
		w.File = filepath.Join(filepath.Dir(n.file), filepath.FromSlash(path))
		b, _ := r.Source(w.File)
		w.Content = string(b)
		w.LineOffset = 0
	} else {
		w.Content = patch
		w.LineOffset = inlineOffset(node, field, index)
	}
	if w.Content == "" {
		return model.KustomizeWriter{}, false
	}
	isJSON := isJSON6902(w.Content)
	if isJSON {
		w.Kind = model.KustomizeJSON6902
	} else {
		w.Kind = model.KustomizeStrategicMerge
	}
	if !targets(target, isJSON, w.Content, a, n) {
		return model.KustomizeWriter{}, false
	}
	return w, true
}

// loads reports whether n reaches the kustomization that listed source.
func (n *kustNode) loads(source string) bool {
	return n.reach[filepath.Dir(source)] || slices.ContainsFunc(n.k.Resources, func(e string) bool {
		return filepath.Join(filepath.Dir(n.file), filepath.FromSlash(e)) == source
	})
}

func nameMatches(name string, a *model.KustomizeAttribution) bool {
	return name == a.SourceName || name == a.RenderedName
}

// expectedName is a source name after the affixes of a kustomization level.
func expectedName(affixes Affixes, name string) string {
	return affixes.Prefix + name + affixes.Suffix
}

// targets reports whether a patch target selects the resource. It follows
// Kustomize's Selector semantics: kind, group and version are matched against
// the resource's kind and apiVersion, name and namespace against the names
// visible at the patch's level, and label and annotation selectors against
// the resource's labels and annotations.
func targets(t *types.Selector, isJSON bool, content string, a *model.KustomizeAttribution, n *kustNode) bool {
	if t != nil {
		if t.Group != "" && !regexMatch(t.Group, apiVersionGroup(a.APIVersion)) {
			return false
		}
		if t.Version != "" && !regexMatch(t.Version, apiVersionVersion(a.APIVersion)) {
			return false
		}
		if t.Kind != "" && !regexMatch(t.Kind, a.Kind) {
			return false
		}
		if t.Name != "" && !visibleNameMatches(t.Name, n, a) {
			return false
		}
		if t.Namespace != "" && !regexMatch(t.Namespace, a.RenderedNamespace) &&
			!regexMatch(t.Namespace, a.SourceNamespace) {
			return false
		}
		return selectorsMatch(t, a)
	}
	if isJSON {
		// A legacy JSON 6902 patch without a target is invalid for Kustomize.
		return false
	}
	return docTargets(content, a, n)
}

// selectorsMatch evaluates a patch target's label and annotation selectors
// against the state carried by the attribution.
func selectorsMatch(t *types.Selector, a *model.KustomizeAttribution) bool {
	return selectorMatches(t.LabelSelector, a.Labels) && selectorMatches(t.AnnotationSelector, a.Annotations)
}

// kustomizationLabels collects the label keys the kustomization's label
// transformers set, common labels included.
func kustomizationLabels(k *types.Kustomization) map[string]string {
	out := map[string]string{}
	for key, v := range k.CommonLabels { //nolint:staticcheck // legacy kustomizations still declare commonLabels
		out[key] = v
	}
	for _, l := range k.Labels {
		for key, v := range l.Pairs {
			out[key] = v
		}
	}
	return out
}

// kustomizationAnnotations collects the annotation keys the kustomization's
// annotation transformers set.
func kustomizationAnnotations(k *types.Kustomization) map[string]string {
	out := map[string]string{}
	for key, v := range k.CommonAnnotations { //nolint:staticcheck // legacy kustomizations still declare commonAnnotations
		out[key] = v
	}
	return out
}

// mergeKV returns a copy of base with the entries of overrides winning.
func mergeKV(base, overrides map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(overrides))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overrides {
		out[k] = v
	}
	return out
}

// docTargets reports whether any document of an SMP patch content targets the
// resource: same kind and a name visible at n's level.
func docTargets(content string, a *model.KustomizeAttribution, n *kustNode) bool {
	for _, d := range decodeDocs(content) {
		if d.kind != a.Kind {
			continue
		}
		if nameMatches(d.name, a) {
			return true
		}
		if a.SourceName != "" && d.name == expectedName(n.parentAffixes, a.SourceName) {
			return true
		}
		if a.SourceName != "" && d.name == expectedName(n.affixes, a.SourceName) {
			return true
		}
	}
	return false
}

// visibleNameMatches matches a target name regex against every name the
// resource can carry at n's level: as written, with the affixes of each
// kustomization that loads the source file, and as rendered.
func visibleNameMatches(pattern string, n *kustNode, a *model.KustomizeAttribution) bool {
	if regexMatch(pattern, a.RenderedName) || (a.SourceName != "" && regexMatch(pattern, a.SourceName)) {
		return true
	}
	if a.SourceName == "" {
		return false
	}
	for _, affixes := range []Affixes{n.parentAffixes, n.affixes} {
		if expectedName(affixes, a.SourceName) != "" && regexMatch(pattern, expectedName(affixes, a.SourceName)) {
			return true
		}
	}
	return false
}

// selectorMatches reports whether the Kubernetes label selector selects the
// resource's labels: equality, set-based, existence and inequality
// requirements per labels.Parse, never regex. An unparsable selector matches
// nothing, as Kustomize refuses the patch.
func selectorMatches(selector string, have map[string]string) bool {
	if strings.TrimSpace(selector) == "" {
		return true
	}
	req, err := labels.Parse(selector)
	if err != nil {
		return false
	}
	return req.Matches(labels.Set(have))
}

func apiVersionGroup(apiVersion string) string {
	if i := strings.IndexByte(apiVersion, '/'); i >= 0 {
		return apiVersion[:i]
	}
	return "core"
}

func apiVersionVersion(apiVersion string) string {
	if i := strings.IndexByte(apiVersion, '/'); i >= 0 {
		return apiVersion[i+1:]
	}
	return apiVersion
}

func regexMatch(pattern, s string) bool {
	re, err := regexp.Compile("^(?:" + pattern + ")$")
	return err == nil && re.MatchString(s)
}

// isJSON6902 reports whether content is a JSON 6902 patch: a list of ops
// with non-empty op fields.
func isJSON6902(content string) bool {
	var ops []struct {
		Op   string `yaml:"op"`
		Path string `yaml:"path"`
	}
	if err := yaml.Unmarshal([]byte(content), &ops); err != nil || len(ops) == 0 {
		return false
	}
	for _, o := range ops {
		if o.Op == "" {
			return false
		}
	}
	return true
}

func decodeDocs(content string) []sourceDoc {
	var docs []sourceDoc
	dec := yaml.NewDecoder(strings.NewReader(content))
	for {
		var d struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
		}
		err := dec.Decode(&d)
		if err != nil {
			return docs
		}
		docs = append(docs, sourceDoc{kind: d.Kind, name: d.Metadata.Name})
	}
}

// parseKustNode parses a kustomization file into a YAML node, or nil.
func parseKustNode(content []byte) *yaml.Node {
	if len(content) == 0 {
		return nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	return doc.Content[0]
}

// mappingValue returns the value node of key in a mapping node.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// inlineOffset is the 0-based line of kust before the index-th entry of
// field's inline patch, taken from the parsed kustomization node: two inline
// patches sharing a first line no longer collide.
func inlineOffset(root *yaml.Node, field string, index int) int {
	seq := mappingValue(root, field)
	if seq == nil || seq.Kind != yaml.SequenceNode || index >= len(seq.Content) {
		return 0
	}
	item := seq.Content[index]
	if item.Kind == yaml.ScalarNode {
		// A legacy inline SMP: the scalar itself is the patch.
		return item.Line - 1
	}
	if patch := mappingValue(item, "patch"); patch != nil {
		if patch.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
			// A block scalar's content starts on the line after its marker.
			return patch.Line
		}
		return patch.Line - 1
	}
	return item.Line - 1
}
