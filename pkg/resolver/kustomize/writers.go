package kustomize

import (
	"path/filepath"

	"sigs.k8s.io/kustomize/api/types"
)

// kustNode is a kustomization of a render, with its distance from the root
// and the affixes it applies.
type kustNode struct {
	file      string
	k         *types.Kustomization
	depth     int
	component bool
	// affixes are the name prefix and suffix applied to the resources this
	// kustomization loads, root first; parentAffixes exclude its own.
	affixes, parentAffixes Affixes
}

// renderGraph indexes the kustomizations a render read, with the affixes the
// plan verified. It returns nil when the render read no root kustomization.
func (r *Renderer) renderGraph(res *Result, rootKust string, closure map[string]Affixes) *kustGraph {
	byDir := r.collectKustNodes(res)
	rootDir := filepath.Dir(rootKust)
	if byDir[rootDir] == nil {
		return nil
	}
	assignDepthsAndAffixes(byDir, rootDir, closure)
	return r.buildGraph(byDir)
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

func closureAffix(closure map[string]Affixes, dir string) Affixes {
	if closure == nil {
		return Affixes{}
	}
	return closure[dir]
}

// kustGraph is the load graph of one render: the nodes the root reaches and,
// per source, the nodes that load it. It keeps no per-node descendant sets,
// which a converging tree would retain quadratically: a loader query is one
// reverse walk over the graph's edges, computed once per source.
type kustGraph struct {
	nodes []*kustNode
	// parents maps each kustomization directory to the nodes loading it, and
	// atDir holds the node rooted at each directory (it loads its own files).
	parents map[string][]*kustNode
	atDir   map[string]*kustNode
	loaders map[string]map[*kustNode]bool
	// probes counts node examinations and edge walks: tests bound it to
	// prove a loader query stays linear in nodes plus edges.
	probes int
}

// renderGraph indexes the kustomizations a render read into the load graph.
func (r *Renderer) buildGraph(byDir map[string]*kustNode) *kustGraph {
	g := &kustGraph{parents: map[string][]*kustNode{}, atDir: map[string]*kustNode{},
		loaders: map[string]map[*kustNode]bool{}}
	for _, n := range byDir {
		if n.depth < 0 {
			continue
		}
		g.nodes = append(g.nodes, n)
		g.atDir[filepath.Dir(n.file)] = n
		for _, c := range children(filepath.Dir(n.file), n.k) {
			g.parents[c] = append(g.parents[c], n)
		}
	}
	return g
}

// loadersOf returns the nodes that load source: those that reach its
// directory, found by one reverse walk from it, plus those that list the
// file itself. Cached per source.
func (g *kustGraph) loadersOf(source string) map[*kustNode]bool {
	if l, ok := g.loaders[source]; ok {
		return l
	}
	l := map[*kustNode]bool{}
	root := filepath.Dir(source)
	// The node rooted at the source's directory loads the source itself, and
	// so does any node listing the file directly; both seed the reverse walk,
	// so a file-only child propagates to its outer loaders.
	if n := g.atDir[root]; n != nil {
		g.probes++
		l[n] = true
	}
	queue, seen := []string{root, source}, map[string]bool{root: true, source: true}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		for _, p := range g.parents[d] {
			g.probes++
			if l[p] {
				continue
			}
			l[p] = true
			if pd := filepath.Dir(p.file); !seen[pd] {
				seen[pd] = true
				queue = append(queue, pd)
			}
		}
	}
	g.loaders[source] = l
	return l
}

// children lists the kustomization directories dir references, resolved as
// the render's reads are so an aliased base matches its target directory.
func children(dir string, k *types.Kustomization) []string {
	if k == nil {
		return nil
	}
	out := make([]string, 0, len(k.Resources)+len(k.Components))
	for _, e := range append(append([]string{}, k.Resources...), k.Components...) {
		out = append(out, canonicalPath(filepath.Join(dir, filepath.FromSlash(e))))
	}
	return out
}

// canonicalPath resolves p's symlinks, as the render's reads are keyed.
func canonicalPath(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return filepath.Clean(p)
}
