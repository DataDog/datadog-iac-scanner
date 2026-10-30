package kustomize

import (
	"path/filepath"
	"slices"

	"sigs.k8s.io/kustomize/api/types"
)

// kustNode is a kustomization of a render, with its distance from the root
// and the affixes it applies.
type kustNode struct {
	file      string
	k         *types.Kustomization
	depth     int
	component bool
	reach     map[string]bool // directories reachable from this one, itself included
	// affixes are the name prefix and suffix applied to the resources this
	// kustomization loads, root first; parentAffixes exclude its own.
	affixes, parentAffixes Affixes
}

// renderGraph indexes the kustomizations a render read, with the affixes the
// plan verified.
func (r *Renderer) renderGraph(res *Result, rootKust string, closure map[string]Affixes) []*kustNode {
	byDir := r.collectKustNodes(res)
	rootDir := filepath.Dir(rootKust)
	if byDir[rootDir] == nil {
		return nil
	}
	assignDepthsAndAffixes(byDir, rootDir, closure)
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

func closureAffix(closure map[string]Affixes, dir string) Affixes {
	if closure == nil {
		return Affixes{}
	}
	return closure[dir]
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

// loads reports whether n reaches the kustomization that listed source.
func (n *kustNode) loads(source string) bool {
	return n.reach[filepath.Dir(source)] || slices.ContainsFunc(n.k.Resources, func(e string) bool {
		return filepath.Join(filepath.Dir(n.file), filepath.FromSlash(e)) == source
	})
}
