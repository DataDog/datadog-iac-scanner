package kustomize

import (
	"path/filepath"
	"sort"

	"sigs.k8s.io/kustomize/api/types"
)

// Affixes are the name prefix and suffix the kustomizations from a render
// root down to one directory add, outermost first. MultiChain marks a
// directory reached through several chains, where path-dependent affixes
// have no single value.
type Affixes struct {
	Prefix     string
	Suffix     string
	MultiChain bool
}

// PlannedRoot is a kustomization directory to render on its own.
type PlannedRoot struct {
	Dir string
	// Skip is the reason the root is not rendered, empty when it is.
	Skip string
	// Closure maps each kustomization directory the root reaches to the
	// affixes applied to resources loaded there.
	Closure map[string]Affixes
	// steps counts the nodes visited and the edges examined while planning
	// the root's closure.
	steps int
}

// Plan picks the top-level roots among dirs (kustomization directories):
// those no other one references, that are not components and that are not
// Helm charts. read returns a file's bytes. Output is sorted by directory.
func Plan(dirs, chartRoots []string, read func(string) ([]byte, error)) []PlannedRoot {
	known := make(map[string]bool, len(dirs))
	for _, d := range dirs {
		known[filepath.Clean(d)] = true
	}
	charts := make(map[string]bool, len(chartRoots))
	for _, c := range chartRoots {
		charts[filepath.Clean(c)] = true
	}
	kusts := make(map[string]*types.Kustomization, len(known))
	for d := range known {
		kusts[d] = loadKustomization(d, read)
	}
	referenced := map[string]bool{}
	for d, k := range kusts {
		for _, child := range children(d, k) {
			if known[child] && child != d {
				referenced[child] = true
			}
		}
	}
	var out []PlannedRoot
	for d, k := range kusts {
		if referenced[d] || charts[d] || (k != nil && k.Kind == types.ComponentKind) {
			continue
		}
		root := PlannedRoot{Dir: d, Closure: map[string]Affixes{}}
		if !planClosure(d, kusts, known, root.Closure, &root.steps) {
			root.Skip = ReasonPlanSkip
		}
		out = append(out, root)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out
}

func loadKustomization(dir string, read func(string) ([]byte, error)) *types.Kustomization {
	for _, n := range KustomizationFileNames {
		content, err := read(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		k, err := decodeKustomization(content)
		if err != nil {
			return nil
		}
		return k
	}
	return nil
}

func children(dir string, k *types.Kustomization) []string {
	if k == nil {
		return nil
	}
	out := make([]string, 0, len(k.Resources)+len(k.Components))
	for _, e := range append(append([]string{}, k.Resources...), k.Components...) {
		out = append(out, filepath.Join(dir, filepath.FromSlash(e)))
	}
	return out
}

// planClosure records the directories dir reaches with their affixes,
// visiting each directory once so a converging graph costs nodes plus edges,
// not once per path. It reports false on a refused kustomization or a cycle.
// A directory reached through several chains, or below one, is marked
// MultiChain with empty affixes: the affixes are path-dependent and unknown,
// so attribution must fail closed instead of using one arbitrary chain.
func planClosure(dir string, kusts map[string]*types.Kustomization, known map[string]bool,
	closure map[string]Affixes, steps *int) bool {
	// states: 1 visiting (on the current path), 2 done.
	state := make(map[string]int, len(kusts))
	postorder := make([]string, 0, len(kusts))
	edges := make(map[string][]string, len(kusts))
	var walk func(d string, outer Affixes) bool
	walk = func(d string, outer Affixes) bool {
		switch state[d] {
		case 1:
			return false
		case 2:
			return true
		}
		*steps++
		k := kusts[d]
		if k == nil {
			return false
		}
		state[d] = 1
		closure[d] = Affixes{Prefix: outer.Prefix + k.NamePrefix, Suffix: k.NameSuffix + outer.Suffix}
		kids := children(d, k)
		*steps += len(kids)
		for _, child := range kids {
			if known[child] {
				edges[d] = append(edges[d], child)
				if !walk(child, closure[d]) {
					return false
				}
			}
		}
		state[d] = 2
		postorder = append(postorder, d)
		return true
	}
	if !walk(dir, Affixes{}) {
		return false
	}
	// Count the paths from the root to every directory over the recorded
	// edges, in reverse post-order (root first), capped at 2: two or more
	// paths mean the directory is multi-chain, and so is everything below it.
	paths := make(map[string]int, len(postorder))
	paths[dir] = 1
	for i := len(postorder) - 1; i >= 0; i-- {
		d := postorder[i]
		for _, child := range edges[d] {
			if paths[d] > 0 {
				if paths[d]+paths[child] > 2 {
					paths[child] = 2
				} else {
					paths[child] += paths[d]
				}
			}
		}
	}
	for d, n := range paths {
		if n >= 2 {
			a := closure[d]
			a.Prefix, a.Suffix, a.MultiChain = "", "", true
			closure[d] = a
		}
	}
	return true
}
