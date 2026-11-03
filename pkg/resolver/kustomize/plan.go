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
	// Files are the paths the kustomizations of Closure list that are not
	// kustomization directories themselves: manifests, patches and generator
	// sources, wherever they live.
	Files []string
}

// Plan picks the top-level roots among dirs (kustomization directories):
// those no other one references, that are not components and that are not
// Helm charts. deployed lists directories an in-repo Argo CD or Flux object
// deploys as-is; they are rendered as roots even when referenced. read
// returns a file's bytes and canonical maps a path to its symlink-free form
// inside the repository, refusing anything outside, so a dependency reached
// through a symlink matches the directory discovered by its real path.
// Output is sorted by directory; each root's Dir keeps the lexicographically
// smallest input path that maps to its node.
func Plan(dirs, chartRoots, deployed []string, read func(string) ([]byte, error),
	canonical func(string) (string, bool)) []PlannedRoot {
	known := make(map[string]bool, len(dirs))
	display := make(map[string]string, len(dirs))
	for _, d := range dirs {
		node, ok := canonical(d)
		if !ok {
			continue
		}
		known[node] = true
		if cur, seen := display[node]; !seen || d < cur {
			display[node] = d
		}
	}
	charts := make(map[string]bool, len(chartRoots))
	for _, c := range chartRoots {
		if node, ok := canonical(c); ok {
			charts[node] = true
		}
	}
	kusts := make(map[string]*types.Kustomization, len(known))
	for d := range known {
		kusts[d] = loadKustomization(d, read)
	}
	return selectRoots(known, display, charts, kusts, canonical, deployed)
}

// selectRoots keeps the kustomization directories nothing references, that
// are not components and that are not Helm charts, and plans each one.
func selectRoots(known map[string]bool, display map[string]string, charts map[string]bool,
	kusts map[string]*types.Kustomization, canonical func(string) (string, bool), deployed []string) []PlannedRoot {
	referenced := map[string]bool{}
	for d, k := range kusts {
		for _, child := range canonicalChildren(d, k, canonical) {
			if known[child] && child != d {
				referenced[child] = true
			}
		}
	}
	forced := make(map[string]bool, len(deployed))
	for _, d := range deployed {
		if node, ok := canonical(d); ok {
			forced[node] = true
		}
	}
	return planRoots(kusts, known, referenced, charts, forced, display, canonical)
}

// planRoots renders a root for every kustomization not referenced, not a
// chart and not a component — plus the forced (deployed) ones — and walks
// each closure.
func planRoots(kusts map[string]*types.Kustomization, known, referenced, charts, forced map[string]bool,
	display map[string]string, canonical func(string) (string, bool)) []PlannedRoot {
	var out []PlannedRoot
	for node, k := range kusts {
		if (referenced[node] || charts[node] || (k != nil && k.Kind == types.ComponentKind)) && !forced[node] {
			continue
		}
		root := PlannedRoot{Dir: display[node], Closure: map[string]Affixes{}}
		if !planClosure(node, kusts, known, canonical, root.Closure, &root.steps) {
			root.Skip = ReasonPlanSkip
		}
		root.Files = closureFiles(root.Closure, kusts, canonical)
		out = append(out, root)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out
}

// closureFiles lists the files the kustomizations of closure reference,
// canonicalized inside the repository: an entry that escapes it is dropped.
func closureFiles(closure map[string]Affixes, kusts map[string]*types.Kustomization,
	canonical func(string) (string, bool)) []string {
	var out []string
	for d := range closure {
		k := kusts[d]
		if k == nil {
			continue
		}
		for _, p := range kustomizationPaths(k) {
			if p == "" {
				continue
			}
			if f, ok := canonical(filepath.Join(d, filepath.FromSlash(p))); ok {
				out = append(out, f)
			}
		}
	}
	sort.Strings(out)
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

// canonicalChildren lists the entries a kustomization references, as paths
// canonicalized inside the repository: entries that escape it are dropped.
func canonicalChildren(dir string, k *types.Kustomization, canonical func(string) (string, bool)) []string {
	if k == nil {
		return nil
	}
	out := make([]string, 0, len(k.Resources)+len(k.Components))
	for _, e := range append(append([]string{}, k.Resources...), k.Components...) {
		if node, ok := canonical(filepath.Join(dir, filepath.FromSlash(e))); ok {
			out = append(out, node)
		}
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
	canonical func(string) (string, bool), closure map[string]Affixes, steps *int) bool {
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
		kids := canonicalChildren(d, k, canonical)
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
