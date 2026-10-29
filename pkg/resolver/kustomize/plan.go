package kustomize

import (
	"path/filepath"
	"sort"

	"sigs.k8s.io/kustomize/api/types"
)

// Affixes are the name prefix and suffix the kustomizations from a render
// root down to one directory add, outermost first.
type Affixes struct{ Prefix, Suffix string }

// PlannedRoot is a kustomization directory to render on its own.
type PlannedRoot struct {
	Dir string
	// Skip is the reason the root is not rendered, empty when it is.
	Skip string
	// Closure maps each kustomization directory the root reaches to the
	// affixes applied to resources loaded there.
	Closure map[string]Affixes
	// Files are the paths the kustomizations of Closure list that are not
	// kustomization directories themselves: manifests, patches and generator
	// sources, wherever they live.
	Files []string
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
		if !walkClosure(d, Affixes{}, kusts, known, root.Closure, map[string]bool{}) {
			root.Skip = ReasonPlanSkip
		}
		root.Files = closureFiles(root.Closure, kusts, known)
		out = append(out, root)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out
}

// closureFiles lists the files the kustomizations of closure reference.
func closureFiles(closure map[string]Affixes, kusts map[string]*types.Kustomization, known map[string]bool) []string {
	var out []string
	for d := range closure {
		k := kusts[d]
		if k == nil {
			continue
		}
		for _, p := range kustomizationPaths(k) {
			if f := filepath.Join(d, filepath.FromSlash(p)); p != "" && !known[f] {
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

// canonicalPath resolves p's symlinks, as the planned directories and the
// render's reads are, so an aliased base or component is the same directory.
func canonicalPath(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return filepath.Clean(p)
}

// walkClosure records the directories dir reaches with their affixes. It
// reports false on a refused kustomization or a cycle.
func walkClosure(dir string, outer Affixes, kusts map[string]*types.Kustomization, known map[string]bool,
	closure map[string]Affixes, onPath map[string]bool) bool {
	k := kusts[dir]
	if k == nil || onPath[dir] {
		return false
	}
	affixes := Affixes{Prefix: outer.Prefix + k.NamePrefix, Suffix: k.NameSuffix + outer.Suffix}
	closure[dir] = affixes
	onPath[dir] = true
	defer delete(onPath, dir)
	for _, child := range children(dir, k) {
		if known[child] && !walkClosure(child, affixes, kusts, known, closure, onPath) {
			return false
		}
	}
	return true
}
