/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfeval

// callChain is an immutable path. Descending into a module adds one node rather
// than copying all its ancestors. Cache entries and instances share these nodes.
type callChain struct {
	parent *callChain
	site   CallSite
	depth  int
}

func (c *callChain) append(site *CallSite) *callChain {
	depth := 1
	if c != nil {
		depth += c.depth
	}
	return &callChain{parent: c, site: *site, depth: depth}
}

// chainRebaser shares each rewritten suffix between resources and instances in
// one cache restoration. The seeded base maps the old caller to the new caller.
type chainRebaser map[*callChain]*callChain

func (r chainRebaser) rebase(c *callChain) *callChain {
	var pending []*callChain
	for {
		if base, ok := r[c]; ok {
			for i := len(pending) - 1; i >= 0; i-- {
				base = base.append(&pending[i].site)
				r[pending[i]] = base
			}
			return base
		}
		pending = append(pending, c)
		c = c.parent
	}
}

// chainView owns the unused tail of a slice. A child may extend it once; a
// sibling forks instead of overwriting an already published descendant.
type chainView struct {
	sites []CallSite
	used  *int
}

type chainMaterializer map[*callChain]chainView

// materialize preserves the public slice API. Prefix views share geometrically
// grown storage, so exporting every prefix of a linear path also costs O(D).
// No chain retains mutable export state, allowing independent exports to run
// concurrently without touching cached evaluation metadata.
func (m chainMaterializer) materialize(c *callChain) []CallSite {
	var pending []*callChain
	for c != nil {
		if _, ok := m[c]; ok {
			break
		}
		pending = append(pending, c)
		c = c.parent
	}
	view := m[c]
	for i := len(pending) - 1; i >= 0; i-- {
		if view.used == nil || *view.used != len(view.sites) {
			sites := make([]CallSite, len(view.sites), 2*len(view.sites)+1)
			copy(sites, view.sites)
			used := len(sites)
			view = chainView{sites: sites, used: &used}
		}
		view.sites = append(view.sites, pending[i].site)
		*view.used = len(view.sites)
		m[pending[i]] = view
	}
	return view.sites[:len(view.sites):len(view.sites)]
}

// materializeResources takes ownership of a freshly flattened result slice.
// Cached resource nodes are never passed here or changed during export.
func materializeResources(out []ResolvedResource) []ResolvedResource {
	chains := chainMaterializer{}
	for i := range out {
		out[i].CallChain = chains.materialize(out[i].chain)
		out[i].chain = nil
	}
	return out
}
