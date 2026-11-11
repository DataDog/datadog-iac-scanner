/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"path"
	"slices"
	"strconv"

	"github.com/open-policy-agent/opa/v1/ast"
)

// parts are the pieces an input is assembled from, kept to merge projections.
type parts struct {
	typed                       map[string]map[string][]*ast.Term
	lists                       map[string][]*ast.Term
	byID                        [][2]*ast.Term
	docs                        []*ast.Term
	nested                      [][2]*ast.Term
	related, targets, referrers *ast.Term
}

// Merge assembles the projections of several roots into one input. Ids are
// unique across roots and relations never cross roots, so the merged input
// holds what each root's own input holds. Only rules that read blocks one at
// a time can tell the merged input from the separate ones.
func Merge(projs []*Projection) *Projection {
	if len(projs) == 1 {
		return projs[0]
	}
	typed := map[string]map[string][]*ast.Term{}
	for _, k := range typedKinds {
		typed[k] = map[string][]*ast.Term{}
	}
	lists := map[string][]*ast.Term{}
	var byID [][2]*ast.Term
	var docs []*ast.Term
	var nested [][2]*ast.Term
	related, targets, referrers := ast.NewObject(), ast.NewObject(), ast.NewObject()
	out := &Projection{Blocks: map[string]*Located{}, Unknown: map[TypeKey]bool{}, External: map[string]bool{}, BlocksComplete: true}
	var placeholder *ast.Term
	for _, pr := range projs {
		pt := pr.parts
		for kind, byType := range pt.typed {
			for typ, list := range byType {
				typed[kind][typ] = append(typed[kind][typ], list...)
			}
		}
		for kind, list := range pt.lists {
			lists[kind] = append(lists[kind], list...)
		}
		byID = append(byID, pt.byID...)
		docs = append(docs, pt.docs...)
		nested = append(nested, pt.nested...)
		for _, m := range []struct{ into, from *ast.Term }{
			{ast.NewTerm(related), pt.related}, {ast.NewTerm(targets), pt.targets}, {ast.NewTerm(referrers), pt.referrers},
		} {
			m.from.Value.(ast.Object).Foreach(func(k, v *ast.Term) { m.into.Value.(ast.Object).Insert(k, v) })
		}
		out.absorb(pr)
		out.BlocksComplete = out.BlocksComplete && pr.BlocksComplete
		if placeholder == nil {
			placeholder = placeholderOf(pr)
		}
	}
	blocks := make([][2]*ast.Term, 0, len(typedKinds)+len(listKinds))
	for _, kind := range typedKinds {
		byType := make([][2]*ast.Term, 0, len(typed[kind]))
		for typ, list := range typed[kind] {
			byType = append(byType, ast.Item(ast.StringTerm(typ), ast.ArrayTerm(list...)))
		}
		blocks = append(blocks, ast.Item(ast.StringTerm(kind), ast.ObjectTerm(byType...)))
	}
	for _, kind := range listKinds {
		blocks = append(blocks, ast.Item(ast.StringTerm(kind), ast.ArrayTerm(lists[kind]...)))
	}
	ddPairs := [][2]*ast.Term{
		ast.Item(ast.StringTerm("placeholder"), placeholder),
		ast.Item(ast.StringTerm("blocks_complete"), ast.BooleanTerm(out.BlocksComplete)),
		ast.Item(ast.StringTerm("blocks"), ast.ObjectTerm(blocks...)),
		ast.Item(ast.StringTerm("by_id"), ast.ObjectTerm(byID...)),
		ast.Item(ast.StringTerm("related"), ast.NewTerm(related)),
		ast.Item(ast.StringTerm("targets"), ast.NewTerm(targets)),
		ast.Item(ast.StringTerm("referrers"), ast.NewTerm(referrers)),
	}
	if len(nested) > 0 {
		ddPairs = append(ddPairs, ast.Item(ast.StringTerm("nested"), ast.ObjectTerm(nested...)))
	}
	dd := ast.NewObject(ddPairs...)
	out.Input = ast.NewObject(
		ast.Item(ast.StringTerm("document"), ast.ArrayTerm(docs...)),
		ast.Item(ast.StringTerm("_dd"), ast.NewTerm(dd)),
	)
	return out
}

// absorb adds what locates the blocks of pr to p.
func (p *Projection) absorb(pr *Projection) {
	for id, loc := range pr.Blocks {
		p.Blocks[id] = loc
	}
	for k, v := range pr.Unknown {
		p.Unknown[k] = v
	}
	p.Open = p.Open || pr.Open
	for id := range pr.External {
		p.External[id] = true
	}
	p.Cross = append(p.Cross, pr.Cross...)
	p.Incompleteness = append(p.Incompleteness, pr.Incompleteness...)
}

func placeholderOf(pr *Projection) *ast.Term {
	dd, _ := pr.Input.(ast.Object).Get(ast.StringTerm("_dd")).Value.(ast.Object)
	return dd.Get(ast.StringTerm("placeholder"))
}

// BlockOrder lists the ids of the blocks of the projection in a fixed order
// that depends on the content only: typed kinds in order, types sorted, then
// the list kinds.
func (pr *Projection) BlockOrder() []string {
	var ids []string
	pt := pr.parts
	for _, kind := range typedKinds {
		types := make([]string, 0, len(pt.typed[kind]))
		for typ := range pt.typed[kind] {
			types = append(types, typ)
		}
		slices.Sort(types)
		for _, typ := range types {
			for _, t := range pt.typed[kind][typ] {
				ids = append(ids, blockTermID(t))
			}
		}
	}
	for _, kind := range listKinds {
		for _, t := range pt.lists[kind] {
			ids = append(ids, blockTermID(t))
		}
	}
	return ids
}

func blockTermID(t *ast.Term) string {
	meta, _ := t.Value.(ast.Object).Get(ast.StringTerm("_dd_meta")).Value.(ast.Object)
	id, _ := meta.Get(ast.StringTerm("id")).Value.(ast.String)
	return string(id)
}

// Digest identifies the projection modulo ids, the root and the directory of
// the files: two projections with the same digest give a rule the same
// results up to the ids in them. ids is BlockOrder.
func (pr *Projection) Digest(ids []string) string {
	ord := make(map[string]int, len(ids))
	for i, id := range ids {
		ord[id] = i
	}
	dd := pr.Input.(ast.Object).Get(ast.StringTerm("_dd")).Value
	h := sha256.New()
	canonical(h, dd, ord, false)
	return hex.EncodeToString(h.Sum(nil))
}

const (
	metaKey  = "_dd_meta"
	metaID   = "id"
	metaRoot = "root"
	metaFile = "file"
)

func canonical(w io.Writer, v ast.Value, ord map[string]int, meta bool) {
	switch x := v.(type) {
	case ast.String:
		if i, ok := ord[string(x)]; ok {
			_, _ = io.WriteString(w, "i"+strconv.Itoa(i)+";")
			return
		}
		_, _ = io.WriteString(w, "s"+strconv.Quote(string(x))+";")
	case *ast.Array:
		_, _ = io.WriteString(w, "[")
		x.Foreach(func(e *ast.Term) { canonical(w, e.Value, ord, false) })
		_, _ = io.WriteString(w, "]")
	case ast.Object:
		type entry struct {
			key string
			val ast.Value
			// meta marks the value as a _dd_meta object.
			meta bool
		}
		var entries []entry
		x.Foreach(func(k, e *ast.Term) {
			var kb bytes.Buffer
			canonical(&kb, k.Value, ord, false)
			ks, _ := k.Value.(ast.String)
			if meta {
				switch string(ks) {
				case metaID, metaRoot:
					return
				case metaFile:
					if f, ok := e.Value.(ast.String); ok {
						entries = append(entries, entry{key: kb.String(), val: ast.String(path.Base(string(f)))})
						return
					}
				}
			}
			entries = append(entries, entry{key: kb.String(), val: e.Value, meta: string(ks) == metaKey})
		})
		slices.SortFunc(entries, func(a, b entry) int { return bytes.Compare([]byte(a.key), []byte(b.key)) })
		_, _ = io.WriteString(w, "{")
		for _, e := range entries {
			_, _ = io.WriteString(w, e.key)
			canonical(w, e.val, ord, e.meta)
		}
		_, _ = io.WriteString(w, "}")
	case ast.Set:
		var elems []string
		x.Foreach(func(e *ast.Term) {
			var b bytes.Buffer
			canonical(&b, e.Value, ord, false)
			elems = append(elems, b.String())
		})
		slices.Sort(elems)
		_, _ = io.WriteString(w, "(")
		for _, e := range elems {
			_, _ = io.WriteString(w, e)
		}
		_, _ = io.WriteString(w, ")")
	default:
		_, _ = io.WriteString(w, v.String()+";")
	}
}
