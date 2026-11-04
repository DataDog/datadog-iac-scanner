package engine

import (
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// tfIndexKey is the input key of the cross-root index of literal attribute
// values: {type: {attribute: {value: {root: true}}}}, each value with the
// roots whose documents write it. Data sources are keyed data.<type> and
// ephemeral resources ephemeral.<type>, so a rule evaluated on one root can
// see the values written by every other root.
const tfIndexKey = "_dd_tf_index"

// tfRootKey is the input key of the root a per-root input stands for, as the
// index names it, so a rule can leave out the values its own root writes:
// those it joins on its documents instead.
const tfRootKey = "_dd_root"

var tfIndexSections = [...]struct{ section, prefix string }{
	{"resource", ""},
	{"data", dataTypePrefix},
	{ephemeralSection, ephemeralPrefix},
}

// buildTerraformIndex indexes the known string attributes of the resource,
// data and ephemeral blocks of every document. A value marked unknown or still
// holding an interpolation is left out, and so is one the block's
// _dd_meta.references does not trace to nothing (references: []): a value
// resolved from a reference, or one that could not be traced, must not clear
// findings in other roots via literal_seen. A block with metadata but no
// references is untraced and indexes nothing. A block without metadata is
// as-written source, where only interpolation-free strings are literals.
// literalIndex accumulates literal attribute values across documents, each
// with the roots writing it.
type literalIndex map[string]map[string]map[string]map[string]struct{}

// buildTerraformIndex indexes list, the roots of each document read from
// docRoots by document ID.
func buildTerraformIndex(list []*ast.Term, docRoots map[string][]string) ast.Object {
	index := make(literalIndex)
	for _, term := range list {
		id, _ := termDocumentID(term)
		index.addTerm(term, docRoots[id])
	}
	return index.object()
}

func (index literalIndex) addTerm(term *ast.Term, roots []string) {
	forEachIndexedBlock(term, func(typ string, block ast.Object) {
		unknown := ddMetaUnknown(block)
		refs := ddMetaReferences(block)
		block.Foreach(func(k, v *ast.Term) {
			attr, value, ok := indexableLiteral(k, v, unknown, refs)
			if !ok {
				return
			}
			index.put(typ, attr, value, roots)
		})
	})
}

// addDocument indexes one Terraform document from its Go value, matching
// addTerm on the payload after jsonencode strings are parsed. Batched
// evaluation uses it so the index exists before any document is converted.
func (index literalIndex) addDocument(doc interface{}, roots []string) {
	m, ok := asStringMap(doc)
	if !ok {
		return
	}
	for _, s := range tfIndexSections {
		types, ok := asStringMap(m[s.section])
		if !ok {
			continue
		}
		for name, byName := range types {
			blocks, ok := asStringMap(byName)
			if !ok {
				continue
			}
			for _, block := range blocks {
				index.addBlock(s.prefix+name, block, roots)
			}
		}
	}
}

func (index literalIndex) addBlock(typ string, block interface{}, roots []string) {
	if items, ok := block.([]interface{}); ok {
		for _, item := range items {
			index.addBlock(typ, item, roots)
		}
		return
	}
	m, ok := asStringMap(block)
	if !ok {
		return
	}
	meta, _ := asStringMap(m[ddMetaKey])
	unknown, _ := asStringMap(meta[unknownKey])
	var refs map[string]interface{}
	if _, hasMeta := m[ddMetaKey]; hasMeta {
		refs, _ = asStringMap(meta[referencesKey])
		if refs == nil {
			refs = map[string]interface{}{}
		}
	}
	for key, value := range m {
		lit, ok := indexableMapLiteral(key, value, unknown, refs)
		if !ok {
			continue
		}
		index.put(typ, key, lit, roots)
	}
}

// put records value under typ and attr for roots; a document of no root is
// recorded under "".
func (index literalIndex) put(typ, attr, value string, roots []string) {
	byAttr := index[typ]
	if byAttr == nil {
		byAttr = map[string]map[string]map[string]struct{}{}
		index[typ] = byAttr
	}
	values := byAttr[attr]
	if values == nil {
		values = map[string]map[string]struct{}{}
		byAttr[attr] = values
	}
	writers := values[value]
	if writers == nil {
		writers = map[string]struct{}{}
		values[value] = writers
	}
	if len(roots) == 0 {
		writers[""] = struct{}{}
	}
	for _, root := range roots {
		writers[root] = struct{}{}
	}
}

func (index literalIndex) object() ast.Object {
	return indexObject(index)
}

// indexableLiteral returns the attribute and value of k = v when v is a
// literal string other roots may join on.
func indexableLiteral(k, v *ast.Term, unknown, refs ast.Object) (attr, value string, ok bool) {
	key, ok := k.Value.(ast.String)
	if !ok || strings.HasPrefix(string(key), "_dd_") {
		return "", "", false
	}
	s, ok := v.Value.(ast.String)
	if !ok || strings.Contains(string(s), "${") {
		return "", "", false
	}
	if unknown != nil && unknown.Get(k) != nil {
		return "", "", false
	}
	if refs != nil && !tracedToNothing(refs.Get(k)) {
		return "", "", false
	}
	return string(key), string(s), true
}

// forEachIndexedBlock calls fn on every resource, data and ephemeral block of
// one document, with its indexed type.
func forEachIndexedBlock(term *ast.Term, fn func(typ string, block ast.Object)) {
	doc, ok := term.Value.(ast.Object)
	if !ok {
		return
	}
	for _, s := range tfIndexSections {
		types, ok := termObject(doc.Get(ast.StringTerm(s.section)))
		if !ok {
			continue
		}
		types.Foreach(func(typ, byName *ast.Term) {
			name, ok := typ.Value.(ast.String)
			if !ok {
				return
			}
			blocks, ok := termObject(byName)
			if !ok {
				return
			}
			blocks.Foreach(func(_, block *ast.Term) {
				forEachBlockObject(block, func(obj ast.Object) { fn(s.prefix+string(name), obj) })
			})
		})
	}
}

func indexObject(index literalIndex) ast.Object {
	out := ast.NewObject()
	for typ, byAttr := range index {
		attrs := ast.NewObject()
		for attr, values := range byAttr {
			literals := ast.NewObject()
			for value, roots := range values {
				writers := ast.NewObject()
				for root := range roots {
					writers.Insert(ast.StringTerm(root), ast.BooleanTerm(true))
				}
				literals.Insert(ast.StringTerm(value), ast.NewTerm(writers))
			}
			attrs.Insert(ast.StringTerm(attr), ast.NewTerm(literals))
		}
		out.Insert(ast.StringTerm(typ), ast.NewTerm(attrs))
	}
	return out
}

// forEachBlockObject calls fn on a block, or on each item when the document
// holds several blocks under one name.
func forEachBlockObject(block *ast.Term, fn func(ast.Object)) {
	switch v := block.Value.(type) {
	case ast.Object:
		fn(v)
	case *ast.Array:
		v.Foreach(func(item *ast.Term) {
			if obj, ok := item.Value.(ast.Object); ok {
				fn(obj)
			}
		})
	}
}

// tracedToNothing reports whether an attribute's references entry is the
// empty list. A missing entry means untraced.
func tracedToNothing(refs *ast.Term) bool {
	if refs == nil {
		return false
	}
	arr, ok := refs.Value.(*ast.Array)
	return ok && arr.Len() == 0
}

func ddMetaUnknown(block ast.Object) ast.Object {
	meta, ok := termObject(block.Get(ast.StringTerm(ddMetaKey)))
	if !ok {
		return nil
	}
	unknown, _ := termObject(meta.Get(ast.StringTerm(unknownKey)))
	return unknown
}

func ddMetaReferences(block ast.Object) ast.Object {
	meta, ok := termObject(block.Get(ast.StringTerm(ddMetaKey)))
	if !ok {
		return nil
	}
	refs, ok := termObject(meta.Get(ast.StringTerm(referencesKey)))
	if !ok {
		// A block with metadata but no references was never traced: no
		// attribute is a literal. Only a block with no metadata is source
		// as written.
		return ast.NewObject()
	}
	return refs
}

// indexableMapLiteral is indexableLiteral for a document map, including a
// top-level jsonencode string replaced by its parsed value.
func indexableMapLiteral(key string, value interface{}, unknown, refs map[string]interface{}) (string, bool) {
	if strings.HasPrefix(key, ddPrefix) {
		return "", false
	}
	raw, ok := value.(string)
	if !ok {
		return "", false
	}
	s, ok := indexedString(raw)
	if !ok {
		return "", false
	}
	if _, present := unknown[key]; present {
		return "", false
	}
	if refs != nil && !goTracedToNothing(refs[key]) {
		return "", false
	}
	return s, true
}

// indexedString is the literal a payload stores for s. A standalone jsonencode
// call is parsed first, the same way payload conversion rewrites it. A call
// that parses to a non-string is not a literal.
func indexedString(s string) (string, bool) {
	if strings.Contains(s, "jsonencode(") {
		trimmed := strings.TrimSpace(s)
		standalone := strings.HasPrefix(trimmed, "jsonencode(") || strings.HasPrefix(trimmed, "${jsonencode(")
		if standalone {
			parsed, err := parseJsonencodeHCL(s)
			if err == nil {
				str, ok := parsed.(ast.String)
				if !ok {
					return "", false
				}
				s = string(str)
			}
		}
	}
	if strings.Contains(s, "${") {
		return "", false
	}
	return s, true
}

func goTracedToNothing(v interface{}) bool {
	refs, ok := v.([]interface{})
	return ok && len(refs) == 0
}

func termObject(term *ast.Term) (ast.Object, bool) {
	if term == nil {
		return nil, false
	}
	obj, ok := term.Value.(ast.Object)
	return obj, ok
}

// withTerraformIndex adds the index to a payload built by
// assembleDocumentPayload, in place: payloads are not shared before then.
// root is the root the payload stands for, "" for a payload of several.
func withTerraformIndex(payload ast.Value, index ast.Object, root string) ast.Value {
	if obj, ok := payload.(ast.Object); ok && index != nil {
		obj.Insert(ast.StringTerm(tfIndexKey), ast.NewTerm(index))
		if root != "" {
			obj.Insert(ast.StringTerm(tfRootKey), ast.StringTerm(root))
		}
	}
	return payload
}

// soleRoot is the one root of docRoots, "" when there are several or none.
func soleRoot(docRoots map[string][]string) string {
	sole := ""
	for _, roots := range docRoots {
		for _, root := range roots {
			if sole != "" && root != sole {
				return ""
			}
			sole = root
		}
	}
	return sole
}

// documentTypeNames returns the resource, data and ephemeral type names present
// in one Terraform document term.
func documentTypeNames(term *ast.Term) map[string]bool {
	out := map[string]bool{}
	forEachIndexedBlock(term, func(typ string, _ ast.Object) {
		out[typ] = true
	})
	return out
}

// rootTypeIndex maps each root to the resource types in its eval documents.
func rootTypeIndex(docs map[string][]*ast.Term) map[string]map[string]bool {
	if len(docs) == 0 {
		return nil
	}
	out := make(map[string]map[string]bool, len(docs))
	for root, terms := range docs {
		types := map[string]bool{}
		for _, term := range terms {
			for typ := range documentTypeNames(term) {
				types[typ] = true
			}
		}
		out[root] = types
	}
	return out
}
