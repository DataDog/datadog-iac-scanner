/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package project

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/value"
	"github.com/DataDog/datadog-iac-scanner/test/tfcorpus"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

// TestProjectionsStayFaithfulToTheModel walks every attribute-state cell of
// the fixture corpus and checks, for every path the model writes:
//
//   - the contract input and the legacy documents both carry it; a known
//     value matches the model, a written-but-unknown value stays readable
//     (the placeholder in the contract input, its "${...}" source text or the
//     placeholder in the legacy document);
//   - the placeholder appears only where the model holds an unknown, a
//     template or JSON part, or a computed value — never for a value the
//     configuration wrote and never for one it never wrote;
//   - a null or absent attribute is missing from both projections and from
//     _dd_meta.written.
//
// An attribute the configuration writes must be readable even when its value
// is unknown; one it never writes must stay undefined. No projection may
// invent a stand-in for it.
func TestProjectionsStayFaithfulToTheModel(t *testing.T) {
	cells := tfcorpus.StateGrid()
	dir, names := tfcorpus.MaterializeState(t, cells)
	placeholder := value.NewPlaceholder()
	for i, cell := range cells {
		t.Run(cell.Name(), func(t *testing.T) {
			root := filepath.Join(dir, names[i])
			scan, err := model.Load(t.Context(), root, &model.Options{})
			require.NoError(t, err)
			proj := Project(scan.Roots, Options{Placeholder: placeholder})
			docs := LegacyDocs(scan.Roots, LegacyOptions{
				Base:        root,
				Placeholder: placeholder,
				FileID:      func(string) (string, bool) { return "doc", true },
			})
			for _, r := range scan.Roots {
				for _, m := range r.Modules {
					for _, b := range m.Blocks {
						if b.Kind != "resource" && b.Kind != "data" && b.Kind != "ephemeral" {
							continue
						}
						for _, inst := range b.Instances {
							checkInstance(t, proj, docs, placeholder, inst, cell.Name())
						}
					}
				}
			}
		})
	}
}

// leafClass is what the model holds at one written path.
type leafClass int

const (
	leafKnown leafClass = iota
	leafUnknown
	leafNull
)

// modelLeaf is one written path of an instance with its value and class.
type modelLeaf struct {
	path  []string
	value cty.Value
	class leafClass
}

// writtenLeaves flattens an instance's attributes into written paths, the
// same way the projector's written set is built: null attributes are not
// written, unknown ones are.
func writtenLeaves(attrs map[string]cty.Value) []modelLeaf {
	var out []modelLeaf
	var walk func(path []string, v cty.Value)
	walk = func(path []string, v cty.Value) {
		v, _ = v.UnmarkDeep()
		if v.IsNull() {
			out = append(out, modelLeaf{path: path, value: v, class: leafNull})
			return
		}
		if !v.IsKnown() {
			out = append(out, modelLeaf{path: path, value: v, class: leafUnknown})
			return
		}
		ty := v.Type()
		switch {
		case ty.IsListType() || ty.IsTupleType() || ty.IsSetType():
			i := 0
			for it := v.ElementIterator(); it.Next(); i++ {
				_, e := it.Element()
				walk(append(append([]string{}, path...), strconv.Itoa(i)), e)
			}
		case ty.IsMapType() || ty.IsObjectType():
			m := v.AsValueMap()
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(append(append([]string{}, path...), k), m[k])
			}
		default:
			out = append(out, modelLeaf{path: path, value: v, class: leafKnown})
		}
	}
	for _, name := range sortedAttrNames(attrs) {
		walk([]string{name}, attrs[name])
	}
	return out
}

func sortedAttrNames(attrs map[string]cty.Value) []string {
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// checkInstance checks one block instance's projections against the model.
func checkInstance(t *testing.T, proj *Projection, docs []*LegacyDoc, placeholder string, inst *model.Instance, cell string) {
	t.Helper()
	// The contract block of this instance.
	var loc *Located
	for _, l := range proj.Blocks {
		if l.Instance() == inst {
			loc = l
			break
		}
	}
	require.NotNil(t, loc, "%s: the contract input has no block for instance %s%s", cell, inst.Block.Name, inst.Key)

	// The legacy document holding this instance.
	legacy := legacyEntry(t, docs, inst, cell)

	leaves := writtenLeaves(inst.Attrs)
	contract := contractTree{root: loc.Term, nested: nestedOf(proj, loc.ID), placeholder: placeholder}
	for _, leaf := range leaves {
		path := strings.Join(leaf.path, ".")
		switch leaf.class {
		case leafNull:
			require.False(t, contract.has(leaf.path), "%s: %s: a null attribute is in the contract input", cell, path)
			require.False(t, legacyHas(legacy, leaf.path), "%s: %s: a null attribute is in the legacy document", cell, path)
		case leafUnknown:
			require.True(t, contract.holdsPlaceholder(leaf.path),
				"%s: %s: an unknown written attribute is not readable in the contract input", cell, path)
			require.False(t, contract.isExactlyPlaceholder(leaf.path) && !contract.isWholeValue(leaf.path),
				"%s: %s: the contract input replaced a written attribute with a stand-in", cell, path)
			require.True(t, legacyHoldsUnknown(legacy, leaf.path, placeholder),
				"%s: %s: an unknown written attribute is not readable in the legacy document", cell, path)
		case leafKnown:
			require.True(t, contract.has(leaf.path),
				"%s: %s: a written attribute is missing from the contract input", cell, path)
			got, err := contract.jsonAt(leaf.path)
			require.NoError(t, err, "%s: %s", cell, path)
			want, err := json.Marshal((value.Converter{Placeholder: placeholder}).Go(leaf.value))
			require.NoError(t, err, "%s: %s", cell, path)
			require.JSONEq(t, string(want), got,
				"%s: %s: the contract input does not match the model", cell, path)
			require.True(t, legacyHas(legacy, leaf.path),
				"%s: %s: a written attribute is missing from the legacy document", cell, path)
			lgot, ok := legacyAt(legacy, leaf.path)
			require.True(t, ok, "%s: %s", cell, path)
			require.JSONEq(t, string(want), marshalAny(t, lgot),
				"%s: %s: the legacy document does not match the model", cell, path)
			require.False(t, contract.holdsPlaceholder(leaf.path),
				"%s: %s: the contract input holds a placeholder for a known value", cell, path)
		}
	}

	// The written set of the contract input is exactly the paths the model
	// writes: every non-null path, containers included, without recursing
	// into unknown values.
	written := writtenSet(proj, loc.ID)
	require.Equal(t, expectedWritten(inst.Attrs), written, "%s: _dd_meta.written does not match the model", cell)

	// No placeholder outside the paths the model leaves unknown.
	checkNoInventedPlaceholders(t, contract, inst, placeholder, cell)
}

// expectedWritten computes the written paths of an instance the way the
// projector builds its written set: every non-null path, containers
// included, without recursing into unknown values, nulls left out.
func expectedWritten(attrs map[string]cty.Value) []string {
	var out []string
	var walk func(prefix, name string, v cty.Value)
	walk = func(prefix, name string, v cty.Value) {
		v, _ = v.UnmarkDeep()
		if v.IsNull() {
			return
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		out = append(out, path)
		if !v.IsKnown() {
			return
		}
		ty := v.Type()
		switch {
		case ty.IsListType() || ty.IsTupleType() || ty.IsSetType():
			i := 0
			for it := v.ElementIterator(); it.Next(); i++ {
				_, e := it.Element()
				walk(path, strconv.Itoa(i), e)
			}
		case ty.IsMapType() || ty.IsObjectType():
			m := v.AsValueMap()
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(path, k, m[k])
			}
		}
	}
	for _, name := range sortedAttrNames(attrs) {
		walk("", name, attrs[name])
	}
	sort.Strings(out)
	return out
}

// checkNoInventedPlaceholders walks the contract block and its nested
// entries: every placeholder must sit at a path the model leaves unknown, or
// under an attribute with template or JSON parts, or a computed one.
func checkNoInventedPlaceholders(t *testing.T, contract contractTree, inst *model.Instance, placeholder, cell string) {
	t.Helper()
	known := map[string]bool{}
	for path, parts := range inst.Templates {
		known[path] = true
		_ = parts
	}
	for path := range inst.JSON {
		known[path] = true
	}
	for path := range inst.JSONExpr {
		known[path] = true
	}
	for path := range inst.Computed {
		known[path] = true
	}
	contract.eachPlaceholder(func(path []string) {
		// The derived and computed metadata hold the unknown parts of
		// templates and JSON documents by design.
		if len(path) > 0 && path[0] == "_dd_meta" {
			return
		}
		p := strings.Join(path, ".")
		if known[p] {
			return
		}
		// An unknown ancestor stands for everything under it.
		for i := len(path) - 1; i > 0; i-- {
			if known[strings.Join(path[:i], ".")] {
				return
			}
		}
		// The model value at the path is unknown.
		v, ok := modelAt(inst.Attrs, path)
		if ok {
			uv, _ := v.UnmarkDeep()
			if !uv.IsKnown() {
				return
			}
		}
		t.Errorf("%s: the contract input holds a placeholder at %s, where the model holds a written known value", cell, p)
	})
}

// contractTree navigates one block instance's contract term, with the
// nested-block lists the input keeps beside it.
type contractTree struct {
	root        *ast.Term
	nested      map[string]*ast.Term // nested block name -> list term
	placeholder string
}

// nestedOf extracts the nested-block entries of one block id from the input.
func nestedOf(proj *Projection, id string) map[string]*ast.Term {
	out := map[string]*ast.Term{}
	obj, ok := proj.Input.(ast.Object)
	if !ok {
		return out
	}
	ddTerm := obj.Get(ast.StringTerm("_dd"))
	if ddTerm == nil {
		return out
	}
	dd, ok := ddTerm.Value.(ast.Object)
	if !ok {
		return out
	}
	allTerm := dd.Get(ast.StringTerm("nested"))
	if allTerm == nil {
		return out
	}
	all, ok := allTerm.Value.(ast.Object)
	if !ok {
		return out
	}
	idTerm := all.Get(ast.StringTerm(id))
	if idTerm == nil {
		return out
	}
	m, ok := idTerm.Value.(ast.Object)
	if !ok {
		return out
	}
	for _, key := range m.Keys() {
		if s, ok := key.Value.(ast.String); ok {
			out[string(s)] = m.Get(key)
		}
	}
	return out
}

// termAt navigates the term by path: names for objects, indexes for lists.
// A nested block name reads the nested list instead of the instance term.
func (c contractTree) termAt(path []string) (*ast.Term, bool) {
	if len(path) == 0 {
		return c.root, true
	}
	var current *ast.Term
	if list, ok := c.nested[path[0]]; ok {
		if len(path) == 1 {
			return list, true
		}
		i, err := strconv.Atoi(path[1])
		if err != nil {
			return nil, false
		}
		arr, ok := list.Value.(*ast.Array)
		if !ok || i >= arr.Len() {
			return nil, false
		}
		current = arr.Elem(i)
		path = path[2:]
	} else {
		current = c.root
	}
	for _, seg := range path {
		if current == nil {
			return nil, false
		}
		switch v := current.Value.(type) {
		case ast.Object:
			next := v.Get(ast.StringTerm(seg))
			if next == nil {
				return nil, false
			}
			current = next
		case *ast.Array:
			i, err := strconv.Atoi(seg)
			if err != nil || i >= v.Len() {
				return nil, false
			}
			current = v.Elem(i)
		default:
			return nil, false
		}
	}
	return current, true
}

func (c contractTree) has(path []string) bool {
	t, ok := c.termAt(path)
	return ok && t != nil
}

// holdsPlaceholder reports whether the value at the path is or contains the
// placeholder.
func (c contractTree) holdsPlaceholder(path []string) bool {
	t, ok := c.termAt(path)
	if !ok || t == nil {
		return false
	}
	return termContains(t, c.placeholder)
}

// isExactlyPlaceholder reports whether the value at the path is the
// placeholder itself.
func (c contractTree) isExactlyPlaceholder(path []string) bool {
	t, ok := c.termAt(path)
	return ok && t != nil && t.Value.Compare(ast.String(c.placeholder)) == 0
}

// isWholeValue reports whether the path resolves at all (its value exists as
// a written attribute, not only inside a rendered string).
func (c contractTree) isWholeValue(path []string) bool {
	_, ok := c.termAt(path)
	return ok
}

func (c contractTree) jsonAt(path []string) (string, error) {
	t, ok := c.termAt(path)
	if !ok || t == nil {
		return "", fmt.Errorf("no value at %v", path)
	}
	b, err := ast.JSON(t.Value)
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// eachPlaceholder walks the term and its nested lists, visiting the
// dot-joined path of every placeholder occurrence.
func (c contractTree) eachPlaceholder(visit func(path []string)) {
	var walk func(t *ast.Term, path []string)
	walk = func(t *ast.Term, path []string) {
		if t == nil {
			return
		}
		switch v := t.Value.(type) {
		case ast.String:
			if string(v) == c.placeholder {
				visit(path)
			}
		case ast.Object:
			for _, key := range v.Keys() {
				if s, ok := key.Value.(ast.String); ok {
					walk(v.Get(key), append(append([]string{}, path...), string(s)))
				}
			}
		case *ast.Array:
			for i := 0; i < v.Len(); i++ {
				walk(v.Elem(i), append(append([]string{}, path...), strconv.Itoa(i)))
			}
		}
	}
	walk(c.root, nil)
	for name, list := range c.nested {
		walk(list, []string{name})
	}
}

func termContains(t *ast.Term, placeholder string) bool {
	if t == nil {
		return false
	}
	switch v := t.Value.(type) {
	case ast.String:
		return strings.Contains(string(v), placeholder)
	case ast.Object:
		for _, key := range v.Keys() {
			if termContains(v.Get(key), placeholder) {
				return true
			}
		}
	case *ast.Array:
		for i := 0; i < v.Len(); i++ {
			if termContains(v.Elem(i), placeholder) {
				return true
			}
		}
	}
	return false
}

// legacyEntry finds the legacy attribute map of one block instance.
func legacyEntry(t *testing.T, docs []*LegacyDoc, inst *model.Instance, cell string) map[string]any {
	t.Helper()
	name := inst.Block.Name + inst.Key
	for _, d := range docs {
		if inst.Block.Module.Address != "" && d.Module != inst.Block.Module {
			continue
		}
		if inst.Block.Module.Address == "" && d.Module != nil {
			continue
		}
		byKind, ok := d.Doc[inst.Block.Kind].(map[string]any)
		if !ok {
			continue
		}
		byType, ok := byKind[inst.Block.Type].(map[string]any)
		if !ok {
			continue
		}
		if attrs, ok := byType[name].(map[string]any); ok {
			return attrs
		}
	}
	t.Fatalf("%s: the legacy documents hold no entry for %s%s", cell, inst.Block.Name, inst.Key)
	return nil
}

// legacyAt navigates the legacy attribute map by path. A nested block
// written once collapses to an object, so an index step into it is skipped.
func legacyAt(attrs map[string]any, path []string) (any, bool) {
	var current any = attrs
	for i, seg := range path {
		switch node := current.(type) {
		case map[string]any:
			next, ok := node[seg]
			if !ok {
				// A collapsed nested block: the model carries the index,
				// the document does not.
				if _, err := strconv.Atoi(seg); err == nil && i > 0 {
					continue
				}
				return nil, false
			}
			current = next
		case []any:
			i2, err := strconv.Atoi(seg)
			if err != nil || i2 >= len(node) {
				return nil, false
			}
			current = node[i2]
		default:
			return nil, false
		}
	}
	return current, true
}

func legacyHas(attrs map[string]any, path []string) bool {
	_, ok := legacyAt(attrs, path)
	return ok
}

// legacyHoldsUnknown reports whether the value at the path renders an
// unknown: the expression source text, or a value holding the placeholder.
func legacyHoldsUnknown(attrs map[string]any, path []string, placeholder string) bool {
	v, ok := legacyAt(attrs, path)
	if !ok {
		return false
	}
	escaped := strings.ReplaceAll(placeholder, "\u0000", `\u0000`)
	switch node := v.(type) {
	case string:
		return strings.HasPrefix(node, "${") ||
			strings.Contains(node, placeholder) ||
			strings.Contains(node, escaped)
	case map[string]any, []any:
		b, err := json.Marshal(v)
		if err != nil {
			return false
		}
		return strings.Contains(string(b), placeholder) ||
			strings.Contains(string(b), escaped)
	}
	return false
}

// writtenSet reads _dd_meta.written of one block id.
func writtenSet(proj *Projection, id string) []string {
	obj, ok := proj.Input.(ast.Object)
	if !ok {
		return nil
	}
	ddTerm := obj.Get(ast.StringTerm("_dd"))
	if ddTerm == nil {
		return nil
	}
	dd, ok := ddTerm.Value.(ast.Object)
	if !ok {
		return nil
	}
	byID := dd.Get(ast.StringTerm("by_id"))
	if byID == nil {
		return nil
	}
	byIDObj, ok := byID.Value.(ast.Object)
	if !ok {
		return nil
	}
	block := byIDObj.Get(ast.StringTerm(id))
	if block == nil {
		return nil
	}
	blockObj, ok := block.Value.(ast.Object)
	if !ok {
		return nil
	}
	meta := blockObj.Get(ast.StringTerm("_dd_meta"))
	if meta == nil {
		return nil
	}
	metaObj, ok := meta.Value.(ast.Object)
	if !ok {
		return nil
	}
	w := metaObj.Get(ast.StringTerm("written"))
	if w == nil {
		return nil
	}
	set, ok := w.Value.(ast.Set)
	if !ok {
		return nil
	}
	var out []string
	for _, term := range set.Slice() {
		if s, ok := term.Value.(ast.String); ok {
			out = append(out, string(s))
		}
	}
	sort.Strings(out)
	return out
}

func marshalAny(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

// modelAt reads the model value at a path.
func modelAt(attrs map[string]cty.Value, path []string) (cty.Value, bool) {
	var current cty.Value
	var ok bool
	if len(path) == 0 {
		return current, false
	}
	if current, ok = attrs[path[0]]; !ok {
		return current, false
	}
	for _, seg := range path[1:] {
		current, _ = current.UnmarkDeep()
		if !current.IsKnown() || current.IsNull() {
			return current, false
		}
		ty := current.Type()
		switch {
		case ty.IsListType() || ty.IsTupleType() || ty.IsSetType():
			i, err := strconv.Atoi(seg)
			if err != nil || i >= current.LengthInt() {
				return current, false
			}
			it := current.ElementIterator()
			for j := 0; j <= i; j++ {
				it.Next()
			}
			_, current = it.Element()
		case ty.IsMapType() || ty.IsObjectType():
			m := current.AsValueMap()
			next, found := m[seg]
			if !found {
				return current, false
			}
			current = next
		default:
			return current, false
		}
	}
	return current, true
}
