/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// rootResourceProjection overlays evaluated root instances onto their
// original source documents, preserving same-file context and cardinality.
type rootResourceProjection map[string]*rootDocumentResources

type rootDocumentResources struct {
	resources map[string]map[string]interface{}
	data      map[string]map[string]interface{}
	instances map[model.TerraformInstanceKey]model.TerraformInstance
}

func overlayRootResources(doc map[string]interface{}, projection *rootDocumentResources) {
	if projection == nil {
		return
	}
	for _, section := range []struct {
		name   string
		blocks map[string]map[string]interface{}
	}{{"resource", projection.resources}, {"data", projection.data}} {
		if len(section.blocks) == 0 {
			continue
		}
		root := docAsMap(doc[section.name])
		if root == nil {
			root = make(map[string]interface{})
			doc[section.name] = root
		}
		for typ, names := range section.blocks {
			byName := docAsMap(root[typ])
			if byName == nil {
				byName = make(map[string]interface{})
				root[typ] = byName
			}
			for name, attrs := range names {
				byName[name] = attrs
			}
		}
	}
}

type rootSuppressedBlock struct {
	fileID string
	kind   string
	name   string
}

func projectRootResources(
	ctx context.Context,
	resources []tfeval.ResolvedResource,
	byAbsPath map[string]*model.FileMetadata,
	repoPath string,
	targets *ruleTargets,
) (projected rootResourceProjection, count int) {
	var cons *rootTreeCons
	for i := range resources {
		r := &resources[i]
		if r.ModuleAddress != "" || !targets.matches(r.Type) {
			continue
		}
		fm := byAbsPath[absPath(r.DefinedIn, repoPath)]
		if fm == nil {
			continue
		}
		if projected == nil {
			projected = make(rootResourceProjection)
			cons = newRootTreeCons()
		}
		projection := projected[fm.ID]
		if projection == nil {
			projection = &rootDocumentResources{}
			projected[fm.ID] = projection
		}
		kind := blockKind(r)
		var section map[string]map[string]interface{}
		typ := kind
		if dataType, ok := strings.CutPrefix(kind, dataTypePrefix); ok {
			if projection.data == nil {
				projection.data = make(map[string]map[string]interface{})
			}
			section, typ = projection.data, dataType
		} else {
			if projection.resources == nil {
				projection.resources = make(map[string]map[string]interface{})
			}
			section = projection.resources
		}
		byName := section[typ]
		if byName == nil {
			byName = make(map[string]interface{})
			section[typ] = byName
		}
		doc := tfeval.AttributesToDocumentWithContext(ctx, r)
		byName[r.Name] = cons.cons(doc)
		base := tfeval.ResourceBaseName(r.Name)
		if r.Name != base {
			if projection.instances == nil {
				projection.instances = make(map[model.TerraformInstanceKey]model.TerraformInstance)
			}
			projection.instances[model.TerraformInstanceKey{Kind: rootSectionKind(r), Type: r.Type, Name: r.Name}] =
				model.TerraformInstance{Label: base, Suffix: strings.TrimPrefix(r.Name, base)}
		}
		count++
	}
	return projected, count
}

// rootTreeCons deduplicates structurally identical map and slice subtrees
// produced by root resource projection within a single root (for example
// shared local tag maps, dynamic blocks, and repeated count/for_each attributes).
// Canonical subtrees are read-only downstream and allow buildPlatformPayloads
// to hit its O(1) pointer memo instead of re-converting every duplicate copy.
type rootTreeCons struct {
	byContent map[docContentKey][]interface{}
	hashes    map[uintptr]docContentKey
}

func newRootTreeCons() *rootTreeCons {
	return &rootTreeCons{
		byContent: make(map[docContentKey][]interface{}),
		hashes:    make(map[uintptr]docContentKey),
	}
}

func (c *rootTreeCons) cons(v interface{}) interface{} {
	res, _, _ := c.consWithHash(v)
	return res
}

func (c *rootTreeCons) consWithHash(v interface{}) (interface{}, docContentKey, bool) {
	switch t := v.(type) {
	case map[string]interface{}:
		return c.consMap(t)
	case []interface{}:
		return c.consSlice(t)
	default:
		h, ok := hashRootScalar(v)
		return v, h, ok
	}
}

func (c *rootTreeCons) consMap(m map[string]interface{}) (interface{}, docContentKey, bool) {
	ptr := reflect.ValueOf(m).Pointer()
	if h, ok := c.hashes[ptr]; ok {
		return m, h, true
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	h := mixRootByte(rootConsBase, 'M')
	shareable := true
	for _, k := range keys {
		child, ch, ok := c.consWithHash(m[k])
		m[k] = child
		if !ok {
			shareable = false
			continue
		}
		h = mixRootString(h, k)
		h = mixRootKey(h, ch)
	}
	if !shareable {
		return m, docContentKey{}, false
	}
	for _, existing := range c.byContent[h] {
		if em, ok := existing.(map[string]interface{}); ok && sameRootMap(em, m) {
			return em, h, true
		}
	}
	c.byContent[h] = append(c.byContent[h], m)
	c.hashes[ptr] = h
	return m, h, true
}

func (c *rootTreeCons) consSlice(s []interface{}) (interface{}, docContentKey, bool) {
	ptr := reflect.ValueOf(s).Pointer()
	if h, ok := c.hashes[ptr]; ok {
		return s, h, true
	}
	h := mixRootByte(rootConsBase, 'S')
	shareable := true
	for i := range s {
		child, ch, ok := c.consWithHash(s[i])
		s[i] = child
		if !ok {
			shareable = false
			continue
		}
		h = mixRootKey(h, ch)
	}
	if !shareable {
		return s, docContentKey{}, false
	}
	for _, existing := range c.byContent[h] {
		if es, ok := existing.([]interface{}); ok && sameRootSlice(es, s) {
			return es, h, true
		}
	}
	c.byContent[h] = append(c.byContent[h], s)
	c.hashes[ptr] = h
	return s, h, true
}

func sameRootMap(a, b map[string]interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || !sameRootValue(va, vb) {
			return false
		}
	}
	return true
}

func sameRootSlice(a, b []interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !sameRootValue(a[i], b[i]) {
			return false
		}
	}
	return true
}

func sameRootValue(a, b interface{}) bool {
	switch ta := a.(type) {
	case map[string]interface{}:
		tb, ok := b.(map[string]interface{})
		return ok && reflect.ValueOf(ta).Pointer() == reflect.ValueOf(tb).Pointer() && len(ta) == len(tb)
	case []interface{}:
		tb, ok := b.([]interface{})
		return ok && reflect.ValueOf(ta).Pointer() == reflect.ValueOf(tb).Pointer() && len(ta) == len(tb)
	case float64:
		tb, ok := b.(float64)
		return ok && math.Float64bits(ta) == math.Float64bits(tb)
	default:
		return a == b
	}
}

var rootConsBase = docContentKey{a: 1469598103934665603, b: 2166136261}

func mixRootByte(k docContentKey, b byte) docContentKey {
	const (
		primeA = 1099511628211
		primeB = 16777619
	)
	return docContentKey{
		a: (k.a ^ uint64(b)) * primeA,
		b: (k.b ^ uint64(b)) * primeB,
	}
}

func mixRootKey(k, x docContentKey) docContentKey {
	const (
		primeA = 1099511628211
		primeB = 16777619
	)
	return docContentKey{
		a: (k.a ^ x.a) * primeA,
		b: (k.b ^ x.b) * primeB,
	}
}

func mixRootString(k docContentKey, s string) docContentKey {
	const (
		primeA = 1099511628211
		primeB = 16777619
	)
	a, b := k.a, k.b
	for i := 0; i < len(s); i++ {
		c := uint64(s[i])
		a = (a ^ c) * primeA
		b = (b ^ c) * primeB
	}
	return docContentKey{a: (a ^ 0xff) * primeA, b: (b ^ 0xff) * primeB}
}

func hashRootScalar(v interface{}) (docContentKey, bool) {
	k := rootConsBase
	switch t := v.(type) {
	case nil:
		return mixRootByte(k, 'N'), true
	case bool:
		if t {
			return mixRootByte(k, 'T'), true
		}
		return mixRootByte(k, 'F'), true
	case string:
		return mixRootString(mixRootByte(k, 's'), t), true
	case json.Number:
		return mixRootString(mixRootByte(k, 'n'), string(t)), true
	case float64:
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], math.Float64bits(t))
		k = mixRootByte(k, 'f')
		for _, b := range buf {
			k = mixRootByte(k, b)
		}
		return k, true
	default:
		return docContentKey{}, false
	}
}

func collectRootSuppressed(
	blocks []*hclsyntax.Block,
	byAbsPath map[string]*model.FileMetadata,
	repoPath string,
	targets *ruleTargets,
) []rootSuppressedBlock {
	// Successful root evaluation accounts for every parsed declaration, including
	// blocks with count = 0 or an empty for_each. Those have no resource value
	// to project, but their as-written copy must not produce findings either.
	suppressed := make([]rootSuppressedBlock, 0, len(blocks))
	for _, block := range blocks {
		if len(block.Labels) != 2 || !targets.matches(block.Labels[0]) {
			continue
		}
		file := byAbsPath[absPath(block.TypeRange.Filename, repoPath)]
		if file == nil {
			continue
		}
		kind := block.Labels[0]
		if block.Type == dataRoot {
			kind = dataTypePrefix + kind
		}
		suppressed = append(suppressed, rootSuppressedBlock{
			fileID: file.ID,
			kind:   kind,
			name:   block.Labels[1],
		})
	}
	return suppressed
}

func (m *rootMerge) applyRootProjection(dir string, projected rootResourceProjection) {
	for _, f := range m.filesByDir[dir] {
		if f == nil {
			continue
		}
		replaced := m.instantiated[f.ID]
		if len(replaced) == 0 {
			continue
		}
		removeInstantiatedResources(f.Document, replaced)
		if projection := projected[f.ID]; projection != nil {
			overlayRootResources(f.Document, projection)
			f.TerraformInstances = projection.instances
		}
		m.rootApplied[f.ID] = true
	}
}

func (m *rootMerge) mergeRootProjection(projected rootResourceProjection) {
	for fileID, proj := range projected {
		existing := m.rootResources[fileID]
		if existing == nil {
			m.rootResources[fileID] = proj
			continue
		}
		for typ, names := range proj.resources {
			if existing.resources == nil {
				existing.resources = make(map[string]map[string]interface{})
			}
			if existing.resources[typ] == nil {
				existing.resources[typ] = names
				continue
			}
			for name, attrs := range names {
				existing.resources[typ][name] = attrs
			}
		}
		for typ, names := range proj.data {
			if existing.data == nil {
				existing.data = make(map[string]map[string]interface{})
			}
			if existing.data[typ] == nil {
				existing.data[typ] = names
				continue
			}
			for name, attrs := range names {
				existing.data[typ][name] = attrs
			}
		}
		for k, v := range proj.instances {
			if existing.instances == nil {
				existing.instances = make(map[model.TerraformInstanceKey]model.TerraformInstance)
			}
			existing.instances[k] = v
		}
	}
}

func rootSectionKind(r *tfeval.ResolvedResource) string {
	if r.Data {
		return "data"
	}
	return "resource"
}

func uniqueRootDeclarations(blocks []*hclsyntax.Block) bool {
	seen := make(map[model.TerraformBlock]bool, len(blocks))
	for _, block := range blocks {
		if len(block.Labels) != 2 {
			continue
		}
		key := model.TerraformBlock{Kind: block.Type, Type: block.Labels[0], Name: block.Labels[1]}
		if seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func (m *rootMerge) recordRootSuppressed(blocks []rootSuppressedBlock) {
	for _, b := range blocks {
		m.instantiated.add(b.fileID, b.kind, b.name)
	}
}
