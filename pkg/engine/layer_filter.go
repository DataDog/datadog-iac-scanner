/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
)

// changedLayerTypes lists, for each later document of an expanded Terraform
// file (see converter.BuildLayers), the block types whose blocks differ from
// the file's first document. The later documents share every other block with
// the first one, so a block that is the same object in both is unchanged.
// Documents of other files, and later documents whose difference cannot be
// told, are left out and are always evaluated.
func changedLayerTypes(files map[string]*model.FileMetadata, docs []model.Document) map[string]map[string]bool {
	first := make(map[string]model.Document)
	for _, d := range docs {
		id, _ := d["id"].(string)
		if f := files[id]; f != nil && f.ExpansionLayer == 0 {
			first[f.FilePath] = d
		}
	}
	var out map[string]map[string]bool
	for _, d := range docs {
		id, _ := d["id"].(string)
		f := files[id]
		if f == nil || f.ExpansionLayer == 0 {
			continue
		}
		base, ok := first[f.FilePath]
		if !ok {
			continue
		}
		changed, ok := diffLayer(base, d)
		if !ok {
			continue
		}
		if out == nil {
			out = make(map[string]map[string]bool)
		}
		out[id] = changed
	}
	return out
}

// layerBlockSections are the top-level sections whose blocks an expansion
// replaces, with whether their blocks are keyed by type and then by name.
var layerBlockSections = map[string]bool{"resource": true, "data": true, "module": false}

// diffLayer compares the first document of a file with a later one. It
// reports false when they differ anywhere but in the blocks of the expanded
// sections.
func diffLayer(base, layer model.Document) (map[string]bool, bool) {
	changed := make(map[string]bool)
	keys := make(map[string]bool, len(base)+len(layer))
	for k := range base {
		keys[k] = true
	}
	for k := range layer {
		keys[k] = true
	}
	for key := range keys {
		switch key {
		case "id", "file":
			continue
		}
		a, b := base[key], layer[key]
		if samePointer(a, b) {
			continue
		}
		byType, isSection := layerBlockSections[key]
		if !isSection || !diffSection(key, byType, a, b, changed) {
			return nil, false
		}
	}
	return changed, true
}

// diffBlocks reports whether two sets of named blocks hold different blocks.
func diffBlocks(a, b map[string]interface{}) bool {
	for name := range unionKeys(a, b) {
		if !samePointer(a[name], b[name]) {
			return true
		}
	}
	return false
}

func unionKeys(a, b map[string]interface{}) map[string]bool {
	out := make(map[string]bool, len(a)+len(b))
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func asMap(v interface{}) (map[string]interface{}, bool) {
	switch m := v.(type) {
	case map[string]interface{}:
		return m, true
	case model.Document:
		return m, true
	}
	return nil, false
}

// samePointer reports whether two values are the very same map.
func samePointer(a, b interface{}) bool {
	am, aok := asMap(a)
	bm, bok := asMap(b)
	if aok && bok {
		return reflect.ValueOf(am).Pointer() == reflect.ValueOf(bm).Pointer()
	}
	return !aok && !bok && reflect.DeepEqual(a, b)
}

// layerFilter picks, for a rule, the documents of a scan it has to evaluate.
type layerFilter struct {
	terms   []*ast.Term
	buckets [][]string
	unknown map[int]bool
	// changed holds, per document, the block types it differs in from its
	// file's first document; nil for a document that is always evaluated.
	changed []map[string]bool
}

// newLayerFilter returns nil when no document is a later layer.
func newLayerFilter(
	terms []*ast.Term, buckets [][]string, unknown []int, allDocs []interface{}, changed map[string]map[string]bool,
) *layerFilter {
	if len(changed) == 0 {
		return nil
	}
	f := &layerFilter{terms: terms, buckets: buckets, unknown: make(map[int]bool, len(unknown)),
		changed: make([]map[string]bool, len(terms))}
	for _, i := range unknown {
		f.unknown[i] = true
	}
	for i, doc := range allDocs {
		if m, ok := doc.(map[string]interface{}); ok {
			if id, ok := m["id"].(string); ok {
				f.changed[i] = changed[id]
			}
		}
	}
	return f
}

// payload returns the input for a rule of the given platform that leaves out
// the later documents whose differences the rule cannot read, or whole when
// there are none.
func (f *layerFilter) payload(
	queryPlatform string, byPlatform map[string]ast.Value, profile *layerProfile, whole ast.Value,
) ast.Value {
	if f == nil || profile == nil || profile.all {
		return whole
	}
	key := canonicalPlatformKey(queryPlatform)
	_, built := byPlatform[key]
	full := key == platformCommon || !built
	list := make([]*ast.Term, 0, len(f.terms))
	skipped := 0
	for i, term := range f.terms {
		if !full && !f.unknown[i] && !contains(f.buckets[i], key) {
			continue
		}
		if f.changed[i] != nil && !profile.reads(f.changed[i]) {
			skipped++
			continue
		}
		list = append(list, term)
	}
	if skipped == 0 {
		return whole
	}
	return assembleDocumentPayload(list)
}

// layerProfiles profiles the Terraform rules of a scan once each.
type layerProfiles struct {
	once      sync.Once
	libraries regoSummaries
	byQuery   sync.Map
}

func (p *layerProfiles) of(query *model.QueryMetadata, libraries func() []string) *layerProfile {
	if !strings.EqualFold(query.Platform, "terraform") {
		return nil
	}
	if cached, ok := p.byQuery.Load(query.Query); ok {
		return cached.(*layerProfile)
	}
	p.once.Do(func() { p.libraries = librarySummaries(libraries()...) })
	profile := queryLayerProfile(query.Content, p.libraries)
	p.byQuery.Store(query.Query, profile)
	return profile
}

// layerFilterEnabled is on unless DD_IAC_LAYER_RULE_FILTER=0.
func layerFilterEnabled() bool { return os.Getenv("DD_IAC_LAYER_RULE_FILTER") != "0" }

// diffSection records the types a section differs in, and reports whether the
// section could be compared.
func diffSection(key string, byType bool, a, b interface{}, changed map[string]bool) bool {
	am, aok := asMap(a)
	bm, bok := asMap(b)
	if !aok || !bok {
		return false
	}
	if !byType {
		if diffBlocks(am, bm) {
			changed[key] = true
		}
		return true
	}
	for blockType := range unionKeys(am, bm) {
		if samePointer(am[blockType], bm[blockType]) {
			continue
		}
		at, atok := asMap(am[blockType])
		bt, btok := asMap(bm[blockType])
		if !atok || !btok {
			return false
		}
		if diffBlocks(at, bt) {
			changed[blockType] = true
		}
	}
	return true
}
