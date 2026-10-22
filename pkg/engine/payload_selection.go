/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"sort"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
)

// selectablePayload is a payload whose documents can be handed to a rule in
// part, the documents the rule's docSelector selects.
type selectablePayload struct {
	payload ast.Value
	docs    []*ast.Term

	indexOnce sync.Once
	// index lists, for each key, the positions of the documents holding it.
	index map[string][]int

	mu      sync.Mutex
	subsets map[string]ast.Value
	// cached counts the documents the subsets hold, which is bounded so that
	// rules selecting many different sets do not each keep one.
	cached int
}

// maxCachedSubsetsFactor bounds the documents the cached subsets hold, as a
// multiple of the documents of the payload.
const maxCachedSubsetsFactor = 4

func newSelectablePayload(payload ast.Value, docs []*ast.Term) *selectablePayload {
	return &selectablePayload{payload: payload, docs: docs, subsets: map[string]ast.Value{}}
}

func (p *selectablePayload) buildIndex() {
	p.index = make(map[string][]int)
	for i, doc := range p.docs {
		obj, ok := doc.Value.(ast.Object)
		if !ok {
			continue
		}
		for _, key := range documentKeys(obj) {
			p.index[key] = append(p.index[key], i)
		}
	}
}

// forSelector returns the payload holding the documents sel selects, in the
// order of the full payload.
func (p *selectablePayload) forSelector(sel docSelector) ast.Value {
	if sel.all {
		return p.payload
	}
	keys := make([]string, 0, len(sel.keys))
	for k := range sel.keys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	cacheKey := strings.Join(keys, "\x00")

	p.mu.Lock()
	cached, ok := p.subsets[cacheKey]
	p.mu.Unlock()
	if ok {
		return cached
	}

	p.indexOnce.Do(p.buildIndex)
	positions := p.positions(keys)
	if len(positions) == len(p.docs) {
		return p.payload
	}
	terms := make([]*ast.Term, len(positions))
	for i, at := range positions {
		terms[i] = p.docs[at]
	}
	subset := assembleDocumentPayload(terms)

	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.subsets[cacheKey]; ok {
		return existing
	}
	if p.cached+len(terms) <= maxCachedSubsetsFactor*len(p.docs) {
		p.subsets[cacheKey] = subset
		p.cached += len(terms)
	}
	return subset
}

// positions merges the positions of the documents holding any of keys.
func (p *selectablePayload) positions(keys []string) []int {
	var lists [][]int
	total := 0
	for _, k := range keys {
		if list := p.index[k]; len(list) > 0 {
			lists = append(lists, list)
			total += len(list)
		}
	}
	switch len(lists) {
	case 0:
		return nil
	case 1:
		return lists[0]
	}
	merged := make([]int, 0, total)
	for _, list := range lists {
		merged = append(merged, list...)
	}
	sort.Ints(merged)
	out := merged[:0]
	for i, at := range merged {
		if i == 0 || at != merged[i-1] {
			out = append(out, at)
		}
	}
	return out
}

// querySelectors works out the documents each query reads, from its Rego and
// the libraries it is compiled with.
func (q *QueryLoader) querySelectors(queries []model.QueryMetadata) []docSelector {
	libraries := make(map[string]regoFunctions)
	out := make([]docSelector, len(queries))
	for i := range queries {
		platform := queries[i].Platform
		libs, ok := libraries[platform]
		if !ok {
			if generic, known := q.parsedGeneric[platform]; known && q.parsedCommon != nil {
				libs = libraryFunctions(q.parsedCommon, generic)
			}
			libraries[platform] = libs
		}
		if libs == nil {
			out[i] = docSelector{all: true}
			continue
		}
		out[i] = querySelector(queries[i].Content, libs)
	}
	return out
}
