/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2026 Datadog, Inc.
 */

package tfeval

import (
	"context"
	"slices"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/zclconf/go-cty/cty"
)

const (
	maxTerraformFactNodes = 8192
	maxTerraformFactDepth = 64
	countIndexKey         = "index"
	forEachKeyKey         = "key"
	forEachValueKey       = "value"
)

// terraformValueFacts bounds the additive sidecar while leaving legacy
// rendering unbounded as before.
type terraformValueFacts struct {
	values    []model.TerraformValueFact
	nodes     int
	truncated bool
	ancestors []int
}

func (f *terraformValueFacts) append(
	path model.TerraformFactPath,
	state model.TerraformNativeValueState,
	presentation model.TerraformPresentation,
	children model.TerraformChildrenState,
) int {
	switch presentation {
	case model.TerraformPresentationUnproven:
		f.markAncestorsUnproven()
	case model.TerraformPresentationNative:
	default:
		f.markAncestorsAdapted()
	}
	f.values = append(f.values, model.TerraformValueFact{
		Path: path, NativeState: state, Presentation: presentation, Children: children,
	})
	f.nodes++
	return len(f.values) - 1
}

func (f *terraformValueFacts) pushAncestor(index int) {
	f.ancestors = append(f.ancestors, index)
}

func (f *terraformValueFacts) popAncestor() {
	f.ancestors = f.ancestors[:len(f.ancestors)-1]
}

func (f *terraformValueFacts) markAncestorsAdapted() {
	for _, index := range f.ancestors {
		f.values[index].Presentation = model.TerraformPresentationAdapted
	}
}

func (f *terraformValueFacts) markAncestorsUnproven() {
	for _, index := range f.ancestors {
		if f.values[index].Presentation == model.TerraformPresentationNative {
			f.values[index].Presentation = model.TerraformPresentationUnproven
		}
	}
}

func (f *terraformValueFacts) markTruncated() {
	f.truncated = true
	f.markAncestorsUnproven()
}

func (f *terraformValueFacts) markUnproven(index int) {
	if f.values[index].Presentation == model.TerraformPresentationNative {
		f.values[index].Presentation = model.TerraformPresentationUnproven
	}
}

func (f *terraformValueFacts) childPath(
	path model.TerraformFactPath, segment model.PathSegment,
) (model.TerraformFactPath, bool) {
	if f == nil {
		return nil, false
	}
	if f.nodes >= maxTerraformFactNodes || len(path)+1 > maxTerraformFactDepth {
		f.markTruncated()
		return nil, false
	}
	return childFactPath(path, segment), true
}

// AttributesToDocumentWithFacts returns the existing legacy document plus
// value-state facts aligned to its emitted paths. Facts contain no values or
// source expressions. The legacy conversion path remains facts-free unless
// this API is explicitly used.
func AttributesToDocumentWithFacts(ctx context.Context, r *ResolvedResource) (map[string]interface{}, model.TerraformValueFacts) {
	capacity := min(len(r.Attributes), maxTerraformFactNodes)
	facts := &terraformValueFacts{values: make([]model.TerraformValueFact, 0, capacity)}
	doc := attributesToDocumentWithFacts(r.Attributes, r.Body, r.DynamicCounts, r.documentScope, newRenderer(ctx, r), facts)
	if enrichResourceDocument(ctx, r, doc) {
		markCertificateEnrichmentAdapted(facts)
	}
	slices.SortFunc(facts.values, compareTerraformValueFacts)
	return doc, model.TerraformValueFacts{Values: facts.values, Truncated: facts.truncated}
}

func markCertificateEnrichmentAdapted(facts *terraformValueFacts) {
	for i := range facts.values {
		path := facts.values[i].Path
		if len(path) == 1 && !path[0].IsIndex && path[0].Key == "certificate_body" {
			facts.values[i].Presentation = model.TerraformPresentationAdapted
			facts.values[i].Children = model.TerraformChildrenUnknown
			return
		}
	}
}

func nativeFactState(v cty.Value) model.TerraformNativeValueState {
	if v != cty.NilVal && v.IsMarked() {
		v, _ = v.Unmark()
	}
	if v == cty.NilVal || !v.IsKnown() {
		return model.TerraformNativeUnknown
	}
	if v.IsNull() {
		return model.TerraformNativeNull
	}
	if v.IsWhollyKnown() {
		return model.TerraformNativeKnown
	}
	return model.TerraformNativePartial
}

func nativeFactPresentation(v cty.Value, src *attrSource) model.TerraformPresentation {
	if isDocumentAggregate(v.Type()) && src != nil && (src.body != nil || len(src.blocks) > 0) {
		return model.TerraformPresentationAdapted
	}
	return model.TerraformPresentationNative
}

func nativeFactChildren(v cty.Value, src *attrSource, presentation model.TerraformPresentation) model.TerraformChildrenState {
	if presentation != model.TerraformPresentationNative && presentation != model.TerraformPresentationAdapted {
		return model.TerraformChildrenUnknown
	}
	if v == cty.NilVal || v.IsMarked() || !v.IsKnown() || v.IsNull() || !isDocumentAggregate(v.Type()) {
		return model.TerraformChildrenUnknown
	}
	if v.Type().IsSetType() && !v.IsWhollyKnown() {
		// A set's display indices are not stable when one or more members are
		// unknown, so do not publish child paths that could point at another value.
		return model.TerraformChildrenUnknown
	}
	if src != nil && src.dynamic != nil {
		for _, count := range src.dynamic {
			if count == unknownDynamicCount {
				return model.TerraformChildrenOpen
			}
		}
	}
	return model.TerraformChildrenClosed
}

func childFactPath(path model.TerraformFactPath, segment model.PathSegment) model.TerraformFactPath {
	child := make(model.TerraformFactPath, len(path)+1)
	copy(child, path)
	child[len(path)] = segment
	return child
}

func compareTerraformValueFacts(a, b model.TerraformValueFact) int {
	for i := 0; i < min(len(a.Path), len(b.Path)); i++ {
		left, right := a.Path[i], b.Path[i]
		if left.IsIndex != right.IsIndex {
			if left.IsIndex {
				return 1
			}
			return -1
		}
		if left.IsIndex {
			if left.Index < right.Index {
				return -1
			}
			if left.Index > right.Index {
				return 1
			}
		} else if c := strings.Compare(left.Key, right.Key); c != 0 {
			return c
		}
	}
	return len(a.Path) - len(b.Path)
}
