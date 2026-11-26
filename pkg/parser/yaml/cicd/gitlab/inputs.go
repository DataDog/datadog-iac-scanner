/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package gitlab

import (
	"context"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/yamlnode"
	"gopkg.in/yaml.v3"
)

// inputExprRE matches simple GitLab CI input interpolation expressions of the
// form `$[[ inputs.<name> ]]`. Expressions using pipes/functions are left
// untouched so rules see the original syntax.
var (
	inputExprRE      = regexp.MustCompile(`\$\[\[\s*inputs\.([A-Za-z0-9_-]+)\s*\]\]`)
	inputWholeExprRE = regexp.MustCompile(`^\$\[\[\s*inputs\.([A-Za-z0-9_-]+)\s*\]\]$`)
)

// extractIncludeInputs extracts typed input values from an include entry's
// `inputs:` mapping.
func extractIncludeInputs(node *yaml.Node) map[string]*yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	out := make(map[string]*yaml.Node, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		k, v := node.Content[i], node.Content[i+1]
		if k.Kind == yaml.ScalarNode && v != nil && v.Tag != yamlnode.NullTag {
			out[k.Value] = v
		}
	}
	return out
}

// extractSpecInputDefaults extracts typed default values from a `spec: inputs:`
// header document. Cycle cleanup is run on specRoot before extraction so cyclic
// aliases inside input defaults cannot trigger unbounded traversal later.
func extractSpecInputDefaults(specRoot *yaml.Node) map[string]*yaml.Node {
	yamlnode.BreakAliasCycles(specRoot)
	spec := yamlnode.MappingValue(specRoot, kwSpec)
	inputs := yamlnode.MappingValue(spec, "inputs")
	if inputs == nil || inputs.Kind != yaml.MappingNode {
		return nil
	}
	out := make(map[string]*yaml.Node, len(inputs.Content)/2)
	for i := 0; i+1 < len(inputs.Content); i += 2 {
		k, v := inputs.Content[i], inputs.Content[i+1]
		if k.Kind != yaml.ScalarNode || v == nil || v.Kind != yaml.MappingNode {
			continue
		}
		def := yamlnode.ResolveAlias(yamlnode.MappingValue(v, kwDefault))
		if def != nil && def.Tag != yamlnode.NullTag {
			out[k.Value] = def
		}
	}
	return out
}

// mergeInputs overlays include-provided input overrides onto spec defaults.
func mergeInputs(defaults, overrides map[string]*yaml.Node) map[string]*yaml.Node {
	if len(defaults) == 0 && len(overrides) == 0 {
		return nil
	}
	out := make(map[string]*yaml.Node, len(defaults)+len(overrides))
	for k, v := range defaults {
		out[k] = v
	}
	for k, v := range overrides {
		out[k] = v
	}
	return out
}

// markNoInputNodes records every node in root whose subtree contains no `$[[`
// input interpolation marker so parameterized include variants skip untouched
// subtrees in O(1) and share them directly with the base decoded AST.
func markNoInputNodes(root *yaml.Node, noInput map[*yaml.Node]bool) {
	visited := make(map[*yaml.Node]bool)
	var walk func(n *yaml.Node) bool
	walk = func(n *yaml.Node) bool {
		if n == nil {
			return false
		}
		if has, seen := visited[n]; seen {
			return has
		}
		visited[n] = false
		has := false
		switch n.Kind {
		case yaml.ScalarNode:
			has = strings.Contains(n.Value, "$[[")
		case yaml.MappingNode, yaml.SequenceNode:
			for _, child := range n.Content {
				if walk(child) {
					has = true
				}
			}
		}
		visited[n] = has
		if !has {
			noInput[n] = true
		}
		return has
	}
	walk(root)
}

type interpolateVisit struct {
	node    *yaml.Node
	keyOnly bool
}

// Whole container fields (including a sole nested list) can share the input
// value. Mixed lists still materialize their distinct combined output.
type inputInterpolator struct {
	scopes    map[*model.LineOverlay]*yaml.Node
	positions map[*yaml.Node]*model.LineOverlay
	origins   map[*yaml.Node]model.SourcePosition
	edges     map[sequenceEdge]model.SourcePosition
}

// interpolateInputs substitutes `$[[ inputs.<name> ]]` across n using
// copy-on-write and DAG memoization. Subtrees without `$[[` expressions are
// returned unchanged and shared (never mutated), preserving YAML types and
// local comments for scalar substitutions and literal surrounding
// whitespace for embedded substitutions.
func (s *FileState) interpolateInputs(
	n *yaml.Node,
	inputs map[string]*yaml.Node,
	cachedNoInput map[*yaml.Node]bool,
) *yaml.Node {
	if n == nil || len(inputs) == 0 {
		return n
	}
	i := inputInterpolator{positions: s.keyOverlays, scopes: s.useSiteScopes, origins: s.nodeOrigins, edges: s.sequenceOrigins}
	res, _ := i.interpolateNodeCOW(s.ctx, n, inputs, false, cachedNoInput, make(map[interpolateVisit]*yaml.Node))
	return res
}

func (r *inputInterpolator) interpolateNodeCOW(
	ctx context.Context,
	n *yaml.Node,
	inputs map[string]*yaml.Node,
	keyOnly bool,
	cachedNoInput map[*yaml.Node]bool,
	memo map[interpolateVisit]*yaml.Node,
) (*yaml.Node, bool) {
	if n == nil || ctx.Err() != nil {
		return n, false
	}
	if cachedNoInput[n] {
		return n, false
	}
	vk := interpolateVisit{node: n, keyOnly: keyOnly}
	if cached, seen := memo[vk]; seen {
		return cached, cached != n
	}

	switch n.Kind {
	case yaml.ScalarNode:
		res, changed := r.interpolateScalarCOW(ctx, n, inputs, keyOnly)
		memo[vk] = res
		return res, changed
	case yaml.MappingNode:
		return r.interpolateMappingCOW(ctx, n, inputs, cachedNoInput, memo, vk)
	case yaml.SequenceNode:
		return r.interpolateSequenceCOW(ctx, n, inputs, cachedNoInput, memo, vk)
	default:
		memo[vk] = n
		return n, false
	}
}

func (r *inputInterpolator) interpolateMappingCOW(
	ctx context.Context,
	n *yaml.Node,
	inputs map[string]*yaml.Node,
	cachedNoInput map[*yaml.Node]bool,
	memo map[interpolateVisit]*yaml.Node,
	vk interpolateVisit,
) (*yaml.Node, bool) {
	var newContent []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		if ctx.Err() != nil {
			return n, false
		}
		k, v := n.Content[i], n.Content[i+1]
		useLine := r.containerInputLine(v, inputs)
		nk, kChanged := r.interpolateNodeCOW(ctx, k, inputs, true, cachedNoInput, memo)
		if kChanged {
			r.positions[nk] = r.positions[k]
			r.origins[nk] = r.origins[k]
		}
		nv, vChanged := r.interpolateNodeCOW(ctx, v, inputs, false, cachedNoInput, memo)
		if vChanged && useLine > 0 {
			if !kChanged {
				if !Reserve(ctx, 1, nodeAllocationBytes) {
					return n, false
				}
				ownedKey := *k
				nk = &ownedKey
				r.origins[nk] = r.origins[k]
			}
			site := r.origins[v]
			site.Line = useLine
			r.positions[nk] = scopedSourceOverlay(site, nv, r.scopes)
		}
		if kChanged || vChanged {
			if newContent == nil {
				if !Reserve(ctx, 1, nodeAllocationBytes+len(n.Content)*pointerAllocationBytes) {
					return n, false
				}
				newContent = make([]*yaml.Node, len(n.Content))
				copy(newContent, n.Content)
			}
			newContent[i] = nk
			newContent[i+1] = nv
		}
	}
	if newContent == nil {
		memo[vk] = n
		return n, false
	}
	cp := *n
	cp.Content = newContent
	r.origins[&cp] = r.origins[n]
	memo[vk] = &cp
	return &cp, true
}

func (r *inputInterpolator) interpolateSequenceCOW(
	ctx context.Context,
	n *yaml.Node,
	inputs map[string]*yaml.Node,
	cachedNoInput map[*yaml.Node]bool,
	memo map[interpolateVisit]*yaml.Node,
	vk interpolateVisit,
) (*yaml.Node, bool) {
	var newContent []*yaml.Node
	for i, child := range n.Content {
		if ctx.Err() != nil {
			return n, false
		}
		nc, changed := r.interpolateNodeCOW(ctx, child, inputs, false, cachedNoInput, memo)
		if changed {
			if newContent == nil {
				if !Reserve(ctx, 1, nodeAllocationBytes+len(n.Content)*pointerAllocationBytes) {
					return n, false
				}
				newContent = make([]*yaml.Node, len(n.Content))
				copy(newContent, n.Content)
			}
			newContent[i] = nc
		}
	}
	if newContent == nil {
		memo[vk] = n
		return n, false
	}
	cp := *n
	cp.Content = newContent
	for index, old := range n.Content {
		position, exists := r.edges[sequenceEdge{n, index}]
		if old.Kind == yaml.ScalarNode && newContent[index].Kind != yaml.ScalarNode {
			position = r.origins[old]
			exists = true
		}
		if exists {
			r.edges[sequenceEdge{&cp, index}] = position
		}
	}
	r.origins[&cp] = r.origins[n]
	memo[vk] = &cp
	return &cp, true
}

func (r *inputInterpolator) interpolateScalarCOW(
	ctx context.Context,
	n *yaml.Node,
	inputs map[string]*yaml.Node,
	keyOnly bool,
) (*yaml.Node, bool) {
	if !strings.Contains(n.Value, "$[[") {
		return n, false
	}
	if whole := inputWholeExprRE.FindStringSubmatch(n.Value); len(whole) == 2 {
		if val, ok := inputs[whole[1]]; ok && (!keyOnly || val.Kind == yaml.ScalarNode) {
			if val.Kind != yaml.ScalarNode {
				return val, true
			}
			if !Reserve(ctx, 1, nodeAllocationBytes) {
				return n, false
			}
			cloned := cloneScalarAtLine(val, n.Line)
			r.origins[cloned] = r.origins[n]
			cloned.HeadComment = n.HeadComment
			cloned.LineComment = n.LineComment
			cloned.FootComment = n.FootComment
			return cloned, true
		}
	}

	expanded, changed := applyStreamingInputExpansion(ctx, n.Value, inputs)
	if !changed {
		return n, false
	}
	cp := *n
	cp.Value = expanded
	cp.Tag = yamlnode.StrTag
	r.origins[&cp] = r.origins[n]
	return &cp, true
}

// maxScalarBytes limits a newly materialized embedded input string. Whole-value
// scalar substitutions share existing bytes; cumulative allocations are charged
// separately. Reaching a limit rejects the file rather than hiding its contents.
const maxScalarBytes = 1 * 1024 * 1024

func applyStreamingInputExpansion(ctx context.Context, src string, inputs map[string]*yaml.Node) (string, bool) {
	finalLen := len(src)
	changed := false
	for pos := 0; pos < len(src); {
		if ctx.Err() != nil {
			return src, false
		}
		m := inputExprRE.FindStringSubmatchIndex(src[pos:])
		if m == nil {
			break
		}
		name := src[pos+m[2] : pos+m[3]]
		if val, ok := inputs[name]; ok && val.Kind == yaml.ScalarNode {
			changed = true
			finalLen += len(val.Value) - (m[1] - m[0])
		}
		pos += m[1]
	}
	if !changed {
		return src, false
	}
	if finalLen > maxScalarBytes {
		ExceedLimit(ctx, "interpolated scalar bytes")
		return src, false
	}
	if !Reserve(ctx, 1, finalLen) {
		return src, false
	}

	var b strings.Builder
	b.Grow(finalLen)
	for pos := 0; pos < len(src); {
		m := inputExprRE.FindStringSubmatchIndex(src[pos:])
		if m == nil {
			b.WriteString(src[pos:])
			break
		}
		b.WriteString(src[pos : pos+m[0]])
		name := src[pos+m[2] : pos+m[3]]
		if val, ok := inputs[name]; ok && val.Kind == yaml.ScalarNode {
			b.WriteString(val.Value)
		} else {
			b.WriteString(src[pos+m[0] : pos+m[1]])
		}
		pos += m[1]
	}
	return b.String(), true
}

func (r *inputInterpolator) containerInputLine(node *yaml.Node, inputs map[string]*yaml.Node) int {
	for node != nil && node.Kind == yaml.SequenceNode && len(node.Content) == 1 {
		node = node.Content[0]
	}
	if node == nil || node.Kind != yaml.ScalarNode {
		return 0
	}
	match := inputWholeExprRE.FindStringSubmatch(node.Value)
	if len(match) != 2 {
		return 0
	}
	value := inputs[match[1]]
	if value == nil || value.Kind == yaml.ScalarNode {
		return 0
	}
	return node.Line
}
