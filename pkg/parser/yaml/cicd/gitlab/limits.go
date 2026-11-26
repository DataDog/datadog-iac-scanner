/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com) Copyright 2026 Datadog, Inc.
 */

package gitlab

import (
	"context"
	"errors"
	"fmt"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/yamlnode"
	"gopkg.in/yaml.v3"
)

// ErrInvalidInclude means an included source is invalid and compilation failed.
var ErrInvalidInclude = errors.New("invalid GitLab CI include")

// ErrInvalidPipeline means a recognized entrypoint cannot be compiled.
var ErrInvalidPipeline = errors.New("invalid GitLab CI pipeline")

// ErrConditionalInclude reports partial coverage without invalidating the
// unconditional pipeline retained for rule evaluation.
var ErrConditionalInclude = errors.New("GitLab CI conditional include requires unavailable context")

// ErrLimitExceeded means the pipeline could not be analyzed completely. Callers
// must discard all documents, including documents completed before the cutoff.
var ErrLimitExceeded = errors.New("GitLab CI analysis resource limit exceeded")

const (
	maxAllocatedNodes      = 1_000_000
	maxAllocatedBytes      = 64 * 1024 * 1024
	maxGraphDepth          = 256
	nodeAllocationBytes    = 256
	pointerAllocationBytes = 8
)

type limitsKey struct{}
type parseLimits struct {
	nodes, bytes int
	cancel       context.CancelCauseFunc
}

// WithLimits creates one allocation/work allowance for the entire file. The
// derived context also stops existing graph walks immediately on exhaustion.
func WithLimits(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(ctx)
	limits := &parseLimits{nodes: maxAllocatedNodes, bytes: maxAllocatedBytes, cancel: cancel}
	return context.WithValue(ctx, limitsKey{}, limits), func() { cancel(nil) }
}

// ExceedLimit aborts the parse without publishing a partial pipeline.
func ExceedLimit(ctx context.Context, operation string) {
	if limits, ok := ctx.Value(limitsKey{}).(*parseLimits); ok {
		limits.cancel(fmt.Errorf("%w: %s", ErrLimitExceeded, operation))
	}
}

// failParse aborts a compilation atomically when an included source is invalid.
func failParse(ctx context.Context, err error) {
	if limits, ok := ctx.Value(limitsKey{}).(*parseLimits); ok {
		limits.cancel(err)
	}
}

// Reserve charges allocations before they happen. Nodes includes traversal work
// and materialized list entries; bytes includes strings and container storage.
func Reserve(ctx context.Context, nodes, bytes int) bool {
	if ctx.Err() != nil {
		return false
	}
	limits, ok := ctx.Value(limitsKey{}).(*parseLimits)
	if !ok {
		return true
	}
	if nodes < 0 || bytes < 0 || nodes > limits.nodes || bytes > limits.bytes {
		ExceedLimit(ctx, "cumulative expansion")
		return false
	}
	limits.nodes -= nodes
	limits.bytes -= bytes
	return true
}

// Scalar strings are shared by YAML clones; their bytes are charged when
// decoded or interpolated, not on every graph visit.
// reserveGraph measures unique DAG nodes, rather than following every logical
// alias path. Charges incrementally and checks depth before recursive helpers
// run, so preflight itself cannot expand an alias bomb or overflow the stack.
func reserveGraph(ctx context.Context, root *yaml.Node) bool {
	type entry struct {
		node  *yaml.Node
		depth int
	}
	stack := []entry{{root, 0}}
	seen := make(map[*yaml.Node]bool)
	for len(stack) > 0 {
		e := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if e.node == nil {
			continue
		}
		if e.depth > maxGraphDepth {
			ExceedLimit(ctx, "YAML nesting depth")
			return false
		}
		if seen[e.node] {
			continue
		}
		seen[e.node] = true
		n := e.node
		// The source index shares sequence entries across use sites.
		if n.Kind == yaml.SequenceNode && !Reserve(ctx, 0, len(n.Content)*pointerAllocationBytes) {
			return false
		}
		if !Reserve(ctx, 1, nodeAllocationBytes+len(n.Content)*pointerAllocationBytes) {
			return false
		}
		if n.Alias != nil {
			stack = append(stack, entry{n.Alias, e.depth + 1})
		}
		for _, child := range n.Content {
			stack = append(stack, entry{child, e.depth + 1})
		}
	}
	return true
}

type mergePair struct{ base, overlay *yaml.Node }

// deepMergeMappings preflights the same pairs the shared merger will allocate.
// Unchanged branches stay shared; all newly built mapping slices are charged.
func deepMergeMappings(ctx context.Context, base, overlay *yaml.Node) *yaml.Node {
	pending := []mergePair{{base, overlay}}
	seen := make(map[mergePair]bool)
	for len(pending) > 0 {
		pair := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		a, b := pair.base, pair.overlay
		if a == nil || b == nil || a.Kind != yaml.MappingNode || b.Kind != yaml.MappingNode || a == b || seen[pair] {
			continue
		}
		seen[pair] = true
		if !Reserve(ctx, 1, nodeAllocationBytes+(len(a.Content)+len(b.Content))*pointerAllocationBytes) {
			return overlay
		}
		index := make(map[string]*yaml.Node, len(b.Content)/2)
		for i := 0; i+1 < len(b.Content); i += 2 {
			index[b.Content[i].Value] = b.Content[i+1]
		}
		for i := 0; i+1 < len(a.Content); i += 2 {
			if v := index[a.Content[i].Value]; v != nil {
				pending = append(pending, mergePair{a.Content[i+1], v})
			}
		}
	}
	if ctx.Err() != nil {
		return overlay
	}
	return yamlnode.DeepMergeMappings(base, overlay)
}
