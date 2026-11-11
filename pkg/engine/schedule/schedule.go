/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package schedule decides which Terraform contract rules run on which
// evaluations, without evaluating them.
//
// The harvest reads a compiled rule and the libraries it reaches and lists the
// block kinds and types the rule can read through input._dd.blocks. A rule
// whose result does not depend on blocks of any other type can be skipped on
// an evaluation holding none of those types. When the harvest cannot bound
// what the rule reads, the rule always runs.
//
// The classification tells anchored rules, whose result for a block depends
// only on that block, from relational ones. The planner turns both into an
// evaluation plan.
package schedule

import (
	"sort"
)

// Block kinds of input._dd.blocks. The first four are keyed by type, the
// others are plain lists.
const (
	KindResource  = "resource"
	KindData      = "data"
	KindEphemeral = "ephemeral"
	KindProvider  = "provider"
	KindModule    = "module"
	KindVariable  = "variable"
	KindOutput    = "output"
	KindLocals    = "locals"
)

var typedKinds = map[string]bool{KindResource: true, KindData: true, KindEphemeral: true, KindProvider: true}

var listKinds = map[string]bool{KindModule: true, KindVariable: true, KindOutput: true, KindLocals: true}

// TypeKey names the blocks a rule reads: a kind and, for typed kinds, a type.
// Type is empty for the list kinds (module, variable, output, locals).
type TypeKey struct {
	Kind string
	Type string
}

func (k TypeKey) String() string {
	if k.Type == "" {
		return k.Kind
	}
	return k.Kind + "." + k.Type
}

func (k TypeKey) less(o TypeKey) bool {
	if k.Kind != o.Kind {
		return k.Kind < o.Kind
	}
	return k.Type < o.Type
}

// Class tells how a rule may be batched.
type Class int

const (
	// Relational rules run once per root.
	Relational Class = iota
	// Anchored rules read one block per result and nothing else of the
	// input, so they may run over several roots at once.
	Anchored
)

func (c Class) String() string {
	if c == Anchored {
		return "anchored"
	}
	return "relational"
}

// Rule is what the harvest knows about one rule.
type Rule struct {
	// ID identifies the rule in a plan. Harvest sets it to the rule path.
	ID string
	// Types the rule can read, sorted. Meaningless when AlwaysRun is set.
	Types []TypeKey
	// AlwaysRun is set when the harvest could not bound what the rule reads.
	AlwaysRun bool
	// Reasons explain AlwaysRun, sorted.
	Reasons []string
	Class   Class
	// ClassReason explains why the rule is relational.
	ClassReason string
	// Relations is set when the rule reads the relation indexes (related,
	// targets, referrers, by_id, provider configurations, literals).
	Relations bool
}

func sortTypes(set map[TypeKey]struct{}) []TypeKey {
	out := make([]TypeKey, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].less(out[j]) })
	return out
}

func sortStrings(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
