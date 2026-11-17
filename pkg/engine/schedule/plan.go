/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package schedule

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// DefaultMaxBatchBlocks bounds the blocks of one anchored batch.
const DefaultMaxBatchBlocks = 4096

// Presence describes the blocks of one kind and type in one root.
type Presence struct {
	// Blocks is the number of blocks.
	Blocks int
	// Digest identifies the projected blocks modulo their ids. Two roots
	// with the same digest for every type a rule reads give that rule the
	// same results up to ids. Empty means unknown: the root is never
	// deduplicated on this type.
	Digest string
}

// Roots maps a root to the kinds and types present in it. Absent types have
// no blocks.
type Roots map[string]map[TypeKey]Presence

// PlanOptions tunes NewPlan.
type PlanOptions struct {
	// MaxBatchBlocks bounds the blocks of an anchored batch. A unit larger
	// than the bound is a batch of its own. Zero means DefaultMaxBatchBlocks.
	MaxBatchBlocks int
}

// Plan says which rule runs on which roots. It is pure data, sorted.
type Plan struct {
	// Skipped lists the (rule, root) pairs that need no evaluation.
	Skipped []Skip
	// Anchored lists the cross-root batches of anchored rules.
	Anchored []Batch
	// Relational lists, per root, the rules evaluated on that root alone.
	Relational []RootRun
}

// Skip is a rule that has no type it reads in a root.
type Skip struct {
	Rule string
	Root string
}

// Batch is one evaluation of an anchored rule over several roots.
type Batch struct {
	Rule  string
	Units []Unit
	// Blocks counts the blocks of the rule's types over the units.
	Blocks int
}

// Unit is a root evaluated in a batch. Its results also stand for the roots
// in Duplicates, whose blocks of the rule's types have the same digests.
type Unit struct {
	Root       string
	DedupKey   string
	Duplicates []string
}

// RootRun is the relational and always-run rules of one root.
type RootRun struct {
	Root  string
	Rules []string
}

// NewPlan schedules rules over roots. A rule that always runs is evaluated
// on every root. Any other rule is skipped on the roots holding none of its
// types: rules must produce no result when no block they read is present.
func NewPlan(rules []Rule, roots Roots, opts PlanOptions) Plan {
	maxBlocks := opts.MaxBatchBlocks
	if maxBlocks <= 0 {
		maxBlocks = DefaultMaxBatchBlocks
	}
	names := make([]string, 0, len(roots))
	for name := range roots {
		names = append(names, name)
	}
	sort.Strings(names)
	sorted := append([]Rule(nil), rules...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	var p Plan
	perRoot := map[string][]string{}
	for i := range sorted {
		r := &sorted[i]
		var units []Unit
		blocks := map[string]int{}
		for _, root := range names {
			if r.AlwaysRun {
				perRoot[root] = append(perRoot[root], r.ID)
				continue
			}
			n, key := present(r.Types, roots[root])
			switch {
			case n == 0:
				p.Skipped = append(p.Skipped, Skip{Rule: r.ID, Root: root})
			case r.Class != Anchored:
				perRoot[root] = append(perRoot[root], r.ID)
			default:
				units = append(units, Unit{Root: root, DedupKey: key})
				blocks[root] = n
			}
		}
		p.Anchored = append(p.Anchored, pack(r.ID, dedup(units), blocks, maxBlocks)...)
	}
	for _, root := range names {
		if ids := perRoot[root]; len(ids) > 0 {
			p.Relational = append(p.Relational, RootRun{Root: root, Rules: ids})
		}
	}
	return p
}

// present counts the blocks of types in a root and hashes their digests. The
// key is empty when no block is present or a digest is unknown.
func present(types []TypeKey, root map[TypeKey]Presence) (n int, key string) {
	known := true
	h := sha256.New()
	for _, t := range types {
		pr, ok := root[t]
		if !ok || pr.Blocks == 0 {
			continue
		}
		n += pr.Blocks
		if pr.Digest == "" {
			known = false
			continue
		}
		for _, s := range []string{t.Kind, t.Type, pr.Digest} {
			h.Write([]byte(s))
			h.Write([]byte{0})
		}
	}
	if n == 0 || !known {
		return n, ""
	}
	return n, hex.EncodeToString(h.Sum(nil))
}

// dedup folds the units sharing a key into the first one, whose root is the
// smallest since units come sorted by root.
func dedup(units []Unit) []Unit {
	first := map[string]int{}
	out := units[:0]
	for _, u := range units {
		if u.DedupKey != "" {
			if i, ok := first[u.DedupKey]; ok {
				out[i].Duplicates = append(out[i].Duplicates, u.Root)
				continue
			}
			first[u.DedupKey] = len(out)
		}
		out = append(out, u)
	}
	return out
}

// pack splits units into batches of at most maxBlocks blocks, in order.
func pack(rule string, units []Unit, blocks map[string]int, maxBlocks int) []Batch {
	var out []Batch
	var cur Batch
	for _, u := range units {
		n := blocks[u.Root]
		if len(cur.Units) > 0 && cur.Blocks+n > maxBlocks {
			out = append(out, cur)
			cur = Batch{}
		}
		cur.Rule = rule
		cur.Units = append(cur.Units, u)
		cur.Blocks += n
	}
	if len(cur.Units) > 0 {
		out = append(out, cur)
	}
	return out
}
