/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/schedule"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodel "github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
)

// terraformChunkBlocks bounds the blocks of the projections held at once.
// Roots are projected one by one and evaluated a chunk at a time: rules that
// read blocks one at a time are evaluated once over the roots of a chunk.
const terraformChunkBlocks = 4096

// logCrossMatches logs every cross-root match a projection uses, so that a
// block that clears a finding from another root is visible.
func logCrossMatches(ctx context.Context, p *project.Projection) {
	contextLogger := logger.FromContext(ctx)
	for _, m := range p.Cross {
		line := 0
		if m.Evidence.Block != nil {
			line = m.Evidence.Block.Range.Start.Line
		}
		contextLogger.Info().Str("target", m.Target.Root+"/"+m.Target.Address).
			Str("evidence", m.Evidence.Root+"/"+m.Evidence.Address).
			Str("file", m.Evidence.File).Int("line", line).
			Msg("A literal in another root relates to a block")
	}
}

// logIncompleteness reports the roots whose relations an unresolved module
// call makes incomplete, and how many blocks that reaches.
func logIncompleteness(ctx context.Context, p *project.Projection) {
	contextLogger := logger.FromContext(ctx)
	for _, i := range p.Incompleteness {
		contextLogger.Debug().Str("root", i.Root).Int("unresolved_module_calls", i.Unresolved).
			Int("incomplete_blocks", i.Exposed).Int("blocks", i.Blocks).
			Msg("An unresolved module call makes the relations of the blocks it may reach incomplete")
	}
}

// terraformRoot is a projected root waiting for its chunk to be evaluated.
type terraformRoot struct {
	root  *tfmodel.Root
	input *terraformInput
	// order and digest identify the projection modulo ids (see
	// project.Projection.Digest); they are set when the chunk needs them.
	order  []string
	digest string
}

// terraformRun is what the evaluation of a chunk needs besides the roots.
type terraformRun struct {
	scanID         string
	filesMap       map[string]*model.FileMetadata
	ready          []model.QueryMetadata
	prepared       map[int]*rego.PreparedEvalQuery
	baseStores     map[string]storage.Store
	baseDataHashes map[string]uint64
	routing        *findingRouting
	rules          *terraformRules
	queries        *queryRun
}

// presence counts the blocks of each kind and type of a projection.
func presence(p *project.Projection) map[schedule.TypeKey]schedule.Presence {
	out := map[schedule.TypeKey]schedule.Presence{}
	for id, loc := range p.Blocks {
		if p.External[id] {
			continue
		}
		key := schedule.TypeKey{Kind: loc.Kind}
		switch loc.Kind {
		case schedule.KindResource, schedule.KindData, schedule.KindEphemeral, schedule.KindProvider:
			key.Type = loc.Type
		}
		pr := out[key]
		pr.Blocks++
		out[key] = pr
	}
	return out
}

// planRules are the harvested rules of the run, named by query.
func (r *terraformRun) planRules() []schedule.Rule {
	out := make([]schedule.Rule, len(r.ready))
	for i := range r.ready {
		name := r.ready[i].Query
		if rule := r.rules.rule(name); rule != nil {
			out[i] = rule.harvest
		} else {
			out[i] = alwaysRun("the rule was not harvested")
		}
		out[i].ID = name
	}
	return out
}

// evalChunk evaluates every rule on the roots of a chunk as the plan says:
// relational and always-run rules root by root, the others once over the
// roots that differ.
func (c *Inspector) evalChunk(ctx context.Context, run *terraformRun, chunk []*terraformRoot) ([]model.Vulnerability, error) {
	if len(chunk) == 0 {
		return nil, nil
	}
	roots := make(schedule.Roots, len(chunk))
	byName := make(map[string]*terraformRoot, len(chunk))
	for _, r := range chunk {
		roots[r.root.ID] = presence(r.input.projection)
		byName[r.root.ID] = r
	}
	plan := schedule.NewPlan(run.planRules(), roots, schedule.PlanOptions{})
	index := make(map[string]int, len(run.ready))
	for i := range run.ready {
		index[run.ready[i].Query] = i
	}

	var vulns []model.Vulnerability
	for _, rr := range plan.Relational {
		r := byName[rr.Root]
		found, err := c.runQueries(ctx, run, rr.Rules, index, platformPayloads{full: r.input.projection.Input, terraform: r.input})
		if err != nil {
			return nil, err
		}
		vulns = append(vulns, found...)
	}
	found, err := c.evalAnchored(ctx, run, plan, chunk, index)
	if err != nil {
		return nil, err
	}
	return append(vulns, found...), nil
}

// evalAnchored evaluates the anchored rules once over the merged input of the
// roots that differ, and fans their results out to the duplicates.
func (c *Inspector) evalAnchored(
	ctx context.Context, run *terraformRun, plan schedule.Plan, chunk []*terraformRoot, index map[string]int,
) ([]model.Vulnerability, error) {
	var rules []string
	needed := map[string]bool{}
	for _, b := range plan.Anchored {
		if !slices.Contains(rules, b.Rule) {
			rules = append(rules, b.Rule)
		}
		for _, u := range b.Units {
			needed[u.Root] = true
		}
	}
	if len(rules) == 0 {
		return nil, nil
	}
	var roots []*terraformRoot
	for _, r := range chunk {
		if needed[r.root.ID] {
			roots = append(roots, r)
		}
	}
	units, fan := dedupRoots(ctx, roots)
	projs := make([]*project.Projection, len(units))
	for i, u := range units {
		projs[i] = u.input.projection
	}
	merged := *units[0].input
	merged.projection = project.Merge(projs)
	merged.fan = fan
	return c.runQueries(ctx, run, rules, index, platformPayloads{full: merged.projection.Input, terraform: &merged})
}

// runQueries evaluates the named rules on one payload.
func (c *Inspector) runQueries(
	ctx context.Context, run *terraformRun, names []string, index map[string]int, payloads platformPayloads,
) ([]model.Vulnerability, error) {
	only := make(map[int]bool, len(names))
	for _, name := range names {
		only[index[name]] = true
	}
	if err := c.executeQueries(ctx, run.queries, payloads, only, c.numWorkers); err != nil {
		return nil, err
	}
	return run.queries.findings(false), nil
}

// dedupRoots keeps the first root of each digest. With a single root there is
// nothing to compare.
func dedupRoots(ctx context.Context, roots []*terraformRoot) ([]*terraformRoot, *terraformFanout) {
	if len(roots) < 2 {
		return roots, nil
	}
	first := map[string]*terraformRoot{}
	var units []*terraformRoot
	fan := &terraformFanout{dups: map[string][]*terraformDup{}, ordinal: map[string]int{}}
	for _, r := range roots {
		r.order = r.input.projection.BlockOrder()
		r.digest = r.input.projection.Digest(r.order)
		u, ok := first[r.digest]
		if !ok {
			first[r.digest] = r
			units = append(units, r)
			for i, id := range r.order {
				fan.ordinal[id] = i
			}
			continue
		}
		fan.dups[u.root.ID] = append(fan.dups[u.root.ID], &terraformDup{input: r.input, ids: r.order})
	}
	if len(fan.dups) == 0 {
		return units, nil
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Int("roots", len(roots)).Int("distinct", len(units)).
		Msg("Terraform roots with the same content are evaluated once")
	return units, fan
}

// terraformFanout maps the results of a unit root to its duplicates.
type terraformFanout struct {
	// dups lists, per unit root, the roots with the same content.
	dups map[string][]*terraformDup
	// ordinal is the position of the id of a unit block in the order of its root.
	ordinal map[string]int
}

type terraformDup struct {
	input *terraformInput
	// ids are the block ids of the duplicate in the order of the unit's.
	ids []string
}

// fanCopy is the results of a unit as the duplicate has them.
type fanCopy struct {
	input   *terraformInput
	results rego.ResultSet
}

// copies returns the results of the duplicates. It reads the items before the
// unit's are decoded, which empties them.
func (f *terraformFanout) copies(results rego.ResultSet, blocks map[string]*project.Located) []fanCopy {
	items, err := resultItems(results)
	if err != nil || len(items) == 0 {
		return nil
	}
	byRoot := map[string][]interface{}{}
	for _, item := range items {
		obj, _ := item.(map[string]interface{})
		id, _ := obj[blockResultField].(string)
		if loc := blocks[id]; loc != nil && len(f.dups[loc.Root]) > 0 {
			byRoot[loc.Root] = append(byRoot[loc.Root], item)
		}
	}
	names := make([]string, 0, len(byRoot))
	for name := range byRoot {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []fanCopy
	for _, name := range names {
		for _, dup := range f.dups[name] {
			mapped := make([]interface{}, len(byRoot[name]))
			for i, item := range byRoot[name] {
				mapped[i] = f.remap(item, dup)
			}
			out = append(out, fanCopy{input: dup.input, results: rego.ResultSet{{Bindings: rego.Vars{"result": mapped}}}})
		}
	}
	return out
}

// remap rewrites the block ids of a result for a duplicate.
func (f *terraformFanout) remap(item interface{}, dup *terraformDup) interface{} {
	obj, _ := item.(map[string]interface{})
	out := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		out[k] = v
	}
	out[blockResultField] = f.mapID(obj[blockResultField], dup)
	if ev, ok := obj["evidence"].([]interface{}); ok {
		mapped := make([]interface{}, len(ev))
		for i, e := range ev {
			pair, ok := e.([]interface{})
			if !ok || len(pair) == 0 {
				mapped[i] = e
				continue
			}
			p := slices.Clone(pair)
			p[0] = f.mapID(pair[0], dup)
			mapped[i] = p
		}
		out["evidence"] = mapped
	}
	return out
}

func (f *terraformFanout) mapID(v interface{}, dup *terraformDup) interface{} {
	id, _ := v.(string)
	if n, ok := f.ordinal[id]; ok && n < len(dup.ids) {
		return dup.ids[n]
	}
	return v
}

// decodeResults decodes the results of a rule and, for a rule evaluated once
// over roots with the same content, the copies for the duplicates.
func (c *Inspector) decodeResults(
	ctx context.Context, qCtx *QueryContext, results rego.ResultSet, d time.Duration,
) (vulns []model.Vulnerability, raised int, severity model.Severity, err error) {
	var copies []fanCopy
	if t := qCtx.terraform; t != nil && t.fan != nil {
		copies = t.fan.copies(results, t.projection.Blocks)
	}
	vulns, raised, severity, err = c.DecodeQueryResults(ctx, qCtx, qCtx.Ctx, results, d)
	for _, cp := range copies {
		if err != nil {
			break
		}
		dup := *qCtx
		dup.terraform = cp.input
		var more []model.Vulnerability
		var r int
		var s model.Severity
		more, r, s, err = c.DecodeQueryResults(ctx, &dup, dup.Ctx, cp.results, d)
		raised += r
		if severity == "" {
			severity = s
		}
		vulns = append(vulns, more...)
	}
	return vulns, raised, severity, err
}
