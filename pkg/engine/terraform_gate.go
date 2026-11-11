/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/schedule"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/unknowngate"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	tfmodel "github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

// gateQuery is the result set of a rule compiled on its own.
const gateQuery = "data.datadog.DatadogPolicy"

// terraformPlaceholderRule is the Terraform library rule holding the
// placeholder; the library compares values with it to handle unknowns.
const terraformPlaceholderRule = "data.generic.terraform._placeholder"

// terraformRules holds, per Terraform rule of a scan, what the harvest found
// and the rule's unknown gate, keyed by query name.
type terraformRules struct {
	byQuery map[string]*terraformRule
}

// terraformRule is one rule. Its gate is compiled on the first candidate.
type terraformRule struct {
	name    string
	harvest schedule.Rule
	newGate func() (*unknowngate.Gate, error)

	once       sync.Once
	gate       *unknowngate.Gate
	gateErr    error
	loadLogged atomic.Bool

	candidates atomic.Int64
	suppressed atomic.Int64
}

func (r *terraformRule) loadGate() (*unknowngate.Gate, error) {
	r.once.Do(func() { r.gate, r.gateErr = r.newGate() })
	return r.gate, r.gateErr
}

func (t *terraformRules) rule(query string) *terraformRule {
	if t == nil {
		return nil
	}
	return t.byQuery[query]
}

// newTerraformRules harvests queries and prepares their gates. It copies the
// library modules first: compiling a query rewrites them in place.
func (c *Inspector) newTerraformRules(
	ctx context.Context, queries []model.QueryMetadata, placeholder string, baseStores map[string]storage.Store,
) *terraformRules {
	libs := map[string]*ast.Module{}
	if m := c.QueryLoader.parsedCommon; m != nil {
		libs["Common"] = m.Copy()
	}
	if m := terraformLibrary(c.QueryLoader, queries); m != nil {
		libs["Generic"] = m.Copy()
	} else {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Error().
			Msg("The Terraform library was not found: rules are compiled without it, so none can be harvested or gated")
	}
	harvest := c.QueryLoader.harvestTerraformRules(ctx, queries, copyModules(libs))
	out := &terraformRules{byQuery: make(map[string]*terraformRule, len(queries))}
	for i := range queries {
		q := queries[i]
		out.byQuery[q.Query] = &terraformRule{
			name:    q.Query,
			harvest: harvest[i],
			newGate: func() (*unknowngate.Gate, error) {
				return newRuleGate(&q, placeholder, baseStores, c.QueryLoader, copyModules(libs))
			},
		}
	}
	return out
}

// terraformLibrary is the parsed Terraform library: the module of package
// generic.terraform, else the generic library of the platform of the queries.
func terraformLibrary(q *QueryLoader, queries []model.QueryMetadata) *ast.Module {
	want := ast.MustParseRef("data.generic.terraform")
	for _, m := range q.parsedGeneric {
		if m != nil && m.Package != nil && m.Package.Path.Equal(want) {
			return m
		}
	}
	for i := range queries {
		if m := q.parsedGeneric[queries[i].Platform]; m != nil {
			return m
		}
	}
	return nil
}

func copyModules(in map[string]*ast.Module) map[string]*ast.Module {
	out := make(map[string]*ast.Module, len(in))
	for name, m := range in {
		out[name] = m.Copy()
	}
	return out
}

// newRuleGate compiles the unknown gate of query against libs and its data.
// libs are not retained: compilation rewrites them.
func newRuleGate(
	query *model.QueryMetadata, placeholder string, baseStores map[string]storage.Store, q *QueryLoader, libs map[string]*ast.Module,
) (*unknowngate.Gate, error) {
	mod, err := ast.ParseModuleWithOpts(query.Query, query.Content, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return nil, err
	}
	modules := libs
	modules[query.Query] = mod
	store, ok := baseStores[query.Platform]
	if !ok || !source.IsEmptyInputData(query.InputData) {
		data, err := q.buildMergedInputData(query, nil)
		if err != nil {
			return nil, err
		}
		store = inmem.NewFromReader(bytes.NewBufferString(data))
	}
	return unknowngate.New(unknowngate.Options{
		Placeholder:  placeholder,
		Modules:      modules,
		Query:        gateQuery,
		Capabilities: safeCapabilities(),
		Store:        store,
		Sentinels:    []string{terraformPlaceholderRule},
	})
}

// harvestTerraformRules harvests every query, compiled together with the
// Terraform libraries; a query that does not compile with the others is
// compiled alone. A query the harvest cannot read always runs.
func (q *QueryLoader) harvestTerraformRules(
	ctx context.Context, queries []model.QueryMetadata, libs map[string]*ast.Module,
) []schedule.Rule {
	out := make([]schedule.Rule, len(queries))
	paths := make([]ast.Ref, len(queries))
	modules := make([]*ast.Module, len(queries))
	shared := copyModules(libs)
	for i := range queries {
		pkg := fmt.Sprintf("datadog.q%d", i)
		renamed := pkgDatadogDecl.ReplaceAllString(queries[i].Content, "${1}package "+pkg)
		mod, err := ast.ParseModuleWithOpts(queries[i].Query, renamed, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			out[i] = alwaysRun(err.Error())
			continue
		}
		paths[i] = ast.MustParseRef("data." + pkg + ".DatadogPolicy")
		modules[i] = mod
		shared[fmt.Sprintf("rule%d", i)] = mod
	}
	sharedCompiler := ast.NewCompiler().WithCapabilities(safeCapabilities())
	sharedCompiler.Compile(shared)
	if !sharedCompiler.Failed() {
		h := schedule.NewHarvester(sharedCompiler, schedule.Options{})
		for i := range queries {
			if paths[i] != nil {
				out[i] = h.Harvest(paths[i])
			}
		}
		return out
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Info().Err(sharedCompiler.Errors).Msg("Terraform rules do not compile together; harvesting each rule alone")
	for i := range queries {
		if paths[i] == nil {
			continue
		}
		alone := copyModules(libs)
		alone["rule"] = modules[i]
		c := compileModules(alone)
		if c == nil {
			out[i] = alwaysRun("the rule does not compile")
			continue
		}
		out[i] = schedule.NewHarvester(c, schedule.Options{}).Harvest(paths[i])
	}
	return out
}

func compileModules(modules map[string]*ast.Module) *ast.Compiler {
	c := ast.NewCompiler().WithCapabilities(safeCapabilities())
	c.Compile(modules)
	if c.Failed() {
		return nil
	}
	return c
}

func alwaysRun(reason string) schedule.Rule {
	return schedule.Rule{AlwaysRun: true, Reasons: []string{reason}, ClassReason: reason}
}

// gateResults removes from results the results of an uncertain verdict. A
// result is a candidate (stage 0) when its block holds the placeholder or,
// for a rule that is not anchored, when the blocks it may have read do; the
// gate decides the candidates.
func (t *terraformInput) gateResults(ctx context.Context, qCtx *QueryContext, input ast.Value, results rego.ResultSet) {
	rule := t.rules.rule(qCtx.Query.Metadata.Query)
	if rule == nil {
		return
	}
	items, err := resultItems(results)
	if err != nil || len(items) == 0 {
		return
	}
	cands, at := t.candidates(rule, items, input)
	if len(cands) == 0 {
		return
	}
	contextLogger := logger.FromContext(ctx)
	uncertain := make([]bool, len(cands))
	reasons := make([]string, len(cands))
	gate, err := rule.loadGate()
	if err != nil {
		// A gate that cannot be built is an engine error, not a verdict: the
		// results are kept.
		if rule.loadLogged.CompareAndSwap(false, true) {
			contextLogger.Error().Err(err).Str("queryID", qCtx.Query.Metadata.Query).
				Msg("The unknown gate could not be built; the results of the rule are reported without it")
		}
		return
	}
	rep, err := gate.Check(ctx, input, cands)
	if err != nil {
		contextLogger.Error().Err(err).Str("queryID", qCtx.Query.Metadata.Query).
			Msg("The unknown gate failed; the results of the rule are reported without it")
		return
	}
	for i, v := range rep.Verdicts {
		uncertain[i], reasons[i] = v.Uncertain, v.Reason
	}
	drop := make(map[int]bool, len(cands))
	for i, u := range uncertain {
		if !u {
			continue
		}
		drop[at[i]] = true
		contextLogger.Debug().Str("queryID", qCtx.Query.Metadata.Query).
			Str("result", unknowngate.Identity(cands[i].Result, t.placeholder).String()).
			Str("reason", reasons[i]).Msg("Suppressed an uncertain result")
	}
	rule.candidates.Add(int64(len(cands)))
	rule.suppressed.Add(int64(len(drop)))
	if len(drop) == 0 {
		return
	}
	kept := make([]interface{}, 0, len(items)-len(drop))
	for i, item := range items {
		if !drop[i] {
			kept = append(kept, item)
		}
	}
	results[0].Bindings["result"] = kept
}

// candidates applies stage 0 to items and returns the candidates with the
// index of the item each one is.
func (t *terraformInput) candidates(
	rule *terraformRule, items []interface{}, input ast.Value,
) (cands []unknowngate.Candidate, at []int) {
	minimal := map[string]ast.Value{}
	for i, item := range items {
		v, err := ast.InterfaceToValue(item)
		if err != nil {
			continue
		}
		if cand, ok := t.candidate(rule, v, input, minimal); ok {
			cands = append(cands, cand)
			at = append(at, i)
		}
	}
	return cands, at
}

// candidate applies stage 0 to result res of rule on input.
func (t *terraformInput) candidate(
	rule *terraformRule, res, input ast.Value, minimal map[string]ast.Value,
) (unknowngate.Candidate, bool) {
	var loc *project.Located
	if id, ok := field(res, blockResultField).(ast.String); ok {
		loc = t.projection.Blocks[string(id)]
	}
	h := &rule.harvest
	if loc == nil {
		return t.unlocatedCandidate(h, res)
	}
	if h.Class == schedule.Anchored && !h.AlwaysRun {
		if !loc.Placeholder {
			return unknowngate.Candidate{}, false
		}
		id := blockID(loc)
		in, ok := minimal[id]
		if !ok {
			in = anchoredInput(loc, input)
			minimal[id] = in
		}
		return unknowngate.Candidate{Result: res, Input: in, Scope: blockScope(nil, loc, input)}, true
	}
	return t.relationalCandidate(rule, loc, res, input, minimal)
}

// unlocatedCandidate is stage 0 for a result that names no block.
func (t *terraformInput) unlocatedCandidate(h *schedule.Rule, res ast.Value) (unknowngate.Candidate, bool) {
	if !h.AlwaysRun && !t.projection.Open {
		return unknowngate.Candidate{}, false
	}
	scope := t.placeholderBlocks()
	if len(scope) == 0 {
		scope = noScope
	}
	return unknowngate.Candidate{Result: res, Scope: scope}, true
}

// relationalCandidate is stage 0 for a result of a rule that is not anchored.
// It is a candidate when its block holds the placeholder, a relation list of
// its block ends with it or names a block that holds it, or a block of a type
// the rule reads does.
func (t *terraformInput) relationalCandidate(
	rule *terraformRule, loc *project.Located, res, input ast.Value, minimal map[string]ast.Value,
) (unknowngate.Candidate, bool) {
	h := &rule.harvest
	if !h.AlwaysRun && !loc.Placeholder && !loc.RelPlaceholder && !t.typesUnknown(loc.Root, h.Types) {
		return unknowngate.Candidate{}, false
	}
	cand := unknowngate.Candidate{Result: res, Scope: t.linkedScope(loc, input)}
	if !h.AlwaysRun && len(h.Types) > 0 {
		// The rule reads blocks of these types and what they relate to: the
		// gate falls back to the whole input if this does not reproduce the
		// result.
		key := rule.name + "\x00" + loc.Root
		in, ok := minimal[key]
		if !ok {
			in = t.relationalInput(loc.Root, h.Types, input)
			minimal[key] = in
		}
		cand.Input = in
	}
	return cand, true
}

// noScope is a substitution scope without placeholder: an empty scope would
// let the gate substitute every placeholder of the input, the one the
// library reads from input._dd included.
var noScope = []ast.Value{ast.NewObject()}

// typesUnknown reports whether a block of one of types in root holds the
// placeholder.
func (t *terraformInput) typesUnknown(root string, types []schedule.TypeKey) bool {
	for _, k := range types {
		if k.Type != "" {
			if t.projection.Unknown[project.TypeKey{Root: root, Kind: k.Kind, Type: k.Type}] {
				return true
			}
			continue
		}
		for u := range t.projection.Unknown {
			if u.Root == root && u.Kind == k.Kind {
				return true
			}
		}
	}
	return false
}

// placeholderBlocks are the blocks of the input holding the placeholder, the
// scope of a result that names no block.
func (t *terraformInput) placeholderBlocks() []ast.Value {
	var out []ast.Value
	for _, loc := range t.projection.Blocks {
		if loc.Placeholder {
			out = append(out, loc.Term.Value)
		}
	}
	return out
}

// linkedScope is the substitution scope of a relational result on loc: its
// block, its relation lists, and the blocks they name that hold the
// placeholder.
func (t *terraformInput) linkedScope(loc *project.Located, input ast.Value) []ast.Value {
	scope := blockScope(nil, loc, input)
	id := blockID(loc)
	seen := map[string]bool{}
	var visit func(v ast.Value)
	visit = func(v ast.Value) {
		switch x := v.(type) {
		case ast.String:
			if seen[string(x)] {
				return
			}
			seen[string(x)] = true
			if other := t.projection.Blocks[string(x)]; other != nil && other.Placeholder {
				scope = blockScope(scope, other, input)
			}
		case *ast.Array:
			x.Foreach(func(e *ast.Term) { visit(e.Value) })
		case ast.Object:
			x.Foreach(func(_, e *ast.Term) { visit(e.Value) })
		}
	}
	for _, index := range relationIndexes {
		if lists, ok := field(ddIndex(input, index), id).(ast.Object); ok {
			scope = append(scope, lists)
			visit(lists)
		}
	}
	return scope
}

// blockScope appends the block of loc and its _dd.nested entry, where its
// nested blocks are, to scope.
func blockScope(scope []ast.Value, loc *project.Located, input ast.Value) []ast.Value {
	scope = append(scope, loc.Term.Value)
	if n := field(ddIndex(input, "nested"), blockID(loc)); n != nil {
		scope = append(scope, n)
	}
	return scope
}

// blockID is the id of the block of loc in the input.
func blockID(loc *project.Located) string {
	id, _ := field(field(loc.Term.Value, "_dd_meta"), "id").(ast.String)
	return string(id)
}

// field returns the value at key of v when v is an object, else nil.
func field(v ast.Value, key string) ast.Value {
	obj, ok := v.(ast.Object)
	if !ok {
		return nil
	}
	if t := obj.Get(ast.StringTerm(key)); t != nil {
		return t.Value
	}
	return nil
}

// ddIndex returns the engine index name of input, nil when absent.
func ddIndex(input ast.Value, name string) ast.Value {
	return field(field(input, "_dd"), name)
}

var (
	typedBlockKinds = []string{address.KindResource, address.KindData, address.KindEphemeral, address.KindProvider}
	listBlockKinds  = []string{address.KindModule, address.KindVariable, address.KindOutput, tfmodel.KindLocals}
	relationIndexes = []string{"related", "targets", "referrers"}
)

// anchoredInput is the minimal input of an anchored rule's result on loc:
// the block alone, with the placeholder and the rule arguments of input.
func anchoredInput(loc *project.Located, input ast.Value) ast.Value {
	blocks := make([][2]*ast.Term, 0, len(typedBlockKinds)+len(listBlockKinds))
	for _, kind := range typedBlockKinds {
		byType := ast.ObjectTerm()
		if kind == loc.Kind {
			byType = ast.ObjectTerm(ast.Item(ast.StringTerm(loc.Type), ast.ArrayTerm(loc.Term)))
		}
		blocks = append(blocks, ast.Item(ast.StringTerm(kind), byType))
	}
	for _, kind := range listBlockKinds {
		list := ast.ArrayTerm()
		if kind == loc.Kind {
			list = ast.ArrayTerm(loc.Term)
		}
		blocks = append(blocks, ast.Item(ast.StringTerm(kind), list))
	}
	dd := ast.NewObject(
		ast.Item(ast.StringTerm("blocks"), ast.ObjectTerm(blocks...)),
		ast.Item(ast.StringTerm("by_id"), ast.ObjectTerm(ast.Item(ast.StringTerm(blockID(loc)), loc.Term))),
	)
	for _, name := range relationIndexes {
		dd.Insert(ast.StringTerm(name), ast.ObjectTerm())
	}
	// A nested block list is read by key, so the block keeps its own entry.
	nested := ast.ObjectTerm()
	if entry := field(ddIndex(input, "nested"), blockID(loc)); entry != nil {
		nested = ast.ObjectTerm(ast.Item(ast.StringTerm(blockID(loc)), ast.NewTerm(entry)))
	}
	dd.Insert(ast.StringTerm("nested"), nested)
	for _, name := range []string{"placeholder"} {
		if v := ddIndex(input, name); v != nil {
			dd.Insert(ast.StringTerm(name), ast.NewTerm(v))
		}
	}
	out := ast.NewObject(
		ast.Item(ast.StringTerm("document"), ast.ArrayTerm()),
		ast.Item(ast.StringTerm("_dd"), ast.NewTerm(dd)),
	)
	if args := field(input, "arguments"); args != nil {
		out.Insert(ast.StringTerm("arguments"), ast.NewTerm(args))
	}
	return out
}

// relationalInput is the minimal input of a relational rule on root: the
// blocks of root of the types it reads, the blocks they relate to, directly or
// through other relations, and the relation entries and providers of those.
func (t *terraformInput) relationalInput(root string, types []schedule.TypeKey, input ast.Value) ast.Value {
	m := &minimalInput{t: t, root: root, input: input, have: map[string]bool{}}
	blocks := make([][2]*ast.Term, 0, len(typedBlockKinds)+len(listBlockKinds))
	for _, kind := range typedBlockKinds {
		byType := make([][2]*ast.Term, 0, len(types))
		for _, k := range types {
			if k.Kind == kind && k.Type != "" {
				byType = append(byType, ast.Item(ast.StringTerm(k.Type), m.filter(field(field(ddIndex(input, "blocks"), kind), k.Type))))
			}
		}
		blocks = append(blocks, ast.Item(ast.StringTerm(kind), ast.ObjectTerm(byType...)))
	}
	for _, kind := range listBlockKinds {
		list := ast.ArrayTerm()
		if slices.ContainsFunc(types, func(k schedule.TypeKey) bool { return k.Kind == kind }) {
			list = m.filter(field(ddIndex(input, "blocks"), kind))
		}
		blocks = append(blocks, ast.Item(ast.StringTerm(kind), list))
	}
	byID, relations, nested := m.closure()
	dd := ast.NewObject(
		ast.Item(ast.StringTerm("blocks"), ast.ObjectTerm(blocks...)),
		ast.Item(ast.StringTerm("by_id"), ast.ObjectTerm(byID...)),
	)
	for _, name := range relationIndexes {
		dd.Insert(ast.StringTerm(name), ast.ObjectTerm(relations[name]...))
	}
	dd.Insert(ast.StringTerm("nested"), ast.ObjectTerm(nested...))
	for _, name := range []string{"placeholder"} {
		if v := ddIndex(input, name); v != nil {
			dd.Insert(ast.StringTerm(name), ast.NewTerm(v))
		}
	}
	out := ast.NewObject(
		ast.Item(ast.StringTerm("document"), ast.ArrayTerm()),
		ast.Item(ast.StringTerm("_dd"), ast.NewTerm(dd)),
	)
	if args := field(input, "arguments"); args != nil {
		out.Insert(ast.StringTerm("arguments"), ast.NewTerm(args))
	}
	return out
}

// minimalInput gathers the blocks of a relational rule's minimal input.
type minimalInput struct {
	t     *terraformInput
	root  string
	input ast.Value
	have  map[string]bool
	queue []string
}

func (m *minimalInput) add(id string) {
	if !m.have[id] && m.t.projection.Blocks[id] != nil {
		m.have[id] = true
		m.queue = append(m.queue, id)
	}
}

// filter keeps the blocks of the root of a list of the input.
func (m *minimalInput) filter(list ast.Value) *ast.Term {
	var kept []*ast.Term
	if arr, ok := list.(*ast.Array); ok {
		arr.Foreach(func(b *ast.Term) {
			id := blockTermID(b.Value)
			if loc := m.t.projection.Blocks[id]; loc != nil && loc.Root == m.root {
				kept = append(kept, b)
				m.add(id)
			}
		})
	}
	return ast.ArrayTerm(kept...)
}

// closure adds the blocks the kept ones relate to and returns the by_id items,
// the relation entries and the nested block lists of every block it holds.
func (m *minimalInput) closure() (byID [][2]*ast.Term, relations map[string][][2]*ast.Term, nested [][2]*ast.Term) {
	relations = map[string][][2]*ast.Term{}
	for len(m.queue) > 0 {
		id := m.queue[0]
		m.queue = m.queue[1:]
		loc := m.t.projection.Blocks[id]
		byID = append(byID, ast.Item(ast.StringTerm(id), loc.Term))
		if entry := field(ddIndex(m.input, "nested"), id); entry != nil {
			nested = append(nested, ast.Item(ast.StringTerm(id), ast.NewTerm(entry)))
		}
		if meta, ok := field(loc.Term.Value, "_dd_meta").(ast.Object); ok {
			if p, ok := field(meta, "provider").(ast.String); ok {
				m.add(string(p))
			}
		}
		for _, name := range relationIndexes {
			if entry := field(ddIndex(m.input, name), id); entry != nil {
				relations[name] = append(relations[name], ast.Item(ast.StringTerm(id), ast.NewTerm(entry)))
				forEachID(entry, m.add)
			}
		}
	}
	return byID, relations, nested
}

// forEachID calls f with every string of a relation entry.
func forEachID(v ast.Value, f func(string)) {
	switch x := v.(type) {
	case ast.String:
		f(string(x))
	case *ast.Array:
		x.Foreach(func(e *ast.Term) { forEachID(e.Value, f) })
	case ast.Object:
		x.Foreach(func(_, e *ast.Term) { forEachID(e.Value, f) })
	}
}

func blockTermID(v ast.Value) string {
	meta, _ := field(v, "_dd_meta").(ast.Object)
	id, _ := field(meta, "id").(ast.String)
	return string(id)
}

// logSuppressed logs, per rule, the results the gate suppressed.
func (t *terraformRules) logSuppressed(ctx context.Context) {
	if t == nil {
		return
	}
	contextLogger := logger.FromContext(ctx)
	names := make([]string, 0, len(t.byQuery))
	for name := range t.byQuery {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		r := t.byQuery[name]
		if c := r.candidates.Load(); c > 0 {
			contextLogger.Info().Str("queryID", name).Int64("candidates", c).
				Msgf("Suppressed %d uncertain results", r.suppressed.Load())
		}
	}
}
