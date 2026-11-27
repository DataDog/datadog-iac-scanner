/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/contractlibs"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"golang.org/x/sync/singleflight"
)

const (
	contractV2EntryRule      = "results"
	contractV2RemediateFunc  = "remediate"
	contractV2InputResources = "resources"
	contractV2RelationsField = "relations"
	contractV2ObjectGet      = "object.get"
	contractV2Query          = "result = data.datadog.results"
	contractV2RemediateQry   = "out = data.datadog.remediate(input.resource, input.finding)"
)

type contractV2PreparedRule struct {
	results   *rego.PreparedEvalQuery
	remediate *rego.PreparedEvalQuery
	compiler  *ast.Compiler
	store     storage.Store
}

type contractV2SharedSpec struct {
	index        int
	module       *ast.Module
	hasRemediate bool
}

var sharedContractV2PreparedQueryCache struct {
	sync.Mutex
	key      uint64
	prepared map[int]contractV2PreparedRule
	flight   singleflight.Group
}

func resetContractV2PreparedQueryCacheForTest() {
	sharedContractV2PreparedQueryCache.Lock()
	sharedContractV2PreparedQueryCache.key = 0
	sharedContractV2PreparedQueryCache.prepared = nil
	sharedContractV2PreparedQueryCache.Unlock()
}

func sameContractV2Store(a, b storage.Store) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	typeOfA, typeOfB := reflect.TypeOf(a), reflect.TypeOf(b)
	if typeOfA != typeOfB || !typeOfA.Comparable() {
		return false
	}
	return a == b
}

// contractV2Rule holds one analyzed, compiled Contract v2 rule.
// Unknown safety is provided by the 4-state input model and data.datadog.iac
// facade (verified in CI via pkg/ruletest unknown mutations).
type contractV2Rule struct {
	meta              model.QueryMetadata
	prepared          *rego.PreparedEvalQuery
	remediatePrepared *rego.PreparedEvalQuery
	sharedCompiler    *ast.Compiler
	sharedStore       storage.Store
	sharedPackage     string
	partialSetResults bool
	hasRemediate      bool
	types             map[string]bool
	wildcard          bool
	scopeRoot         bool
	needsRelations    bool
	needsProviders    bool
	needsStaticBlocks bool
	hasNoResources    bool
	needsJSON         bool
	needsFilterAST    bool
}

// UsesContractV2 reports whether q is a Contract v2 rule. Contract selection
// requires zero metadata.json changes: v2 rules declare the top-level entry
// rule `results` (and not legacy `DatadogPolicy`).
func UsesContractV2(q *model.QueryMetadata) bool {
	if q == nil || strings.TrimSpace(q.Content) == "" {
		return false
	}
	_, ok := analyzeContractV2Rule(q)
	return ok
}

// analyzeContractV2Rule parses q once, checks whether it uses Contract v2
// (`results` entry rule), and extracts its target resource types, scope, and
// demand flags for inverted-index dispatch and demand-driven projection.
// nolint:gocyclo
func analyzeContractV2Rule(q *model.QueryMetadata) (*contractV2Rule, bool) {
	mod, err := ast.ParseModuleWithOpts(q.Query, q.Content, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil || mod == nil {
		return nil, false
	}
	hasResults, hasLegacy, hasRemediate := false, false, false
	partialSetResults := true
	for _, r := range mod.Rules {
		if r.Head == nil {
			continue
		}
		name := r.Head.Ref().String()
		if name == contractV2EntryRule && len(r.Head.Args) == 0 {
			if r.Head.Key == nil || r.Head.Value != nil || r.Else != nil {
				partialSetResults = false
			}
		}
		if name == contractV2RemediateFunc && len(r.Head.Args) == 2 {
			hasRemediate = true
			continue
		}
		if len(r.Head.Args) > 0 {
			continue
		}
		switch name {
		case contractV2EntryRule:
			if r.Head.Key != nil {
				hasResults = true
			}
		case "DatadogPolicy":
			hasLegacy = true
		}
	}
	if !hasResults || hasLegacy {
		return nil, false
	}

	spec := &contractV2Rule{
		meta:              *q,
		hasRemediate:      hasRemediate,
		partialSetResults: partialSetResults,
		types:             make(map[string]bool),
	}

	constCollections := extractTopLevelStringCollections(mod)
	imports := resolveModuleImports(mod)

	for _, rule := range mod.Rules {
		inspectRuleAST(rule, imports, constCollections, spec)
	}

	if len(spec.types) == 0 || spec.hasNoResources {
		spec.wildcard = true
	}
	finalizeContractV2Demand(spec)
	return spec, true
}

func finalizeContractV2Demand(spec *contractV2Rule) {
	for t := range spec.types {
		if strings.HasPrefix(t, "provider.") {
			spec.needsProviders = true
		} else if t == "variable" || t == tfSectionOutput || t == "module" {
			spec.needsStaticBlocks = true
		}
	}
	if spec.wildcard {
		spec.needsStaticBlocks = true
		spec.needsProviders = true
	}
	// Providers, absence (`no_resources`), wildcards, and root-level reads
	// must evaluate per root so unrelated roots are never chunked together.
	// Relations are projected on every resource, so reading one resource's
	// relations does not by itself require root scope.
	if spec.needsProviders || spec.hasNoResources || spec.wildcard {
		spec.scopeRoot = true
	}
}

type contractLibraryRule struct {
	rule   *ast.Rule
	module *ast.Module
}

type contractLibraryInspector struct {
	spec  *contractV2Rule
	index map[string][]contractLibraryRule
	seen  map[string]bool
}

// Library helpers can hide relation, JSON, provider, or inventory reads from
// the query module. Follow only reachable library rules so unrelated helpers
// do not turn simple scalar rules into full-root graph evaluations.
func inspectContractV2Libraries(spec *contractV2Rule, libraries ...*ast.Module) {
	walker := contractLibraryInspector{spec: spec, index: map[string][]contractLibraryRule{}, seen: map[string]bool{}}
	for _, mod := range libraries {
		if mod == nil {
			continue
		}
		for _, rule := range mod.Rules {
			if rule.Head == nil {
				continue
			}
			name := mod.Package.Path.String() + "." + rule.Head.Ref().String()
			walker.index[name] = append(walker.index[name], contractLibraryRule{rule, mod})
		}
	}
	query, err := ast.ParseModuleWithOpts(spec.meta.Query, spec.meta.Content, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return
	}
	for _, rule := range query.Rules {
		walker.visit(rule, query)
	}
	finalizeContractV2Demand(spec)
}

func (w *contractLibraryInspector) visit(rule *ast.Rule, mod *ast.Module) {
	imports := resolveModuleImports(mod)
	ast.WalkRefs(rule, func(ref ast.Ref) bool {
		name := resolveRefName(ref, imports)
		if !strings.HasPrefix(name, "data.") {
			name = mod.Package.Path.String() + "." + name
		}
		for key, candidates := range w.index {
			// A reference to an entire package (including dynamic lookup) may
			// invoke any exported rule beneath it.
			if (name != key && !strings.HasPrefix(key, name+".")) || w.seen[key] {
				continue
			}
			w.seen[key] = true
			for _, candidate := range candidates {
				inspectRuleAST(candidate.rule, resolveModuleImports(candidate.module), extractTopLevelStringCollections(candidate.module), w.spec)
				w.visit(candidate.rule, candidate.module)
			}
		}
		return false
	})
}

func resolveModuleImports(mod *ast.Module) map[string]string {
	out := make(map[string]string, len(mod.Imports))
	for _, imp := range mod.Imports {
		ref, ok := imp.Path.Value.(ast.Ref)
		if !ok || len(ref) == 0 {
			continue
		}
		alias := string(imp.Alias)
		if alias == "" {
			if s, ok := ref[len(ref)-1].Value.(ast.String); ok {
				alias = string(s)
			}
		}
		if alias != "" {
			out[alias] = ref.String()
		}
	}
	return out
}

// isConstantRuleBody reports whether body represents a constant rule assignment
// (`x := ...`). In OPA Rego v1, constant assignments have an implicit body `[true]`.
func isConstantRuleBody(body ast.Body) bool {
	if len(body) == 0 {
		return true
	}
	if len(body) != 1 || body[0].Negated || body[0].IsCall() {
		return false
	}
	term, ok := body[0].Terms.(*ast.Term)
	if !ok {
		return false
	}
	b, ok := term.Value.(ast.Boolean)
	return ok && bool(b)
}

type constStringCollection struct {
	keys   []string // non-nil only when EVERY key (for objects) or element (for sets) is a string literal
	values []string // non-nil only when EVERY value/element is a string literal
}

// nolint:gocyclo
func extractTopLevelStringCollections(mod *ast.Module) map[string]constStringCollection {
	out := make(map[string]constStringCollection)
	for _, r := range mod.Rules {
		if !isConstantRuleBody(r.Body) || r.Head == nil || r.Head.Value == nil {
			continue
		}
		name := r.Head.Ref().String()
		if name == "" {
			continue
		}
		switch v := r.Head.Value.Value.(type) {
		case ast.Set:
			items := extractAllStringLiteralsFromSet(v)
			if len(items) > 0 {
				out[name] = constStringCollection{keys: items, values: items}
			}
		case *ast.Array:
			items := extractAllStringLiteralsFromArray(v)
			if len(items) > 0 {
				out[name] = constStringCollection{values: items}
			}
		case ast.Object:
			var keys, vals []string
			allKeysStr, allValsStr := true, true
			_ = v.Iter(func(k, val *ast.Term) error {
				if s, ok := k.Value.(ast.String); ok {
					keys = append(keys, string(s))
				} else {
					allKeysStr = false
				}
				if s, ok := val.Value.(ast.String); ok {
					vals = append(vals, string(s))
				} else {
					allValsStr = false
				}
				return nil
			})
			col := constStringCollection{}
			if allKeysStr && len(keys) > 0 {
				col.keys = keys
			}
			if allValsStr && len(vals) > 0 {
				col.values = vals
			}
			if len(col.keys) > 0 || len(col.values) > 0 {
				out[name] = col
			}
		}
	}
	return out
}

func extractAllStringLiteralsFromSet(s ast.Set) []string {
	if s.Len() == 0 {
		return nil
	}
	var out []string
	allStr := true
	s.Foreach(func(t *ast.Term) {
		if str, ok := t.Value.(ast.String); ok {
			out = append(out, string(str))
		} else {
			allStr = false
		}
	})
	if !allStr {
		return nil
	}
	return out
}

func extractAllStringLiteralsFromArray(a *ast.Array) []string {
	if a.Len() == 0 {
		return nil
	}
	out := make([]string, 0, a.Len())
	for i := 0; i < a.Len(); i++ {
		str, ok := a.Elem(i).Value.(ast.String)
		if !ok {
			return nil
		}
		out = append(out, string(str))
	}
	return out
}

// nolint:gocyclo
func inspectRuleAST(
	rule *ast.Rule,
	imports map[string]string,
	constCols map[string]constStringCollection,
	spec *contractV2Rule,
) {
	ast.WalkTerms(rule, func(term *ast.Term) bool {
		if field, ok := term.Value.(ast.String); ok && string(field) == contractV2RelationsField {
			spec.needsRelations = true
		}
		if call, ok := term.Value.(ast.Call); ok && len(call) >= 3 {
			operator, ok := call[0].Value.(ast.Ref)
			if ok && resolveRefName(operator, imports) == contractV2ObjectGet &&
				objectGetNeedsRelations(call[1], call[2]) {
				spec.needsRelations = true
			}
		}
		return false
	})

	varToTypes := make(map[string][]string)
	resourceVars := make(map[string]bool)
	isResourceCollection := func(term *ast.Term) bool {
		ref, ok := term.Value.(ast.Ref)
		return ok && len(ref) >= 3 &&
			ref[0].Value.Compare(ast.Var("input")) == 0 &&
			ref[1].Value.Compare(ast.String(contractV2InputResources)) == 0
	}
	recordMember := func(op string, ops []*ast.Term) {
		switch {
		case op == ast.Member.Name && len(ops) == 2:
			// `some v in dom`: binds values for sets, arrays, and objects.
			if v, ok := ops[0].Value.(ast.Var); ok {
				if isResourceCollection(ops[1]) {
					resourceVars[string(v)] = true
				}
				if vals := extractInlineCollectionStrings(ops[1], constCols, false); len(vals) > 0 {
					varToTypes[string(v)] = vals
				}
			}
		case op == ast.MemberWithKey.Name && len(ops) == 3:
			// `some k, v in dom`: binds k to keys and v to values.
			if kv, ok := ops[0].Value.(ast.Var); ok {
				if keys := extractInlineCollectionStrings(ops[2], constCols, true); len(keys) > 0 {
					varToTypes[string(kv)] = keys
				}
			}
			if vv, ok := ops[1].Value.(ast.Var); ok {
				if isResourceCollection(ops[2]) {
					resourceVars[string(vv)] = true
				}
				if vals := extractInlineCollectionStrings(ops[2], constCols, false); len(vals) > 0 {
					varToTypes[string(vv)] = vals
				}
			}
		}
	}
	for _, expr := range rule.Body {
		if expr.IsCall() {
			recordMember(expr.Operator().String(), expr.Operands())
			continue
		}
		if sd, ok := expr.Terms.(*ast.SomeDecl); ok {
			for _, sym := range sd.Symbols {
				if call, ok := sym.Value.(ast.Call); ok && len(call) >= 3 {
					recordMember(call[0].String(), call[1:])
				}
			}
		}
	}

	// Enforce root isolation independently of relation/provider usage:
	// a rule is safe for multi-root chunking ONLY if `input.resources` appears
	// at most once per `results` body as a single top-level positive element
	// iteration (never inside helpers, self-joins, `not`, `every`, comprehensions,
	// or aggregate calls like `count(input.resources.<T>)`).
	isResultsRule := rule.Head != nil && len(rule.Head.Args) == 0 && rule.Head.Ref().String() == contractV2EntryRule
	resRefsInBody := 0
	for _, expr := range rule.Body {
		exprResRefs := countInputResourcesRefs(expr)
		if exprResRefs == 0 {
			continue
		}
		resRefsInBody += exprResRefs
		if !isResultsRule || exprResRefs > 1 || !isSimpleResourceIterationExpr(expr) {
			spec.scopeRoot = true
		}
	}
	if resRefsInBody > 1 {
		spec.scopeRoot = true
	}

	ast.WalkRefs(rule, func(ref ast.Ref) bool {
		if len(ref) >= 2 {
			base, isVar := ref[0].Value.(ast.Var)
			if isVar && base == ast.Var("input") && len(ref) >= 4 && ref[1].Value.Compare(ast.String(contractV2InputResources)) == 0 {
				for _, step := range ref[3:] {
					if field, ok := step.Value.(ast.String); ok && string(field) == contractV2RelationsField {
						spec.needsRelations = true
						break
					}
				}
			}
			if isVar && base != ast.Var("input") {
				for _, step := range ref[1:] {
					if field, ok := step.Value.(ast.String); ok && string(field) == contractV2RelationsField {
						spec.needsRelations = true
						break
					}
				}
			}
		}
		if len(ref) >= 2 && ref[0].Value.Compare(ast.Var("input")) == 0 {
			if k, ok := ref[1].Value.(ast.String); ok {
				switch string(k) {
				case contractV2InputResources:
					if len(ref) >= 3 {
						switch step := ref[2].Value.(type) {
						case ast.String:
							spec.types[string(step)] = true
						case ast.Var:
							if bound := varToTypes[string(step)]; len(bound) > 0 {
								for _, t := range bound {
									spec.types[t] = true
								}
							} else {
								spec.wildcard = true
							}
						default:
							spec.wildcard = true
						}
					} else {
						spec.wildcard = true
					}
				case "by_id", "scope_complete":
					spec.scopeRoot = true
					spec.needsRelations = true
				}
			} else {
				spec.wildcard = true
			}
		}
		// Detect direct reads of res.derived.template_parts / derived.json.
		for i := 1; i+1 < len(ref); i++ {
			if s, ok := ref[i].Value.(ast.String); ok && string(s) == "derived" {
				if next, ok := ref[i+1].Value.(ast.String); ok {
					switch string(next) {
					case "json", "json_refs", "json_unknown", "template_parts":
						spec.needsJSON = true
					case "filter_expr":
						spec.needsFilterAST = true
					}
				}
			}
		}

		resolved := resolveRefName(ref, imports)
		switch {
		case strings.HasPrefix(resolved, "data.datadog.iac.related"),
			strings.HasPrefix(resolved, "data.datadog.iac.no_related"),
			strings.HasPrefix(resolved, "data.datadog.iac.targets"),
			strings.HasPrefix(resolved, "data.datadog.iac.targets_complete"),
			strings.HasPrefix(resolved, "data.datadog.iac.referrers"),
			strings.HasPrefix(resolved, "data.datadog.iac.no_referrers"):
			spec.needsRelations = true
			spec.scopeRoot = true
		case strings.HasPrefix(resolved, "data.datadog.iac.no_resources"):
			spec.hasNoResources = true
			spec.wildcard = true
			spec.scopeRoot = true
		case strings.HasPrefix(resolved, "data.datadog.terraform.provider_config"),
			strings.HasPrefix(resolved, "data.datadog.terraform.same_provider_config"):
			spec.needsProviders = true
			spec.scopeRoot = true
		case strings.HasPrefix(resolved, "data.datadog.iac.json"),
			strings.HasPrefix(resolved, "data.datadog.iac.template_parts"):
			spec.needsJSON = true
		case strings.HasPrefix(resolved, "data.datadog.terraform.filter_"):
			spec.needsFilterAST = true
		}
		return false
	})

	// Calls nested inside membership declarations, comprehensions, and rule
	// heads are terms rather than expressions. A bare input passed there can
	// also expose the entire inventory (for example object.get(input, ...)).
	ast.WalkTerms(rule, func(term *ast.Term) bool {
		if call, ok := term.Value.(ast.Call); ok && len(call) > 1 {
			op := call[0].String()
			// object.get(r, "relations" | ["relations", ...], _) reads the
			// relations field of whatever r is bound to.
			if operator, ok := call[0].Value.(ast.Ref); ok && len(call) >= 3 &&
				resolveRefName(operator, imports) == contractV2ObjectGet && objectGetNeedsRelations(call[1], call[2]) {
				spec.needsRelations = true
			}
			if op == "object.keys" {
				for _, operand := range call[1:] {
					if variable, ok := operand.Value.(ast.Var); ok && resourceVars[string(variable)] {
						spec.needsRelations = true
					}
				}
			}
			for _, operand := range call[1:] {
				if isBareContractInput(operand) {
					spec.wildcard = true
					spec.scopeRoot = true
				}
			}
		}
		return false
	})

	ast.WalkExprs(rule, func(expr *ast.Expr) bool {
		if !expr.IsCall() {
			return false
		}
		op := resolveRefName(expr.Operator(), imports)
		ops := expr.Operands()
		if op == contractV2ObjectGet && len(ops) >= 2 && objectGetNeedsRelations(ops[0], ops[1]) {
			spec.needsRelations = true
		}
		if op == "walk" {
			for _, operand := range ops {
				if variable, ok := operand.Value.(ast.Var); ok && resourceVars[string(variable)] {
					spec.needsRelations = true
				}
			}
		}
		// Passing bare `input` as an operand (e.g. helper(input, r) or
		// object.get(input, ...)) prevents static type narrowing.
		for _, operand := range ops {
			if isBareContractInput(operand) {
				spec.wildcard = true
				spec.scopeRoot = true
			}
		}
		if strings.HasPrefix(op, "data.datadog.iac.no_resources") && len(ops) >= 1 {
			spec.hasNoResources = true
			spec.wildcard = true
			spec.scopeRoot = true
			if s, ok := ops[0].Value.(ast.String); ok {
				spec.types[string(s)] = true
			}
		}
		return false
	})

	if rule.Else != nil {
		inspectRuleAST(rule.Else, imports, constCols, spec)
	}
}

func objectGetNeedsRelations(receiver, key *ast.Term) bool {
	return objectGetReadsRelations(key) || (objectGetHasDynamicKey(key) && !isContractInputResourcesObject(receiver))
}

func isContractInputResourcesObject(term *ast.Term) bool {
	ref, ok := term.Value.(ast.Ref)
	return ok && len(ref) == 2 &&
		ref[0].Value.Compare(ast.Var("input")) == 0 &&
		ref[1].Value.Compare(ast.String(contractV2InputResources)) == 0
}

func objectGetHasDynamicKey(key *ast.Term) bool {
	switch value := key.Value.(type) {
	case ast.String:
		return false
	case *ast.Array:
		for i := 0; i < value.Len(); i++ {
			if _, ok := value.Elem(i).Value.(ast.String); !ok {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func objectGetReadsRelations(key *ast.Term) bool {
	switch value := key.Value.(type) {
	case ast.String:
		return string(value) == contractV2RelationsField
	case *ast.Array:
		if value.Len() == 0 {
			return false
		}
		first, ok := value.Elem(0).Value.(ast.String)
		return ok && string(first) == contractV2RelationsField
	default:
		return false
	}
}

func isBareContractInput(term *ast.Term) bool {
	switch value := term.Value.(type) {
	case ast.Var:
		return value == ast.Var("input")
	case ast.Ref:
		return len(value) == 1 && value[0].Equal(ast.VarTerm("input"))
	default:
		return false
	}
}

func resolveRefName(ref ast.Ref, imports map[string]string) string {
	if len(ref) == 0 {
		return ""
	}
	head, ok := ref[0].Value.(ast.Var)
	if !ok {
		return ref.String()
	}
	base := string(head)
	if full, found := imports[base]; found {
		base = full
	}
	var b strings.Builder
	b.WriteString(base)
	for _, t := range ref[1:] {
		s, ok := t.Value.(ast.String)
		if !ok {
			break
		}
		b.WriteByte('.')
		b.WriteString(string(s))
	}
	return b.String()
}

// nolint:gocyclo
func extractInlineCollectionStrings(term *ast.Term, constCols map[string]constStringCollection, wantKeys bool) []string {
	if term == nil {
		return nil
	}
	switch v := term.Value.(type) {
	case ast.Var:
		col := constCols[string(v)]
		if wantKeys {
			return col.keys
		}
		return col.values
	case ast.Ref:
		if len(v) == 1 {
			if name, ok := v[0].Value.(ast.Var); ok {
				col := constCols[string(name)]
				if wantKeys {
					return col.keys
				}
				return col.values
			}
		}
	case ast.Set:
		return extractAllStringLiteralsFromSet(v)
	case *ast.Array:
		if wantKeys {
			return nil
		}
		return extractAllStringLiteralsFromArray(v)
	case ast.Object:
		var out []string
		allStr := true
		_ = v.Iter(func(k, val *ast.Term) error {
			target := val
			if wantKeys {
				target = k
			}
			if s, ok := target.Value.(ast.String); ok {
				out = append(out, string(s))
			} else {
				allStr = false
			}
			return nil
		})
		if !allStr || len(out) == 0 {
			return nil
		}
		return out
	}
	return nil
}

// compileContractV2Rules compiles all Contract v2 queries once against
// data.datadog.results and the embedded Contract v2 libraries.
func (c *Inspector) compileContractV2Rules(
	ctx context.Context,
	specs []*contractV2Rule,
	baseStores map[string]storage.Store,
	baseDataHashes map[string]uint64,
) ([]*contractV2Rule, error) {
	v2Libs, err := contractlibs.Modules()
	if err != nil {
		return nil, err
	}
	readyByIndex := make([]*contractV2Rule, len(specs))
	groups, sharedPlans, isolatedIndices, err := c.contractV2SharePlan(ctx, specs, baseStores)
	if err != nil {
		return nil, err
	}
	sharedFallback, err := c.compileContractV2SharedSpecs(
		ctx, specs, sharedPlans, groups, v2Libs, baseStores, baseDataHashes, readyByIndex,
	)
	if err != nil {
		return nil, err
	}
	isolatedIndices = append(isolatedIndices, sharedFallback...)
	if err := c.compileContractV2IsolatedSpecs(ctx, specs, isolatedIndices, v2Libs, baseStores, baseDataHashes, readyByIndex); err != nil {
		return nil, err
	}
	ready := make([]*contractV2Rule, 0, len(specs))
	for _, spec := range readyByIndex {
		if spec != nil {
			ready = append(ready, spec)
		}
	}
	return ready, nil
}

func (c *Inspector) contractV2SharePlan(
	ctx context.Context,
	specs []*contractV2Rule,
	baseStores map[string]storage.Store,
) (sharedByPlatform map[string][]contractV2SharedSpec, sharedPlans []contractV2SharedSpec, isolatedIndices []int, err error) {
	sharedByPlatform = make(map[string][]contractV2SharedSpec)
	for i, spec := range specs {
		if ctx.Err() != nil {
			return nil, nil, nil, ctx.Err()
		}
		inspectContractV2Libraries(spec, c.QueryLoader.parsedCommon, c.QueryLoader.parsedGeneric[spec.meta.Platform])
		if !source.IsEmptyInputData(spec.meta.InputData) || baseStores[spec.meta.Platform] == nil {
			isolatedIndices = append(isolatedIndices, i)
			continue
		}
		module, shareable := contractV2ModuleForSharedCompiler(&spec.meta, i)
		if !shareable {
			isolatedIndices = append(isolatedIndices, i)
			continue
		}
		shared := contractV2SharedSpec{index: i, module: module, hasRemediate: spec.hasRemediate}
		sharedPlans = append(sharedPlans, shared)
		sharedByPlatform[spec.meta.Platform] = append(sharedByPlatform[spec.meta.Platform], shared)
	}
	return sharedByPlatform, sharedPlans, isolatedIndices, nil
}

func (c *Inspector) compileContractV2SharedSpecs(
	ctx context.Context,
	specs []*contractV2Rule,
	plans []contractV2SharedSpec,
	groups map[string][]contractV2SharedSpec,
	v2Libs map[string]*ast.Module,
	baseStores map[string]storage.Store,
	baseDataHashes map[string]uint64,
	readyByIndex []*contractV2Rule,
) ([]int, error) {
	if len(plans) == 0 {
		return nil, nil
	}
	var prepared map[int]contractV2PreparedRule
	var err error
	if c.useRulesCache {
		prepared, err = c.loadSharedContractV2Rules(ctx, specs, plans, groups, v2Libs, baseStores, baseDataHashes)
	} else {
		prepared, err = c.compileSharedContractV2Rules(ctx, groups, v2Libs, baseStores)
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// A shared compile conflict must not make otherwise valid isolated rules
		// disappear. Retry these rules through the established single-rule path.
		fallback := make([]int, 0, len(plans))
		for _, plan := range plans {
			fallback = append(fallback, plan.index)
		}
		return fallback, nil
	}
	fallback := make([]int, 0)
	for _, plan := range plans {
		compiled, ok := prepared[plan.index]
		if !ok || compiled.results == nil {
			fallback = append(fallback, plan.index)
			continue
		}
		spec := specs[plan.index]
		spec.prepared = compiled.results
		spec.remediatePrepared = compiled.remediate
		spec.sharedCompiler = compiled.compiler
		spec.sharedStore = compiled.store
		spec.sharedPackage = "data.datadog.q" + strconv.Itoa(plan.index)
		readyByIndex[plan.index] = spec
	}
	return fallback, nil
}

func (c *Inspector) compileContractV2IsolatedSpecs(
	ctx context.Context,
	specs []*contractV2Rule,
	indices []int,
	v2Libs map[string]*ast.Module,
	baseStores map[string]storage.Store,
	baseDataHashes map[string]uint64,
	readyByIndex []*contractV2Rule,
) error {
	for _, index := range indices {
		spec := specs[index]
		if ctx.Err() != nil {
			return ctx.Err()
		}
		pq, err := c.compileOneContractV2Rule(ctx, &spec.meta, contractV2Query, v2Libs, baseStores, baseDataHashes)
		if err != nil {
			contextLogger := logger.FromContext(ctx)
			contextLogger.Warn().Err(err).Msgf("failed to compile contract v2 query %s", spec.meta.Query)
			c.recordQueryFailure(&spec.meta, err, QueryFailureCompile)
			continue
		}
		spec.prepared = pq
		if spec.hasRemediate {
			if rpq, rErr := c.compileOneContractV2Rule(ctx, &spec.meta, contractV2RemediateQry, v2Libs, baseStores, baseDataHashes); rErr == nil {
				spec.remediatePrepared = rpq
			}
		}
		readyByIndex[index] = spec
	}
	return nil
}

func contractV2ModuleForSharedCompiler(query *model.QueryMetadata, index int) (*ast.Module, bool) {
	mod, err := ast.ParseModuleWithOpts(query.Query, query.Content, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil || mod == nil || mod.Package == nil || mod.Package.Path.String() != "data.datadog" || !contractV2ModuleCanShare(mod) {
		return nil, false
	}
	mod.Package.Path = ast.MustParseRef("data.datadog.q" + strconv.Itoa(index))
	return mod, true
}

func contractV2ModuleCanShare(mod *ast.Module) bool {
	if mod == nil {
		return false
	}
	for _, imp := range mod.Imports {
		ref, ok := imp.Path.Value.(ast.Ref)
		if ok && !contractV2DataRefCanShare(ref) {
			return false
		}
	}
	for _, rule := range mod.Rules {
		shareable := true
		ast.WalkRefs(rule, func(ref ast.Ref) bool {
			if !contractV2DataRefCanShare(ref) {
				shareable = false
				return true
			}
			return false
		})
		if !shareable {
			return false
		}
		if contractV2RuleHasBareData(rule) {
			return false
		}
	}
	return true
}

// contractV2SelectPlatformLibraries keeps the platform libraries needed by a
// module cohort and their transitive references. Bare or dynamic data references
// conservatively retain both modules because their package dependency is unknown.
func contractV2SelectPlatformLibraries(
	roots []*ast.Module,
	common, generic *ast.Module,
) (includeCommon, includeGeneric bool) {
	candidates := contractV2PlatformLibraryCandidates(common, generic)
	included := make(map[*ast.Module]bool, len(candidates))
	contractV2MarkDirectPlatformLibraries(roots, candidates, included)
	contractV2ClosePlatformLibraryDependencies(candidates, included)
	return common != nil && included[common], generic != nil && included[generic]
}

func contractV2PlatformLibraryCandidates(common, generic *ast.Module) []*ast.Module {
	candidates := make([]*ast.Module, 0, 2)
	for _, module := range []*ast.Module{common, generic} {
		if module != nil && module.Package != nil {
			candidates = append(candidates, module)
		}
	}
	return candidates
}

func contractV2MarkDirectPlatformLibraries(
	roots, candidates []*ast.Module,
	included map[*ast.Module]bool,
) {
	for _, root := range roots {
		if root == nil {
			continue
		}
		if contractV2ModuleHasUnboundedDataReference(root) {
			contractV2MarkAllPlatformLibraries(candidates, included)
			continue
		}
		contractV2MarkReferencedPlatformLibraries(root, candidates, included)
	}
}

func contractV2ClosePlatformLibraryDependencies(candidates []*ast.Module, included map[*ast.Module]bool) {
	for changed := true; changed; {
		changed = false
		for _, module := range candidates {
			if !included[module] {
				continue
			}
			if contractV2ModuleHasUnboundedDataReference(module) {
				changed = contractV2MarkAllPlatformLibraries(candidates, included) || changed
				continue
			}
			changed = contractV2MarkReferencedPlatformLibraries(module, candidates, included) || changed
		}
	}
}

func contractV2MarkReferencedPlatformLibraries(
	module *ast.Module,
	candidates []*ast.Module,
	included map[*ast.Module]bool,
) bool {
	changed := false
	for _, candidate := range candidates {
		if included[candidate] || !contractV2ModuleReferencesPackage(module, candidate.Package.Path) {
			continue
		}
		included[candidate] = true
		changed = true
	}
	return changed
}

func contractV2MarkAllPlatformLibraries(candidates []*ast.Module, included map[*ast.Module]bool) bool {
	changed := false
	for _, candidate := range candidates {
		if included[candidate] {
			continue
		}
		included[candidate] = true
		changed = true
	}
	return changed
}

func contractV2ModuleReferencesPackage(module *ast.Module, packagePath ast.Ref) bool {
	if module == nil || len(packagePath) == 0 {
		return false
	}
	for _, imp := range module.Imports {
		if imp == nil || imp.Path == nil {
			continue
		}
		if ref, ok := imp.Path.Value.(ast.Ref); ok && contractV2RefsOverlap(ref, packagePath) {
			return true
		}
	}
	found := false
	ast.WalkRefs(module, func(ref ast.Ref) bool {
		if contractV2RefsOverlap(ref, packagePath) {
			found = true
			return true
		}
		return false
	})
	return found
}

func contractV2RefsOverlap(a, b ast.Ref) bool {
	for i := 0; i < min(len(a), len(b)); i++ {
		if a[i].Value.Compare(b[i].Value) != 0 {
			return false
		}
	}
	return len(a) > 0 && len(b) > 0
}

func contractV2ModuleHasUnboundedDataReference(module *ast.Module) bool {
	if module == nil {
		return false
	}
	for _, rule := range module.Rules {
		dataRefs := 0
		unbounded := false
		ast.WalkRefs(rule, func(ref ast.Ref) bool {
			if len(ref) == 0 || ref[0].Value.Compare(ast.Var("data")) != 0 {
				return false
			}
			dataRefs++
			if len(ref) == 1 {
				unbounded = true
				return false
			}
			for _, part := range ref[1:] {
				if _, ok := part.Value.(ast.String); !ok {
					unbounded = true
					break
				}
			}
			return false
		})
		dataVars := 0
		ast.WalkVars(rule, func(variable ast.Var) bool {
			if variable == ast.Var("data") {
				dataVars++
			}
			return false
		})
		if unbounded || dataVars > dataRefs {
			return true
		}
	}
	return false
}

func contractV2RuleHasBareData(rule *ast.Rule) bool {
	dataRefs := 0
	ast.WalkRefs(rule, func(ref ast.Ref) bool {
		if len(ref) > 0 && ref[0].Value.Compare(ast.Var("data")) == 0 {
			dataRefs++
		}
		return false
	})
	dataVars := 0
	ast.WalkVars(rule, func(v ast.Var) bool {
		if v == ast.Var("data") {
			dataVars++
		}
		return false
	})
	return dataVars > dataRefs
}

func contractV2DataRefCanShare(ref ast.Ref) bool {
	if len(ref) == 0 || ref[0].Value.Compare(ast.Var("data")) != 0 {
		return true
	}
	if len(ref) == 1 {
		return false
	}
	root, ok := ref[1].Value.(ast.String)
	if !ok {
		return false
	}
	if string(root) != "datadog" {
		return true
	}
	if len(ref) < 3 {
		return false
	}
	facade, ok := ref[2].Value.(ast.String)
	return ok && (string(facade) == "iac" || string(facade) == tfSectionOutput || string(facade) == contractV2PlatformTerraform)
}

func (c *Inspector) compileSharedContractV2Rules(
	ctx context.Context,
	groups map[string][]contractV2SharedSpec,
	v2Libs map[string]*ast.Module,
	baseStores map[string]storage.Store,
) (map[int]contractV2PreparedRule, error) {
	prepared := make(map[int]contractV2PreparedRule)
	for _, platform := range slices.Sorted(maps.Keys(groups)) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		modules, err := c.contractV2SharedModules(platform, groups[platform], v2Libs)
		if err != nil {
			return nil, err
		}
		store := baseStores[platform]
		if err := contractV2CheckNamespaceCollisions(ctx, modules, groups[platform], store); err != nil {
			return nil, err
		}
		compiler := ast.NewCompiler().WithCapabilities(safeCapabilities())
		compiler.Compile(modules)
		if compiler.Failed() {
			return nil, fmt.Errorf("shared contract v2 compile failed for platform %s: %v", platform, compiler.Errors)
		}
		for _, shared := range groups[platform] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			pkg := "data.datadog.q" + strconv.Itoa(shared.index)
			results, err := prepareContractV2SharedEntrypoint(ctx, compiler, store, "result = "+pkg+".results")
			if err != nil {
				return nil, fmt.Errorf("preparing contract v2 rule %s: %w", shared.module.Package.Path.String(), err)
			}
			entry := contractV2PreparedRule{results: results, compiler: compiler, store: store}
			// A missing or invalid optional remediation entrypoint keeps the
			// finding query usable, as before.
			if shared.hasRemediate {
				if remediate, err := prepareContractV2SharedEntrypoint(ctx, compiler, store,
					"out = "+pkg+".remediate(input.resource, input.finding)"); err == nil {
					entry.remediate = remediate
				}
			}
			prepared[shared.index] = entry
		}
	}
	return prepared, nil
}

func (c *Inspector) contractV2SharedModules(
	platform string,
	plans []contractV2SharedSpec,
	v2Libs map[string]*ast.Module,
) (map[string]*ast.Module, error) {
	modules, err := c.contractV2SharedPlatformModules(platform)
	if err != nil {
		return nil, err
	}
	modules = expandContractV2SharedModules(modules, plans, v2Libs)
	contractV2PruneSharedPlatformModules(modules, plans, v2Libs)
	if err := validateContractV2SharedModules(modules); err != nil {
		return nil, err
	}
	return modules, nil
}

func (c *Inspector) contractV2SharedPlatformModules(platform string) (map[string]*ast.Module, error) {
	modules := make(map[string]*ast.Module, 2)
	if mod := c.QueryLoader.parsedCommon; mod != nil {
		modules["Common"] = mod.Copy()
	} else if strings.TrimSpace(c.QueryLoader.commonLibrary.LibraryCode) != "" {
		mod, err := ast.ParseModuleWithOpts("Common", c.QueryLoader.commonLibrary.LibraryCode,
			ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			return nil, err
		}
		modules["Common"] = mod
	}
	if mod := c.QueryLoader.parsedGeneric[platform]; mod != nil {
		modules["Generic"] = mod.Copy()
	} else if lib, ok := c.QueryLoader.platformLibraries[platform]; ok && strings.TrimSpace(lib.LibraryCode) != "" {
		mod, err := ast.ParseModuleWithOpts("Generic", lib.LibraryCode, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			return nil, err
		}
		modules["Generic"] = mod
	}
	return modules, nil
}

func expandContractV2SharedModules(
	modules map[string]*ast.Module,
	plans []contractV2SharedSpec,
	v2Libs map[string]*ast.Module,
) map[string]*ast.Module {
	for name, mod := range v2Libs {
		modules[name] = mod.Copy()
	}
	for _, plan := range plans {
		modules["contract_v2_rule_"+strconv.Itoa(plan.index)] = plan.module
	}
	return modules
}

func contractV2PruneSharedPlatformModules(
	modules map[string]*ast.Module,
	plans []contractV2SharedSpec,
	v2Libs map[string]*ast.Module,
) {
	dependencyRoots := make([]*ast.Module, 0, len(v2Libs)+len(plans))
	for _, mod := range v2Libs {
		dependencyRoots = append(dependencyRoots, mod)
	}
	for _, plan := range plans {
		dependencyRoots = append(dependencyRoots, plan.module)
	}
	includeCommon, includeGeneric := contractV2SelectPlatformLibraries(
		dependencyRoots, modules["Common"], modules["Generic"],
	)
	if !includeCommon {
		delete(modules, "Common")
	}
	if !includeGeneric {
		delete(modules, "Generic")
	}
}

func validateContractV2SharedModules(modules map[string]*ast.Module) error {
	for _, mod := range modules {
		if !contractV2ModuleCanShare(mod) {
			return fmt.Errorf("contract v2 shared compiler cannot safely include module %s", mod.Package.Path.String())
		}
	}
	return nil
}

func contractV2CheckNamespaceCollisions(
	ctx context.Context,
	modules map[string]*ast.Module,
	plans []contractV2SharedSpec,
	store storage.Store,
) error {
	generatedModules := make(map[*ast.Module]bool, len(plans))
	generatedPaths := make([]ast.Ref, 0, len(plans))
	for _, plan := range plans {
		if plan.module == nil || plan.module.Package == nil {
			return fmt.Errorf("contract v2 shared rule %d has no package", plan.index)
		}
		generatedModules[plan.module] = true
		generatedPaths = append(generatedPaths, plan.module.Package.Path)
	}
	for _, module := range modules {
		if module == nil || module.Package == nil || generatedModules[module] {
			continue
		}
		for _, generated := range generatedPaths {
			if contractV2PackagePathsOverlap(module.Package.Path, generated) {
				return fmt.Errorf("shared contract v2 rule package %s overlaps library package %s",
					generated.String(), module.Package.Path.String())
			}
		}
	}
	if store == nil {
		return nil
	}
	txn, err := store.NewTransaction(ctx)
	if err != nil {
		return fmt.Errorf("checking shared contract v2 base data namespaces: %w", err)
	}
	defer store.Abort(ctx, txn)
	for _, plan := range plans {
		path := storage.Path{"datadog", "q" + strconv.Itoa(plan.index)}
		if _, err := store.Read(ctx, txn, path); err == nil {
			return fmt.Errorf("shared contract v2 rule package data.%s collides with base input data", path.String())
		} else if !storage.IsNotFound(err) {
			return fmt.Errorf("checking shared contract v2 base data namespace %s: %w", path.String(), err)
		}
	}
	return nil
}

func contractV2PackagePathsOverlap(a, b ast.Ref) bool {
	return contractV2PackagePathPrefix(a, b) || contractV2PackagePathPrefix(b, a)
}

func contractV2PackagePathPrefix(prefix, path ast.Ref) bool {
	if len(prefix) > len(path) {
		return false
	}
	for i := range prefix {
		if !prefix[i].Equal(path[i]) {
			return false
		}
	}
	return true
}

func prepareContractV2SharedEntrypoint(
	ctx context.Context,
	compiler *ast.Compiler,
	store storage.Store,
	query string,
) (*rego.PreparedEvalQuery, error) {
	prepared, err := rego.New(
		rego.Query(query),
		rego.SetRegoVersion(ast.RegoV1),
		rego.Compiler(compiler),
		rego.Store(store),
		rego.UnsafeBuiltins(unsafeRegoFunctions),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	return &prepared, nil
}

func contractV2SharedCacheKey(
	c *Inspector,
	specs []*contractV2Rule,
	plans []contractV2SharedSpec,
	v2Libs map[string]*ast.Module,
	baseDataHashes map[string]uint64,
) uint64 {
	fields := []string{"contract-v2-shared-v1", contractV2Query, contractV2RemediateQry}
	for _, plan := range plans {
		spec := specs[plan.index]
		fields = append(fields,
			strconv.Itoa(plan.index), spec.meta.Platform, spec.meta.Query, spec.meta.Content, spec.meta.InputData,
			strconv.FormatUint(c.QueryLoader.platformKeyBases[spec.meta.Platform], 10),
			strconv.FormatUint(baseDataHashes[spec.meta.Platform], 10),
			strconv.FormatBool(spec.hasRemediate),
		)
	}
	for _, name := range slices.Sorted(maps.Keys(v2Libs)) {
		fields = append(fields, name, v2Libs[name].String())
	}
	return hashFields(fields...)
}

func (c *Inspector) loadSharedContractV2Rules(
	ctx context.Context,
	specs []*contractV2Rule,
	plans []contractV2SharedSpec,
	groups map[string][]contractV2SharedSpec,
	v2Libs map[string]*ast.Module,
	baseStores map[string]storage.Store,
	baseDataHashes map[string]uint64,
) (map[int]contractV2PreparedRule, error) {
	key := contractV2SharedCacheKey(c, specs, plans, v2Libs, baseDataHashes)
	flightKey := "contract-v2-" + strconv.FormatUint(key, 16)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sharedContractV2PreparedQueryCache.Lock()
		if sharedContractV2PreparedQueryCache.prepared != nil && sharedContractV2PreparedQueryCache.key == key {
			cached := sharedContractV2PreparedQueryCache.prepared
			sharedContractV2PreparedQueryCache.Unlock()
			return cached, nil
		}
		sharedContractV2PreparedQueryCache.Unlock()
		resultCh := sharedContractV2PreparedQueryCache.flight.DoChan(flightKey, func() (any, error) {
			sharedContractV2PreparedQueryCache.Lock()
			if sharedContractV2PreparedQueryCache.prepared != nil && sharedContractV2PreparedQueryCache.key == key {
				cached := sharedContractV2PreparedQueryCache.prepared
				sharedContractV2PreparedQueryCache.Unlock()
				return cached, nil
			}
			sharedContractV2PreparedQueryCache.Unlock()
			compiled, err := c.compileSharedContractV2Rules(ctx, groups, v2Libs, baseStores)
			if err != nil {
				return nil, err
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			sharedContractV2PreparedQueryCache.Lock()
			sharedContractV2PreparedQueryCache.key = key
			sharedContractV2PreparedQueryCache.prepared = compiled
			sharedContractV2PreparedQueryCache.Unlock()
			return compiled, nil
		})
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case call := <-resultCh:
			if call.Err != nil {
				retry, err := retrySharedContractV2Compile(ctx, call.Err)
				if retry {
					continue
				}
				return nil, err
			}
			compiled, ok := call.Val.(map[int]contractV2PreparedRule)
			if !ok {
				return nil, fmt.Errorf("unexpected contract v2 cache value %T", call.Val)
			}
			return compiled, nil
		}
	}
}

func retrySharedContractV2Compile(ctx context.Context, compileErr error) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if compileErr == context.Canceled || compileErr == context.DeadlineExceeded {
		return true, nil
	}
	return false, compileErr
}

func (c *Inspector) compileOneContractV2Rule(
	ctx context.Context,
	query *model.QueryMetadata,
	regoQuery string,
	v2Libs map[string]*ast.Module,
	baseStores map[string]storage.Store,
	baseDataHashes map[string]uint64,
) (*rego.PreparedEvalQuery, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store, hasStore := baseStores[query.Platform]
	hasCustomInput := !source.IsEmptyInputData(query.InputData)
	useCache := c.useRulesCache && hasStore && !hasCustomInput
	var cacheKey uint64
	if useCache {
		// The entrypoint namespace separates findings, optional remediation,
		// and legacy queries even when their source modules are identical.
		libraryBase := c.QueryLoader.platformKeyBases[query.Platform] ^ hashFields("contract-v2", regoQuery)
		cacheKey = preparedCacheKey(query, libraryBase, baseDataHashes[query.Platform])
		if cached, ok := preparedQueryCache.Load(cacheKey); ok {
			return cached.(*rego.PreparedEvalQuery), nil
		}
	}
	if !hasStore || hasCustomInput {
		merged, err := c.QueryLoader.buildMergedInputData(query, nil)
		if err != nil {
			return nil, err
		}
		store = inmem.NewFromReader(bytes.NewBufferString(merged))
	}
	opts := []func(*rego.Rego){
		rego.Query(regoQuery),
		rego.SetRegoVersion(ast.RegoV1),
		rego.Store(store),
		rego.UnsafeBuiltins(unsafeRegoFunctions),
		rego.Module(query.Query, query.Content),
	}
	opts = append(opts, c.contractV2RulePlatformModuleOptions(query, v2Libs)...)
	pq, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	if useCache {
		actual, _ := preparedQueryCache.LoadOrStore(cacheKey, &pq)
		return actual.(*rego.PreparedEvalQuery), nil
	}
	return &pq, nil
}

func (c *Inspector) contractV2RulePlatformModuleOptions(
	query *model.QueryMetadata,
	v2Libs map[string]*ast.Module,
) []func(*rego.Rego) {
	dependencyRoots := make([]*ast.Module, 0, len(v2Libs)+1)
	module, parseErr := ast.ParseModuleWithOpts(query.Query, query.Content, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if parseErr == nil {
		dependencyRoots = append(dependencyRoots, module)
	}
	for _, module := range v2Libs {
		dependencyRoots = append(dependencyRoots, module)
	}
	includeCommon, includeGeneric := true, true
	if parseErr == nil {
		includeCommon, includeGeneric = contractV2SelectPlatformLibraries(
			dependencyRoots,
			c.QueryLoader.parsedCommon,
			c.QueryLoader.parsedGeneric[query.Platform],
		)
	}
	return contractV2ParsedPlatformModuleOptions(
		query.Platform,
		includeCommon,
		includeGeneric,
		c.QueryLoader.parsedCommon,
		c.QueryLoader.parsedGeneric,
		v2Libs,
	)
}

func contractV2ParsedPlatformModuleOptions(
	platform string,
	includeCommon bool,
	includeGeneric bool,
	common *ast.Module,
	genericModules map[string]*ast.Module,
	v2Libs map[string]*ast.Module,
) []func(*rego.Rego) {
	opts := make([]func(*rego.Rego), 0, len(v2Libs)+2)
	if includeCommon && common != nil {
		opts = append(opts, rego.ParsedModule(common.Copy()))
	}
	if gen, ok := genericModules[platform]; includeGeneric && ok && gen != nil {
		opts = append(opts, rego.ParsedModule(gen.Copy()))
	}
	for _, name := range slices.Sorted(maps.Keys(v2Libs)) {
		opts = append(opts, rego.ParsedModule(v2Libs[name].Copy()))
	}
	return opts
}

func countInputResourcesRefs(node any) int {
	n := 0
	ast.WalkRefs(node, func(ref ast.Ref) bool {
		if len(ref) >= 2 && ref[0].Value.Compare(ast.Var("input")) == 0 {
			if k, ok := ref[1].Value.(ast.String); ok && string(k) == contractV2InputResources {
				n++
			}
		}
		return false
	})
	return n
}

func isInputResourcesBucketRef(term *ast.Term) bool {
	if term == nil {
		return false
	}
	ref, ok := term.Value.(ast.Ref)
	if !ok || len(ref) != 3 || ref[0].Value.Compare(ast.Var("input")) != 0 {
		return false
	}
	k, ok := ref[1].Value.(ast.String)
	return ok && string(k) == contractV2InputResources
}

// isSimpleResourceIterationExpr reports whether expr is a single top-level
// position-independent positive element iteration directly over
// input.resources.<type> (for example `some r in input.resources.aws_s3_bucket`
// or `r := input.resources.aws_s3_bucket[_]`), never keyed membership
// (its index can be constrained elsewhere), never negated, never `every`,
// never a comprehension, never a fixed index like `[0]`, and never a wrapped
// call like `array.slice(input.resources.aws_s3_bucket, 0, 1)`.
// nolint:gocyclo
func isSimpleResourceIterationExpr(expr *ast.Expr) bool {
	if expr == nil || expr.Negated || expr.IsEvery() {
		return false
	}
	hasComp := false
	ast.WalkTerms(expr, func(t *ast.Term) bool {
		switch t.Value.(type) {
		case *ast.ArrayComprehension, *ast.SetComprehension, *ast.ObjectComprehension:
			hasComp = true
			return true
		}
		return false
	})
	if hasComp {
		return false
	}
	if sd, ok := expr.Terms.(*ast.SomeDecl); ok {
		for _, sym := range sd.Symbols {
			call, ok := sym.Value.(ast.Call)
			if !ok || len(call) < 3 {
				return false
			}
			op := call[0].String()
			if op != ast.Member.Name || !isInputResourcesBucketRef(call[len(call)-1]) {
				return false
			}
		}
		return true
	}
	if expr.IsCall() {
		op := expr.Operator().String()
		ops := expr.Operands()
		switch op {
		case ast.Member.Name:
			return len(ops) == 2 && isInputResourcesBucketRef(ops[1])
		case ast.Assign.Name, ast.Equality.Name:
			// `r := input.resources.<T>[_]` must have len(ref) == 4 with a variable
			// index (not a constant position like `[0]`).
			if len(ops) == 2 {
				for _, operand := range ops {
					if ref, ok := operand.Value.(ast.Ref); ok && len(ref) == 4 &&
						ref[0].Value.Compare(ast.Var("input")) == 0 {
						if k, ok := ref[1].Value.(ast.String); ok && string(k) == contractV2InputResources {
							if index, isVarIdx := ref[3].Value.(ast.Var); isVarIdx && index.IsWildcard() {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

// evalOptionalRemediation evaluates a rule's optional `remediate(resource, finding)`
// function independently of finding proof. If `remediate` is undefined (for example
// because iac.get returned undefined on an unknown attribute), it returns
// ("", "", false) without ever suppressing the already-proven finding.
func evalOptionalRemediation(
	ctx context.Context,
	rule *contractV2Rule,
	res *policy.Resource,
	f *policy.Finding,
) (remediation, remediationType string, ok bool) {
	if rule == nil || rule.remediatePrepared == nil || res == nil || f == nil {
		return "", "", false
	}
	u := &policy.Unit{
		ID:            "remediate",
		Platform:      contractV2PlatformTerraform,
		ScopeComplete: true,
		Resources:     []*policy.Resource{res},
	}
	projected := policy.ProjectUnits(contractV2PlatformTerraform, []*policy.Unit{u}, policy.ProjectOptions{
		IncludeRelations: true,
		IncludeByID:      true,
	})
	byID := projected.(ast.Object).Get(ast.StringTerm("by_id"))
	if byID == nil {
		return "", "", false
	}
	resTerm := byID.Value.(ast.Object).Get(ast.StringTerm(res.ID))
	if resTerm == nil {
		return "", "", false
	}
	findingVal, err := ast.InterfaceToValue(f.Raw)
	if err != nil {
		return "", "", false
	}
	inputVal := ast.NewObject(
		[2]*ast.Term{ast.StringTerm("resource"), resTerm},
		[2]*ast.Term{ast.StringTerm("finding"), ast.NewTerm(findingVal)},
	)
	rs, err := rule.remediatePrepared.Eval(ctx, rego.EvalParsedInput(inputVal))
	if err != nil || len(rs) == 0 {
		return "", "", false
	}
	raw, exists := rs[0].Bindings["out"]
	if !exists {
		return "", "", false
	}
	m, isMap := raw.(map[string]any)
	if !isMap {
		return "", "", false
	}
	rem, _ := m["remediation"].(string)
	remType, _ := m["remediationType"].(string)
	if rem == "" || strings.Contains(rem, policy.UnknownSlotKey) {
		return "", "", false
	}
	return rem, remType, true
}

// buildReplacementRemediation resolves scanner-derived "before" text when a
// Contract v2 rule supplies `after` without computing `before` in Rego. If the
// source expression is dynamic/unpatchable, returns ("", "") without dropping
// the finding.
func buildReplacementRemediation(res *policy.Resource, f *policy.Finding) (remediation, remediationType string) {
	if f.Remediation != "" {
		return f.Remediation, f.RemediationType
	}
	if f.After == "" || res == nil || res.Source == nil || res.Source.BeforeValue == nil {
		return "", ""
	}
	before, ok := res.Source.BeforeValue(f.Path)
	if !ok {
		return "", ""
	}
	raw, err := json.Marshal(map[string]string{
		"before": before,
		"after":  f.After,
	})
	if err != nil {
		return "", ""
	}
	return string(raw), "replacement"
}
