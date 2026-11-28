/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
)

const (
	tfSectionsCap  = 8
	tfTypesCap     = 64
	k8sKindsCap    = 32
	k8sKeysCap     = 128
	k8sSeenCap     = 64
	cfnTypesCap    = 64
	cfnSeenCap     = 16
	aliasExtraCap  = 4
	maxSubtreePass = 5
	maxCFNPass     = 4

	regoInputArgumentsKey = "arguments"
	regoInputDocumentKey  = "document"
	tfSectionResource     = "resource"
	tfSectionProvider     = "provider"
	tfSectionModule       = "module"
	tfSectionLocals       = "locals"
	tfSectionVariable     = "variable"
	tfSectionOutput       = "output"
)

var trivialTrueExpr = ast.MustParseExpr("true")

// docIndex indexes per-platform documents so rules with statically provable
// document requirements can skip evaluation when no document can match, or
// evaluate against only the matching document subset when proven single-document.
type docIndex struct {
	platformTerms map[string][]*ast.Term
	unknownCount  int

	tfSections map[string][]int
	tfTypes    map[tfResourceKey][]int
	tfIndexed  bool

	k8sExact   map[string][]int
	k8sLower   map[string][]int
	k8sKeys    map[string][]int
	k8sIndexed bool

	cfnTypes   map[string][]int
	cfnIndexed bool

	mu      sync.Mutex
	subsets map[subsetCacheKey]ast.Value
}

type tfResourceKey struct {
	section string
	typ     string
}

type subsetCacheKey struct {
	platform string
	key      string
}

type nodeVisitKey struct {
	ptr uintptr
	n   int // -1 for maps, slice length for slices
}

// docIndexBuilder incrementally indexes documents during buildPlatformPayloads
// so source document maps can be released immediately after conversion without
// being pinned until the end of the loop.
type docIndexBuilder struct {
	neededPlatforms map[string]bool
	tfSections      map[string][]int
	tfTypes         map[tfResourceKey][]int
	k8sExact        map[string][]int
	k8sLower        map[string][]int
	k8sKeys         map[string][]int
	k8sSeen         map[string]struct{}
	cfnTypes        map[string][]int
	cfnSeen         map[string]struct{}
	visited         map[nodeVisitKey]struct{}

	bucketPos   map[string]int
	unknownDocs []unknownDocEntry
}

type unknownDocEntry struct {
	tfSections []string
	tfTypes    []tfResourceKey
	k8sKind    string
	k8sKeys    []string
	cfnTypes   []string
}

func newDocIndexBuilder(neededPlatforms map[string]bool) *docIndexBuilder {
	b := &docIndexBuilder{
		neededPlatforms: neededPlatforms,
		bucketPos:       make(map[string]int, len(neededPlatforms)),
	}
	if neededPlatforms[platformTerraform] {
		b.tfSections = make(map[string][]int, tfSectionsCap)
		b.tfTypes = make(map[tfResourceKey][]int, tfTypesCap)
	}
	if neededPlatforms[platformKubernetes] {
		b.k8sExact = make(map[string][]int, k8sKindsCap)
		b.k8sLower = make(map[string][]int, k8sKindsCap)
		b.k8sKeys = make(map[string][]int, k8sKeysCap)
		b.k8sSeen = make(map[string]struct{}, k8sSeenCap)
	}
	if neededPlatforms[platformCloudFormation] {
		b.cfnTypes = make(map[string][]int, cfnTypesCap)
		b.cfnSeen = make(map[string]struct{}, cfnSeenCap)
	}
	if neededPlatforms[platformKubernetes] || neededPlatforms[platformCloudFormation] {
		b.visited = make(map[nodeVisitKey]struct{}, k8sSeenCap)
	}
	return b
}

func (b *docIndexBuilder) addDoc(doc interface{}, keys []string) {
	if len(keys) == 0 {
		b.addUnknownDoc(doc)
		return
	}
	m, ok := asStringMap(doc)
	for _, key := range keys {
		if !b.neededPlatforms[key] {
			continue
		}
		pos := b.bucketPos[key]
		b.bucketPos[key] = pos + 1
		if ok {
			b.indexPlatformDoc(key, pos, m)
		}
	}
}

func (b *docIndexBuilder) addUnknownDoc(doc interface{}) {
	var entry unknownDocEntry
	if m, ok := asStringMap(doc); ok {
		if b.neededPlatforms[platformTerraform] {
			entry.tfSections, entry.tfTypes = extractTerraformDocFacts(m)
		}
		if b.neededPlatforms[platformKubernetes] {
			if k, ok := m["kind"].(string); ok {
				entry.k8sKind = k
			}
			clear(b.k8sSeen)
			clear(b.visited)
			collectObjectKeys(m, b.k8sSeen, b.visited)
			for k := range b.k8sSeen {
				entry.k8sKeys = append(entry.k8sKeys, k)
			}
		}
		if b.neededPlatforms[platformCloudFormation] {
			clear(b.cfnSeen)
			clear(b.visited)
			collectCFNTypes(m, b.cfnSeen, b.visited)
			for t := range b.cfnSeen {
				entry.cfnTypes = append(entry.cfnTypes, t)
			}
		}
	}
	b.unknownDocs = append(b.unknownDocs, entry)
}

func (b *docIndexBuilder) indexPlatformDoc(key string, pos int, m map[string]interface{}) {
	switch key {
	case platformTerraform:
		secs, types := extractTerraformDocFacts(m)
		for _, sec := range secs {
			b.tfSections[sec] = append(b.tfSections[sec], pos)
		}
		for _, tk := range types {
			b.tfTypes[tk] = append(b.tfTypes[tk], pos)
		}
	case platformKubernetes:
		if kind, ok := m["kind"].(string); ok && kind != "" {
			b.k8sExact[kind] = append(b.k8sExact[kind], pos)
			b.k8sLower[strings.ToLower(kind)] = append(b.k8sLower[strings.ToLower(kind)], pos)
		}
		clear(b.k8sSeen)
		clear(b.visited)
		collectObjectKeys(m, b.k8sSeen, b.visited)
		for k := range b.k8sSeen {
			b.k8sKeys[k] = append(b.k8sKeys[k], pos)
		}
	case platformCloudFormation:
		clear(b.cfnSeen)
		clear(b.visited)
		collectCFNTypes(m, b.cfnSeen, b.visited)
		for typ := range b.cfnSeen {
			b.cfnTypes[typ] = append(b.cfnTypes[typ], pos)
		}
	}
}

func extractTerraformDocFacts(doc map[string]interface{}) (sections []string, types []tfResourceKey) {
	for _, sec := range [...]string{tfSectionResource, dataRoot, tfSectionProvider} {
		raw, exists := doc[sec]
		if !exists {
			continue
		}
		m, ok := asStringMap(raw)
		if !ok {
			continue
		}
		sections = append(sections, sec)
		for typ := range m {
			if strings.HasPrefix(typ, "_") {
				continue
			}
			types = append(types, tfResourceKey{section: sec, typ: typ})
		}
	}
	for _, sec := range [...]string{tfSectionModule, tfSectionLocals, tfSectionVariable, tfSectionOutput, platformTerraform} {
		if _, exists := doc[sec]; exists {
			sections = append(sections, sec)
		}
	}
	return sections, types
}

func (b *docIndexBuilder) finish(platformTerms map[string][]*ast.Term) *docIndex {
	for i := range b.unknownDocs {
		b.appendUnknownEntry(&b.unknownDocs[i])
	}
	return &docIndex{
		platformTerms: platformTerms,
		unknownCount:  len(b.unknownDocs),
		tfSections:    b.tfSections,
		tfTypes:       b.tfTypes,
		tfIndexed:     b.neededPlatforms[platformTerraform],
		k8sExact:      b.k8sExact,
		k8sLower:      b.k8sLower,
		k8sKeys:       b.k8sKeys,
		k8sIndexed:    b.neededPlatforms[platformKubernetes],
		cfnTypes:      b.cfnTypes,
		cfnIndexed:    b.neededPlatforms[platformCloudFormation],
		subsets:       make(map[subsetCacheKey]ast.Value),
	}
}

func (b *docIndexBuilder) appendUnknownEntry(entry *unknownDocEntry) {
	if b.neededPlatforms[platformTerraform] {
		pos := b.bucketPos[platformTerraform]
		b.bucketPos[platformTerraform] = pos + 1
		for _, sec := range entry.tfSections {
			b.tfSections[sec] = append(b.tfSections[sec], pos)
		}
		for _, tk := range entry.tfTypes {
			b.tfTypes[tk] = append(b.tfTypes[tk], pos)
		}
	}
	if b.neededPlatforms[platformKubernetes] {
		pos := b.bucketPos[platformKubernetes]
		b.bucketPos[platformKubernetes] = pos + 1
		if entry.k8sKind != "" {
			b.k8sExact[entry.k8sKind] = append(b.k8sExact[entry.k8sKind], pos)
			b.k8sLower[strings.ToLower(entry.k8sKind)] = append(b.k8sLower[strings.ToLower(entry.k8sKind)], pos)
		}
		for _, k := range entry.k8sKeys {
			b.k8sKeys[k] = append(b.k8sKeys[k], pos)
		}
	}
	if b.neededPlatforms[platformCloudFormation] {
		pos := b.bucketPos[platformCloudFormation]
		b.bucketPos[platformCloudFormation] = pos + 1
		for _, typ := range entry.cfnTypes {
			b.cfnTypes[typ] = append(b.cfnTypes[typ], pos)
		}
	}
}

func markNodeVisited(visited map[nodeVisitKey]struct{}, ptr uintptr, n int) bool {
	if ptr == 0 || visited == nil {
		return false
	}
	k := nodeVisitKey{ptr: ptr, n: n}
	if _, seen := visited[k]; seen {
		return true
	}
	visited[k] = struct{}{}
	return false
}

func collectObjectKeys(node interface{}, seen map[string]struct{}, visited map[nodeVisitKey]struct{}) {
	if v, ok := asStringMap(node); ok {
		if markNodeVisited(visited, reflect.ValueOf(v).Pointer(), -1) {
			return
		}
		for k, child := range v {
			if k != "" && k[0] != '_' {
				seen[k] = struct{}{}
			}
			collectObjectKeys(child, seen, visited)
		}
		return
	}
	if v, ok := node.([]interface{}); ok {
		if markNodeVisited(visited, reflect.ValueOf(v).Pointer(), len(v)) {
			return
		}
		for _, elem := range v {
			collectObjectKeys(elem, seen, visited)
		}
	}
}

func collectCFNTypes(node interface{}, seen map[string]struct{}, visited map[nodeVisitKey]struct{}) {
	if v, ok := asStringMap(node); ok {
		if markNodeVisited(visited, reflect.ValueOf(v).Pointer(), -1) {
			return
		}
		if t, ok := v["Type"].(string); ok && t != "" {
			seen[t] = struct{}{}
		}
		for _, child := range v {
			collectCFNTypes(child, seen, visited)
		}
		return
	}
	if v, ok := node.([]interface{}); ok {
		if markNodeVisited(visited, reflect.ValueOf(v).Pointer(), len(v)) {
			return
		}
		for _, elem := range v {
			collectCFNTypes(elem, seen, visited)
		}
	}
}

// ruleDocFilter describes a conservative, provably sound prefilter derived from
// a rule's AST.
type ruleDocFilter struct {
	constrained bool
	canSubset   bool
	platform    string

	tfPreds         []tfResourceKey
	k8sExact        []string
	k8sLower        []string
	k8sKeyConjuncts [][]string
	cfnTypes        []string

	cacheKey string
}

// resolve returns (subsetPayload, subsetKey, skip). When skip is true, the rule
// is mathematically guaranteed to produce zero findings against idx. When skip
// is false and subsetPayload != nil, evaluating against subsetPayload produces
// the exact same results as evaluating against the full platform payload.
func (f *ruleDocFilter) resolve(idx *docIndex) (subsetPayload ast.Value, subsetKey string, skip bool) {
	if idx == nil || !f.constrained {
		return nil, "", false
	}
	pTerms := idx.platformTerms[f.platform]
	if len(pTerms) == 0 {
		return nil, "", true
	}

	matched, effectiveKey, indexed := f.matchDocs(idx)
	if !indexed {
		return nil, "", false
	}
	if len(matched) == 0 {
		return nil, "", true
	}
	if !f.canSubset || len(matched) >= len(pTerms) {
		return nil, "", false
	}
	return idx.getOrBuildSubset(f.platform, effectiveKey, pTerms, matched), effectiveKey, false
}

func (f *ruleDocFilter) matchDocs(idx *docIndex) (matched []int, effectiveKey string, ok bool) {
	switch f.platform {
	case platformTerraform:
		if !idx.tfIndexed {
			return nil, "", false
		}
		return idx.matchTerraform(f.tfPreds), f.cacheKey, true
	case platformKubernetes:
		if !idx.k8sIndexed {
			return nil, "", false
		}
		if len(f.k8sExact) > 0 || len(f.k8sLower) > 0 {
			return idx.matchKubernetes(f.k8sExact, f.k8sLower), f.cacheKey, true
		}
		if len(f.k8sKeyConjuncts) > 0 {
			m, k := idx.matchKubernetesKeyConjuncts(f.k8sKeyConjuncts)
			return m, k, true
		}
		return nil, "", false
	case platformCloudFormation:
		if !idx.cfnIndexed {
			return nil, "", false
		}
		return idx.matchCloudFormation(f.cfnTypes), f.cacheKey, true
	default:
		return nil, "", false
	}
}

func (idx *docIndex) getOrBuildSubset(platform, key string, pTerms []*ast.Term, matched []int) ast.Value {
	ck := subsetCacheKey{platform: platform, key: key}
	idx.mu.Lock()
	if cached, ok := idx.subsets[ck]; ok {
		idx.mu.Unlock()
		return cached
	}
	idx.mu.Unlock()

	subTerms := make([]*ast.Term, len(matched))
	for i, pos := range matched {
		subTerms[i] = pTerms[pos]
	}
	pv := assembleDocumentPayload(subTerms)

	idx.mu.Lock()
	if existing, ok := idx.subsets[ck]; ok {
		idx.mu.Unlock()
		return existing
	}
	idx.subsets[ck] = pv
	idx.mu.Unlock()
	return pv
}

func (idx *docIndex) matchKubernetesKeyConjuncts(conjuncts [][]string) (best []int, bestKey string) {
	bestLen := -1
	for _, group := range conjuncts {
		var lists [][]int
		for _, k := range group {
			if l := idx.k8sKeys[k]; len(l) > 0 {
				lists = append(lists, l)
			}
		}
		m := unionSortedInts(lists)
		if len(m) == 0 {
			return nil, ""
		}
		if bestLen < 0 || len(m) < bestLen {
			best = m
			bestLen = len(m)
			bestKey = "k:" + strings.Join(group, ",")
		}
	}
	return best, bestKey
}

func (idx *docIndex) matchTerraform(preds []tfResourceKey) []int {
	if len(preds) == 1 {
		p := preds[0]
		if p.typ != "" {
			return idx.tfTypes[p]
		}
		return idx.tfSections[p.section]
	}
	var lists [][]int
	for _, p := range preds {
		var l []int
		if p.typ != "" {
			l = idx.tfTypes[p]
		} else {
			l = idx.tfSections[p.section]
		}
		if len(l) > 0 {
			lists = append(lists, l)
		}
	}
	return unionSortedInts(lists)
}

func (idx *docIndex) matchKubernetes(exact, lower []string) []int {
	if len(exact) == 1 && len(lower) == 0 {
		return idx.k8sExact[exact[0]]
	}
	if len(lower) == 1 && len(exact) == 0 {
		return idx.k8sLower[lower[0]]
	}
	var lists [][]int
	for _, k := range exact {
		if l := idx.k8sExact[k]; len(l) > 0 {
			lists = append(lists, l)
		}
	}
	for _, k := range lower {
		if l := idx.k8sLower[k]; len(l) > 0 {
			lists = append(lists, l)
		}
	}
	return unionSortedInts(lists)
}

func (idx *docIndex) matchCloudFormation(types []string) []int {
	if len(types) == 1 {
		return idx.cfnTypes[types[0]]
	}
	var lists [][]int
	for _, t := range types {
		if l := idx.cfnTypes[t]; len(l) > 0 {
			lists = append(lists, l)
		}
	}
	return unionSortedInts(lists)
}

func unionSortedInts(lists [][]int) []int {
	if len(lists) == 0 {
		return nil
	}
	if len(lists) == 1 {
		return lists[0]
	}
	total := 0
	for _, l := range lists {
		total += len(l)
	}
	out := make([]int, 0, total)
	for _, l := range lists {
		out = append(out, l...)
	}
	sort.Ints(out)
	w := 1
	for i := 1; i < len(out); i++ {
		if out[i] != out[w-1] {
			out[w] = out[i]
			w++
		}
	}
	return out[:w]
}

// moduleHasInputImport reports whether mod imports `input` or any subpath of
// `input` (e.g. `import input.document as docs`).
func moduleHasInputImport(mod *ast.Module) bool {
	if mod == nil {
		return false
	}
	for _, imp := range mod.Imports {
		if ref, ok := imp.Path.Value.(ast.Ref); ok && len(ref) > 0 && ref[0].Equal(ast.InputRootDocument) {
			return true
		}
	}
	return false
}

// moduleHasWith reports whether mod contains any `with` replacement modifier.
func moduleHasWith(mod *ast.Module) bool {
	if mod == nil {
		return false
	}
	found := false
	ast.WalkWiths(mod, func(*ast.With) bool {
		found = true
		return true
	})
	return found
}

// moduleReadsInput reports whether any rule in mod references the `input`
// global variable (directly or via an `import input...`). Used once per loaded
// library to prove libraries do not perform hidden cross-document reads.
func moduleReadsInput(mod *ast.Module) bool {
	if mod == nil {
		return false
	}
	if moduleHasInputImport(mod) {
		return true
	}
	found := false
	ast.WalkRefs(mod, func(r ast.Ref) bool {
		if len(r) > 0 && r[0].Equal(ast.InputRootDocument) {
			found = true
			return true
		}
		return false
	})
	if found {
		return true
	}
	ast.WalkVars(mod, func(v ast.Var) bool {
		if v == ast.InputRootDocument.Value {
			found = true
			return true
		}
		return false
	})
	return found
}

// moduleNeedsTerraformFacts reports whether a module might read the additive
// Terraform facts envelope. Only references provably rooted at
// input.document are safe to ignore here. Imported input aliases and whole
// input references are conservative positives.
func moduleNeedsTerraformFacts(mod *ast.Module) bool {
	if mod == nil {
		return false
	}
	if moduleHasInputImport(mod) {
		return true
	}
	needsFacts := false
	inputRoots := make(map[*ast.Term]struct{})
	ast.WalkRefs(mod, func(ref ast.Ref) bool {
		if len(ref) == 0 || !ref[0].Equal(ast.InputRootDocument) {
			return false
		}
		inputRoots[ref[0]] = struct{}{}
		if len(ref) < 2 {
			needsFacts = true
			return true
		}
		key, ok := ref[1].Value.(ast.String)
		if !ok || key != regoInputDocumentKey {
			needsFacts = true
			return true
		}
		return false
	})
	if needsFacts {
		return true
	}
	// A bare `input` variable (including passing the whole object to a helper)
	// is not represented as an input-rooted Ref. Ignore the root term when it
	// belongs to the provable legacy `input.document` reference.
	ast.WalkTerms(mod, func(term *ast.Term) bool {
		if v, ok := term.Value.(ast.Var); ok && v == ast.InputRootDocument.Value {
			if _, isRefRoot := inputRoots[term]; isRefRoot {
				return false
			}
			needsFacts = true
			return true
		}
		return false
	})
	return needsFacts
}

// moduleUsesUnsafeBuiltin reports whether mod references any blocked builtin
// anywhere in its expressions (including nested calls inside assignments).
func moduleUsesUnsafeBuiltin(mod *ast.Module) bool {
	if mod == nil {
		return false
	}
	found := false
	ast.WalkExprs(mod, func(e *ast.Expr) bool {
		if e.IsCall() {
			if _, unsafe := unsafeRegoFunctions[e.Operator().String()]; unsafe {
				found = true
				return true
			}
		}
		return false
	})
	if found {
		return true
	}
	ast.WalkTerms(mod, func(t *ast.Term) bool {
		if call, ok := t.Value.(ast.Call); ok && len(call) > 0 {
			if _, unsafe := unsafeRegoFunctions[call[0].String()]; unsafe {
				found = true
				return true
			}
		}
		return false
	})
	return found
}

// extractLibSubtreeFuncs inspects a parsed platform library AST and returns
// single-parameter helper functions whose return value (or named object fields
// of the return value) is provably a subtree of the input argument in every
// rule branch (e.g., k8s `spec_info(document)` returns `{"spec": document...}`).
func extractLibSubtreeFuncs(mod *ast.Module) map[string]map[string]bool {
	if mod == nil || moduleHasWith(mod) {
		return nil
	}
	byName := make(map[string][]*ast.Rule)
	for _, r := range mod.Rules {
		if r.Head == nil || len(r.Head.Args) != 1 {
			continue
		}
		name := string(r.Head.Name)
		for cur := r; cur != nil; cur = cur.Else {
			byName[name] = append(byName[name], cur)
		}
	}

	out := make(map[string]map[string]bool)
	for name, branches := range byName {
		if fields := intersectBranchSubtreeFields(branches); len(fields) > 0 {
			out[name] = fields
		}
	}
	return out
}

func intersectBranchSubtreeFields(branches []*ast.Rule) map[string]bool {
	var common map[string]bool
	for bi, r := range branches {
		if r.Head == nil || len(r.Head.Args) != 1 {
			return nil
		}
		argVar, ok := r.Head.Args[0].Value.(ast.Var)
		if !ok || argVar.IsWildcard() {
			return nil
		}
		bf := branchSubtreeFields(r, argVar)
		if len(bf) == 0 {
			return nil
		}
		if bi == 0 {
			common = bf
			continue
		}
		for k := range common {
			if !bf[k] {
				delete(common, k)
			}
		}
		if len(common) == 0 {
			return nil
		}
	}
	return common
}

func resolveHeadReturnTerm(r *ast.Rule) *ast.Term {
	val := r.Head.Value
	if val == nil {
		return nil
	}
	v, isVar := val.Value.(ast.Var)
	if !isVar {
		return val
	}
	for _, expr := range r.Body {
		lhs, rhs, ok := topLevelAssignOperands(expr)
		if !ok {
			continue
		}
		if lv, ok := lhs.Value.(ast.Var); ok && lv == v {
			return rhs
		}
		if rv, ok := rhs.Value.(ast.Var); ok && rv == v {
			return lhs
		}
	}
	return val
}

func branchSubtreeFields(r *ast.Rule, argVar ast.Var) map[string]bool {
	val := resolveHeadReturnTerm(r)
	if val == nil {
		return nil
	}
	fields := make(map[string]bool)
	switch tv := val.Value.(type) {
	case ast.Ref:
		if len(tv) >= 1 {
			if rv, ok := tv[0].Value.(ast.Var); ok && rv == argVar {
				fields[""] = true
			}
		}
	case ast.Object:
		_ = tv.Iter(func(k, v *ast.Term) error {
			ks, ok := k.Value.(ast.String)
			if !ok {
				return nil
			}
			if ref, ok := v.Value.(ast.Ref); ok && len(ref) >= 1 {
				if rv, ok := ref[0].Value.(ast.Var); ok && rv == argVar {
					fields[string(ks)] = true
				}
			}
			return nil
		})
	}
	return fields
}

func topLevelAssignOperands(expr *ast.Expr) (lhs, rhs *ast.Term, ok bool) {
	if expr.Negated || !expr.IsCall() {
		return nil, nil, false
	}
	op := expr.Operator().String()
	if op != ast.Assign.Name && op != ast.Equal.Name && op != ast.Equality.Name {
		return nil, nil, false
	}
	ops := expr.Operands()
	if len(ops) != 2 {
		return nil, nil, false
	}
	return ops[0], ops[1], true
}

// analyzeRuleFilter inspects a parsed rule module and returns a sound
// ruleDocFilter for supported platforms (terraform, kubernetes, cloudformation).
// Any unrecognized pattern conservatively returns an unconstrained filter.
func analyzeRuleFilter(
	mod *ast.Module,
	platform string,
	libReadsInput bool,
	libSubtreeFuncs map[string]map[string]bool,
) ruleDocFilter {
	canonPlat := canonicalPlatformKey(platform)
	if mod == nil || (canonPlat != platformTerraform && canonPlat != platformKubernetes && canonPlat != platformCloudFormation) {
		return ruleDocFilter{}
	}
	if moduleUsesUnsafeBuiltin(mod) || moduleHasWith(mod) {
		return ruleDocFilter{}
	}

	policyRules, helperReadsInput, ok := collectPolicyRules(mod)
	if !ok {
		return ruleDocFilter{}
	}

	constSets := extractConstStringSets(mod)
	allSingleDoc := !libReadsInput && !helperReadsInput && !moduleHasInputImport(mod) && allRulesSingleDoc(policyRules)

	switch canonPlat {
	case platformTerraform:
		return analyzeTerraformRule(policyRules, constSets, allSingleDoc)
	case platformKubernetes:
		return analyzeKubernetesRule(mod, policyRules, constSets, libSubtreeFuncs, allSingleDoc)
	case platformCloudFormation:
		return analyzeCloudFormationRule(policyRules, constSets, allSingleDoc)
	default:
		return ruleDocFilter{}
	}
}

func collectPolicyRules(mod *ast.Module) (policyRules []*ast.Rule, helperReadsInput, ok bool) {
	for _, r := range mod.Rules {
		if r.Head != nil && r.Head.Name == policyRuleName {
			if r.Else != nil {
				return nil, false, false
			}
			policyRules = append(policyRules, r)
			continue
		}
		if ruleReadsInputDocument(r) {
			helperReadsInput = true
		}
	}
	return policyRules, helperReadsInput, len(policyRules) > 0
}

func allRulesSingleDoc(rules []*ast.Rule) bool {
	for _, r := range rules {
		if _, ok := singleDocIndexVar(r); !ok {
			return false
		}
	}
	return true
}

func ruleReadsInputDocument(r *ast.Rule) bool {
	found := false
	ast.WalkRefs(r, func(ref ast.Ref) bool {
		if len(ref) > 0 && ref[0].Equal(ast.InputRootDocument) {
			if len(ref) >= 2 {
				if s, ok := ref[1].Value.(ast.String); ok && s == regoInputArgumentsKey {
					return false
				}
			}
			found = true
			return true
		}
		return false
	})
	if found {
		return true
	}
	ast.WalkTerms(r, func(t *ast.Term) bool {
		if v, ok := t.Value.(ast.Var); ok && v == ast.InputRootDocument.Value {
			found = true
			return true
		}
		return false
	})
	return found
}

// singleDocIndexVar verifies that every reference to `input` in r (other than
// `input.arguments...`) has the form `input.document[v]...` for the exact same
// non-wildcard variable `v`, AND that `v` is never used outside `input.document[v]`
// and `some` declarations.
func singleDocIndexVar(r *ast.Rule) (ast.Var, bool) {
	hasClosure := false
	ast.WalkClosures(r, func(interface{}) bool {
		hasClosure = true
		return true
	})
	if hasClosure {
		return "", false
	}
	allowed := collectSomeDeclTerms(r)
	docVar, ok := findSingleInputDocVar(r, allowed)
	if !ok {
		return "", false
	}
	if hasDisallowedInputOrDocVar(r, docVar, allowed) {
		return "", false
	}
	return docVar, true
}

func collectSomeDeclTerms(r *ast.Rule) map[*ast.Term]struct{} {
	allowed := make(map[*ast.Term]struct{})
	ast.WalkExprs(r, func(e *ast.Expr) bool {
		if decl, isSome := e.Terms.(*ast.SomeDecl); isSome {
			for _, t := range decl.Symbols {
				allowed[t] = struct{}{}
			}
		}
		return false
	})
	return allowed
}

func findSingleInputDocVar(r *ast.Rule, allowed map[*ast.Term]struct{}) (ast.Var, bool) {
	var docVar ast.Var
	hasDocVar := false
	ok := true

	ast.WalkTerms(r, func(t *ast.Term) bool {
		if !ok {
			return true
		}
		val, isRef := t.Value.(ast.Ref)
		if !isRef || len(val) == 0 || !val[0].Equal(ast.InputRootDocument) {
			return false
		}
		if len(val) >= 2 {
			if s, isStr := val[1].Value.(ast.String); isStr && s == regoInputArgumentsKey {
				allowed[val[0]] = struct{}{}
				return false
			}
		}
		v, valid := extractSingleDocSubscript(val)
		if !valid || (hasDocVar && docVar != v) {
			ok = false
			return true
		}
		docVar = v
		hasDocVar = true
		allowed[val[0]] = struct{}{}
		allowed[val[2]] = struct{}{}
		return false
	})
	return docVar, ok && hasDocVar
}

func extractSingleDocSubscript(ref ast.Ref) (ast.Var, bool) {
	if len(ref) < 3 {
		return "", false
	}
	if s, isStr := ref[1].Value.(ast.String); !isStr || s != regoInputDocumentKey {
		return "", false
	}
	v, isVar := ref[2].Value.(ast.Var)
	if !isVar || v.IsWildcard() {
		return "", false
	}
	return v, true
}

func hasDisallowedInputOrDocVar(r *ast.Rule, docVar ast.Var, allowed map[*ast.Term]struct{}) bool {
	disallowed := false
	ast.WalkTerms(r, func(t *ast.Term) bool {
		if disallowed {
			return true
		}
		v, isVar := t.Value.(ast.Var)
		if !isVar {
			return false
		}
		if v == ast.InputRootDocument.Value || v == docVar {
			if _, ok := allowed[t]; !ok {
				disallowed = true
				return true
			}
		}
		return false
	})
	return disallowed
}

func isTrivialRuleBody(body ast.Body) bool {
	if len(body) == 0 {
		return true
	}
	return len(body) == 1 && body[0].Equal(trivialTrueExpr)
}

// extractConstStringSets collects module-level constant string sets/arrays
// (e.g. `kinds := {"Deployment", "DaemonSet"}`). Only complete, single-name
// rules defined once unconditionally are recorded so partial objects, partial
// sets, and multi-branch definitions are never misread.
func extractConstStringSets(mod *ast.Module) map[string][]string {
	counts := make(map[ast.Var]int, len(mod.Rules))
	for _, r := range mod.Rules {
		if r.Head != nil {
			counts[r.Head.Name]++
		}
	}
	out := make(map[string][]string)
	for _, r := range mod.Rules {
		if !isCompleteConstRule(r, counts) {
			continue
		}
		if strs, ok := extractStringLiterals(r.Head.Value.Value); ok && len(strs) > 0 {
			out[string(r.Head.Name)] = strs
		}
	}
	return out
}

func isCompleteConstRule(r *ast.Rule, counts map[ast.Var]int) bool {
	if r.Head == nil || r.Default || r.Else != nil || len(r.Head.Args) > 0 || r.Head.Value == nil {
		return false
	}
	if counts[r.Head.Name] != 1 || !isTrivialRuleBody(r.Body) {
		return false
	}
	return r.Head.DocKind() == ast.CompleteDoc && r.Head.Key == nil && len(r.Head.Ref()) == 1
}

// bodyConstSets removes any module-level constant name that body locally
// shadows via `:=`, `some`, or `every` bindings so local definitions are never
// resolved to module-level constants.
func bodyConstSets(body ast.Body, moduleConstSets map[string][]string) map[string][]string {
	if len(moduleConstSets) == 0 {
		return nil
	}
	var shadowed map[string]struct{}
	mark := func(v ast.Var) {
		name := string(v)
		if _, exists := moduleConstSets[name]; !exists {
			return
		}
		if shadowed == nil {
			shadowed = make(map[string]struct{}, 2)
		}
		shadowed[name] = struct{}{}
	}
	for _, expr := range body {
		collectExprLocalBindings(expr, mark)
	}
	if len(shadowed) == 0 {
		return moduleConstSets
	}
	filtered := make(map[string][]string, len(moduleConstSets)-len(shadowed))
	for k, v := range moduleConstSets {
		if _, isShadowed := shadowed[k]; !isShadowed {
			filtered[k] = v
		}
	}
	return filtered
}

func collectExprLocalBindings(expr *ast.Expr, mark func(ast.Var)) {
	switch terms := expr.Terms.(type) {
	case *ast.SomeDecl:
		for _, t := range terms.Symbols {
			ast.WalkVars(t, func(v ast.Var) bool {
				mark(v)
				return false
			})
		}
	case *ast.Every:
		if terms.Key != nil {
			if v, ok := terms.Key.Value.(ast.Var); ok {
				mark(v)
			}
		}
		if terms.Value != nil {
			if v, ok := terms.Value.Value.(ast.Var); ok {
				mark(v)
			}
		}
	default:
		if expr.IsCall() && expr.Operator().String() == ast.Assign.Name {
			if ops := expr.Operands(); len(ops) == 2 {
				ast.WalkVars(ops[0], func(v ast.Var) bool {
					mark(v)
					return false
				})
			}
		}
	}
}

func allNonEmptyStrings(strs []string) bool {
	if len(strs) == 0 {
		return false
	}
	for _, s := range strs {
		if s == "" {
			return false
		}
	}
	return true
}

func allIndexableKeys(strs []string) bool {
	if len(strs) == 0 {
		return false
	}
	for _, s := range strs {
		if s == "" || s[0] == '_' {
			return false
		}
	}
	return true
}

func extractStringLiterals(v ast.Value) ([]string, bool) {
	switch c := v.(type) {
	case ast.Set:
		out := make([]string, 0, c.Len())
		ok := true
		c.Foreach(func(t *ast.Term) {
			if s, isStr := t.Value.(ast.String); isStr {
				out = append(out, string(s))
			} else {
				ok = false
			}
		})
		return out, ok && len(out) > 0
	case *ast.Array:
		out := make([]string, 0, c.Len())
		for i := 0; i < c.Len(); i++ {
			s, isStr := c.Elem(i).Value.(ast.String)
			if !isStr {
				return nil, false
			}
			out = append(out, string(s))
		}
		return out, len(out) > 0
	}
	return nil, false
}

// bodyAliases tracks simple top-level non-negated variable assignments to
// input.document[i] within a single rule body.
type bodyAliases struct {
	docVars map[ast.Var]ast.Var
}

func collectBodyDocAliases(body ast.Body) bodyAliases {
	a := bodyAliases{docVars: make(map[ast.Var]ast.Var)}
	for _, expr := range body {
		lhs, rhs, ok := topLevelAssignOperands(expr)
		if !ok {
			continue
		}
		a.tryBindDoc(lhs, rhs)
		a.tryBindDoc(rhs, lhs)
	}
	return a
}

func (a bodyAliases) tryBindDoc(lhs, rhs *ast.Term) {
	v, ok := lhs.Value.(ast.Var)
	if !ok || v.IsWildcard() {
		return
	}
	if idxVar, isDoc := matchInputDocRef(rhs); isDoc {
		a.docVars[v] = idxVar
	}
}

func matchInputDocRef(t *ast.Term) (ast.Var, bool) {
	ref, ok := t.Value.(ast.Ref)
	if !ok || len(ref) != 3 {
		return "", false
	}
	if !ref[0].Equal(ast.InputRootDocument) {
		return "", false
	}
	if s, ok := ref[1].Value.(ast.String); !ok || s != regoInputDocumentKey {
		return "", false
	}
	v, ok := ref[2].Value.(ast.Var)
	if !ok {
		return "", false
	}
	return v, true
}

func (a bodyAliases) docRefTail(ref ast.Ref) ([]*ast.Term, bool) {
	if len(ref) >= 4 && ref[0].Equal(ast.InputRootDocument) {
		if s, ok := ref[1].Value.(ast.String); ok && s == regoInputDocumentKey {
			if _, isVar := ref[2].Value.(ast.Var); isVar {
				return ref[3:], true
			}
		}
	}
	if len(ref) >= 2 {
		if v, ok := ref[0].Value.(ast.Var); ok {
			if _, isAlias := a.docVars[v]; isAlias {
				return ref[1:], true
			}
		}
	}
	return nil, false
}

func collectVarStringConstraints(body ast.Body, constSets map[string][]string) (exact, lower map[ast.Var][]string) {
	exact = make(map[ast.Var][]string)
	lower = make(map[ast.Var][]string)

	for _, expr := range body {
		if expr.Negated {
			continue
		}
		collectExprStringConstraint(expr, constSets, exact, lower)
	}
	return exact, lower
}

func collectExprStringConstraint(expr *ast.Expr, constSets map[string][]string, exact, lower map[ast.Var][]string) {
	if expr.IsCall() {
		op := expr.Operator().String()
		ops := expr.Operands()
		if len(ops) != 2 {
			return
		}
		switch op {
		case ast.Equal.Name, ast.Equality.Name, ast.Assign.Name:
			extractEqStringConstraint(ops[0], ops[1], constSets, exact, lower)
			extractEqStringConstraint(ops[1], ops[0], constSets, exact, lower)
		case ast.Member.Name:
			if v, ok := ops[0].Value.(ast.Var); ok && !v.IsWildcard() {
				if strs, ok := resolveStringCollection(ops[1], constSets); ok {
					exact[v] = append(exact[v], strs...)
				}
			}
		}
		return
	}
	if t, ok := expr.Terms.(*ast.Term); ok {
		if ref, ok := t.Value.(ast.Ref); ok && len(ref) == 2 {
			if v, ok := ref[1].Value.(ast.Var); ok && !v.IsWildcard() {
				if strs, ok := resolveStringCollection(ref[0], constSets); ok {
					exact[v] = append(exact[v], strs...)
				}
			}
		}
	}
}

func extractEqStringConstraint(lhs, rhs *ast.Term, constSets map[string][]string, exact, lower map[ast.Var][]string) {
	if v, ok := lhs.Value.(ast.Var); ok && !v.IsWildcard() {
		if s, ok := rhs.Value.(ast.String); ok {
			exact[v] = append(exact[v], string(s))
			return
		}
		if ref, ok := rhs.Value.(ast.Ref); ok && len(ref) == 2 {
			if strs, ok := resolveStringCollection(ref[0], constSets); ok {
				exact[v] = append(exact[v], strs...)
				return
			}
		}
	}
	if call, ok := lhs.Value.(ast.Call); ok && len(call) == 2 && call[0].String() == ast.Lower.Name {
		if v, ok := call[1].Value.(ast.Var); ok && !v.IsWildcard() {
			if s, ok := rhs.Value.(ast.String); ok {
				lower[v] = append(lower[v], strings.ToLower(string(s)))
			}
		}
	}
}

func resolveStringCollection(t *ast.Term, constSets map[string][]string) ([]string, bool) {
	if strs, ok := extractStringLiterals(t.Value); ok {
		return strs, true
	}
	if v, ok := t.Value.(ast.Var); ok {
		if strs, exists := constSets[string(v)]; exists {
			return strs, true
		}
	}
	return nil, false
}

// walkTopLevelNonNegatedRefs visits refs in a single top-level non-negated
// expression without descending into comprehensions or closures.
func walkTopLevelNonNegatedRefs(expr *ast.Expr, fn func(ast.Ref)) {
	if expr.Negated {
		return
	}
	var visit func(interface{})
	visit = func(x interface{}) {
		switch node := x.(type) {
		case *ast.Term:
			if node != nil {
				visit(node.Value)
			}
		case []*ast.Term:
			for _, t := range node {
				visit(t)
			}
		case ast.Call:
			for _, t := range node {
				visit(t)
			}
		case ast.Ref:
			fn(node)
			for _, t := range node {
				visit(t)
			}
		case *ast.Array:
			for i := 0; i < node.Len(); i++ {
				visit(node.Elem(i))
			}
		case ast.Object:
			_ = node.Iter(func(k, v *ast.Term) error {
				visit(k)
				visit(v)
				return nil
			})
		case ast.Set:
			node.Foreach(func(t *ast.Term) { visit(t) })
		}
	}
	visit(expr.Terms)
}

func analyzeTerraformRule(policyRules []*ast.Rule, constSets map[string][]string, canSubset bool) ruleDocFilter {
	predSet := make(map[tfResourceKey]struct{})
	for _, r := range policyRules {
		bodyPreds := extractTerraformBodyPreds(r.Body, constSets)
		if len(bodyPreds) == 0 {
			return ruleDocFilter{}
		}
		for _, p := range bodyPreds {
			predSet[p] = struct{}{}
		}
	}
	if len(predSet) == 0 {
		return ruleDocFilter{}
	}
	preds := make([]tfResourceKey, 0, len(predSet))
	for p := range predSet {
		preds = append(preds, p)
	}
	sort.Slice(preds, func(i, j int) bool {
		if preds[i].section != preds[j].section {
			return preds[i].section < preds[j].section
		}
		return preds[i].typ < preds[j].typ
	})
	var kb strings.Builder
	for i, p := range preds {
		if i > 0 {
			kb.WriteByte('|')
		}
		kb.WriteString(p.section)
		if p.typ != "" {
			kb.WriteByte(':')
			kb.WriteString(p.typ)
		}
	}
	return ruleDocFilter{
		constrained: true,
		canSubset:   canSubset,
		platform:    platformTerraform,
		tfPreds:     preds,
		cacheKey:    kb.String(),
	}
}

func extractTerraformBodyPreds(body ast.Body, constSets map[string][]string) []tfResourceKey {
	scopedSets := bodyConstSets(body, constSets)
	aliases := collectBodyDocAliases(body)
	exactVar, _ := collectVarStringConstraints(body, scopedSets)

	var specific []tfResourceKey
	var sectionOnly []tfResourceKey

	for _, expr := range body {
		if expr.Negated {
			continue
		}
		walkTopLevelNonNegatedRefs(expr, func(ref ast.Ref) {
			collectTerraformRefPred(aliases, exactVar, ref, &specific, &sectionOnly)
		})
	}
	if len(specific) > 0 {
		return specific
	}
	return sectionOnly
}

func collectTerraformRefPred(
	aliases bodyAliases,
	exactVar map[ast.Var][]string,
	ref ast.Ref,
	specific, sectionOnly *[]tfResourceKey,
) {
	tail, ok := aliases.docRefTail(ref)
	if !ok || len(tail) == 0 {
		return
	}
	sec, ok := tail[0].Value.(ast.String)
	if !ok {
		return
	}
	secStr := string(sec)
	switch secStr {
	case tfSectionResource, dataRoot, tfSectionProvider:
		if len(tail) >= 2 {
			switch t := tail[1].Value.(type) {
			case ast.String:
				if s := string(t); s != "" && s[0] != '_' {
					*specific = append(*specific, tfResourceKey{section: secStr, typ: s})
					return
				}
			case ast.Var:
				if strs := exactVar[t]; allIndexableKeys(strs) {
					for _, s := range strs {
						*specific = append(*specific, tfResourceKey{section: secStr, typ: s})
					}
					return
				}
			}
		}
		*sectionOnly = append(*sectionOnly, tfResourceKey{section: secStr})
	case tfSectionModule, tfSectionLocals, tfSectionVariable, tfSectionOutput, platformTerraform:
		*sectionOnly = append(*sectionOnly, tfResourceKey{section: secStr})
	}
}

func analyzeKubernetesRule(
	mod *ast.Module,
	policyRules []*ast.Rule,
	constSets map[string][]string,
	libSubtreeFuncs map[string]map[string]bool,
	canSubset bool,
) ruleDocFilter {
	if filter, ok := analyzeKubernetesKinds(policyRules, constSets, canSubset); ok {
		return filter
	}
	if len(policyRules) != 1 {
		return ruleDocFilter{}
	}
	k8sLibAliases := findPlatformLibAliases(mod, "k8s")
	conjuncts := extractK8sBodyKeyConjuncts(policyRules[0].Body, constSets, k8sLibAliases, libSubtreeFuncs)
	if len(conjuncts) == 0 {
		return ruleDocFilter{}
	}
	return ruleDocFilter{
		constrained:     true,
		canSubset:       canSubset,
		platform:        platformKubernetes,
		k8sKeyConjuncts: conjuncts,
	}
}

func analyzeKubernetesKinds(policyRules []*ast.Rule, constSets map[string][]string, canSubset bool) (ruleDocFilter, bool) {
	exactSet := make(map[string]struct{})
	lowerSet := make(map[string]struct{})

	for _, r := range policyRules {
		ex, lo := extractK8sBodyKinds(r.Body, constSets)
		if len(ex) == 0 && len(lo) == 0 {
			return ruleDocFilter{}, false
		}
		for _, k := range ex {
			exactSet[k] = struct{}{}
		}
		for _, k := range lo {
			lowerSet[k] = struct{}{}
		}
	}
	exact := sortedMapKeys(exactSet)
	lower := sortedMapKeys(lowerSet)
	var kb strings.Builder
	kb.WriteString("e:")
	kb.WriteString(strings.Join(exact, ","))
	kb.WriteString("|l:")
	kb.WriteString(strings.Join(lower, ","))
	return ruleDocFilter{
		constrained: true,
		canSubset:   canSubset,
		platform:    platformKubernetes,
		k8sExact:    exact,
		k8sLower:    lower,
		cacheKey:    kb.String(),
	}, true
}

func sortedMapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func findPlatformLibAliases(mod *ast.Module, libName string) map[string]bool {
	aliases := make(map[string]bool)
	for _, imp := range mod.Imports {
		ref, ok := imp.Path.Value.(ast.Ref)
		if !ok || len(ref) != 3 || !ref[0].Equal(ast.DefaultRootDocument) {
			continue
		}
		s1, ok1 := ref[1].Value.(ast.String)
		s2, ok2 := ref[2].Value.(ast.String)
		if ok1 && ok2 && s1 == "generic" && string(s2) == libName {
			if imp.Alias != "" {
				aliases[string(imp.Alias)] = true
			} else {
				aliases[libName] = true
			}
		}
	}
	return aliases
}

type k8sSubtreeTracker struct {
	aliases         bodyAliases
	docSubtreeVars  map[ast.Var]bool
	wrappedSubtrees map[ast.Var]map[string]bool
	k8sLibAliases   map[string]bool
	libSubtreeFuncs map[string]map[string]bool
}

func (tr *k8sSubtreeTracker) isSubtreeRef(ref ast.Ref) (int, bool) {
	if _, ok := tr.aliases.docRefTail(ref); ok {
		if len(ref) >= 4 && ref[0].Equal(ast.InputRootDocument) {
			return 3, true
		}
		return 1, true
	}
	if len(ref) < 2 {
		return 0, false
	}
	v, ok := ref[0].Value.(ast.Var)
	if !ok {
		return 0, false
	}
	if tr.docSubtreeVars[v] {
		return 1, true
	}
	if fields, ok := tr.wrappedSubtrees[v]; ok {
		if f, ok := ref[1].Value.(ast.String); ok && fields[string(f)] {
			return 2, true
		}
	}
	return 0, false
}

func (tr *k8sSubtreeTracker) isSubtreeTerm(t *ast.Term) bool {
	if v, ok := t.Value.(ast.Var); ok {
		return tr.docSubtreeVars[v]
	}
	if ref, ok := t.Value.(ast.Ref); ok {
		_, ok := tr.isSubtreeRef(ref)
		return ok
	}
	return false
}

func (tr *k8sSubtreeTracker) bind(lhs, rhs *ast.Term) bool {
	v, ok := lhs.Value.(ast.Var)
	if !ok || v.IsWildcard() {
		return false
	}
	if tr.isSubtreeTerm(rhs) {
		if !tr.docSubtreeVars[v] {
			tr.docSubtreeVars[v] = true
			return true
		}
		return false
	}
	return tr.bindLibCall(v, rhs)
}

func (tr *k8sSubtreeTracker) bindLibCall(v ast.Var, rhs *ast.Term) bool {
	call, ok := rhs.Value.(ast.Call)
	if !ok || len(call) != 2 || !tr.isSubtreeTerm(call[1]) {
		return false
	}
	fnRef, ok := call[0].Value.(ast.Ref)
	if !ok || len(fnRef) != 2 {
		return false
	}
	alias, ok1 := fnRef[0].Value.(ast.Var)
	fnName, ok2 := fnRef[1].Value.(ast.String)
	if !ok1 || !ok2 || !tr.k8sLibAliases[string(alias)] {
		return false
	}
	fields, ok := tr.libSubtreeFuncs[string(fnName)]
	if !ok {
		return false
	}
	changed := false
	if fields[""] && !tr.docSubtreeVars[v] {
		tr.docSubtreeVars[v] = true
		changed = true
	}
	if _, exists := tr.wrappedSubtrees[v]; !exists {
		tr.wrappedSubtrees[v] = fields
		changed = true
	}
	return changed
}

func (tr *k8sSubtreeTracker) propagate(body ast.Body) {
	for pass := 0; pass < maxSubtreePass; pass++ {
		changed := false
		for _, expr := range body {
			lhs, rhs, ok := topLevelAssignOperands(expr)
			if !ok {
				continue
			}
			changed = tr.bind(lhs, rhs) || changed
			changed = tr.bind(rhs, lhs) || changed
		}
		if !changed {
			break
		}
	}
}

// extractK8sBodyKeyConjuncts finds object keys (or finite OR-sets of keys) that
// MUST exist inside `input.document[i]` for a single-body K8s rule to match.
func extractK8sBodyKeyConjuncts(
	body ast.Body,
	constSets map[string][]string,
	k8sLibAliases map[string]bool,
	libSubtreeFuncs map[string]map[string]bool,
) [][]string {
	scopedSets := bodyConstSets(body, constSets)
	aliases := collectBodyDocAliases(body)
	exactVar, _ := collectVarStringConstraints(body, scopedSets)

	docSubtreeVars := make(map[ast.Var]bool, len(aliases.docVars)+aliasExtraCap)
	for v := range aliases.docVars {
		docSubtreeVars[v] = true
	}
	tracker := &k8sSubtreeTracker{
		aliases:         aliases,
		docSubtreeVars:  docSubtreeVars,
		wrappedSubtrees: make(map[ast.Var]map[string]bool),
		k8sLibAliases:   k8sLibAliases,
		libSubtreeFuncs: libSubtreeFuncs,
	}
	tracker.propagate(body)

	seenGroups := make(map[string]struct{})
	var conjuncts [][]string
	for _, expr := range body {
		if expr.Negated {
			continue
		}
		walkTopLevelNonNegatedRefs(expr, func(ref ast.Ref) {
			start, ok := tracker.isSubtreeRef(ref)
			if !ok {
				return
			}
			for i := start; i < len(ref); i++ {
				if group := k8sStepKeys(ref[i].Value, exactVar, scopedSets); len(group) > 0 {
					conjuncts = appendUniqueKeyGroup(conjuncts, seenGroups, group)
				}
			}
		})
	}
	return conjuncts
}

func k8sStepKeys(v ast.Value, exactVar map[ast.Var][]string, constSets map[string][]string) []string {
	switch step := v.(type) {
	case ast.String:
		return []string{string(step)}
	case ast.Var:
		return exactVar[step]
	case ast.Ref:
		if len(step) == 2 {
			if strs, ok := resolveStringCollection(step[0], constSets); ok {
				return strs
			}
		}
	}
	return nil
}

func appendUniqueKeyGroup(conjuncts [][]string, seen map[string]struct{}, keys []string) [][]string {
	if !allIndexableKeys(keys) {
		return conjuncts
	}
	cp := make([]string, len(keys))
	copy(cp, keys)
	sort.Strings(cp)
	w := 1
	for i := 1; i < len(cp); i++ {
		if cp[i] != cp[w-1] {
			cp[w] = cp[i]
			w++
		}
	}
	cp = cp[:w]
	sig := strings.Join(cp, ",")
	if _, exists := seen[sig]; exists {
		return conjuncts
	}
	seen[sig] = struct{}{}
	return append(conjuncts, cp)
}

func extractK8sBodyKinds(body ast.Body, constSets map[string][]string) (exact, lower []string) {
	scopedSets := bodyConstSets(body, constSets)
	aliases := collectBodyDocAliases(body)
	exactVar, lowerVar := collectVarStringConstraints(body, scopedSets)

	for v := range collectKindAliasVars(body, aliases) {
		if ex := exactVar[v]; allNonEmptyStrings(ex) {
			exact = append(exact, ex...)
		}
		if lo := lowerVar[v]; allNonEmptyStrings(lo) {
			lower = append(lower, lo...)
		}
	}

	for _, expr := range body {
		if expr.Negated {
			continue
		}
		ex, lo := extractDirectKindExpr(expr, aliases, scopedSets)
		if allNonEmptyStrings(ex) {
			exact = append(exact, ex...)
		}
		if allNonEmptyStrings(lo) {
			lower = append(lower, lo...)
		}
	}
	return exact, lower
}

func collectKindAliasVars(body ast.Body, aliases bodyAliases) map[ast.Var]struct{} {
	kindVars := make(map[ast.Var]struct{})
	check := func(lhs, rhs *ast.Term) {
		if ref, ok := rhs.Value.(ast.Ref); ok && isDocKindRef(aliases, ref) {
			if v, ok := lhs.Value.(ast.Var); ok && !v.IsWildcard() {
				kindVars[v] = struct{}{}
			}
		}
	}
	for _, expr := range body {
		lhs, rhs, ok := topLevelAssignOperands(expr)
		if !ok {
			continue
		}
		check(lhs, rhs)
		check(rhs, lhs)
	}
	return kindVars
}

func extractDirectKindExpr(expr *ast.Expr, aliases bodyAliases, constSets map[string][]string) (exact, lower []string) {
	if expr.IsCall() {
		op := expr.Operator().String()
		ops := expr.Operands()
		if len(ops) != 2 {
			return nil, nil
		}
		switch op {
		case ast.Equal.Name, ast.Equality.Name, ast.Assign.Name:
			ex1, lo1 := matchDirectKindEq(ops[0], ops[1], aliases, constSets)
			ex2, lo2 := matchDirectKindEq(ops[1], ops[0], aliases, constSets)
			return append(ex1, ex2...), append(lo1, lo2...)
		case ast.Member.Name:
			if ref, ok := ops[0].Value.(ast.Ref); ok && isDocKindRef(aliases, ref) {
				if strs, ok := resolveStringCollection(ops[1], constSets); ok {
					return strs, nil
				}
			}
		}
		return nil, nil
	}
	if t, ok := expr.Terms.(*ast.Term); ok {
		if ref, ok := t.Value.(ast.Ref); ok && len(ref) == 2 {
			if inner, ok := ref[1].Value.(ast.Ref); ok && isDocKindRef(aliases, inner) {
				if strs, ok := resolveStringCollection(ref[0], constSets); ok {
					return strs, nil
				}
			}
		}
	}
	return nil, nil
}

func matchDirectKindEq(lhs, rhs *ast.Term, aliases bodyAliases, constSets map[string][]string) (exact, lower []string) {
	if ref, ok := lhs.Value.(ast.Ref); ok && isDocKindRef(aliases, ref) {
		if s, ok := rhs.Value.(ast.String); ok && string(s) != "" {
			return []string{string(s)}, nil
		}
		if r2, ok := rhs.Value.(ast.Ref); ok && len(r2) == 2 {
			if strs, ok := resolveStringCollection(r2[0], constSets); ok {
				return strs, nil
			}
		}
	}
	if call, ok := lhs.Value.(ast.Call); ok && len(call) == 2 && call[0].String() == ast.Lower.Name {
		if ref, ok := call[1].Value.(ast.Ref); ok && isDocKindRef(aliases, ref) {
			if s, ok := rhs.Value.(ast.String); ok && string(s) != "" {
				return nil, []string{strings.ToLower(string(s))}
			}
		}
	}
	return nil, nil
}

func isDocKindRef(aliases bodyAliases, ref ast.Ref) bool {
	tail, ok := aliases.docRefTail(ref)
	if !ok || len(tail) != 1 {
		return false
	}
	s, ok := tail[0].Value.(ast.String)
	return ok && s == "kind"
}

func analyzeCloudFormationRule(policyRules []*ast.Rule, constSets map[string][]string, canSubset bool) ruleDocFilter {
	typeSet := make(map[string]struct{})
	for _, r := range policyRules {
		types := extractCFNBodyTypes(r.Body, constSets)
		if len(types) == 0 {
			return ruleDocFilter{}
		}
		for _, t := range types {
			typeSet[t] = struct{}{}
		}
	}
	types := sortedMapKeys(typeSet)
	return ruleDocFilter{
		constrained: true,
		canSubset:   canSubset,
		platform:    platformCloudFormation,
		cfnTypes:    types,
		cacheKey:    strings.Join(types, ","),
	}
}

type cfnSubtreeTracker struct {
	aliases        bodyAliases
	derivedFromDoc map[ast.Var]struct{}
}

func (tr *cfnSubtreeTracker) isDocSubtree(t *ast.Term) bool {
	if ref, ok := t.Value.(ast.Ref); ok {
		if _, ok := tr.aliases.docRefTail(ref); ok {
			return true
		}
		if len(ref) >= 1 {
			if v, ok := ref[0].Value.(ast.Var); ok {
				_, ok = tr.derivedFromDoc[v]
				return ok
			}
		}
	}
	if v, ok := t.Value.(ast.Var); ok {
		_, ok = tr.derivedFromDoc[v]
		return ok
	}
	return false
}

func (tr *cfnSubtreeTracker) isDerivedTypeRef(ref ast.Ref) bool {
	if len(ref) < 2 {
		return false
	}
	last, ok := ref[len(ref)-1].Value.(ast.String)
	if !ok || last != "Type" {
		return false
	}
	if _, ok := tr.aliases.docRefTail(ref); ok {
		return true
	}
	if v, ok := ref[0].Value.(ast.Var); ok {
		_, ok = tr.derivedFromDoc[v]
		return ok
	}
	return false
}

func (tr *cfnSubtreeTracker) bind(lhs, rhs *ast.Term) bool {
	if call, ok := rhs.Value.(ast.Call); ok && len(call) == 2 && call[0].String() == ast.WalkBuiltin.Name {
		if !tr.isDocSubtree(call[1]) {
			return false
		}
		if arr, ok := lhs.Value.(*ast.Array); ok && arr.Len() == 2 {
			if v, ok := arr.Elem(1).Value.(ast.Var); ok && !v.IsWildcard() {
				if _, exists := tr.derivedFromDoc[v]; !exists {
					tr.derivedFromDoc[v] = struct{}{}
					return true
				}
			}
		}
		return false
	}
	if v, ok := lhs.Value.(ast.Var); ok && !v.IsWildcard() && tr.isDocSubtree(rhs) {
		if _, exists := tr.derivedFromDoc[v]; !exists {
			tr.derivedFromDoc[v] = struct{}{}
			return true
		}
	}
	return false
}

func (tr *cfnSubtreeTracker) propagate(body ast.Body) {
	for pass := 0; pass < maxCFNPass; pass++ {
		changed := false
		for _, expr := range body {
			lhs, rhs, ok := topLevelAssignOperands(expr)
			if !ok {
				continue
			}
			changed = tr.bind(lhs, rhs) || changed
			changed = tr.bind(rhs, lhs) || changed
		}
		if !changed {
			break
		}
	}
}

func extractCFNBodyTypes(body ast.Body, constSets map[string][]string) []string {
	scopedSets := bodyConstSets(body, constSets)
	aliases := collectBodyDocAliases(body)
	exactVar, _ := collectVarStringConstraints(body, scopedSets)

	derived := make(map[ast.Var]struct{}, len(aliases.docVars)+aliasExtraCap)
	for v := range aliases.docVars {
		derived[v] = struct{}{}
	}
	tracker := &cfnSubtreeTracker{aliases: aliases, derivedFromDoc: derived}
	tracker.propagate(body)

	var out []string
	typeVars := make(map[ast.Var]struct{})
	for _, expr := range body {
		if expr.Negated || !expr.IsCall() {
			continue
		}
		out = appendCFNExprTypes(out, expr, tracker, scopedSets, typeVars)
	}
	for v := range typeVars {
		if strs := exactVar[v]; allNonEmptyStrings(strs) {
			out = append(out, strs...)
		}
	}
	if !allNonEmptyStrings(out) {
		return nil
	}
	return out
}

func appendCFNExprTypes(
	out []string,
	expr *ast.Expr,
	tracker *cfnSubtreeTracker,
	constSets map[string][]string,
	typeVars map[ast.Var]struct{},
) []string {
	op := expr.Operator().String()
	ops := expr.Operands()
	if len(ops) != 2 {
		return out
	}
	switch op {
	case ast.Equal.Name, ast.Equality.Name, ast.Assign.Name:
		out = matchCFNTypeEq(out, ops[0], ops[1], tracker, constSets, typeVars)
		out = matchCFNTypeEq(out, ops[1], ops[0], tracker, constSets, typeVars)
	case ast.Member.Name:
		if ref, ok := ops[0].Value.(ast.Ref); ok && tracker.isDerivedTypeRef(ref) {
			if strs, ok := resolveStringCollection(ops[1], constSets); ok {
				out = append(out, strs...)
			}
		}
	}
	return out
}

func matchCFNTypeEq(
	out []string,
	lhs, rhs *ast.Term,
	tracker *cfnSubtreeTracker,
	constSets map[string][]string,
	typeVars map[ast.Var]struct{},
) []string {
	ref, ok := lhs.Value.(ast.Ref)
	if !ok || !tracker.isDerivedTypeRef(ref) {
		return out
	}
	switch rv := rhs.Value.(type) {
	case ast.String:
		if string(rv) != "" {
			return append(out, string(rv))
		}
	case ast.Var:
		if !rv.IsWildcard() {
			typeVars[rv] = struct{}{}
		}
	case ast.Ref:
		if len(rv) == 2 {
			if strs, ok := resolveStringCollection(rv[0], constSets); ok {
				return append(out, strs...)
			}
		}
	}
	return out
}
