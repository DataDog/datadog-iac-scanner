/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
)

// ContractVersionV2 identifies the resource-centric, 4-state IaC rule contract.
const (
	ContractVersionV2  = "v2"
	UnknownSlotKey     = "$unknown"
	defaultKeyCacheCap = 64
	resourceFieldCap   = 13
	stateFieldCap      = 4
	derivedFieldCap    = 5
)

// UnknownSlot returns the structured placeholder object used inside lists/arrays
// to preserve exact element indices without shifting concrete elements or using
// string sentinels. The slot path must also be recorded in ValueState.Unknown
// or ValueState.Null; matching literal objects remain ordinary known data.
func UnknownSlot() map[string]any {
	return map[string]any{UnknownSlotKey: true}
}

// IsUnknownSlot reports only whether v has the placeholder shape. Callers must
// consult value-state provenance to classify the value as unknown or null.
func IsUnknownSlot(v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return false
	}
	b, ok := m[UnknownSlotKey].(bool)
	return ok && b
}

// SourceSpan locates a block or attribute in a source file (1-based lines/cols).
type SourceSpan struct {
	File      string
	StartLine int
	StartCol  int
	EndLine   int
	EndCol    int
}

// Valid reports whether the span carries a usable 1-based line number.
func (s SourceSpan) Valid() bool {
	return s.StartLine > 0
}

// ToResourceLocation converts s into the scanner's reporting location struct.
func (s SourceSpan) ToResourceLocation() model.ResourceLocation {
	endLine := max(s.EndLine, s.StartLine)
	startCol := max(s.StartCol, 1)
	endCol := max(s.EndCol, 1)
	if endLine == s.StartLine && endCol < startCol {
		endCol = startCol
	}
	return model.ResourceLocation{
		Start: model.ResourceLine{Line: s.StartLine, Col: startCol},
		End:   model.ResourceLine{Line: endLine, Col: endCol},
	}
}

// ValueState tracks the explicit 4-state provenance (Known, Unknown, Null,
// Absent) of a resource's attributes without encoding unknowns as sentinel
// strings inside Attributes.
type ValueState struct {
	Unknown               map[string]bool
	Null                  map[string]bool
	Written               map[string]bool
	IncompleteCollections map[string]bool
}

// TypedRef records structured reference provenance (for example inside a
// jsonencode policy leaf) so rules never need regexes over raw "${...}" text.
type TypedRef struct {
	Kind string // "resource", "data", "ephemeral", "var", "local", "module", ...
	Type string
	Name string
	Attr string
}

// TemplatePart is one segment of a partially known template string.
type TemplatePart struct {
	Known bool
	Value string
	// Ref is present only when this chunk is exactly a traversal or alias.
	Ref *TypedRef
}

// DerivedData holds demand-computed structured interpretations of raw string
// attributes (embedded JSON policies, filter ASTs, template parts).
type DerivedData struct {
	JSON          map[string]any
	JSONUnknown   map[string]map[string]bool
	JSONRefs      map[string]map[string][]TypedRef
	FilterExpr    map[string]any
	TemplateParts map[string][]TemplatePart
}

// RelationList is the resolved set of related resource IDs plus an explicit
// completeness flag. Complete is false when unresolved modules, unknown
// references, or uncertain literals may hide additional matches.
type RelationList struct {
	IDs      []string
	Complete bool
}

// ResourceRelations holds intra-unit graph edges for one resource.
type ResourceRelations struct {
	Targets    map[string]RelationList
	TargetsVia map[string]map[string]RelationList
	Related    map[string]map[string]RelationList
	Referrers  map[string]RelationList
}

// SourceMapping retains Go-side source ranges and attribution metadata for a
// resource without exposing engine internals to Rego.
type SourceMapping struct {
	BlockSpan         SourceSpan
	Ranges            map[string]SourceSpan
	ModuleAttribution *model.ModuleAttribution
	ModuleCallChain   string
	TerraformAddress  string
	RootModule        string
	StaticInModule    bool
	// OverrideInventoryLine anchors an effective overridden resource to its declaration.
	OverrideInventoryLine int
	// BeforeValue resolves the raw source text at path for scanner-derived
	// replacement remediations when a rule specifies "after" without "before".
	BeforeValue func(path Path) (string, bool)
	// RemediationPoint resolves the HCL insertion point for a given line.
	RemediationPoint func(line int, file *model.FileMetadata) (int, int, bool)
}

// Range resolves path to its tightest recorded SourceSpan, falling back to
// deepest ancestor and finally BlockSpan.
func (m *SourceMapping) Range(path Path) SourceSpan {
	if m == nil {
		return SourceSpan{}
	}
	for n := len(path); n > 0; n-- {
		key := PathKey(path[:n])
		if sp, ok := m.Ranges[key]; ok && sp.Valid() {
			return sp
		}
		if sp, ok := m.Ranges[key+".0"]; ok && sp.Valid() {
			return sp
		}
	}
	if sp, ok := m.Ranges[""]; ok && sp.Valid() {
		return sp
	}
	return m.BlockSpan
}

// Resource is one normalized, platform-agnostic infrastructure entity exposed
// to Contract v2 Rego rules under input.resources[type].
type Resource struct {
	ID          string
	Kind        string
	Type        string
	ResourceKey string // Key under input.resources (e.g. "aws_s3_bucket", "data.aws_caller_identity", "Service")
	Name        string
	Address     string
	File        string
	Attributes  map[string]any
	State       ValueState
	Derived     *DerivedData
	Relations   *ResourceRelations
	Platform    map[string]any
	Source      *SourceMapping
}

// BucketKey returns the map key under input.resources where r is indexed.
func (r *Resource) BucketKey() string {
	if r.ResourceKey != "" {
		return r.ResourceKey
	}
	return r.Type
}

// Unit is one independent deployment/evaluation boundary (for example one
// Terraform root module or plan file, one CloudFormation template, or one
// Kubernetes namespace+directory scope).
type Unit struct {
	ID            string
	Platform      string
	ScopeComplete bool
	Resources     []*Resource
	ByID          map[string]*Resource
}

// ProjectOptions controls how a Unit (or chunk of Units) is projected into an
// OPA ast.Value so single-resource rules pay no relation/by_id overhead.
type ProjectOptions struct {
	IncludeRelations bool
	IncludeByID      bool
	// AllowedTypes, when non-nil, restricts input.resources to the requested
	// bucket keys (referenced targets in by_id are still included when
	// IncludeByID is true).
	AllowedTypes map[string]bool
	// PlatformData attaches optional unit-level platform metadata under
	// input.platform.<platform>.
	PlatformData map[string]any
}

// ProjectUnits builds a single OPA input ast.Value from one or more Units.
// Resource terms are constructed once and pointer-shared between
// input.resources[type] and input.by_id[id].
func ProjectUnits(platform string, units []*Unit, opts ProjectOptions) ast.Value {
	input, _ := projectUnits(platform, units, opts, false)
	return input
}

// ProjectUnitsWithResourceCache builds the root-scope input and a cache of its
// resource terms for later resource-chunk projections. When relations are
// included, the cached terms preserve them so both scopes see the same resource.
func ProjectUnitsWithResourceCache(platform string, units []*Unit, opts ProjectOptions) (ast.Value, ast.Object) {
	return projectUnits(platform, units, opts, true)
}

func projectUnits(platform string, units []*Unit, opts ProjectOptions, cacheResourceTerms bool) (ast.Value, ast.Object) {
	byType := make(map[string][]*ast.Term)
	var cachedByType map[string][]*ast.Term
	if cacheResourceTerms {
		cachedByType = make(map[string][]*ast.Term)
	}
	var byIDPairs [][2]*ast.Term
	scopeComplete := true

	keyCache := make(map[string]*ast.Term, defaultKeyCacheCap)
	internKey := func(k string) *ast.Term {
		if t, ok := keyCache[k]; ok {
			return t
		}
		t := ast.StringTerm(k)
		keyCache[k] = t
		return t
	}

	for _, u := range units {
		if u == nil {
			continue
		}
		if !u.ScopeComplete {
			scopeComplete = false
		}
		appendUnitResources(u, opts, cacheResourceTerms, internKey, byType, cachedByType, &byIDPairs)
	}

	resPairs := make([][2]*ast.Term, 0, len(byType))
	for _, k := range sortedMapKeys(byType) {
		resPairs = append(resPairs, [2]*ast.Term{internKey(k), ast.NewTerm(ast.NewArray(byType[k]...))})
	}

	rootPairs := [][2]*ast.Term{
		{internKey("contract_version"), ast.StringTerm(ContractVersionV2)},
		{internKey("platform"), ast.StringTerm(platform)},
		{internKey("scope_complete"), ast.BooleanTerm(scopeComplete)},
		{internKey("resources"), ast.ObjectTerm(resPairs...)},
	}
	if opts.IncludeByID {
		rootPairs = append(rootPairs, [2]*ast.Term{internKey("by_id"), ast.ObjectTerm(byIDPairs...)})
	}
	if len(opts.PlatformData) > 0 {
		rootPairs = append(rootPairs, [2]*ast.Term{internKey("platform_data"), goToTerm(opts.PlatformData, internKey)})
	}
	input := ast.NewObject(rootPairs...)
	if !cacheResourceTerms {
		return input, nil
	}
	cachedResourcePairs := make([][2]*ast.Term, 0, len(cachedByType))
	for _, key := range sortedMapKeys(cachedByType) {
		cachedResourcePairs = append(cachedResourcePairs, [2]*ast.Term{
			internKey(key), ast.NewTerm(ast.NewArray(cachedByType[key]...)),
		})
	}
	return input, ast.NewObject(cachedResourcePairs...)
}

func appendUnitResources(
	unit *Unit,
	opts ProjectOptions,
	cacheResourceTerms bool,
	internKey func(string) *ast.Term,
	byType, cachedByType map[string][]*ast.Term,
	byIDPairs *[][2]*ast.Term,
) {
	for _, resource := range unit.Resources {
		if resource == nil {
			continue
		}
		bucket := resource.BucketKey()
		inAllowed := opts.AllowedTypes == nil || opts.AllowedTypes[bucket]
		if !inAllowed && !opts.IncludeByID {
			continue
		}
		var term, cachedTerm *ast.Term
		if cacheResourceTerms {
			term, cachedTerm = resourceToTermAndCache(resource, unit.ScopeComplete, opts.IncludeRelations, internKey)
		} else {
			term = resourceToTerm(resource, unit.ScopeComplete, opts.IncludeRelations, internKey)
		}
		if inAllowed {
			byType[bucket] = append(byType[bucket], term)
			if cacheResourceTerms {
				cachedByType[bucket] = append(cachedByType[bucket], cachedTerm)
			}
		}
		if opts.IncludeByID {
			*byIDPairs = append(*byIDPairs, [2]*ast.Term{ast.StringTerm(resource.ID), term})
		}
	}
}

func resourceToTerm(r *Resource, scopeComplete, includeRelations bool, internKey func(string) *ast.Term) *ast.Term {
	rootTerm, _ := resourceToTermAndCache(r, scopeComplete, includeRelations, internKey)
	return rootTerm
}

func resourceToTermAndCache(
	r *Resource,
	scopeComplete, includeRelations bool,
	internKey func(string) *ast.Term,
) (rootTerm, resourceTerm *ast.Term) {
	pairs := make([][2]*ast.Term, 0, resourceFieldCap)
	pairs = append(pairs,
		[2]*ast.Term{internKey("id"), ast.StringTerm(r.ID)},
		[2]*ast.Term{internKey("kind"), ast.StringTerm(r.Kind)},
		[2]*ast.Term{internKey("type"), ast.StringTerm(r.Type)},
		[2]*ast.Term{internKey("name"), ast.StringTerm(r.Name)},
		[2]*ast.Term{internKey("address"), ast.StringTerm(r.Address)},
		[2]*ast.Term{internKey("file"), ast.StringTerm(r.File)},
		[2]*ast.Term{internKey("scope_complete"), ast.BooleanTerm(scopeComplete)},
		[2]*ast.Term{internKey("attributes"), mapToTerm(r.Attributes, internKey)},
		[2]*ast.Term{internKey("state"), valueStateToTerm(r.State, internKey)},
	)
	if r.Derived != nil {
		pairs = append(pairs, [2]*ast.Term{internKey("derived"), derivedToTerm(r.Derived, internKey)})
	}
	if len(r.Platform) > 0 {
		pairs = append(pairs, [2]*ast.Term{internKey("platform"), mapToTerm(r.Platform, internKey)})
	}
	resourceTerm = ast.ObjectTerm(pairs...)
	if includeRelations && r.Relations != nil {
		pairs = append(pairs, [2]*ast.Term{internKey("relations"), relationsToTerm(r.Relations, internKey)})
		rootTerm = ast.ObjectTerm(pairs...)
		return rootTerm, rootTerm
	}
	return resourceTerm, resourceTerm
}

func valueStateToTerm(s ValueState, internKey func(string) *ast.Term) *ast.Term {
	pairs := make([][2]*ast.Term, 0, stateFieldCap)
	if len(s.Unknown) > 0 {
		pairs = append(pairs, [2]*ast.Term{internKey("unknown"), boolSetToTerm(s.Unknown, internKey)})
	}
	if len(s.Null) > 0 {
		pairs = append(pairs, [2]*ast.Term{internKey("null"), boolSetToTerm(s.Null, internKey)})
	}
	if len(s.Written) > 0 {
		pairs = append(pairs, [2]*ast.Term{internKey("written"), boolSetToTerm(s.Written, internKey)})
	}
	if len(s.IncompleteCollections) > 0 {
		pairs = append(pairs, [2]*ast.Term{internKey("incomplete_collections"), boolSetToTerm(s.IncompleteCollections, internKey)})
	}
	return ast.ObjectTerm(pairs...)
}

func boolSetToTerm(m map[string]bool, internKey func(string) *ast.Term) *ast.Term {
	pairs := make([][2]*ast.Term, 0, len(m))
	for _, k := range sortedMapKeys(m) {
		if m[k] {
			pairs = append(pairs, [2]*ast.Term{internKey(k), ast.BooleanTerm(true)})
		}
	}
	return ast.ObjectTerm(pairs...)
}

func derivedToTerm(d *DerivedData, internKey func(string) *ast.Term) *ast.Term {
	pairs := make([][2]*ast.Term, 0, derivedFieldCap)
	if len(d.JSON) > 0 {
		pairs = append(pairs, [2]*ast.Term{internKey("json"), mapToTerm(d.JSON, internKey)})
	}
	if len(d.JSONUnknown) > 0 {
		sub := make([][2]*ast.Term, 0, len(d.JSONUnknown))
		for _, k := range sortedMapKeys(d.JSONUnknown) {
			sub = append(sub, [2]*ast.Term{internKey(k), boolSetToTerm(d.JSONUnknown[k], internKey)})
		}
		pairs = append(pairs, [2]*ast.Term{internKey("json_unknown"), ast.ObjectTerm(sub...)})
	}
	if len(d.JSONRefs) > 0 {
		sub := make([][2]*ast.Term, 0, len(d.JSONRefs))
		for _, attr := range sortedMapKeys(d.JSONRefs) {
			byLeaf := d.JSONRefs[attr]
			leafPairs := make([][2]*ast.Term, 0, len(byLeaf))
			for _, leaf := range sortedMapKeys(byLeaf) {
				refs := byLeaf[leaf]
				items := make([]*ast.Term, 0, len(refs))
				for _, ref := range refs {
					items = append(items, ast.ObjectTerm(
						[2]*ast.Term{internKey("kind"), ast.StringTerm(ref.Kind)},
						[2]*ast.Term{internKey("type"), ast.StringTerm(ref.Type)},
						[2]*ast.Term{internKey("name"), ast.StringTerm(ref.Name)},
						[2]*ast.Term{internKey("attr"), ast.StringTerm(ref.Attr)},
					))
				}
				leafPairs = append(leafPairs, [2]*ast.Term{internKey(leaf), ast.ArrayTerm(items...)})
			}
			sub = append(sub, [2]*ast.Term{internKey(attr), ast.ObjectTerm(leafPairs...)})
		}
		pairs = append(pairs, [2]*ast.Term{internKey("json_refs"), ast.ObjectTerm(sub...)})
	}
	if len(d.FilterExpr) > 0 {
		pairs = append(pairs, [2]*ast.Term{internKey("filter_expr"), mapToTerm(d.FilterExpr, internKey)})
	}
	if len(d.TemplateParts) > 0 {
		sub := make([][2]*ast.Term, 0, len(d.TemplateParts))
		for _, k := range sortedMapKeys(d.TemplateParts) {
			parts := d.TemplateParts[k]
			items := make([]*ast.Term, 0, len(parts))
			for _, p := range parts {
				fields := [][2]*ast.Term{
					{internKey("known"), ast.BooleanTerm(p.Known)},
					{internKey("value"), ast.StringTerm(p.Value)},
				}
				if p.Ref != nil {
					fields = append(fields, [2]*ast.Term{internKey("ref"), ast.ObjectTerm(
						[2]*ast.Term{internKey("kind"), ast.StringTerm(p.Ref.Kind)},
						[2]*ast.Term{internKey("type"), ast.StringTerm(p.Ref.Type)},
						[2]*ast.Term{internKey("name"), ast.StringTerm(p.Ref.Name)},
						[2]*ast.Term{internKey("attr"), ast.StringTerm(p.Ref.Attr)},
					)})
				}
				items = append(items, ast.ObjectTerm(fields...))
			}
			sub = append(sub, [2]*ast.Term{internKey(k), ast.ArrayTerm(items...)})
		}
		pairs = append(pairs, [2]*ast.Term{internKey("template_parts"), ast.ObjectTerm(sub...)})
	}
	return ast.ObjectTerm(pairs...)
}

func relationsToTerm(r *ResourceRelations, internKey func(string) *ast.Term) *ast.Term {
	pairs := make([][2]*ast.Term, 0, 3)
	if len(r.Targets) > 0 {
		pairs = append(pairs, [2]*ast.Term{internKey("targets"), relationMapToTerm(r.Targets, internKey)})
	}
	if len(r.TargetsVia) > 0 {
		sub := make([][2]*ast.Term, 0, len(r.TargetsVia))
		for _, path := range sortedMapKeys(r.TargetsVia) {
			sub = append(sub, [2]*ast.Term{internKey(path), relationMapToTerm(r.TargetsVia[path], internKey)})
		}
		pairs = append(pairs, [2]*ast.Term{internKey("targets_via"), ast.ObjectTerm(sub...)})
	}
	if len(r.Related) > 0 {
		sub := make([][2]*ast.Term, 0, len(r.Related))
		for _, typ := range sortedMapKeys(r.Related) {
			sub = append(sub, [2]*ast.Term{internKey(typ), relationMapToTerm(r.Related[typ], internKey)})
		}
		pairs = append(pairs, [2]*ast.Term{internKey("related"), ast.ObjectTerm(sub...)})
	}
	if len(r.Referrers) > 0 {
		pairs = append(pairs, [2]*ast.Term{internKey("referrers"), relationMapToTerm(r.Referrers, internKey)})
	}
	return ast.ObjectTerm(pairs...)
}

func relationMapToTerm(m map[string]RelationList, internKey func(string) *ast.Term) *ast.Term {
	pairs := make([][2]*ast.Term, 0, len(m))
	for _, k := range sortedMapKeys(m) {
		rl := m[k]
		ids := make([]*ast.Term, len(rl.IDs))
		for i, id := range rl.IDs {
			ids[i] = ast.StringTerm(id)
		}
		pairs = append(pairs, [2]*ast.Term{
			internKey(k),
			ast.ObjectTerm(
				[2]*ast.Term{internKey("ids"), ast.ArrayTerm(ids...)},
				[2]*ast.Term{internKey("complete"), ast.BooleanTerm(rl.Complete)},
			),
		})
	}
	return ast.ObjectTerm(pairs...)
}

func mapToTerm(m map[string]any, internKey func(string) *ast.Term) *ast.Term {
	if len(m) == 0 {
		return ast.ObjectTerm()
	}
	pairs := make([][2]*ast.Term, 0, len(m))
	for _, k := range sortedMapKeys(m) {
		pairs = append(pairs, [2]*ast.Term{internKey(k), goToTerm(m[k], internKey)})
	}
	return ast.ObjectTerm(pairs...)
}

// nolint:gocyclo // flat type switch over Go JSON primitives
func goToTerm(v any, internKey func(string) *ast.Term) *ast.Term {
	switch x := v.(type) {
	case nil:
		return ast.NullTerm()
	case bool:
		return ast.BooleanTerm(x)
	case string:
		return ast.StringTerm(x)
	case int:
		return ast.IntNumberTerm(x)
	case int64:
		return ast.NumberTerm(json.Number(strconv.FormatInt(x, 10)))
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return ast.NullTerm()
		}
		return ast.FloatNumberTerm(x)
	case json.Number:
		return ast.NumberTerm(x)
	case []any:
		items := make([]*ast.Term, len(x))
		for i, e := range x {
			items[i] = goToTerm(e, internKey)
		}
		return ast.ArrayTerm(items...)
	case []string:
		items := make([]*ast.Term, len(x))
		for i, e := range x {
			items[i] = ast.StringTerm(e)
		}
		return ast.ArrayTerm(items...)
	case map[string]any:
		return mapToTerm(x, internKey)
	default:
		val, err := ast.InterfaceToValue(x)
		if err != nil {
			return ast.NullTerm()
		}
		return ast.NewTerm(val)
	}
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var pathEscaper = strings.NewReplacer(`\`, `\\`, `.`, `\.`)

// EscapeStep formats one Step into its unambiguous path-key segment: string
// keys escape backslashes, dots, and leading digits so string keys never
// collide with integer array indexes or dot separators.
func EscapeStep(s Step) string {
	if pos, isIdx := s.Position(); isIdx {
		return strconv.FormatInt(pos, 10)
	}
	key, _ := s.Property()
	escaped := pathEscaper.Replace(key)
	if escaped != "" && escaped[0] >= '0' && escaped[0] <= '9' {
		return `\` + escaped
	}
	return escaped
}

// PathKey joins path into a canonical key matching the Rego library's
// _path_key implementation.
func PathKey(path Path) string {
	if len(path) == 0 {
		return ""
	}
	if len(path) == 1 {
		return EscapeStep(path[0])
	}
	parts := make([]string, len(path))
	for i, s := range path {
		parts[i] = EscapeStep(s)
	}
	return strings.Join(parts, ".")
}

// JoinPathKey appends a single property or index step to an existing PathKey.
func JoinPathKey(prefix string, step Step) string {
	seg := EscapeStep(step)
	if prefix == "" {
		return seg
	}
	return prefix + "." + seg
}

// ErrInvalidPath identifies a malformed Contract v2 finding path.
var ErrInvalidPath = errors.New("contract/invalid-path")

// Finding is the decoded result emitted by dd_output.format(resource, details).
type Finding struct {
	ResourceID      string
	Path            Path
	Key             string
	Remediation     string
	RemediationType string
	// After lets a rule request a replacement remediation without reading the
	// current attribute value in Rego; the scanner extracts "before" from source.
	After       string
	OverrideKey string
	Raw         map[string]any
}

// DecodeFinding parses a raw OPA object produced by dd_output.format.
func DecodeFinding(raw map[string]any) (Finding, error) {
	id, _ := raw["_dd_id"].(string)
	if id == "" {
		return Finding{}, fmt.Errorf("contract v2 finding missing _dd_id")
	}
	pathRaw, pathPresent := raw["path"]
	if !pathPresent {
		return Finding{}, fmt.Errorf("contract v2 finding missing path")
	}
	for _, legacy := range []string{"documentId", "searchKey", "resourceType", "resourceName"} {
		if _, present := raw[legacy]; present {
			return Finding{}, fmt.Errorf("contract v2 finding includes legacy derived field %q", legacy)
		}
	}
	for _, field := range []string{"after", "remediation", "remediationType", "overrideKey"} {
		if value, present := raw[field]; present {
			if _, valid := value.(string); !valid {
				return Finding{}, fmt.Errorf("contract v2 finding field %q must be a string", field)
			}
		}
	}
	path, err := DecodePath(pathRaw)
	if err != nil {
		return Finding{}, fmt.Errorf("%w: %w", ErrInvalidPath, err)
	}
	f := Finding{
		ResourceID: id,
		Path:       path,
		Raw:        raw,
	}
	if k, ok := raw["key"].(string); ok {
		f.Key = k
	}
	if rem, ok := raw["remediation"].(string); ok {
		f.Remediation = rem
	}
	if rt, ok := raw["remediationType"].(string); ok {
		f.RemediationType = rt
	}
	if after, ok := raw["after"].(string); ok {
		f.After = after
	}
	if ov, ok := raw["overrideKey"].(string); ok {
		f.OverrideKey = ov
	}
	return f, nil
}

// DecodePath converts a Rego path value (nil, string, or []any of string/number)
// into a typed policy.Path.
func DecodePath(raw any) (Path, error) {
	if raw == nil {
		return nil, fmt.Errorf("expected string or array path, got %T", raw)
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil, nil
		}
		return Path{Key(v)}, nil
	case []any:
		if len(v) == 0 {
			return nil, nil
		}
		out := make(Path, 0, len(v))
		for _, item := range v {
			step, err := decodeStep(item)
			if err != nil {
				return nil, err
			}
			out = append(out, step)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected string or array path, got %T", raw)
	}
}

func decodeStep(item any) (Step, error) {
	switch s := item.(type) {
	case string:
		return Key(s), nil
	case int:
		return Index(int64(s)), nil
	case int64:
		return Index(s), nil
	case float64:
		if s != math.Trunc(s) {
			return Step{}, fmt.Errorf("non-integer path index %v", s)
		}
		return Index(int64(s)), nil
	case json.Number:
		i, err := s.Int64()
		if err != nil {
			return Step{}, fmt.Errorf("non-integer path index %q: %w", s, err)
		}
		return Index(i), nil
	default:
		return Step{}, fmt.Errorf("unsupported path step type %T", item)
	}
}
