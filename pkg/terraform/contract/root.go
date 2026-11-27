/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package contract

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	tfdetector "github.com/DataDog/datadog-iac-scanner/pkg/detector/terraform"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

const terraformPlatform = "terraform"

// RootOptions configures streaming Terraform root evaluation for Contract v2.
type RootOptions struct {
	FS             vfs.FS
	RepoPath       string
	MergeAllow     map[string]struct{}
	RemoteResolver tfeval.RemoteResolver
	LiteralKeys    LiteralKeyMap
	// ComputeRelations enables demand-driven intra-root relation indexing.
	ComputeRelations bool
	// RelationTypes, when non-nil alongside ComputeRelations, restricts
	// buildIntraRootRelations to roots containing at least one matching type.
	RelationTypes map[string]bool
	// NeedStaticBlocks, when true (or when AllowedTypes is nil), models static
	// provider/variable/output/module blocks. When false and no provider_config
	// is requested, skips static block evaluation for speed.
	NeedStaticBlocks bool
	// NeedProviders ensures provider blocks are always modeled (including for
	// roots with no direct resources, only child modules).
	NeedProviders bool
	// Derive configures demand-driven JSON / filter AST derivations.
	Derive DeriveOptions
	// RootScope optionally supplies the evaluated root ModuleScope so static
	// blocks (provider, variable, output, module) are still emitted when the
	// root has zero locally-evaluated resources/data (e.g. count=0 or remote
	// modules only).
	RootScope *tfeval.ModuleScope
	// ModuleInstances carries evaluated module scopes when relation tracing is
	// requested, including instances whose modules declare no resources.
	ModuleInstances []tfeval.ModuleInstance
	// ScopeComplete records whether the root's module graph resolved without
	// unresolved/skipped child modules. Zero value defaults to true unless
	// ScopeIncomplete is set.
	ScopeIncomplete bool
	// AttributionFunc and CallChainFunc attach child-module SARIF attribution
	// and fingerprint call chains from the shared per-root moduleAttributionCache.
	AttributionFunc func(r *tfeval.ResolvedResource) *model.ModuleAttribution
	CallChainFunc   func(r *tfeval.ResolvedResource) string
	// ResourceHook, when set, receives each root's raw tfeval.ResolvedResource
	// slice so callers (such as pkg/inventory) can consume the same evaluation
	// pass without re-evaluating the root.
	ResourceHook func(dir string, resources []tfeval.ResolvedResource)
}

// EvaluateRoot evaluates one Terraform root directory via evaluator and returns
// its normalized Contract v2 policy.Unit. Callers own cache lifetime.
func EvaluateRoot(
	ctx context.Context,
	evaluator *tfeval.Evaluator,
	dir string,
	opts *RootOptions,
) (*policy.Unit, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if opts == nil {
		opts = &RootOptions{}
	}
	evaluator.SetTrackModuleInstances(opts.ComputeRelations)
	evaluator.SetTrackModuleScopes(opts.ComputeRelations)
	inputs := evaluator.LoadRootVarsWithContext(ctx, dir)
	resources, _, _, err := evaluator.EvaluateModule(ctx, dir, inputs)
	droppedFiles := evaluator.TakeDroppedFiles()
	moduleInstances := evaluator.TakeModuleInstances()
	if err != nil {
		return nil, err
	}
	if opts.ResourceHook != nil {
		opts.ResourceHook(dir, resources)
	}
	callOpts := *opts
	if callOpts.RootScope == nil {
		callOpts.RootScope = evaluator.LastRootScope()
	}
	if callOpts.ComputeRelations {
		callOpts.ModuleInstances = moduleInstances
	}
	if len(droppedFiles) > 0 || len(evaluator.NotEvaluatedDirs()) > 0 || evaluator.HasUnresolvedModules() {
		callOpts.ScopeIncomplete = true
	}
	unit, err := BuildUnitFromEvalContext(ctx, dir, resources, &callOpts)
	evaluator.ReleaseEvalCache()
	if err != nil {
		return nil, err
	}
	return unit, nil
}

// BuildUnitFromEval converts evaluated tfeval.ResolvedResource entries for a
// single Terraform root into a normalized policy.Unit. It cannot be canceled;
// scan code uses BuildUnitFromEvalContext.
func BuildUnitFromEval(rootDir string, resolved []tfeval.ResolvedResource, opts *RootOptions) *policy.Unit {
	return buildUnitFromEval(context.Background(), rootDir, resolved, opts)
}

// BuildUnitFromEvalContext is BuildUnitFromEval bounded by ctx. Relation
// construction stops as soon as ctx is done, and the partly built unit is then
// discarded: it returns ctx.Err() and a nil unit, never a unit whose relations
// are unfinished, unsorted or not deduplicated.
func BuildUnitFromEvalContext(
	ctx context.Context,
	rootDir string,
	resolved []tfeval.ResolvedResource,
	opts *RootOptions,
) (*policy.Unit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	unit := buildUnitFromEval(ctx, rootDir, resolved, opts)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return unit, nil
}

// nolint:gocyclo
func buildUnitFromEval(
	ctx context.Context,
	rootDir string,
	resolved []tfeval.ResolvedResource,
	opts *RootOptions,
) *policy.Unit {
	if opts == nil {
		opts = &RootOptions{}
	}
	rootID := relativeRootID(rootDir, opts.RepoPath)
	unit := &policy.Unit{
		ID:            rootID,
		Platform:      terraformPlatform,
		ScopeComplete: !opts.ScopeIncomplete,
		ByID:          make(map[string]*policy.Resource, len(resolved)),
	}

	// Collect unique module scopes in deterministic address order, including
	// the explicit RootScope (for roots with zero evaluated resources) and
	// every intermediate caller scope along CallChain.
	scopesByModule := make(map[string]*tfeval.ModuleScope)
	moduleOrder := make([]string, 0)
	recordScope := func(modAddr string, scope *tfeval.ModuleScope) {
		if scope == nil {
			return
		}
		if _, seen := scopesByModule[modAddr]; !seen {
			scopesByModule[modAddr] = scope
			moduleOrder = append(moduleOrder, modAddr)
		}
	}
	if opts.RootScope != nil {
		recordScope("", opts.RootScope)
	}
	for i := range resolved {
		r := &resolved[i]
		modAddr := resolvedModuleAddr(r)
		recordScope(modAddr, r.Scope)
		if len(r.CallChain) > 0 {
			prefix := ""
			for idx := range r.CallChain {
				cs := &r.CallChain[idx]
				recordScope(prefix, cs.Caller)
				if idx < len(r.CallChain)-1 {
					step := "module." + cs.ModuleName + formatInstanceKey(cs.InstanceKey)
					if prefix == "" {
						prefix = step
					} else {
						prefix += "." + step
					}
				}
			}
		}
	}
	sort.Strings(moduleOrder)

	idPrefix := ""
	if rootID != "" {
		idPrefix = rootID + "|"
	}
	nextID := 0
	allocID := func(prefix string) string {
		id := fmt.Sprintf("%s%s:%d", idPrefix, prefix, nextID)
		nextID++
		return id
	}
	type instanceSetKey struct {
		body  *hclsyntax.Body
		scope *tfeval.ModuleScope
	}
	instanceSetCache := make(map[instanceSetKey]bool)
	instanceSetComplete := func(body *hclsyntax.Body, scope *tfeval.ModuleScope) bool {
		key := instanceSetKey{body: body, scope: scope}
		if complete, ok := instanceSetCache[key]; ok {
			return complete
		}
		complete := resourceInstanceSetComplete(body, scope)
		instanceSetCache[key] = complete
		return complete
	}

	var hclMetas []*hclResourceMeta
	providersByMod := make(map[string]map[string]string)

	// 1. Add static blocks (provider, variable, output, module) per module scope
	// only when rules need static blocks or provider configs (never on pure
	// single-resource scans).
	modelStatic := opts.NeedStaticBlocks || opts.NeedProviders || opts.ComputeRelations
	hasRelationType := len(opts.RelationTypes) == 0
	seenStaticDir := make(map[string]bool)
	for _, modAddr := range moduleOrder {
		scope := scopesByModule[modAddr]
		if scope == nil || !modelStatic {
			continue
		}
		isChildModule := modAddr != ""
		var scopeDir string
		for _, body := range scope.Bodies {
			for _, blk := range body.Blocks {
				if scopeDir == "" && blk.TypeRange.Filename != "" {
					scopeDir = filepath.Clean(filepath.Dir(blk.TypeRange.Filename))
				}
				switch blk.Type {
				case address.KindProvider:
					if len(blk.Labels) != 1 {
						continue
					}
					res := buildStaticBlock(allocID("p"), rootID, modAddr, blk, scope, isChildModule)
					unit.Resources = append(unit.Resources, res)
					unit.ByID[res.ID] = res
					if opts.RelationTypes != nil && opts.RelationTypes[res.BucketKey()] {
						hasRelationType = true
					}
					hclMetas = append(hclMetas, &hclResourceMeta{
						res: res, moduleAddr: modAddr, body: blk.Body, scope: scope,
					})
					if providersByMod[modAddr] == nil {
						providersByMod[modAddr] = make(map[string]string)
					}
					providersByMod[modAddr][providerKey(blk.Labels[0], res.Name)] = res.ID
				case address.KindVariable, address.KindOutput:
					if !opts.NeedStaticBlocks && (!opts.ComputeRelations || blk.Type != address.KindOutput) {
						continue
					}
					if len(blk.Labels) != 1 {
						continue
					}
					if isChildModule && scopeDir != "" && seenStaticDir[scopeDir+"\x00"+blk.Type+"\x00"+blk.Labels[0]] {
						continue
					}
					if scopeDir != "" {
						seenStaticDir[scopeDir+"\x00"+blk.Type+"\x00"+blk.Labels[0]] = true
					}
					res := buildStaticBlock(allocID("s"), rootID, modAddr, blk, scope, isChildModule)
					unit.Resources = append(unit.Resources, res)
					unit.ByID[res.ID] = res
					if opts.RelationTypes != nil && opts.RelationTypes[res.BucketKey()] {
						hasRelationType = true
					}
					hclMetas = append(hclMetas, &hclResourceMeta{
						res: res, moduleAddr: modAddr, body: blk.Body, scope: scope,
					})
				case address.KindModule:
					if !opts.NeedStaticBlocks && !opts.ComputeRelations {
						continue
					}
					if len(blk.Labels) != 1 {
						continue
					}
					res := buildStaticBlock(allocID("m"), rootID, modAddr, blk, scope, isChildModule)
					unit.Resources = append(unit.Resources, res)
					unit.ByID[res.ID] = res
					if opts.RelationTypes != nil && opts.RelationTypes[res.BucketKey()] {
						hasRelationType = true
					}
					hclMetas = append(hclMetas, &hclResourceMeta{
						res: res, moduleAddr: modAddr, body: blk.Body, scope: scope,
					})
				}
			}
		}
	}

	// 2. Add evaluated resource and data instances.
	bodyBlocks := make(map[*hclsyntax.Body]*hclsyntax.Block)
	for _, scope := range scopesByModule {
		if scope == nil {
			continue
		}
		for _, body := range scope.Bodies {
			for _, blk := range body.Blocks {
				bodyBlocks[blk.Body] = blk
			}
		}
	}

	for i := range resolved {
		if i%64 == 0 && ctx.Err() != nil {
			// BuildUnitFromEvalContext discards this partial unit.
			return unit
		}
		r := &resolved[i]
		modAddr := resolvedModuleAddr(r)
		kind := address.KindResource
		resKey := r.Type
		if r.Data {
			kind = address.KindData
			resKey = address.DataPrefix + r.Type
		}
		if opts.RelationTypes != nil && opts.RelationTypes[resKey] {
			hasRelationType = true
		}
		baseName := tfeval.ResourceBaseName(r.Name)
		instKey := formatInstanceKey(r.InstanceKey)
		keyUnknown := r.InstanceKey != cty.NilVal && !r.InstanceKey.IsKnown()

		blockAddr := address.Addr(address.Block{Kind: kind, Type: r.Type, Name: baseName}) + instKey
		fullAddr := blockAddr
		if modAddr != "" {
			fullAddr = modAddr + "." + blockAddr
		}

		var synBlk *hclsyntax.Block
		if r.Body != nil {
			synBlk = bodyBlocks[r.Body]
		}
		headerRange := hcl.Range{
			Filename: r.DefinedIn,
			Start:    hcl.Pos{Line: r.DefLine, Column: max(r.DefColumn, 1)},
			End:      hcl.Pos{Line: max(r.DefEndLine, r.DefLine), Column: max(r.DefEndColumn, 1)},
		}
		blockSpan := hclRangeToSpan(headerRange)
		if synBlk != nil {
			headerRange = synBlk.DefRange()
			blockSpan = hclRangeToSpan(synBlk.Range())
		}

		var src []byte
		if r.Scope != nil && r.DefinedIn != "" {
			src, _ = r.Scope.Source(r.DefinedIn)
		}

		attrs, state, ranges := convertBody(r.Attributes, r.Body, r.DynamicCounts, resourceMetaArgs, headerRange)
		tfPlatform := map[string]any{
			platformKeySource: sourceKindHCL,
			platformKeyModule: modAddr,
			platformKeyInst:   instKey,
		}
		if provID := resolveProviderID(r.Body, r.Type, modAddr, r.CallChain, providersByMod); provID != "" {
			tfPlatform["provider_id"] = provID
		}

		var modAttr *model.ModuleAttribution
		if opts.AttributionFunc != nil {
			modAttr = opts.AttributionFunc(r)
		}
		callChain := ""
		if opts.CallChainFunc != nil {
			callChain = opts.CallChainFunc(r)
		}

		overrideInventoryLine := 0
		beforeValue := buildBeforeExtractor(r.Body, r.DynamicCounts, src)
		if r.DeclarationBody != nil {
			overrideInventoryLine = r.DefLine
			if tfpath.IsJSONConfig(r.DefinedIn) {
				overrideInventoryLine = r.DeclarationBody.SrcRange.Start.Line
			}
			beforeValue = buildOverrideBeforeExtractor(r.Body, r.DynamicCounts, r.Scope)
		}

		res := &policy.Resource{
			ID:          allocID("r"),
			Kind:        kind,
			Type:        r.Type,
			ResourceKey: resKey,
			Name:        baseName,
			Address:     fullAddr,
			File:        r.DefinedIn,
			Attributes:  attrs,
			State:       state,
			Platform:    map[string]any{terraformPlatform: tfPlatform},
			Source: &policy.SourceMapping{
				BlockSpan:             blockSpan,
				Ranges:                ranges,
				ModuleAttribution:     modAttr,
				ModuleCallChain:       callChain,
				TerraformAddress:      fullAddr,
				RootModule:            rootID,
				BeforeValue:           beforeValue,
				OverrideInventoryLine: overrideInventoryLine,
				RemediationPoint:      buildRemediationPoint(synBlk, tfdetector.RemediationPoint),
			},
		}
		iterBindings := r.IterationBindings()
		resourceSetComplete := !keyUnknown && instanceSetComplete(r.Body, r.Scope)
		for i := range r.CallChain {
			call := &r.CallChain[i]
			if call.InstanceKey != cty.NilVal && !call.InstanceKey.IsKnown() {
				resourceSetComplete = false
				break
			}
			if !instanceSetComplete(call.Body, call.Caller) {
				resourceSetComplete = false
				break
			}
		}
		if !resourceSetComplete {
			tfPlatform["instance_set_complete"] = false
		}
		deriveResource(res, r.Body, r.Scope, iterBindings, opts.Derive, r)

		unit.Resources = append(unit.Resources, res)
		unit.ByID[res.ID] = res
		hclMetas = append(hclMetas, &hclResourceMeta{
			res:        res,
			resolved:   r,
			moduleAddr: modAddr,
			body:       r.Body,
			scope:      r.Scope,
			dynCounts:  r.DynamicCounts,
			iteration:  iterBindings,
			keyUnknown: keyUnknown,
			callChain:  r.CallChain,
		})
	}

	if opts.ComputeRelations && hasRelationType {
		buildIntraRootRelations(ctx, unit, hclMetas, opts.LiteralKeys, opts.ModuleInstances)
	}
	return unit
}

// resourceInstanceSetComplete reports whether a block's count/for_each
// expression determines its full instance-key set. Map values may be unknown
// because they do not affect the keys; unknown set elements may add keys.
func resourceInstanceSetComplete(body *hclsyntax.Body, scope *tfeval.ModuleScope) bool {
	if body == nil {
		return true
	}
	ctx := (*hcl.EvalContext)(nil)
	if scope != nil {
		ctx = scope.EvalContext()
	}
	if ctx == nil {
		ctx = &hcl.EvalContext{}
	}
	if attr := body.Attributes["count"]; attr != nil {
		value, diags := attr.Expr.Value(ctx)
		return !diags.HasErrors() && completeTerraformCount(value)
	}
	if attr := body.Attributes["for_each"]; attr != nil {
		value, diags := attr.Expr.Value(ctx)
		return !diags.HasErrors() && completeTerraformForEach(value)
	}
	return true
}

func completeTerraformCount(value cty.Value) bool {
	return value != cty.NilVal && value.IsKnown() && value.IsWhollyKnown() && !value.IsNull()
}

func completeTerraformForEach(value cty.Value) bool {
	if value == cty.NilVal || !value.IsKnown() || value.IsNull() {
		return false
	}
	if value.Type().IsMapType() || value.Type().IsObjectType() {
		return true
	}
	return value.Type().IsSetType() && value.IsWhollyKnown()
}

// nolint:gocyclo
func buildStaticBlock(
	id, rootID, modAddr string,
	blk *hclsyntax.Block,
	scope *tfeval.ModuleScope,
	staticInModule bool,
) *policy.Resource {
	evalCtx := scope.EvalContext()
	if evalCtx == nil {
		evalCtx = &hcl.EvalContext{}
	}
	staticDynCounts := tfeval.DynamicCounts{}
	evalAttrs := evalStaticBodyToCty(blk.Body, evalCtx, staticDynCounts)

	skip := map[string]bool(nil)
	if blk.Type == address.KindModule {
		skip = moduleMetaArgs
	}
	attrs, state, ranges := convertBody(evalAttrs, blk.Body, staticDynCounts, skip, blk.DefRange())

	typ := ""
	name := ""
	resKey := blk.Type
	switch blk.Type {
	case address.KindProvider:
		typ = blk.Labels[0]
		if alias, ok := attrs["alias"].(string); ok {
			name = alias
		}
		resKey = "provider." + typ
	default:
		if len(blk.Labels) > 0 {
			name = blk.Labels[0]
		}
	}
	addr := address.Addr(address.Block{Kind: blk.Type, Type: typ, Name: name})
	if modAddr != "" {
		addr = modAddr + "." + addr
	}

	var src []byte
	if scope != nil && blk.TypeRange.Filename != "" {
		src, _ = scope.Source(blk.TypeRange.Filename)
	}
	return &policy.Resource{
		ID:          id,
		Kind:        blk.Type,
		Type:        typ,
		ResourceKey: resKey,
		Name:        name,
		Address:     addr,
		File:        blk.TypeRange.Filename,
		Attributes:  attrs,
		State:       state,
		Platform: map[string]any{
			terraformPlatform: map[string]any{
				platformKeySource: sourceKindHCL,
				platformKeyModule: modAddr,
			},
		},
		Source: &policy.SourceMapping{
			BlockSpan:        hclRangeToSpan(blk.Range()),
			Ranges:           ranges,
			TerraformAddress: addr,
			RootModule:       rootID,
			StaticInModule:   staticInModule,
			BeforeValue:      buildBeforeExtractor(blk.Body, nil, src),
			RemediationPoint: buildRemediationPoint(blk, tfdetector.RemediationPoint),
		},
	}
}

func evalStaticBodyToCty(body *hclsyntax.Body, evalCtx *hcl.EvalContext, dynCounts tfeval.DynamicCounts) map[string]cty.Value {
	if body == nil {
		return nil
	}
	out := make(map[string]cty.Value, len(body.Attributes)+len(body.Blocks))
	for name, attr := range body.Attributes {
		val, diags := attr.Expr.Value(evalCtx)
		if diags.HasErrors() {
			out[name] = cty.DynamicVal
		} else {
			out[name] = val
		}
	}
	for _, nested := range body.Blocks {
		if nested.Type == blockTypeDynamic {
			if dynamicblock.Is(nested) {
				dynCounts[nested] = tfeval.DynamicKeptAsWritten
			}
			continue
		}
		objVal := cty.ObjectVal(evalStaticBodyToCty(nested.Body, evalCtx, dynCounts))
		if prev, ok := out[nested.Type]; ok && prev.Type().IsTupleType() {
			elems := prev.AsValueSlice()
			elems = append(elems, objVal)
			out[nested.Type] = cty.TupleVal(elems)
		} else {
			out[nested.Type] = cty.TupleVal([]cty.Value{objVal})
		}
	}
	return out
}

func resolvedModuleAddr(r *tfeval.ResolvedResource) string {
	if mod, _, ok := r.PartialAddress(); ok {
		return mod
	}
	return r.ModuleAddress
}

func providerKey(typ, alias string) string {
	if alias == "" {
		return typ
	}
	return typ + "." + alias
}

// resolveProviderID resolves a resource's provider configuration, honoring
// explicit `provider = aws.west` and walking module `providers = { aws = aws.west }`
// remappings up CallChain to intermediate modules and the root module.
// Strictly follows Terraform semantics: an explicit remap that targets a
// missing provider does not silently fall back to an unremapped provider, and
// aliased providers are never implicitly inherited without a `providers` map.
func resolveProviderID(
	body *hclsyntax.Body,
	resourceType, modAddr string,
	callChain []tfeval.CallSite,
	providersByMod map[string]map[string]string,
) string {
	want := ""
	if body != nil {
		if attr, ok := body.Attributes["provider"]; ok {
			want = traversalProviderKey(attr.Expr)
		}
	}
	if want == "" {
		if prefix, _, ok := strings.Cut(resourceType, "_"); ok {
			want = prefix
		}
	}
	if want == "" {
		return ""
	}
	if id := providersByMod[modAddr][want]; id != "" {
		return id
	}
	// Precompute module addresses for each caller level in callChain:
	// callerAddr[0] = "", callerAddr[1] = "module.<c0>", etc.
	callerAddrs := make([]string, len(callChain))
	for i := 1; i < len(callChain); i++ {
		step := "module." + callChain[i-1].ModuleName + formatInstanceKey(callChain[i-1].InstanceKey)
		if callerAddrs[i-1] == "" {
			callerAddrs[i] = step
		} else {
			callerAddrs[i] = callerAddrs[i-1] + "." + step
		}
	}

	cur := want
	for i := len(callChain) - 1; i >= 0; i-- {
		if mapped := lookupModuleProviderRemap(callChain[i].Body, cur); mapped != "" {
			cur = mapped
			if id := providersByMod[callerAddrs[i]][cur]; id != "" {
				return id
			}
			continue
		}
		// Only unaliased default providers inherit implicitly across a module boundary.
		if strings.Contains(cur, ".") {
			return ""
		}
		if id := providersByMod[callerAddrs[i]][cur]; id != "" {
			return id
		}
	}
	return ""
}

func traversalProviderKey(expr hcl.Expression) string {
	if expr == nil {
		return ""
	}
	trav, diags := hcl.AbsTraversalForExpr(expr)
	if diags.HasErrors() || len(trav) == 0 {
		return ""
	}
	key := trav.RootName()
	if len(trav) > 1 {
		if a, ok := trav[1].(hcl.TraverseAttr); ok {
			key += "." + a.Name
		}
	}
	return key
}

func lookupModuleProviderRemap(callBody *hclsyntax.Body, childKey string) string {
	if callBody == nil {
		return ""
	}
	attr, ok := callBody.Attributes["providers"]
	if !ok {
		return ""
	}
	obj, ok := attr.Expr.(*hclsyntax.ObjectConsExpr)
	if !ok {
		return ""
	}
	for _, item := range obj.Items {
		k := traversalProviderKey(item.KeyExpr)
		if k == "" {
			if kv, diags := item.KeyExpr.Value(nil); !diags.HasErrors() && kv.IsKnown() && !kv.IsNull() && kv.Type() == cty.String {
				k = kv.AsString()
			}
		}
		if k == childKey {
			if target := traversalProviderKey(item.ValueExpr); target != "" {
				return target
			}
		}
	}
	return ""
}

func relativeRootID(dir, repoPath string) string {
	if repoPath == "" {
		return filepath.ToSlash(filepath.Clean(dir))
	}
	rel, err := filepath.Rel(repoPath, dir)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(filepath.Clean(dir))
	}
	return filepath.ToSlash(rel)
}
