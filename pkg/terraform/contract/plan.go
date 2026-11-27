/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
	"github.com/DataDog/datadog-iac-scanner/pkg/policy"
)

const (
	planResourcesKey    = "resources"
	planModuleCallsKey  = "module_calls"
	planExpressionKey   = "expression"
	planExpressionsKey  = "expressions"
	planProvisionerKey  = "provisioner"
	planProvisionersKey = "provisioners"
)

// BuildUnitFromPlan converts a Terraform plan JSON payload into the exact same
// normalized policy.Unit shape as HCL roots:
//   - Nested blocks remain arrays,
//   - Nested and top-level after_unknown leaves are recursively stripped from
//     Attributes (array elements become index-preserving policy.UnknownSlot()),
//   - Non-written planned values go to platform.terraform.computed,
//   - configuration.provider_config emits provider.<name> resources with provider_id,
//   - configuration.expressions references and same-root literals populate
//     instance-accurate intra-root Relations with companion incompleteness.
//
// nolint:gocyclo
func BuildUnitFromPlan(planPath string, src []byte, opts *RootOptions) (*policy.Unit, error) {
	if opts == nil {
		opts = &RootOptions{}
	}
	doc, err := decodeJSONWithNumbers(src)
	if err != nil {
		return nil, fmt.Errorf("decoding Terraform plan JSON %s: %w", planPath, err)
	}
	unit := &policy.Unit{
		ID:            relativeRootID(planPath, opts.RepoPath),
		Platform:      terraformPlatform,
		ScopeComplete: true,
		ByID:          make(map[string]*policy.Resource),
	}

	if errored, _ := doc["errored"].(bool); errored {
		unit.ScopeComplete = false
	}
	if complete, ok := doc["complete"].(bool); ok && !complete {
		unit.ScopeComplete = false
	}
	if deferred, _ := doc["deferred_changes"].([]any); len(deferred) > 0 {
		unit.ScopeComplete = false
	}

	afterUnknownByAddr := make(map[string]any)
	deletedByAddr := make(map[string]bool)
	if changes, ok := doc["resource_changes"].([]any); ok {
		for _, item := range changes {
			rc, _ := item.(map[string]any)
			addr, _ := rc["address"].(string)
			ch, _ := rc["change"].(map[string]any)
			if addr == "" || ch == nil {
				continue
			}
			if u, ok := ch["after_unknown"]; ok {
				afterUnknownByAddr[addr] = u
			}
			if acts, _ := ch["actions"].([]any); len(acts) == 1 && acts[0] == "delete" {
				deletedByAddr[addr] = true
			}
		}
	}

	// Index configuration resources (expressions + provider_config_key) by
	// instance-stripped canonical address so for_each/count modules match.
	cfgExprsByAddr := make(map[string]map[string]any)
	cfgProvKeyByAddr := make(map[string]string)
	cfgKnownByAddr := make(map[string]bool)
	moduleConfigs := make(map[string]*planModuleConfig)
	providerIDByKey := make(map[string]string)
	hasConfig := false
	idPrefix := ""
	if unit.ID != "" {
		idPrefix = unit.ID + "|"
	}
	nextID := 0
	allocID := func(prefix string) string {
		id := fmt.Sprintf("%s%s:%d", idPrefix, prefix, nextID)
		nextID++
		return id
	}

	if cfg, ok := doc["configuration"].(map[string]any); ok {
		hasConfig = true
		if provCfgs, ok := cfg["provider_config"].(map[string]any); ok {
			addPlanProviders(unit, planPath, provCfgs, allocID, providerIDByKey)
		}
		if rootMod, ok := cfg["root_module"].(map[string]any); ok {
			indexPlanConfigModule(rootMod, "", cfgExprsByAddr, cfgProvKeyByAddr, cfgKnownByAddr, moduleConfigs)
		}
	}

	// Scan address lines scoped to top-level planned_values first, then prior_state
	// (never fooled by `"prior_state": null` or string literals in other sections).
	plannedLines := scanPlanSectionAddressLines(src, "planned_values")
	priorLines := scanPlanSectionAddressLines(src, "prior_state")
	sourceIndex := newPlanSourceIndex(planPath, src)
	plannedRanges := scanPlanSectionResourceRanges(sourceIndex, "planned_values")
	priorRanges := scanPlanSectionResourceRanges(sourceIndex, "prior_state")
	configRanges := scanPlanConfigurationRanges(sourceIndex)

	seenAddr := make(map[string]bool)
	knownModules := map[string]bool{"": true}
	deferredData := map[string]bool{}
	var planRefs []planResourceRefs
	addModuleValues := func(mod map[string]any, fromPriorState bool) {
		recordPlanModuleAddresses(mod, knownModules)
		walkPlanModuleValues(mod, func(resObj map[string]any, modAddr string) {
			addr, _ := resObj["address"].(string)
			if addr == "" || deletedByAddr[addr] || seenAddr[addr] {
				return
			}
			baseAddr := stripAllPlanInstanceKeys(addr)
			// Never resurrect a data source or resource removed from configuration.
			if fromPriorState && hasConfig && !cfgKnownByAddr[baseAddr] {
				return
			}
			seenAddr[addr] = true

			mode, _ := resObj["mode"].(string)
			kind := address.KindResource
			if mode == address.KindData {
				kind = address.KindData
			}
			typ, _ := resObj["type"].(string)
			name, _ := resObj["name"].(string)
			if typ == "" {
				return
			}
			resKey := typ
			if kind == address.KindData {
				resKey = address.DataPrefix + typ
			}

			values, _ := resObj["values"].(map[string]any)
			exprs := cfgExprsByAddr[baseAddr]
			knownInConfig := cfgKnownByAddr[baseAddr]
			unknownTree := afterUnknownByAddr[addr]

			attrs := make(map[string]any)
			computed := make(map[string]any)
			computedState := policy.ValueState{Unknown: map[string]bool{}, Null: map[string]bool{}, IncompleteCollections: map[string]bool{}}
			state := policy.ValueState{
				Unknown:               make(map[string]bool),
				Null:                  make(map[string]bool),
				Written:               make(map[string]bool),
				IncompleteCollections: make(map[string]bool),
			}

			for k, v := range values {
				pk := policy.EscapeStep(policy.Key(k))
				// If the resource exists in configuration, only attributes in its
				// expressions map are written (expressions: {} means 0 written!).
				written := !hasConfig || !knownInConfig || exprs[k] != nil
				if written {
					state.Written[pk] = true
				}
				if v == nil {
					if written {
						state.Null[pk] = true
					}
					continue
				}
				if written {
					attrs[k] = deepCopyPlanValue(v)
				} else {
					computed[k] = deepCopyPlanValue(v)
				}
			}

			for k := range exprs {
				pk := policy.EscapeStep(policy.Key(k))
				state.Written[pk] = true
			}

			// Normalize written nested blocks against configuration.expressions
			// so provider-computed siblings stay separate from configured fields
			// at every depth, and nested Written/Null states match HCL.
			if hasConfig && knownInConfig && len(exprs) > 0 {
				restorePlanWrittenConstants(attrs, exprs, unknownTree, "", &state)
				for key, value := range normalizePlanWrittenNested(attrs, exprs, "", &state) {
					computed[key] = value
				}
			}
			addPlanProvisionerValues(attrs, exprs, &state)
			// Recursively record nested null provenance in ordinary written maps
			// and lists (e.g. tags = { Owner = null }), stripping nil map entries
			// for HCL parity. Subsequent applyPlanUnknowns clears State.Null for
			// any paths that are actually after_unknown.
			recordPlanNestedNulls(attrs, "", &state)

			seedPlanComputedContainers(unknownTree, values, computed)
			recordPlanNestedNulls(computed, "", &computedState)

			// Split after_unknown into written paths (applied to attrs + state.Unknown)
			// vs unwritten Optional+Computed fields (stripped from computed only so
			// unwritten fields stay absent rather than falsely unknown).
			if hasConfig && knownInConfig {
				applyPlanUnknownsScoped(unknownTree, exprs, attrs, computed, &state, &computedState)
			} else {
				applyPlanUnknowns(unknownTree, "", attrs, &state)
			}

			if deferredData[addr] {
				computedState.Unknown[""] = true
			}

			if len(state.Unknown) == 0 {
				state.Unknown = nil
			}
			if len(state.Null) == 0 {
				state.Null = nil
			}
			if len(state.Written) == 0 {
				state.Written = nil
			}
			if len(state.IncompleteCollections) == 0 {
				state.IncompleteCollections = nil
			}

			line := plannedLines[addr]
			if line <= 0 {
				line = priorLines[addr]
			}
			if line <= 0 {
				line = 1
			}
			span := policy.SourceSpan{
				File:      planPath,
				StartLine: line,
				StartCol:  1,
				EndLine:   line,
				EndCol:    1,
			}
			ranges := plannedRanges[addr]
			if len(ranges) == 0 {
				ranges = priorRanges[addr]
			}
			if len(ranges) == 0 {
				ranges = map[string]policy.SourceSpan{"": span}
			} else if _, ok := ranges[""]; !ok {
				ranges[""] = span
			}

			// Unknown written attributes may have no planned value. Their
			// configuration expression is still a precise source location.
			for path, configSpan := range alignedPlanConfigurationRanges(configRanges[baseAddr], attrs, exprs) {
				if _, present := ranges[path]; !present {
					ranges[path] = configSpan
				}
			}

			tfMeta := map[string]any{
				platformKeySource: sourceKindPlan,
				platformKeyModule: modAddr,
				platformKeyInst:   extractPlanInstanceKey(addr),
			}
			if sourceNull := planSourceNullPaths(exprs, attrs); len(sourceNull) > 0 {
				tfMeta["source_null"] = sourceNull
			}
			if len(computed) > 0 {
				tfMeta["computed"] = computed
			}
			if len(computedState.Unknown) > 0 || len(computedState.Null) > 0 || len(computedState.IncompleteCollections) > 0 {
				tfMeta["computed_state"] = planComputedStateObject(computedState)
			}
			if pid := resolvePlanProviderID(cfgProvKeyByAddr[baseAddr], typ, providerIDByKey); pid != "" {
				tfMeta["provider_id"] = pid
			}

			res := &policy.Resource{
				ID:          allocID("r"),
				Kind:        kind,
				Type:        typ,
				ResourceKey: resKey,
				Name:        name,
				Address:     addr,
				File:        planPath,
				Attributes:  attrs,
				State:       state,
				Platform:    map[string]any{terraformPlatform: tfMeta},
				Source: &policy.SourceMapping{
					BlockSpan:        span,
					Ranges:           ranges,
					TerraformAddress: addr,
					RootModule:       unit.ID,
				},
			}

			deriveResource(res, nil, nil, nil, opts.Derive)
			derivePlanConfiguredTemplates(res, exprs, opts.Derive.ParseJSON)
			unit.Resources = append(unit.Resources, res)
			unit.ByID[res.ID] = res
			planRefs = append(planRefs, planResourceRefs{res: res, modAddr: modAddr, exprs: exprs})
		})
	}

	if pv, ok := doc["planned_values"].(map[string]any); ok {
		if rm, ok := pv["root_module"].(map[string]any); ok {
			addModuleValues(rm, false)
		}
	}
	if ps, ok := doc["prior_state"].(map[string]any); ok {
		if vals, ok := ps["values"].(map[string]any); ok {
			if rm, ok := vals["root_module"].(map[string]any); ok {
				addModuleValues(rm, true)
			}
		}
	}

	for _, mod := range deferredPlanDataModules(moduleConfigs, knownModules) {
		walkPlanModuleValues(mod, func(resource map[string]any, _ string) {
			addr, _ := resource["address"].(string)
			if seenAddr[addr] {
				return
			}
			deferredData[addr] = true
			unknown := map[string]any{}
			for key := range cfgExprsByAddr[stripAllPlanInstanceKeys(addr)] {
				unknown[key] = true
			}
			afterUnknownByAddr[addr] = unknown
		})
		addModuleValues(mod, false)
	}

	if opts.NeedStaticBlocks || opts.ComputeRelations {
		addPlanStaticBlocks(unit, sourceIndex, allocID, opts.ComputeRelations && !opts.NeedStaticBlocks)
	}
	if opts.ComputeRelations {
		buildPlanRelations(unit, planRefs, opts.LiteralKeys, moduleConfigs)
	}
	return unit, nil
}

func addPlanProviders(
	unit *policy.Unit,
	planPath string,
	provCfgs map[string]any,
	allocID func(string) string,
	providerIDByKey map[string]string,
) {
	keys := make([]string, 0, len(provCfgs))
	for k := range provCfgs {
		keys = append(keys, k)
	}
	// Process root provider configs (no ':') before module-scoped providers so
	// root aliases are never clobbered by module-scoped keys.
	sort.Slice(keys, func(i, j int) bool {
		iMod := strings.ContainsRune(keys[i], ':')
		jMod := strings.ContainsRune(keys[j], ':')
		if iMod != jMod {
			return !iMod
		}
		return keys[i] < keys[j]
	})
	for _, cfgKey := range keys {
		cfgObj, ok := provCfgs[cfgKey].(map[string]any)
		if !ok {
			continue
		}
		name, _ := cfgObj["name"].(string)
		if name == "" {
			name = cfgKey
		}
		alias, _ := cfgObj["alias"].(string)
		attrs := make(map[string]any)
		provState := policy.ValueState{
			Unknown: make(map[string]bool),
			Null:    make(map[string]bool),
			Written: make(map[string]bool),
		}
		if alias != "" {
			attrs["alias"] = alias
			provState.Written["alias"] = true
		}
		if exprs, ok := cfgObj["expressions"].(map[string]any); ok {
			extractConstantPlanExpressions(exprs, "", attrs, &provState)
		}
		if len(provState.Unknown) == 0 {
			provState.Unknown = nil
		}
		if len(provState.Null) == 0 {
			provState.Null = nil
		}
		if len(provState.Written) == 0 {
			provState.Written = nil
		}
		id := allocID("p")
		addr := address.Addr(address.Block{Kind: address.KindProvider, Type: name, Name: alias})
		span := policy.SourceSpan{File: planPath, StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 1}
		res := &policy.Resource{
			ID:          id,
			Kind:        address.KindProvider,
			Type:        name,
			ResourceKey: "provider." + name,
			Name:        alias,
			Address:     addr,
			File:        planPath,
			Attributes:  attrs,
			State:       provState,
			Platform: map[string]any{
				terraformPlatform: map[string]any{
					platformKeySource: sourceKindPlan,
				},
			},
			Source: &policy.SourceMapping{
				BlockSpan:        span,
				Ranges:           map[string]policy.SourceSpan{"": span},
				TerraformAddress: addr,
				RootModule:       unit.ID,
			},
		}
		unit.Resources = append(unit.Resources, res)
		unit.ByID[id] = res
		providerIDByKey[cfgKey] = id
		if alias == "" {
			if _, exists := providerIDByKey[name]; !exists {
				providerIDByKey[name] = id
			}
		} else {
			if _, exists := providerIDByKey[name+"."+alias]; !exists {
				providerIDByKey[name+"."+alias] = id
			}
		}
	}
}

func extractConstantPlanExpressions(exprs map[string]any, prefix string, dst map[string]any, state *policy.ValueState) {
	for k, raw := range exprs {
		pk := policy.JoinPathKey(prefix, policy.Key(k))
		state.Written[pk] = true
		switch v := raw.(type) {
		case map[string]any:
			if cv, ok := v["constant_value"]; ok {
				if cv == nil {
					state.Null[pk] = true
				} else {
					dst[k] = cv
				}
			} else {
				state.Unknown[pk] = true
			}
		case []any:
			var blocks []any
			for i, elem := range v {
				if sub, ok := elem.(map[string]any); ok {
					blk := map[string]any{}
					elemPrefix := policy.JoinPathKey(pk, policy.Index(int64(i)))
					extractConstantPlanExpressions(sub, elemPrefix, blk, state)
					blocks = append(blocks, blk)
				}
			}
			if len(blocks) > 0 {
				dst[k] = blocks
			}
		}
	}
}

func resolvePlanProviderID(cfgKey, resType string, providerIDByKey map[string]string) string {
	if cfgKey != "" {
		if id := providerIDByKey[cfgKey]; id != "" {
			return id
		}
		if idx := strings.LastIndexByte(cfgKey, ':'); idx >= 0 {
			if id := providerIDByKey[cfgKey[idx+1:]]; id != "" {
				return id
			}
		}
	}
	if prefix, _, ok := strings.Cut(resType, "_"); ok {
		return providerIDByKey[prefix]
	}
	return ""
}

func indexPlanConfigModule(
	mod map[string]any,
	modPrefix string,
	exprsOut map[string]map[string]any,
	provOut map[string]string,
	knownOut map[string]bool,
	modulesOut map[string]*planModuleConfig,
) {
	moduleConfig := &planModuleConfig{outputs: map[string]any{}, calls: map[string]planModuleCall{}}
	if outputs, ok := mod["outputs"].(map[string]any); ok {
		moduleConfig.outputs = outputs
	}
	modulesOut[stripAllPlanInstanceKeys(modPrefix)] = moduleConfig
	if resources, ok := mod[planResourcesKey].([]any); ok {
		for _, item := range resources {
			r, _ := item.(map[string]any)
			relAddr, _ := r["address"].(string)
			if relAddr == "" {
				continue
			}
			absAddr := relAddr
			if modPrefix != "" {
				absAddr = modPrefix + "." + relAddr
			}
			knownOut[absAddr] = true
			if isScalarPlanDataSource(r) {
				moduleConfig.dataSources = append(moduleConfig.dataSources, r)
			}
			exprsOut[absAddr] = planResourceExpressions(r)
			if pk, ok := r["provider_config_key"].(string); ok && pk != "" {
				provOut[absAddr] = pk
			}
		}
	}
	if calls, ok := mod[planModuleCallsKey].(map[string]any); ok {
		for callName, raw := range calls {
			call, _ := raw.(map[string]any)
			child, _ := call[address.KindModule].(map[string]any)
			nextPrefix := "module." + callName
			if modPrefix != "" {
				nextPrefix = modPrefix + "." + nextPrefix
			}
			expressions, _ := call["expressions"].(map[string]any)
			_, hasCount := call["count_expression"]
			_, hasForEach := call["for_each_expression"]
			moduleConfig.calls[callName] = planModuleCall{
				expressions: expressions, childAddr: nextPrefix, expanded: hasCount || hasForEach,
			}
			if child != nil {
				indexPlanConfigModule(child, nextPrefix, exprsOut, provOut, knownOut, modulesOut)
			}
		}
	}
}

func isScalarPlanDataSource(resource map[string]any) bool {
	_, counted := resource["count_expression"]
	_, keyed := resource["for_each_expression"]
	return resource["mode"] == address.KindData && !counted && !keyed
}

func planResourceExpressions(resource map[string]any) map[string]any {
	expressions, _ := resource[planExpressionsKey].(map[string]any)
	provisioners, ok := resource[planProvisionersKey].([]any)
	if !ok {
		return expressions
	}
	out := make(map[string]any, len(expressions))
	for key, value := range expressions {
		out[key] = value
	}
	blocks := make([]any, len(provisioners))
	for index, raw := range provisioners {
		blocks[index] = map[string]any{}
		provisioner, _ := raw.(map[string]any)
		kind, _ := provisioner["type"].(string)
		body, _ := provisioner[planExpressionsKey].(map[string]any)
		if kind != "" {
			blocks[index] = map[string]any{kind: []any{body}}
		}
	}
	out[planProvisionerKey] = blocks
	return out
}

func planSourceNullPaths(expressions, attributes map[string]any) map[string]bool {
	paths := make(map[string]bool)
	for name, raw := range expressions {
		collectPlanExpressionNulls(raw, attributes[name], policy.Path{policy.Key(name)}, paths)
	}
	return paths
}

func collectPlanExpressionNulls(raw, planned any, path policy.Path, paths map[string]bool) {
	switch value := raw.(type) {
	case map[string]any:
		if constant, ok := value["constant_value"]; ok {
			if constant == nil {
				paths[policy.PathKey(path)] = true
			} else {
				collectPlanLiteralNulls(constant, path, paths)
			}
			return
		}
		plannedMap, _ := planned.(map[string]any)
		for key, child := range value {
			if key == "references" {
				continue
			}
			collectPlanExpressionNulls(child, plannedMap[key], planSourceChildPath(path, policy.Key(key)), paths)
		}
	case []any:
		expressionValues := value
		plannedValues, ok := planned.([]any)
		if !ok || len(plannedValues) == 0 {
			return
		}
		matcher := newPlanNestedExpressionMatcher(expressionValues, len(plannedValues))
		for index, rawPlanned := range plannedValues {
			plannedMap, _ := rawPlanned.(map[string]any)
			expression, matched := planSourceNestedExpression(matcher, plannedMap, len(plannedValues))
			if !matched {
				continue
			}
			collectPlanExpressionNulls(expression, plannedMap, planSourceChildPath(path, policy.Index(int64(index))), paths)
		}
	}
}

func planSourceNestedExpression(
	matcher planNestedExpressionMatcher,
	planned map[string]any,
	plannedCount int,
) (map[string]any, bool) {
	if len(matcher.expressions) == 1 && plannedCount == 1 {
		return planNestedExpression(matcher.expressions, 0), true
	}
	if len(matcher.keys) == 0 {
		return nil, false
	}
	identity := matcher.identity(planned)
	configuredIndex, ok := matcher.byIdentity[identity]
	if !ok || configuredIndex < 0 {
		return nil, false
	}
	expression := planNestedExpression(matcher.expressions, configuredIndex)
	if planConstantsConflict(expression, planned) {
		return nil, false
	}
	return expression, true
}

func collectPlanLiteralNulls(raw any, path policy.Path, paths map[string]bool) {
	switch value := raw.(type) {
	case nil:
		paths[policy.PathKey(path)] = true
	case map[string]any:
		for key, child := range value {
			collectPlanLiteralNulls(child, planSourceChildPath(path, policy.Key(key)), paths)
		}
	}
}

func planSourceChildPath(path policy.Path, step policy.Step) policy.Path {
	child := make(policy.Path, len(path)+1)
	copy(child, path)
	child[len(path)] = step
	return child
}

func addPlanProvisionerValues(attrs, expressions map[string]any, state *policy.ValueState) {
	blocks, ok := expressions[planProvisionerKey].([]any)
	if !ok {
		return
	}
	state.Written[planProvisionerKey] = true
	attrs[planProvisionerKey] = planConfiguredBlockValues(blocks, planProvisionerKey, state)
}

// Configuration-only blocks have known shape and literals, while every
// nonconstant expression remains unknown without an evaluated Plan value.
func planConfiguredBlockValues(blocks []any, prefix string, state *policy.ValueState) []any {
	values := make([]any, len(blocks))
	for index, raw := range blocks {
		body, _ := raw.(map[string]any)
		value := map[string]any{}
		values[index] = value
		blockPath := policy.JoinPathKey(prefix, policy.Index(int64(index)))
		for key, expression := range body {
			path := policy.JoinPathKey(blockPath, policy.Key(key))
			state.Written[path] = true
			if children, ok := expression.([]any); ok {
				value[key] = planConfiguredBlockValues(children, path, state)
				continue
			}
			object, _ := expression.(map[string]any)
			if constant, ok := object["constant_value"]; ok {
				value[key] = deepCopyPlanValue(constant)
			} else {
				state.Unknown[path] = true
			}
		}
	}
	return values
}

func sortedPlanMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Deferred data reads can be absent from both value sections. Their scalar
// declarations still prove known inputs and explicit reference identity. Never
// infer instances of counted/keyed declarations or unobserved expanded modules.
func deferredPlanDataModules(configs map[string]*planModuleConfig, known map[string]bool) []map[string]any {
	pending := sortedPlanMapKeys(known)
	expandedModules := observedPlanExpandedModuleBases(known)
	var result []map[string]any
	for index := 0; index < len(pending); index++ {
		prefix := pending[index]
		config := configs[stripAllPlanInstanceKeys(prefix)]
		if config == nil {
			continue
		}
		for _, name := range sortedPlanMapKeys(config.calls) {
			call := config.calls[name]
			child := "module." + name
			if prefix != "" {
				child = prefix + "." + child
			}
			if !call.expanded && !known[child] && !expandedModules[stripAllPlanInstanceKeys(child)] {
				known[child] = true
				pending = append(pending, child)
			}
		}
		resources := make([]any, 0, len(config.dataSources))
		for _, descriptor := range config.dataSources {
			resource := deepCopyPlanValue(descriptor).(map[string]any)
			if prefix != "" {
				resource["address"] = prefix + "." + resource["address"].(string)
			}
			resource["values"] = map[string]any{}
			resources = append(resources, resource)
		}
		if len(resources) > 0 {
			result = append(result, map[string]any{"address": prefix, planResourcesKey: resources})
		}
	}
	return result
}

func observedPlanExpandedModuleBases(known map[string]bool) map[string]bool {
	result := make(map[string]bool)
	for observed := range known {
		if stripPlanInstanceKey(observed) != observed {
			result[stripAllPlanInstanceKeys(observed)] = true
		}
	}
	return result
}

func recordPlanModuleAddresses(module map[string]any, known map[string]bool) {
	prefix, _ := module["address"].(string)
	known[prefix] = true
	children, _ := module["child_modules"].([]any)
	for _, raw := range children {
		if child, ok := raw.(map[string]any); ok {
			recordPlanModuleAddresses(child, known)
		}
	}
}

func walkPlanModuleValues(mod map[string]any, fn func(res map[string]any, modAddr string)) {
	modAddr, _ := mod["address"].(string)
	if resources, ok := mod[planResourcesKey].([]any); ok {
		for _, item := range resources {
			if r, ok := item.(map[string]any); ok {
				fn(r, modAddr)
			}
		}
	}
	if children, ok := mod["child_modules"].([]any); ok {
		for _, item := range children {
			if child, ok := item.(map[string]any); ok {
				walkPlanModuleValues(child, fn)
			}
		}
	}
}

func deepCopyPlanValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		cp := make(map[string]any, len(x))
		for k, val := range x {
			cp[k] = deepCopyPlanValue(val)
		}
		return cp
	case []any:
		cp := make([]any, len(x))
		for i, elem := range x {
			cp[i] = deepCopyPlanValue(elem)
		}
		return cp
	default:
		return v
	}
}

// normalizePlanWrittenNested keeps configured nested fields in attrs and
// returns their provider-computed siblings at matching paths. Configuration
// block lists are distinct from ordinary attribute expression objects.
//
// Plan configuration omits dynamic blocks, so a planned element may match no
// configured block (a static block without identity fields next to a dynamic
// one, or a dynamically generated element). Such an element keeps in attrs
// only the fields that some configured block of its type writes; its other
// known fields are provider-computed, as for a dynamic-only block type. Its
// unknown fields stay written unknowns (planWrittenUnknowns).
func normalizePlanWrittenNested(attrs, exprs map[string]any, prefix string, state *policy.ValueState) map[string]any {
	computed := map[string]any{}
	for k, rawExpr := range exprs {
		exprSlice, isBlockList := rawExpr.([]any)
		attrSlice, hasBlocks := attrs[k].([]any)
		if !isBlockList || !hasBlocks {
			continue
		}
		matcher := newPlanNestedExpressionMatcher(exprSlice, len(attrSlice))
		computedSlice := make([]any, len(attrSlice))
		hasComputed := false
		var unmatched map[string]any
		for i, elem := range attrSlice {
			computedSlice[i] = map[string]any{}
			elemMap, ok := elem.(map[string]any)
			if !ok {
				continue
			}
			subExpr := matcher.expression(i, elemMap)
			if subExpr == nil {
				if unmatched == nil {
					unmatched = unionPlanBlockExpressions(exprSlice)
				}
				subExpr = unmatched
			}
			elemPrefix := policy.JoinPathKey(policy.JoinPathKey(prefix, policy.Key(k)), policy.Index(int64(i)))
			childComputed := normalizePlanBlockFields(elemMap, subExpr, elemPrefix, state)
			computedSlice[i] = childComputed
			hasComputed = hasComputed || len(childComputed) > 0
		}
		if hasComputed {
			computed[k] = computedSlice
		}
	}
	return computed
}

// unionPlanBlockExpressions merges configured blocks of one type into one
// expression that writes every field any of them writes. Nested block lists
// merge recursively into a single block. It decides only which fields of an
// unmatched element are configured; it never supplies their values.
func unionPlanBlockExpressions(blocks []any) map[string]any {
	union := map[string]any{}
	nested := map[string][]any{}
	for _, raw := range blocks {
		block, _ := raw.(map[string]any)
		for key, value := range block {
			if list, isBlockList := value.([]any); isBlockList {
				nested[key] = append(nested[key], list...)
			} else if _, seen := union[key]; !seen {
				union[key] = value
			}
		}
	}
	for key, list := range nested {
		union[key] = []any{unionPlanBlockExpressions(list)}
	}
	return union
}

func planNestedExpression(exprs []any, index int) map[string]any {
	if index < 0 {
		return nil
	}
	if index >= len(exprs) {
		if len(exprs) != 1 {
			return nil
		}
		index = 0
	}
	expr, _ := exprs[index].(map[string]any)
	return expr
}

// Providers can reorder nested sets. Index common scalar identity fields
// once per list instead of scanning every configuration block per element.
// Ambiguous identities retain the positional behavior of ordered lists, but
// only when the configuration and the plan have the same number of blocks:
// Plan configuration omits dynamic blocks, so planned elements generated by
// a dynamic block shift the positions of the configured ones.
type planNestedExpressionMatcher struct {
	expressions []any
	keys        []string
	byIdentity  map[string]int
	positional  bool
}

func newPlanNestedExpressionMatcher(expressions []any, plannedCount int) planNestedExpressionMatcher {
	matcher := planNestedExpressionMatcher{expressions: expressions, positional: len(expressions) == plannedCount}
	common := map[string]bool{}
	for index, raw := range expressions {
		expression, _ := raw.(map[string]any)
		if index == 0 {
			for key, value := range expression {
				if _, known := planScalarConstant(value); known {
					common[key] = true
				}
			}
		} else {
			for key := range common {
				if _, known := planScalarConstant(expression[key]); !known {
					delete(common, key)
				}
			}
		}
	}
	for key := range common {
		matcher.keys = append(matcher.keys, key)
	}
	if len(matcher.keys) == 0 {
		return matcher
	}
	sort.Strings(matcher.keys)
	matcher.byIdentity = map[string]int{}
	for index, raw := range expressions {
		expression, _ := raw.(map[string]any)
		values := map[string]any{}
		for _, key := range matcher.keys {
			values[key], _ = planScalarConstant(expression[key])
		}
		identity := matcher.identity(values)
		if _, duplicate := matcher.byIdentity[identity]; duplicate {
			matcher.byIdentity[identity] = -1
		} else {
			matcher.byIdentity[identity] = index
		}
	}
	return matcher
}

func planScalarConstant(raw any) (any, bool) {
	expression, _ := raw.(map[string]any)
	value := expression["constant_value"]
	switch literal := value.(type) {
	case string:
		return value, literal != ""
	case bool, json.Number:
		return value, true
	default:
		return nil, false
	}
}

func (m *planNestedExpressionMatcher) identity(value map[string]any) string {
	values := make([]any, 0, len(m.keys))
	for _, key := range m.keys {
		actual, present := value[key]
		if !present || actual == nil {
			return ""
		}
		values = append(values, actual)
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func (m *planNestedExpressionMatcher) expression(index int, value map[string]any) map[string]any {
	return planNestedExpression(m.expressions, m.expressionIndex(index, value))
}

func (m *planNestedExpressionMatcher) expressionIndex(index int, value map[string]any) int {
	if len(m.keys) > 0 {
		if candidate, exists := m.byIdentity[m.identity(value)]; exists && candidate >= 0 {
			expression := planNestedExpression(m.expressions, candidate)
			if !planConstantsConflict(expression, value) {
				return candidate
			}
		}
	}
	if !m.positional {
		return -1
	}
	return index
}

// Configuration fallback locations follow the same set-element identity as
// written fields. Provider reordering must not point an omitted value at a
// different configuration block that happened to use its planned index.
func alignedPlanConfigurationRanges(ranges map[string]policy.SourceSpan, attrs, expressions map[string]any) map[string]policy.SourceSpan {
	if len(ranges) == 0 {
		return nil
	}
	out := map[string]policy.SourceSpan{}
	var walk func(map[string]any, map[string]any, string, string)
	walk = func(values, body map[string]any, configuredPrefix, plannedPrefix string) {
		for key, raw := range body {
			configured := policy.JoinPathKey(configuredPrefix, policy.Key(key))
			planned := policy.JoinPathKey(plannedPrefix, policy.Key(key))
			if span, exists := ranges[configured]; exists {
				out[planned] = span
			}
			blocks, ok := raw.([]any)
			children, hasChildren := values[key].([]any)
			if !ok || !hasChildren {
				continue
			}
			matcher := newPlanNestedExpressionMatcher(blocks, len(children))
			for index, rawChild := range children {
				child, _ := rawChild.(map[string]any)
				configuredIndex := matcher.expressionIndex(index, child)
				nested := planNestedExpression(blocks, configuredIndex)
				if nested != nil {
					walk(child, nested, policy.JoinPathKey(configured, policy.Index(int64(configuredIndex))),
						policy.JoinPathKey(planned, policy.Index(int64(index))))
				}
			}
		}
	}
	walk(attrs, expressions, "", "")
	return out
}

func planConstantsConflict(expression, value map[string]any) bool {
	for key, raw := range expression {
		expr, _ := raw.(map[string]any)
		constant := expr["constant_value"]
		switch literal := constant.(type) {
		case string:
			if literal == "" {
				continue
			}
		case bool, json.Number:
		default:
			continue
		}
		actual, exists := value[key]
		if !exists || actual == nil {
			continue
		}
		if !reflect.DeepEqual(constant, actual) {
			return true
		}
	}
	return false
}

func normalizePlanBlockFields(attrs, exprs map[string]any, prefix string, state *policy.ValueState) map[string]any {
	computed := map[string]any{}
	for key, value := range attrs {
		if _, written := exprs[key]; !written {
			computed[key] = value
			delete(attrs, key)
			continue
		}
		if value == nil {
			state.Null[policy.JoinPathKey(prefix, policy.Key(key))] = true
			delete(attrs, key)
		}
	}
	for key := range exprs {
		state.Written[policy.JoinPathKey(prefix, policy.Key(key))] = true
	}
	for key, value := range normalizePlanWrittenNested(attrs, exprs, prefix, state) {
		computed[key] = value
	}
	return computed
}

// recordPlanNestedNulls recursively records explicit nested nil leaves in
// written Plan JSON maps and slices into State.Null and strips nil map keys
// to match HCL convertValue semantics.
func recordPlanNestedNulls(v any, prefix string, state *policy.ValueState) {
	switch c := v.(type) {
	case map[string]any:
		for k, val := range c {
			pk := policy.JoinPathKey(prefix, policy.Key(k))
			if val == nil {
				state.Null[pk] = true
				delete(c, k)
				continue
			}
			recordPlanNestedNulls(val, pk, state)
		}
	case []any:
		for i, elem := range c {
			pk := policy.JoinPathKey(prefix, policy.Index(int64(i)))
			if elem == nil {
				state.Null[pk] = true
				continue
			}
			recordPlanNestedNulls(elem, pk, state)
		}
	}
}

// applyPlanUnknownsScoped separates written after_unknown entries (which enter
// attrs and state.Unknown) from unwritten Optional+Computed entries (which only
// strip unknown placeholders from computed without polluting state.Unknown).
func applyPlanUnknownsScoped(
	unknown any,
	exprs map[string]any,
	attrs map[string]any,
	computed map[string]any,
	state, computedState *policy.ValueState,
) {
	if b, ok := unknown.(bool); ok {
		if b {
			state.Unknown[""] = true
		}
		return
	}
	uMap, ok := unknown.(map[string]any)
	if !ok {
		return
	}
	writtenUnk := planWrittenUnknowns(uMap, exprs, attrs)
	applyPlanUnknowns(writtenUnk, "", attrs, state)
	applyPlanUnknowns(uMap, "", computed, computedState)
}

// A configured literal remains known when the provider marks the result
// unknown. Known planned values remain authoritative; source templates are
// exposed separately so normalization (such as hashing) does not erase them.
func restorePlanWrittenConstants(attrs, exprs map[string]any, unknown any, prefix string, state *policy.ValueState) {
	unknownFields, _ := unknown.(map[string]any)
	for key, expression := range exprs {
		path := policy.JoinPathKey(prefix, policy.Key(key))
		if object, ok := expression.(map[string]any); ok {
			if constant, exists := object["constant_value"]; exists && planHasUnknown(unknownFields[key]) {
				attrs[key] = deepCopyPlanValue(constant)
				delete(state.Null, path)
			}
			continue
		}
		expressions, ok := expression.([]any)
		values, hasValues := attrs[key].([]any)
		if !ok || !hasValues {
			continue
		}
		matcher := newPlanNestedExpressionMatcher(expressions, len(values))
		for index, value := range values {
			child, isObject := value.(map[string]any)
			nested := matcher.expression(index, child)
			if !isObject || nested == nil {
				continue
			}
			var childUnknown any
			if unknownValues, ok := unknownFields[key].([]any); ok && index < len(unknownValues) {
				childUnknown = unknownValues[index]
			}
			restorePlanWrittenConstants(child, nested, childUnknown, policy.JoinPathKey(path, policy.Index(int64(index))), state)
		}
	}
}

func planHasUnknown(value any) bool {
	switch unknown := value.(type) {
	case bool:
		return unknown
	case map[string]any:
		for _, child := range unknown {
			if planHasUnknown(child) {
				return true
			}
		}
	case []any:
		for _, child := range unknown {
			if planHasUnknown(child) {
				return true
			}
		}
	}
	return false
}

// Configured string chunks retain source content even when a provider stores
// a digest as the known planned value. This does not replace runtime values.
func derivePlanConfiguredTemplates(resource *policy.Resource, expressions map[string]any, enabled bool) {
	if !enabled {
		return
	}
	var walk func(map[string]any, map[string]any, string)
	walk = func(values, body map[string]any, prefix string) {
		for key, raw := range body {
			path := policy.JoinPathKey(prefix, policy.Key(key))
			if expression, ok := raw.(map[string]any); ok {
				if literal, ok := expression["constant_value"].(string); ok {
					if resource.Derived == nil {
						resource.Derived = &policy.DerivedData{}
					}
					if resource.Derived.TemplateParts == nil {
						resource.Derived.TemplateParts = map[string][]policy.TemplatePart{}
					}
					resource.Derived.TemplateParts[path] = []policy.TemplatePart{{Known: true, Value: literal}}
				}
				continue
			}
			blocks, ok := raw.([]any)
			children, hasChildren := values[key].([]any)
			if !ok || !hasChildren {
				continue
			}
			matcher := newPlanNestedExpressionMatcher(blocks, len(children))
			for index, rawChild := range children {
				child, _ := rawChild.(map[string]any)
				if nested := matcher.expression(index, child); nested != nil {
					walk(child, nested, policy.JoinPathKey(path, policy.Index(int64(index))))
				}
			}
		}
	}
	walk(resource.Attributes, expressions, "")
}

// planWrittenUnknowns filters only nested block bodies. Ordinary attribute
// expressions (including maps and lists) retain all unknown descendants.
func planWrittenUnknowns(unknown any, exprs, attrs map[string]any) any {
	fields, ok := unknown.(map[string]any)
	if !ok {
		return unknown
	}
	written := map[string]any{}
	for key, value := range fields {
		expression, exists := exprs[key]
		if !exists {
			continue
		}
		if expressionObject, ok := expression.(map[string]any); ok {
			if _, constant := expressionObject["constant_value"]; constant {
				continue
			}
		}
		blocks, isBlockList := expression.([]any)
		unknownBlocks, hasBlockUnknowns := value.([]any)
		if !isBlockList || !hasBlockUnknowns {
			written[key] = value
			continue
		}
		values, _ := attrs[key].([]any)
		matcher := newPlanNestedExpressionMatcher(blocks, len(unknownBlocks))
		scoped := make([]any, len(unknownBlocks))
		for index, blockUnknown := range unknownBlocks {
			scoped[index] = false
			var child map[string]any
			if index < len(values) {
				child, _ = values[index].(map[string]any)
			}
			if nested := matcher.expression(index, child); nested != nil {
				scoped[index] = planWrittenUnknowns(blockUnknown, nested, child)
			} else {
				// No configuration block matches this element: Plan
				// configuration omits dynamic blocks, so its fields may be
				// written. Keep its unknowns unknown rather than computed.
				scoped[index] = blockUnknown
			}
		}
		written[key] = scoped
	}
	return written
}

// applyPlanUnknowns recursively mirrors after_unknown into State.Unknown /
// State.IncompleteCollections and removes/masks unknown leaves at EVERY depth
// inside target (deleting unknown map keys, clearing mutually exclusive
// State.Null entries, and replacing unknown slice elements with
// index-preserving policy.UnknownSlot()).
// nolint:gocyclo
func applyPlanUnknowns(unknown any, prefix string, target any, state *policy.ValueState) {
	switch u := unknown.(type) {
	case bool:
		if u {
			state.Unknown[prefix] = true
			delete(state.Null, prefix)
		}
	case map[string]any:
		targetMap, _ := target.(map[string]any)
		for k, v := range u {
			pk := policy.JoinPathKey(prefix, policy.Key(k))
			if b, ok := v.(bool); ok && b {
				state.Unknown[pk] = true
				delete(state.Null, pk)
				if targetMap != nil {
					if _, isSlice := targetMap[k].([]any); isSlice {
						state.IncompleteCollections[pk] = true
					}
					delete(targetMap, k)
				}
				continue
			}
			var child any
			if targetMap != nil {
				child = targetMap[k]
			}
			applyPlanUnknowns(v, pk, child, state)
		}
	case []any:
		targetSlice, _ := target.([]any)
		for i, elem := range u {
			pk := policy.JoinPathKey(prefix, policy.Index(int64(i)))
			if b, ok := elem.(bool); ok && b {
				state.Unknown[pk] = true
				delete(state.Null, pk)
				if i < len(targetSlice) {
					targetSlice[i] = policy.UnknownSlot()
				}
				continue
			}
			var child any
			if i < len(targetSlice) {
				child = targetSlice[i]
			}
			applyPlanUnknowns(elem, pk, child, state)
		}
	}
}

type planResourceRefs struct {
	res     *policy.Resource
	modAddr string
	exprs   map[string]any
}

type planModuleCall struct {
	expressions map[string]any
	childAddr   string
	expanded    bool
}

type planModuleConfig struct {
	outputs     map[string]any
	calls       map[string]planModuleCall
	dataSources []map[string]any
}

// nolint:gocyclo
func buildPlanRelations(unit *policy.Unit, items []planResourceRefs, literalKeys LiteralKeyMap, modules map[string]*planModuleConfig) {
	items = appendPlanOutputRelations(unit, items, modules)
	items = appendPlanModuleCallRelations(unit, items, modules)
	if literalKeys == nil {
		literalKeys = DefaultLiteralKeys
	}
	byExactAddr := make(map[string][]*policy.Resource, len(items))
	byBaseAddr := make(map[string][]*policy.Resource, len(items))
	byTargetLiteral := make(map[string]map[string]map[string][]*policy.Resource)
	unknownTargetLiteral := make(map[string]map[string][]*policy.Resource)
	uncertainLiterals := make(map[literalUncertaintyKey]bool)

	for _, it := range items {
		byExactAddr[it.res.Address] = append(byExactAddr[it.res.Address], it.res)
		base := stripPlanInstanceKey(it.res.Address)
		byBaseAddr[base] = append(byBaseAddr[base], it.res)
		for _, byPath := range literalKeys {
			for _, byTarget := range byPath {
				if attrs, ok := byTarget[it.res.Type]; ok {
					for _, a := range attrs {
						if statePathContains(it.res.State.Unknown, policy.EscapeStep(policy.Key(a))) {
							if unknownTargetLiteral[it.res.Type] == nil {
								unknownTargetLiteral[it.res.Type] = map[string][]*policy.Resource{}
							}
							unknownTargetLiteral[it.res.Type][a] = append(unknownTargetLiteral[it.res.Type][a], it.res)
							continue
						}
						recordTargetLiteral(byTargetLiteral, it.res, a)
					}
				}
			}
		}
	}

	incompleteCompanion := make(map[[2]string]bool)

	for _, it := range items {
		resolvedRefPaths := map[string]bool{}
		collectPlanExprRefs(it.exprs, "", func(attrPath string, refs []string) {
			exactBases := make(map[string]bool)
			specificModuleOutputs := make(map[string]bool)
			missingExplicitTarget := false
			for _, originalRef := range refs {
				ref := bindPlanCountIndex(originalRef, it.res.Address)
				_, baseAddr, hasKey := resolvePlanRefAddress(it.modAddr, ref)
				if hasKey && baseAddr != "" {
					exactBases[baseAddr] = true
				}
				if identity, specific := planModuleOutputIdentity(ref); specific {
					specificModuleOutputs[identity] = true
				}
			}

			attrComplete := unit.ScopeComplete
			hasUntraced := false
			matchedAny := false
			for _, originalRef := range refs {
				ref := bindPlanCountIndex(originalRef, it.res.Address)
				if hasUnboundPlanIndex(ref) {
					hasUntraced = true
					attrComplete = false
					continue
				}
				if identity, specific := planModuleOutputIdentity(ref); !specific && specificModuleOutputs[identity] {
					continue
				}
				exactAddr, baseAddr, hasKey := resolvePlanRefAddress(it.modAddr, ref)
				if !hasKey && baseAddr != "" && exactBases[baseAddr] {
					continue
				}
				var dsts []*policy.Resource
				if hasKey {
					dsts = byExactAddr[exactAddr]
				} else if baseAddr != "" {
					dsts = byBaseAddr[baseAddr]
				}
				if len(dsts) > 0 {
					matchedAny = true
					for _, dst := range dsts {
						addRelationEdge(unit, it.res, dst, attrPath, attrComplete)
						addTargetAttributeEdge(unit, it.res, dst, attrPath, planRefReadPath(ref), attrComplete)
					}
				} else if strings.HasPrefix(ref, "var.") || strings.HasPrefix(ref, "local.") || strings.HasPrefix(ref, "module.") {
					resolved, incomplete := resolvePlanModuleReference(it.modAddr, ref, modules, byExactAddr, byBaseAddr, 0)
					if len(resolved) > 0 {
						matchedAny = true
						for _, target := range resolved {
							addRelationEdge(unit, it.res, target.res, attrPath, attrComplete && !incomplete)
							addTargetAttributeEdge(unit, it.res, target.res, attrPath, target.readPath, attrComplete && !incomplete)
						}
					}
					if incomplete || len(resolved) == 0 {
						hasUntraced = true
						attrComplete = false
					}
				} else if baseAddr != "" {
					missingExplicitTarget = true
				}
			}
			if matchedAny && !hasUntraced {
				resolvedRefPaths[attrPath] = true
			}
			if hasUntraced || (!matchedAny && (it.res.State.Unknown[attrPath] || it.res.State.IncompleteCollections[attrPath])) {
				markTargetIncomplete(it.res, attrPath)
				// A known, explicit reference to a resource omitted from the plan
				// cannot target any other candidate. Keep this source path incomplete,
				// but do not invalidate reverse relations for unrelated resources.
				if it.res.Kind == address.KindResource &&
					(!missingExplicitTarget || hasUntraced || statePathContains(it.res.State.IncompleteCollections, attrPath)) {
					incompleteCompanion[[2]string{it.res.BucketKey(), attrPath}] = true
				}
			}
		})

		if byPath, ok := literalKeys[it.res.Type]; ok {
			for attrPath, byTarget := range byPath {
				vals, isUnk := extractStringValues(it.res, attrPath)
				// A direct resource reference (e.g. bucket = aws_s3_bucket.logs.id)
				// has after_unknown=true until apply, yet its structural relation is
				// already completely resolved via configuration.expressions.
				unresolvedUnk := isUnk && !resolvedRefPaths[attrPath]
				attrComplete := unit.ScopeComplete && !unresolvedUnk
				if unresolvedUnk {
					incompleteCompanion[[2]string{it.res.BucketKey(), attrPath}] = true
					markTargetIncomplete(it.res, attrPath)
				}
				for tType, tAttrs := range byTarget {
					for _, tAttr := range tAttrs {
						if markUnknownLiteralTargets(
							it.res, attrPath, vals, tType, tAttr,
							unknownTargetLiteral[tType][tAttr], uncertainLiterals,
						) {
							attrComplete = false
						}
						for _, val := range vals {
							for _, dst := range byTargetLiteral[tType][tAttr][val] {
								if !literalScopeMatches(it.res, dst) {
									continue
								}
								addRelationEdge(unit, it.res, dst, attrPath, attrComplete)
								addTargetAttributeEdge(unit, it.res, dst, attrPath, tAttr, attrComplete)
							}
						}
					}
				}
			}
		}
	}

	propagateIncompleteCompanions(unit, incompleteCompanion, literalKeys)
	sortUnitRelations(unit)
}

func appendPlanModuleCallRelations(unit *policy.Unit, items []planResourceRefs, modules map[string]*planModuleConfig) []planResourceRefs {
	resourcesByAddress := make(map[string]*policy.Resource)
	for _, resource := range unit.Resources {
		if resource.Kind == address.KindModule {
			resourcesByAddress[resource.Address] = resource
		}
	}
	for parentAddr, module := range modules {
		for _, call := range module.calls {
			resource := resourcesByAddress[call.childAddr]
			if resource == nil {
				continue
			}
			items = append(items, planResourceRefs{res: resource, modAddr: parentAddr, exprs: call.expressions})
		}
	}
	return items
}

func appendPlanOutputRelations(unit *policy.Unit, items []planResourceRefs, modules map[string]*planModuleConfig) []planResourceRefs {
	for _, res := range unit.Resources {
		if res.Kind != address.KindOutput {
			continue
		}
		terraformMeta, _ := res.Platform[terraformPlatform].(map[string]any)
		moduleAddr, _ := terraformMeta[platformKeyModule].(string)
		module := modules[stripAllPlanInstanceKeys(moduleAddr)]
		if module == nil {
			continue
		}
		output, _ := module.outputs[res.Name].(map[string]any)
		expression, ok := output["expression"]
		if !ok {
			continue
		}
		items = append(items, planResourceRefs{
			res:     res,
			modAddr: moduleAddr,
			exprs:   map[string]any{"value": expression},
		})
	}
	return items
}

type planRelationTarget struct {
	res      *policy.Resource
	readPath string
}

func planRefReadPath(ref string) string {
	parts := splitPlanRefSteps(ref)
	start := 2
	if strings.HasPrefix(ref, "data.") {
		start = 3
	}
	if len(parts) <= start {
		return ""
	}
	var attrs []string
	for _, part := range parts[start:] {
		name, suffix, hasIndex := strings.Cut(part, "[")
		if name != "" {
			attrs = append(attrs, name)
		}
		for hasIndex {
			index, rest, found := strings.Cut(suffix, "]")
			if !found {
				return strings.Join(attrs, ".")
			}
			if strings.HasPrefix(index, "\"") {
				if key, err := strconv.Unquote(index); err == nil {
					attrs = append(attrs, key)
				} else {
					return strings.Join(attrs, ".")
				}
			} else if _, err := strconv.ParseInt(index, 10, 64); err != nil {
				return strings.Join(attrs, ".")
			}
			if rest == "" {
				break
			}
			name, suffix, hasIndex = strings.Cut(rest, "[")
			if name != "" {
				attrs = append(attrs, name)
			}
		}
	}
	return strings.Join(attrs, ".")
}

// resolvePlanModuleReference follows only unambiguous scalar passthroughs in
// Terraform's flattened plan expression JSON. Object projections lose their
// field structure in that format, so they stay incomplete rather than joining
// references from sibling fields.
const (
	planVarNamespace   = "var"
	planLocalNamespace = "local"
)

func resolvePlanModuleReference(
	modAddr, ref string,
	modules map[string]*planModuleConfig,
	byExactAddr, byBaseAddr map[string][]*policy.Resource,
	depth int,
) ([]planRelationTarget, bool) {
	if depth > maxLocalAliasDepth {
		return nil, true
	}
	parts := splitPlanRefSteps(ref)
	if len(parts) >= 3 && parts[0] == address.KindModule {
		return resolvePlanModuleOutputReference(modAddr, parts, modules, byExactAddr, byBaseAddr, depth)
	}
	if len(parts) == 2 && parts[0] == planVarNamespace {
		return resolvePlanModuleInputReference(modAddr, parts[1], modules, byExactAddr, byBaseAddr, depth)
	}
	if len(parts) >= 2 && parts[0] == planLocalNamespace {
		return nil, true
	}
	return resolvePlanResourceReference(modAddr, ref, byExactAddr, byBaseAddr)
}

func resolvePlanModuleOutputReference(
	modAddr string,
	parts []string,
	modules map[string]*planModuleConfig,
	byExactAddr, byBaseAddr map[string][]*policy.Resource,
	depth int,
) ([]planRelationTarget, bool) {
	callToken := parts[1]
	callName := stripBracketSuffix(callToken)
	if len(parts) != 3 || callName == "" {
		return nil, true
	}
	outputName := stripBracketSuffix(parts[2])
	parent := modules[stripAllPlanInstanceKeys(modAddr)]
	if parent == nil {
		return nil, true
	}
	call, ok := parent.calls[callName]
	if !ok || (call.expanded && !strings.ContainsRune(callToken, '[')) {
		return nil, true
	}
	childAddr := appendPlanModuleCall(modAddr, callToken)
	child := modules[stripAllPlanInstanceKeys(childAddr)]
	if child == nil {
		return nil, true
	}
	output, ok := child.outputs[outputName]
	if !ok {
		return nil, true
	}
	ref, ok := singlePlanExpressionReference(output)
	if !ok {
		return nil, true
	}
	targets, incomplete := resolvePlanModuleReference(childAddr, ref, modules, byExactAddr, byBaseAddr, depth+1)
	if strings.ContainsRune(parts[2], '[') && len(targets) != 1 {
		return nil, true
	}
	return targets, incomplete
}

func planModuleOutputIdentity(ref string) (identity string, specific bool) {
	parts := splitPlanRefSteps(ref)
	if len(parts) != 3 || parts[0] != address.KindModule {
		return "", false
	}
	output := stripBracketSuffix(parts[2])
	if output == "" {
		return "", false
	}
	return strings.Join([]string{parts[0], parts[1], output}, "."), strings.ContainsRune(parts[2], '[')
}

func resolvePlanModuleInputReference(
	modAddr, variable string,
	modules map[string]*planModuleConfig,
	byExactAddr, byBaseAddr map[string][]*policy.Resource,
	depth int,
) ([]planRelationTarget, bool) {
	parentAddr, callName, ok := parentModuleCall(modAddr)
	if !ok {
		return nil, true
	}
	parent := modules[stripAllPlanInstanceKeys(parentAddr)]
	if parent == nil {
		return nil, true
	}
	call, ok := parent.calls[callName]
	if !ok {
		return nil, true
	}
	input, ok := call.expressions[variable]
	if !ok {
		return nil, true
	}
	ref, ok := singlePlanExpressionReference(input)
	if !ok {
		return nil, true
	}
	return resolvePlanModuleReference(parentAddr, ref, modules, byExactAddr, byBaseAddr, depth+1)
}

func resolvePlanResourceReference(
	modAddr, ref string,
	byExactAddr, byBaseAddr map[string][]*policy.Resource,
) ([]planRelationTarget, bool) {
	exactAddr, baseAddr, hasKey := resolvePlanRefAddress(modAddr, ref)
	var resources []*policy.Resource
	if hasKey {
		resources = byExactAddr[exactAddr]
	} else if baseAddr != "" {
		resources = byBaseAddr[baseAddr]
	}
	if len(resources) == 0 {
		return nil, true
	}
	out := make([]planRelationTarget, 0, len(resources))
	for _, resource := range resources {
		out = append(out, planRelationTarget{res: resource, readPath: planRefReadPath(ref)})
	}
	return out, false
}

func parentModuleCall(modAddr string) (parentAddr, callName string, ok bool) {
	if strings.HasPrefix(modAddr, "module.") {
		last := strings.LastIndex(modAddr, ".module.")
		if last >= 0 {
			return modAddr[:last], stripBracketSuffix(modAddr[last+len(".module."):]), true
		}
		return "", stripBracketSuffix(strings.TrimPrefix(modAddr, "module.")), true
	}
	return "", "", false
}

func appendPlanModuleCall(parentAddr, callToken string) string {
	step := "module." + callToken
	if parentAddr == "" {
		return step
	}
	return parentAddr + "." + step
}

func singlePlanExpressionReference(raw any) (string, bool) {
	obj, _ := raw.(map[string]any)
	if expression, ok := obj[planExpressionKey].(map[string]any); ok {
		obj = expression
	}
	values, _ := obj["references"].([]any)
	var refs []string
	for _, value := range values {
		if ref, ok := value.(string); ok {
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		return "", false
	}
	identity := planRefIdentity(refs[0])
	readPath := planRefReadPath(refs[0])
	chosen := refs[0]
	ambiguousPath := false
	for _, ref := range refs[1:] {
		if planRefIdentity(ref) != identity {
			return "", false
		}
		path := planRefReadPath(ref)
		if path == readPath {
			continue
		}
		if path == "" {
			if readPath == "" {
				chosen = ref
			}
			continue
		}
		if readPath == "" {
			chosen = ref
			readPath = path
			continue
		}
		ambiguousPath = true
	}
	if ambiguousPath {
		return identity, true
	}
	return chosen, true
}

func planRefIdentity(ref string) string {
	parts := splitPlanRefSteps(ref)
	if len(parts) == 0 {
		return ref
	}
	switch parts[0] {
	case address.KindModule:
		if len(parts) >= 3 {
			return strings.Join(parts[:3], ".")
		}
	case address.KindData:
		if len(parts) >= 3 {
			return strings.Join(parts[:3], ".")
		}
	case planVarNamespace, planLocalNamespace:
		if len(parts) >= 2 {
			return strings.Join(parts[:2], ".")
		}
	default:
		if len(parts) >= 2 {
			return strings.Join(parts[:2], ".")
		}
	}
	return ref
}

func collectPlanExprRefs(exprs map[string]any, prefix string, fn func(attrPath string, refs []string)) {
	for k, raw := range exprs {
		path := policy.JoinPathKey(prefix, policy.Key(k))
		switch v := raw.(type) {
		case map[string]any:
			if refRaw, ok := v["references"].([]any); ok {
				var refs []string
				for _, r := range refRaw {
					if s, ok := r.(string); ok {
						refs = append(refs, s)
					}
				}
				if len(refs) > 0 {
					fn(path, refs)
				}
			}
		case []any:
			for i, elem := range v {
				if sub, ok := elem.(map[string]any); ok {
					collectPlanExprRefs(sub, policy.JoinPathKey(path, policy.Index(int64(i))), fn)
				}
			}
		}
	}
}

func splitPlanRefSteps(ref string) []string {
	var parts []string
	start := 0
	inBracket := false
	inQuote := false
	escaped := false
	for i := 0; i < len(ref); i++ {
		ch := ref[i]
		if inBracket {
			if inQuote {
				if escaped {
					escaped = false
				} else if ch == '\\' {
					escaped = true
				} else if ch == '"' {
					inQuote = false
				}
				continue
			}
			switch ch {
			case '"':
				inQuote = true
			case ']':
				inBracket = false
			}
			continue
		}
		switch ch {
		case '[':
			inBracket = true
		case '.':
			parts = append(parts, ref[start:i])
			start = i + 1
		}
	}
	parts = append(parts, ref[start:])
	return parts
}

func resolvePlanRefAddress(modAddr, ref string) (exactAddr, baseAddr string, hasKey bool) {
	parts := splitPlanRefSteps(ref)
	var exact, base string
	switch {
	case len(parts) >= 3 && parts[0] == address.KindData:
		exact = address.DataPrefix + parts[1] + "." + parts[2]
		base = address.DataPrefix + parts[1] + "." + stripBracketSuffix(parts[2])
		hasKey = strings.ContainsRune(parts[2], '[')
	case len(parts) >= 2 && parts[0] != "var" && parts[0] != "local" &&
		parts[0] != address.KindModule && parts[0] != "each" && parts[0] != metaArgCount:
		exact = parts[0] + "." + parts[1]
		base = parts[0] + "." + stripBracketSuffix(parts[1])
		hasKey = strings.ContainsRune(parts[1], '[')
	default:
		return "", "", false
	}
	if modAddr != "" {
		return modAddr + "." + exact, modAddr + "." + base, hasKey
	}
	return exact, base, hasKey
}

// bindPlanCountIndex resolves count.index from the concrete address of the
// resource whose configuration expression is being traced. Terraform plan
// references preserve the literal count.index token instead of substituting
// the instance's numeric key.
func bindPlanCountIndex(ref, sourceAddr string) string {
	if !strings.Contains(ref, "count.index") {
		return ref
	}
	parts := splitPlanRefSteps(sourceAddr)
	if len(parts) < 2 {
		return ref
	}
	resourceToken := parts[len(parts)-1]
	open := strings.LastIndexByte(resourceToken, '[')
	if open < 0 || !strings.HasSuffix(resourceToken, "]") {
		return ref
	}
	key := resourceToken[open+1 : len(resourceToken)-1]
	if _, err := strconv.ParseInt(key, 10, 64); err != nil {
		return ref
	}
	var out strings.Builder
	out.Grow(len(ref))
	bound := false
	for i := 0; i < len(ref); {
		if ref[i] != '[' {
			out.WriteByte(ref[i])
			i++
			continue
		}
		end := planIndexEnd(ref, i)
		if end < 0 {
			out.WriteString(ref[i:])
			break
		}
		if ref[i+1:end] == "count.index" {
			out.WriteByte('[')
			out.WriteString(key)
			out.WriteByte(']')
			bound = true
		} else {
			out.WriteString(ref[i : end+1])
		}
		i = end + 1
	}
	if !bound {
		return ref
	}
	return out.String()
}

func planIndexEnd(ref string, start int) int {
	inQuote, escaped := false, false
	for i := start + 1; i < len(ref); i++ {
		ch := ref[i]
		if inQuote {
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inQuote = false
			}
			continue
		}
		switch ch {
		case '"':
			inQuote = true
		case ']':
			return i
		}
	}
	return -1
}

// hasUnboundPlanIndex reports a dynamic collection selector that cannot be
// resolved from the source instance. Treating such a selector as a missing
// explicit address would incorrectly prove that all candidate resources are
// unreferenced.
func hasUnboundPlanIndex(ref string) bool {
	for i := 0; i < len(ref); i++ {
		if ref[i] != '[' {
			continue
		}
		start := i + 1
		end := planIndexEnd(ref, i)
		if end < 0 {
			return true
		}
		index := ref[start:end]
		if _, err := strconv.ParseInt(index, 10, 64); err != nil {
			if _, err := strconv.Unquote(index); err != nil {
				return true
			}
		}
		i = end
	}
	return false
}

func stripBracketSuffix(s string) string {
	if idx := strings.IndexByte(s, '['); idx >= 0 {
		return s[:idx]
	}
	return s
}

func lastTopLevelBracket(addr string) int {
	if !strings.HasSuffix(addr, "]") {
		return -1
	}
	lastOpen := -1
	inBracket := false
	inQuote := false
	escaped := false
	for i := 0; i < len(addr); i++ {
		ch := addr[i]
		if inBracket {
			if inQuote {
				if escaped {
					escaped = false
				} else if ch == '\\' {
					escaped = true
				} else if ch == '"' {
					inQuote = false
				}
				continue
			}
			switch ch {
			case '"':
				inQuote = true
			case ']':
				inBracket = false
			}
			continue
		}
		if ch == '[' {
			inBracket = true
			lastOpen = i
		}
	}
	return lastOpen
}

func stripPlanInstanceKey(addr string) string {
	if idx := lastTopLevelBracket(addr); idx >= 0 {
		return addr[:idx]
	}
	return addr
}

// stripAllPlanInstanceKeys removes bracketed instance keys from both module
// hops and the resource label (e.g. module.app["prod"].aws_s3_bucket.b[0] ->
// module.app.aws_s3_bucket.b) to match configuration.root_module addresses.
func stripAllPlanInstanceKeys(addr string) string {
	if !strings.ContainsRune(addr, '[') {
		return addr
	}
	var out strings.Builder
	out.Grow(len(addr))
	inBracket := false
	inQuote := false
	escaped := false
	for i := 0; i < len(addr); i++ {
		ch := addr[i]
		if inBracket {
			if inQuote {
				if escaped {
					escaped = false
				} else if ch == '\\' {
					escaped = true
				} else if ch == '"' {
					inQuote = false
				}
				continue
			}
			switch ch {
			case '"':
				inQuote = true
			case ']':
				inBracket = false
			}
			continue
		}
		if ch == '[' {
			inBracket = true
			continue
		}
		out.WriteByte(ch)
	}
	return out.String()
}

func extractPlanInstanceKey(addr string) string {
	if idx := lastTopLevelBracket(addr); idx >= 0 {
		return addr[idx:]
	}
	return ""
}

// scanPlanSectionAddressLines scans only inside the named top-level JSON
// section (e.g. "planned_values" or "prior_state") using a structural top-level
// key walk so `"prior_state": null` and nested string literals never misalign
// line numbers.
// nolint:gocyclo
func scanPlanSectionAddressLines(src []byte, sectionName string) map[string]int {
	objStart, objEnd, ok := findTopLevelJSONSection(src, sectionName)
	if !ok {
		return map[string]int{}
	}
	baseLine := 1 + bytes.Count(src[:objStart], []byte{'\n'})
	return scanAddressLinesInSlice(src[objStart:objEnd], baseLine)
}

type planSourceIndex struct {
	file       string
	src        []byte
	lineStarts []int
}

func newPlanSourceIndex(file string, src []byte) *planSourceIndex {
	starts := []int{0}
	for i, char := range src {
		if char == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &planSourceIndex{file: file, src: src, lineStarts: starts}
}

func (s *planSourceIndex) spanAt(offset int) policy.SourceSpan {
	if offset < 0 {
		offset = 0
	}
	if offset > len(s.src) {
		offset = len(s.src)
	}
	lineIdx := sort.Search(len(s.lineStarts), func(i int) bool { return s.lineStarts[i] > offset }) - 1
	if lineIdx < 0 {
		lineIdx = 0
	}
	line := lineIdx + 1
	col := offset - s.lineStarts[lineIdx] + 1
	return policy.SourceSpan{File: s.file, StartLine: line, StartCol: col, EndLine: line, EndCol: col + 1}
}

func scanPlanSectionResourceRanges(source *planSourceIndex, sectionName string) map[string]map[string]policy.SourceSpan {
	start, end, ok := findTopLevelJSONSection(source.src, sectionName)
	if !ok {
		return nil
	}
	rootStart, rootEnd, ok := jsonObjectField(source.src, start, end, "root_module")
	if !ok && sectionName == "prior_state" {
		valuesStart, valuesEnd, found := jsonObjectField(source.src, start, end, "values")
		if !found {
			return nil
		}
		rootStart, rootEnd, ok = jsonObjectField(source.src, valuesStart, valuesEnd, "root_module")
	}
	if !ok {
		return nil
	}
	out := make(map[string]map[string]policy.SourceSpan)
	walkPlanModuleRanges(source, rootStart, rootEnd, out)
	return out
}

func walkPlanModuleRanges(source *planSourceIndex, start, end int, out map[string]map[string]policy.SourceSpan) {
	forEachJSONObjectField(source.src, start, end, func(key string, _, valueStart, valueEnd int) {
		switch key {
		case planResourcesKey:
			forEachJSONArrayValue(source.src, valueStart, valueEnd, func(_, resourceStart, resourceEnd int) {
				addressStart, addressEnd, ok := jsonObjectField(source.src, resourceStart, resourceEnd, "address")
				if !ok {
					return
				}
				addr, ok := jsonStringValue(source.src, addressStart, addressEnd)
				if !ok || addr == "" {
					return
				}
				valuesKeyStart, valuesStart, valuesEnd, ok := jsonObjectFieldLocation(source.src, resourceStart, resourceEnd, "values")
				if !ok || source.src[valuesStart] != '{' {
					return
				}
				ranges := map[string]policy.SourceSpan{"": source.spanAt(valuesKeyStart)}
				walkPlanValueRanges(source, valuesStart, valuesEnd, nil, ranges)
				if len(ranges) > 0 {
					out[addr] = ranges
				}
			})
		case "child_modules":
			forEachJSONArrayValue(source.src, valueStart, valueEnd, func(_, moduleStart, moduleEnd int) {
				walkPlanModuleRanges(source, moduleStart, moduleEnd, out)
			})
		}
	})
}

func walkPlanValueRanges(
	source *planSourceIndex,
	start, end int,
	path policy.Path,
	ranges map[string]policy.SourceSpan,
) {
	if start >= end {
		return
	}
	switch source.src[start] {
	case '{':
		forEachJSONObjectField(source.src, start, end, func(key string, keyStart, valueStart, valueEnd int) {
			childPath := append(slices.Clone(path), policy.Key(key))
			ranges[policy.PathKey(childPath)] = source.spanAt(keyStart)
			walkPlanValueRanges(source, valueStart, valueEnd, childPath, ranges)
		})
	case '[':
		forEachJSONArrayValue(source.src, start, end, func(index, valueStart, valueEnd int) {
			childPath := append(slices.Clone(path), policy.Index(int64(index)))
			ranges[policy.PathKey(childPath)] = source.spanAt(valueStart)
			walkPlanValueRanges(source, valueStart, valueEnd, childPath, ranges)
		})
	}
}

func jsonObjectField(src []byte, start, end int, wanted string) (valueStart, valueEnd int, ok bool) {
	_, valueStart, valueEnd, ok = jsonObjectFieldLocation(src, start, end, wanted)
	return valueStart, valueEnd, ok
}

func jsonObjectFieldLocation(src []byte, start, end int, wanted string) (keyStart, valueStart, valueEnd int, ok bool) {
	forEachJSONObjectField(src, start, end, func(key string, fieldKeyStart, fieldStart, fieldEnd int) {
		if !ok && key == wanted {
			keyStart, valueStart, valueEnd, ok = fieldKeyStart, fieldStart, fieldEnd, true
		}
	})
	return keyStart, valueStart, valueEnd, ok
}

func jsonStringValue(src []byte, start, end int) (string, bool) {
	if start >= end || src[start] != '"' {
		return "", false
	}
	value, err := strconv.Unquote(string(src[start:end]))
	return value, err == nil
}

func forEachJSONObjectField(src []byte, start, end int, fn func(key string, keyStart, valueStart, valueEnd int)) {
	if start >= end || src[start] != '{' {
		return
	}
	for i := skipJSONWhitespace(src, start+1); i < end && src[i] != '}'; {
		if src[i] == ',' {
			i = skipJSONWhitespace(src, i+1)
			continue
		}
		keyStart := i
		keyEnd := findJSONStringEnd(src, i)
		if keyEnd < 0 || keyEnd >= end {
			return
		}
		key, err := strconv.Unquote(string(src[keyStart : keyEnd+1]))
		if err != nil {
			return
		}
		valueStart := skipJSONWhitespace(src, keyEnd+1)
		if valueStart >= end || src[valueStart] != ':' {
			return
		}
		valueStart = skipJSONWhitespace(src, valueStart+1)
		valueEnd := skipJSONValue(src, valueStart)
		if valueEnd <= valueStart || valueEnd > end {
			return
		}
		fn(key, keyStart, valueStart, valueEnd)
		i = skipJSONWhitespace(src, valueEnd)
	}
}

func forEachJSONArrayValue(src []byte, start, end int, fn func(index, valueStart, valueEnd int)) {
	if start >= end || src[start] != '[' {
		return
	}
	count := 0
	for i := skipJSONWhitespace(src, start+1); i < end && src[i] != ']'; {
		if src[i] == ',' {
			i = skipJSONWhitespace(src, i+1)
			continue
		}
		valueEnd := skipJSONValue(src, i)
		if valueEnd <= i || valueEnd > end {
			return
		}
		fn(count, i, valueEnd)
		count++
		i = skipJSONWhitespace(src, valueEnd)
	}
}

// nolint:gocyclo
func findTopLevelJSONSection(src []byte, key string) (start, end int, ok bool) {
	i := skipJSONWhitespace(src, 0)
	if i >= len(src) || src[i] != '{' {
		return 0, 0, false
	}
	i++
	for i < len(src) {
		i = skipJSONWhitespace(src, i)
		if i >= len(src) || src[i] == '}' {
			return 0, 0, false
		}
		if src[i] == ',' {
			i++
			continue
		}
		if src[i] != '"' {
			return 0, 0, false
		}
		kEnd := findJSONStringEnd(src, i)
		if kEnd < 0 {
			return 0, 0, false
		}
		kStr := string(src[i+1 : kEnd])
		i = skipJSONWhitespace(src, kEnd+1)
		if i >= len(src) || src[i] != ':' {
			return 0, 0, false
		}
		i = skipJSONWhitespace(src, i+1)
		if i >= len(src) {
			return 0, 0, false
		}
		valStart := i
		valEnd := skipJSONValue(src, valStart)
		if valEnd <= valStart {
			return 0, 0, false
		}
		if kStr == key {
			if src[valStart] != '{' {
				return 0, 0, false
			}
			return valStart, valEnd, true
		}
		i = valEnd
	}
	return 0, 0, false
}

func skipJSONWhitespace(src []byte, i int) int {
	for i < len(src) && (src[i] == ' ' || src[i] == '\t' || src[i] == '\r' || src[i] == '\n') {
		i++
	}
	return i
}

func findJSONStringEnd(src []byte, quoteIdx int) int {
	escaped := false
	for i := quoteIdx + 1; i < len(src); i++ {
		if escaped {
			escaped = false
			continue
		}
		if src[i] == '\\' {
			escaped = true
			continue
		}
		if src[i] == '"' {
			return i
		}
	}
	return -1
}

func skipJSONValue(src []byte, start int) int {
	if start >= len(src) {
		return start
	}
	switch src[start] {
	case '{':
		return findMatchingDelimiter(src, start, '{', '}')
	case '[':
		return findMatchingDelimiter(src, start, '[', ']')
	case '"':
		end := findJSONStringEnd(src, start)
		if end < 0 {
			return len(src)
		}
		return end + 1
	default:
		i := start
		for i < len(src) && src[i] != ',' && src[i] != '}' && src[i] != ']' &&
			src[i] != ' ' && src[i] != '\t' && src[i] != '\r' && src[i] != '\n' {
			i++
		}
		return i
	}
}

func findMatchingDelimiter(src []byte, openIdx int, openCh, closeCh byte) int {
	depth := 0
	inStr := false
	escaped := false
	for i := openIdx; i < len(src); i++ {
		ch := src[i]
		if inStr {
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inStr = false
			}
			continue
		}
		switch ch {
		case '"':
			inStr = true
		case openCh:
			depth++
		case closeCh:
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(src)
}

// nolint:gocyclo
func scanAddressLinesInSlice(src []byte, startLine int) map[string]int {
	out := make(map[string]int)
	needle := []byte(`"address"`)
	line := startLine
	pos := 0
	for pos < len(src) {
		idx := bytes.Index(src[pos:], needle)
		if idx < 0 {
			break
		}
		line += bytes.Count(src[pos:pos+idx], []byte{'\n'})
		pos += idx + len(needle)
		for pos < len(src) && (src[pos] == ' ' || src[pos] == '\t' || src[pos] == ':' || src[pos] == '\r' || src[pos] == '\n') {
			if src[pos] == '\n' {
				line++
			}
			pos++
		}
		if pos < len(src) && src[pos] == '"' {
			end := pos + 1
			for end < len(src) && src[end] != '"' {
				if src[end] == '\\' && end+1 < len(src) {
					end += 2
					continue
				}
				end++
			}
			if end < len(src) {
				if unq, err := strconv.Unquote(string(src[pos : end+1])); err == nil {
					if _, exists := out[unq]; !exists {
						out[unq] = line
					}
				}
				pos = end + 1
			}
		}
	}
	return out
}

func scanPlanConfigurationRanges(source *planSourceIndex) map[string]map[string]policy.SourceSpan {
	start, end, ok := findTopLevelJSONSection(source.src, "configuration")
	if !ok {
		return nil
	}
	rootStart, rootEnd, ok := jsonObjectField(source.src, start, end, "root_module")
	if !ok {
		return nil
	}
	out := map[string]map[string]policy.SourceSpan{}
	walkPlanConfigurationRanges(source, rootStart, rootEnd, "", out)
	return out
}

func walkPlanConfigurationRanges(source *planSourceIndex, start, end int, prefix string, out map[string]map[string]policy.SourceSpan) {
	forEachJSONObjectField(source.src, start, end, func(key string, _, valueStart, valueEnd int) {
		switch key {
		case planResourcesKey:
			forEachJSONArrayValue(source.src, valueStart, valueEnd, func(_, resourceStart, resourceEnd int) {
				addressStart, addressEnd, ok := jsonObjectField(source.src, resourceStart, resourceEnd, "address")
				if !ok {
					return
				}
				addr, ok := jsonStringValue(source.src, addressStart, addressEnd)
				if !ok || addr == "" {
					return
				}
				if prefix != "" {
					addr = prefix + "." + addr
				}
				ranges := map[string]policy.SourceSpan{}
				if exprStart, exprEnd, ok := jsonObjectField(source.src, resourceStart, resourceEnd, planExpressionsKey); ok {
					walkPlanValueRanges(source, exprStart, exprEnd, nil, ranges)
				}
				walkPlanProvisionerRanges(source, resourceStart, resourceEnd, ranges)
				out[addr] = ranges
			})
		case planModuleCallsKey:
			forEachJSONObjectField(source.src, valueStart, valueEnd, func(name string, _, callStart, callEnd int) {
				moduleStart, moduleEnd, ok := jsonObjectField(source.src, callStart, callEnd, address.KindModule)
				if !ok {
					return
				}
				childPrefix := "module." + name
				if prefix != "" {
					childPrefix = prefix + "." + childPrefix
				}
				walkPlanConfigurationRanges(source, moduleStart, moduleEnd, childPrefix, out)
			})
		}
	})
}

func walkPlanProvisionerRanges(source *planSourceIndex, start, end int, ranges map[string]policy.SourceSpan) {
	keyStart, listStart, listEnd, ok := jsonObjectFieldLocation(source.src, start, end, planProvisionersKey)
	if !ok {
		return
	}
	ranges[planProvisionerKey] = source.spanAt(keyStart)
	forEachJSONArrayValue(source.src, listStart, listEnd, func(index, blockStart, blockEnd int) {
		typeStart, typeEnd, ok := jsonObjectField(source.src, blockStart, blockEnd, "type")
		if !ok {
			return
		}
		kind, ok := jsonStringValue(source.src, typeStart, typeEnd)
		if !ok || kind == "" {
			return
		}
		path := policy.Path{policy.Key(planProvisionerKey), policy.Index(int64(index)), policy.Key(kind), policy.Index(0)}
		for size := 2; size <= len(path); size++ {
			ranges[policy.PathKey(path[:size])] = source.spanAt(blockStart)
		}
		if exprStart, exprEnd, ok := jsonObjectField(source.src, blockStart, blockEnd, planExpressionsKey); ok {
			walkPlanValueRanges(source, exprStart, exprEnd, path, ranges)
		}
	})
}

func addPlanStaticBlocks(unit *policy.Unit, source *planSourceIndex, allocID func(string) string, outputsOnly bool) {
	start, end, ok := findTopLevelJSONSection(source.src, "configuration")
	if !ok {
		return
	}
	start, end, ok = jsonObjectField(source.src, start, end, "root_module")
	if !ok {
		return
	}
	outputSpans := map[string]policy.SourceSpan{}
	if ps, pe, found := findTopLevelJSONSection(source.src, "planned_values"); found {
		if os, oe, found := jsonObjectField(source.src, ps, pe, "outputs"); found {
			forEachJSONObjectField(source.src, os, oe, func(name string, keyStart, _, _ int) { outputSpans[name] = source.spanAt(keyStart) })
		}
	}
	builder := planStaticBuilder{unit: unit, source: source, allocID: allocID, outputSpans: outputSpans, outputsOnly: outputsOnly}
	builder.module(start, end, "")
}

type planStaticBuilder struct {
	unit        *policy.Unit
	source      *planSourceIndex
	allocID     func(string) string
	outputSpans map[string]policy.SourceSpan
	outputsOnly bool
}

func (b *planStaticBuilder) module(start, end int, prefix string) {
	forEachJSONObjectField(b.source.src, start, end, func(key string, _, fieldStart, fieldEnd int) {
		if key == planModuleCallsKey {
			forEachJSONObjectField(b.source.src, fieldStart, fieldEnd, func(name string, keyStart, callStart, callEnd int) {
				b.declaration(address.KindModule, name, prefix, keyStart, callStart, callEnd)
				if childStart, childEnd, found := jsonObjectField(b.source.src, callStart, callEnd, address.KindModule); found {
					childPrefix := address.Instance(prefix, address.Block{Kind: address.KindModule, Name: name}, "")
					b.module(childStart, childEnd, childPrefix)
				}
			})
			return
		}
		kinds := map[string]string{"outputs": address.KindOutput}
		if !b.outputsOnly {
			kinds["variables"] = address.KindVariable
		}
		kind, supported := kinds[key]
		if !supported {
			return
		}
		forEachJSONObjectField(b.source.src, fieldStart, fieldEnd, func(name string, keyStart, itemStart, itemEnd int) {
			b.declaration(kind, name, prefix, keyStart, itemStart, itemEnd)
		})
	})
}

func (b *planStaticBuilder) declaration(kind, name, prefix string, keyStart, start, end int) {
	descriptor, err := decodeJSONWithNumbers(b.source.src[start:end])
	if err != nil {
		return
	}
	attrs, state := planStaticAttributes(kind, descriptor)
	span := b.source.spanAt(keyStart)
	if kind == address.KindOutput && prefix == "" {
		if planned, found := b.outputSpans[name]; found {
			span = planned
		}
	}
	ranges := map[string]policy.SourceSpan{"": span}
	forEachJSONObjectField(b.source.src, start, end, func(key string, keyOffset, valueStart, valueEnd int) {
		if key == address.KindModule {
			return
		}
		ranges[policy.EscapeStep(policy.Key(key))] = b.source.spanAt(keyOffset)
		if key != planExpressionKey && key != planExpressionsKey {
			walkPlanValueRanges(b.source, valueStart, valueEnd, policy.Path{policy.Key(key)}, ranges)
		}
	})
	addr := address.Instance(prefix, address.Block{Kind: kind, Name: name}, "")
	resource := &policy.Resource{
		ID: b.allocID("s"), Kind: kind, ResourceKey: kind, Name: name, Address: addr, File: b.source.file,
		Attributes: attrs, State: state,
		Platform: map[string]any{terraformPlatform: map[string]any{platformKeySource: sourceKindPlan, platformKeyModule: prefix}},
		Source: &policy.SourceMapping{
			BlockSpan: span, Ranges: ranges, TerraformAddress: addr,
			RootModule: b.unit.ID, StaticInModule: prefix != "",
		},
	}
	b.unit.Resources = append(b.unit.Resources, resource)
	b.unit.ByID[resource.ID] = resource
}

func planStaticAttributes(kind string, descriptor map[string]any) (map[string]any, policy.ValueState) {
	attrs := map[string]any{}
	state := policy.ValueState{Unknown: map[string]bool{}, Null: map[string]bool{}, Written: map[string]bool{}}
	for key, value := range descriptor {
		if key == address.KindModule || key == planExpressionKey || key == planExpressionsKey {
			continue
		}
		attrs[key] = deepCopyPlanValue(value)
		state.Written[policy.EscapeStep(policy.Key(key))] = true
	}
	if expressions, ok := descriptor["expressions"].(map[string]any); ok {
		for key, expression := range expressions {
			planStaticExpression(attrs, &state, key, expression)
		}
	}
	if expression, exists := descriptor[planExpressionKey]; exists {
		planStaticExpression(attrs, &state, "value", expression)
	}
	if kind == address.KindVariable {
		if _, present := descriptor["type"]; !present {
			state.Unknown["type"] = true
		}
	}
	recordPlanNestedNulls(attrs, "", &state)
	return attrs, state
}

func planStaticExpression(attrs map[string]any, state *policy.ValueState, key string, expression any) {
	path := policy.EscapeStep(policy.Key(key))
	state.Written[path] = true
	object, _ := expression.(map[string]any)
	if value, constant := object["constant_value"]; constant {
		attrs[key] = deepCopyPlanValue(value)
	} else {
		state.Unknown[path] = true
	}
}

func planComputedStateObject(state policy.ValueState) map[string]any {
	out := map[string]any{}
	fields := map[string]map[string]bool{
		"unknown":                state.Unknown,
		jsonNullLiteral:          state.Null,
		"incomplete_collections": state.IncompleteCollections,
	}
	for name, flags := range fields {
		if len(flags) == 0 {
			continue
		}
		values := map[string]any{}
		for key, enabled := range flags {
			values[key] = enabled
		}
		out[name] = values
	}
	return out
}

// Unknown leaves can sit under configured parent blocks that have no other
// computed fields. Preserve those known container shapes for computed views.
func seedPlanComputedContainers(unknown any, original, computed map[string]any) {
	fields, _ := unknown.(map[string]any)
	for key, value := range fields {
		switch child := value.(type) {
		case map[string]any:
			parent, ok := original[key].(map[string]any)
			if !ok {
				continue
			}
			target, _ := computed[key].(map[string]any)
			if target == nil {
				target = map[string]any{}
				computed[key] = target
			}
			seedPlanComputedContainers(child, parent, target)
		case []any:
			parents, ok := original[key].([]any)
			if !ok {
				continue
			}
			targets, _ := computed[key].([]any)
			if len(targets) < len(parents) {
				targets = make([]any, len(parents))
				computed[key] = targets
			}
			seedPlanComputedArray(child, parents, targets)
		}
	}
}

func seedPlanComputedArray(unknown, original, computed []any) {
	for index, value := range unknown {
		if index >= len(original) || index >= len(computed) {
			break
		}
		fields, isObject := value.(map[string]any)
		parent, hasParent := original[index].(map[string]any)
		if !isObject || !hasParent {
			continue
		}
		target, _ := computed[index].(map[string]any)
		if target == nil {
			target = map[string]any{}
			computed[index] = target
		}
		seedPlanComputedContainers(fields, parent, target)
	}
}
