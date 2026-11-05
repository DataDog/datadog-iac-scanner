/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"encoding/json"
	"fmt"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcl_plan "github.com/hashicorp/terraform-json"
	"github.com/tidwall/gjson"
)

// TFPlan is an auxiliary structure for parsing tfplans as a scanner Document
type TFPlan struct {
	Resource map[string]TFPlanResource `json:"resource"`

	// Data mirrors the HCL parser's data.<type>.<name> shape for data sources.
	Data map[string]map[string]any `json:"data,omitempty"`

	// Output, Module, Variable and Provider mirror the HCL parser's sections
	// of the root module, read from the plan configuration so a rule sees the
	// same blocks on both scans. Each carries a "_dd_lines" key, as a resource
	// type does, holding each block's header line.
	Output   map[string]any `json:"output,omitempty"`
	Module   map[string]any `json:"module,omitempty"`
	Variable map[string]any `json:"variable,omitempty"`
	Provider map[string]any `json:"provider,omitempty"`

	ResourceChanges any `json:"resource_changes,omitempty"`
	Configuration   any `json:"configuration,omitempty"`
}

// TFPlanResource is keyed by resource name, plus a reserved "_dd_lines" key
// holding each resource's header line (see readModule).
type TFPlanResource map[string]any

type TFPlanNamedResource map[string]any

const (
	ddMetaKey        = "_dd_meta"
	constantValueKey = "constant_value"
	referencesKey    = "references"
)

type resourceChangeCorrelation struct {
	afterUnknownByAddress map[string]any

	// configByAddress holds each config resource's raw expressions by
	// canonical address; moduleCalls and moduleOutputs are keyed by the child
	// module's config path.
	configByAddress map[string]gjson.Result
	moduleCalls     map[string]gjson.Result
	moduleOutputs   map[string]gjson.Result
	// moduleVariables and nestedCalls are child modules' variables and the
	// module calls made from inside a module, keyed by the call path.
	moduleVariables map[string]gjson.Result
	nestedCalls     map[string]gjson.Result
	// declared holds the canonical address of every config resource, with
	// or without expressions.
	declared map[string]bool
	// rootOutputs, rootModuleCalls and rootVariables are the root module's
	// configuration blocks. Child modules keep their outputs and calls on
	// moduleOutputs and moduleCalls.
	rootOutputs     gjson.Result
	rootModuleCalls gjson.Result
	rootVariables   gjson.Result
	// providerConfigs is the plan's provider_config, keyed by provider
	// configuration key; providerByAddress the provider configuration
	// address each config resource uses.
	providerConfigs   gjson.Result
	providerByAddress map[string]string
	// forEachByAddress and moduleForEach hold the for_each expressions of
	// config resources and module calls, provisionersByAddress the
	// provisioners of config resources.
	forEachByAddress      map[string]gjson.Result
	moduleForEach         map[string]gjson.Result
	provisionersByAddress map[string]gjson.Result
	// repeatedModules holds the config path of every module call with count
	// or for_each.
	repeatedModules map[string]bool
	// instances and moduleInstances list the planned instance addresses by
	// canonical config address.
	instances       map[string][]string
	moduleInstances map[string][]string
	// resolved memoises resolveReferences by references list and module instance.
	resolved map[string]planTrace
}

func buildResourceChangeCorrelation(rawPlan []byte) resourceChangeCorrelation {
	c := resourceChangeCorrelation{
		afterUnknownByAddress: make(map[string]any),
		configByAddress:       make(map[string]gjson.Result),
		declared:              make(map[string]bool),
		moduleCalls:           make(map[string]gjson.Result),
		moduleOutputs:         make(map[string]gjson.Result),
		moduleVariables:       make(map[string]gjson.Result),
		nestedCalls:           make(map[string]gjson.Result),
		forEachByAddress:      make(map[string]gjson.Result),
		moduleForEach:         make(map[string]gjson.Result),
		provisionersByAddress: make(map[string]gjson.Result),
		repeatedModules:       make(map[string]bool),
		resolved:              make(map[string]planTrace),
		providerByAddress:     make(map[string]string),
		providerConfigs:       gjson.GetBytes(rawPlan, "configuration.provider_config"),
	}
	planned := make(map[string]bool)
	deleted := make(map[string]bool)

	gjson.GetBytes(rawPlan, "resource_changes").ForEach(func(_, change gjson.Result) bool {
		addr := change.Get("address").String()
		if addr == "" {
			return true
		}
		if actions := change.Get("change.actions").Array(); len(actions) == 1 && actions[0].String() == "delete" {
			deleted[addr] = true
		} else {
			planned[addr] = true
		}
		if afterUnknown := change.Get("change.after_unknown"); afterUnknown.Exists() {
			c.afterUnknownByAddress[addr] = afterUnknown.Value()
		}
		return true
	})
	plannedRoot := gjson.GetBytes(rawPlan, "planned_values.root_module")
	collectStateAddresses(&plannedRoot, false, deleted, planned)
	priorRoot := gjson.GetBytes(rawPlan, "prior_state.values.root_module")
	collectStateAddresses(&priorRoot, true, deleted, planned)
	c.indexInstances(planned)

	rootConfigModule := gjson.GetBytes(rawPlan, "configuration.root_module")
	walkConfigModule(&rootConfigModule, "", &c)

	return c
}

// walkConfigModule indexes each config resource's expressions by absolute address.
func walkConfigModule(module *gjson.Result, modulePath string, c *resourceChangeCorrelation) {
	if modulePath == "" {
		c.rootOutputs = module.Get("outputs")
		c.rootModuleCalls = module.Get("module_calls")
		c.rootVariables = module.Get("variables")
	}
	module.Get("resources").ForEach(func(_, resource gjson.Result) bool {
		relativeAddress := resource.Get("address").String()
		if relativeAddress == "" {
			return true
		}
		absoluteAddress := relativeAddress
		if modulePath != "" {
			absoluteAddress = modulePath + "." + relativeAddress
		}
		c.declared[absoluteAddress] = true
		if key := resource.Get("provider_config_key"); key.Type == gjson.String {
			c.providerByAddress[absoluteAddress] = c.providerAddress(key.String(), modulePath)
		}
		if expressions := resource.Get("expressions"); expressions.Exists() {
			c.configByAddress[absoluteAddress] = expressions
		}
		if forEach := resource.Get("for_each_expression"); forEach.Exists() {
			c.forEachByAddress[absoluteAddress] = forEach
		}
		if provisioners := resource.Get("provisioners"); provisioners.Exists() {
			c.provisionersByAddress[absoluteAddress] = provisioners
		}
		return true
	})

	module.Get("module_calls").ForEach(func(callName, call gjson.Result) bool {
		childModule := call.Get("module")
		if !childModule.Exists() {
			return true
		}
		// A constant count/for_each of zero creates no instance: leave no
		// child sections (outputs, variables, nested calls) under it.
		if zeroInstances(&call) {
			return true
		}
		childPath := "module." + callName.String()
		if modulePath != "" {
			childPath = modulePath + "." + childPath
		}
		c.moduleCalls[childPath] = call.Get("expressions")
		c.moduleOutputs[childPath] = childModule.Get("outputs")
		if vars := childModule.Get("variables"); vars.IsObject() {
			c.moduleVariables[childPath] = vars
		}
		// A call made from inside a module. Root calls stay in rootModuleCalls.
		if modulePath != "" {
			c.nestedCalls[childPath] = call
		}
		if forEach := call.Get("for_each_expression"); forEach.Exists() {
			c.moduleForEach[childPath] = forEach
		}
		c.repeatedModules[childPath] = call.Get("count_expression").Exists() || call.Get("for_each_expression").Exists()
		walkConfigModule(&childModule, childPath, c)
		return true
	})
}

// canonicalConfigAddress strips "[...]" instance-key suffixes, e.g.
// "module.staging[\"prod\"].aws_instance.web[2]" -> "module.staging.aws_instance.web".
func canonicalConfigAddress(address string) string {
	traversal, diags := hclsyntax.ParseTraversalAbs([]byte(address), "", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return address
	}

	canonical := ""
	for _, step := range traversal {
		switch t := step.(type) {
		case hcl.TraverseRoot:
			canonical = t.Name
		case hcl.TraverseAttr:
			canonical += "." + t.Name
		case hcl.TraverseIndex:
		}
	}
	return canonical
}

// withDDMeta returns values with _dd_meta attached, creating the object when
// the resource has no planned values.
func withDDMeta(values map[string]any, addr string, unknown, configured map[string]any, c *resourceChangeCorrelation) map[string]any {
	if values == nil {
		values = map[string]any{}
	}
	meta := map[string]any{"address": addr}
	if provider, ok := c.providerByAddress[canonicalConfigAddress(addr)]; ok {
		meta["provider"] = provider
	}
	refs, ambiguous := c.referencesFor(addr)
	// An empty references object is kept: the configuration was read and
	// nothing in it traced, which is different from no configuration at all.
	if refs != nil {
		meta["references"] = refs
	}
	for _, entry := range [...]struct {
		key   string
		value map[string]any
	}{
		{"unknown", unknown},
		{"ambiguous", ambiguous},
		{"configured", configured},
	} {
		if len(entry.value) > 0 {
			meta[entry.key] = entry.value
		}
	}
	values[ddMetaKey] = meta
	return values
}

func (c *resourceChangeCorrelation) referencesFor(addr string) (refs, ambiguous map[string]interface{}) {
	expressions, ok := c.configByAddress[canonicalConfigAddress(addr)]
	if !ok {
		return nil, nil
	}
	return planReferences(&expressions, addr, c)
}

func parseTFPlan(doc model.Document) (model.Document, error) {
	var plan *hcl_plan.Plan
	b, err := json.Marshal(doc)
	if err != nil {
		return model.Document{}, err
	}
	err = json.Unmarshal(b, &plan)
	if err != nil {
		return model.Document{}, err
	}

	// hcl_plan.Plan is typed and drops the injected _dd_lines keys, so read
	// them back from the raw bytes before that information is lost.
	resourceLines := extractResourceHeaderLines(b)
	correlation := buildResourceChangeCorrelation(b)

	parsedPlan := readPlan(plan, doc["resource_changes"], doc["configuration"], resourceLines, &correlation)
	return parsedPlan, nil
}

// extractResourceHeaderLines returns each resource's "values" attribute
// line, keyed by resource address. A data source or managed resource with
// state is in both planned_values and prior_state; its values come from
// planned_values, and so does its line.
func extractResourceHeaderLines(rawPlan []byte) map[string]int {
	lines := make(map[string]int)
	plannedRootModule := gjson.GetBytes(rawPlan, "planned_values.root_module")
	walkModule(&plannedRootModule, lines)
	priorStateRootModule := gjson.GetBytes(rawPlan, "prior_state.values.root_module")
	walkModule(&priorStateRootModule, lines)
	return lines
}

func walkModule(module *gjson.Result, lines map[string]int) {
	table := module.Get(linesKey)
	walkModuleLines(module, &table, lines)
}

// walkModuleLines reads resource header lines from lineTable, keeping a line
// already recorded. A nested module is an array element, so its line table
// lives on the parent (_dd_child_modules._dd_arr), not on the module object.
func walkModuleLines(module, lineTable *gjson.Result, lines map[string]int) {
	resources := module.Get("resources").Array()
	arr := lineTable.Get("_dd_resources._dd_arr").Array()
	for i, resource := range resources {
		if i >= len(arr) {
			break
		}
		address := resource.Get("address").String()
		if _, seen := lines[address]; seen {
			continue
		}
		if line := arr[i].Get("_dd_values._dd_line").Int(); line > 0 {
			lines[address] = int(line)
		}
	}
	children := module.Get("child_modules").Array()
	childArr := lineTable.Get("_dd_child_modules._dd_arr").Array()
	for i, child := range children {
		var table gjson.Result
		if i < len(childArr) {
			table = childArr[i]
		}
		walkModuleLines(&child, &table, lines)
	}
}

func readPlan(
	plan *hcl_plan.Plan,
	resourceChanges, configuration any,
	resourceLines map[string]int,
	correlation *resourceChangeCorrelation,
) model.Document {
	kp := TFPlan{
		Resource:        make(map[string]TFPlanResource),
		ResourceChanges: resourceChanges,
		Configuration:   configuration,
	}

	reader := stateReader{resourceLines: resourceLines, correlation: correlation}
	kp.readModule(plan.PlannedValues.RootModule, &reader)

	if plan.PriorState != nil && plan.PriorState.Values != nil {
		reader.priorState = true
		reader.deleted = deletedAddresses(plan.ResourceChanges)
		kp.readModule(plan.PriorState.Values.RootModule, &reader)
	}
	kp.Output = planOutputBlocks(correlation)
	kp.Module = planModuleCallBlocks(correlation)
	kp.Variable = planVariableBlocks(correlation)
	kp.Provider = planProviderBlocks(&correlation.providerConfigs)

	doc := model.Document{}

	tmpDocBytes, err := json.Marshal(kp)
	if err != nil {
		return model.Document{}
	}
	err = json.Unmarshal(tmpDocBytes, &doc)
	if err != nil {
		return model.Document{}
	}

	return doc
}

// planOutputBlocks is output.<name>. A child module's output is keyed by its
// call path, module.a.module.b.<name>, the same way a child resource is.
// Each block's value expression is resolved into _dd_meta.references the way
// a resource attribute is.
func planOutputBlocks(c *resourceChangeCorrelation) map[string]any {
	out := map[string]any{}
	addPlanOutputs(out, "", &c.rootOutputs, c)
	for path, outputs := range c.moduleOutputs {
		addPlanOutputs(out, path, &outputs, c)
	}
	return withSectionLines(out, &c.rootOutputs)
}

func addPlanOutputs(out map[string]any, prefix string, outputs *gjson.Result, c *resourceChangeCorrelation) {
	if !outputs.IsObject() {
		return
	}
	outputs.ForEach(func(name, output gjson.Result) bool {
		if name.String() == linesKey {
			return true
		}
		key := name.String()
		if prefix != "" {
			key = prefix + "." + key
		}
		block := map[string]any{}
		if desc := output.Get("description"); desc.Type == gjson.String {
			block["description"] = desc.String()
		}
		if sensitive := output.Get("sensitive"); sensitive.IsBool() {
			block["sensitive"] = sensitive.Bool()
		}
		lines := linesOf(&output)
		if expr := output.Get("expression"); expr.Exists() {
			body := gjson.Parse(`{"value":` + expr.Raw + `}`)
			addr := "output." + name.String()
			if prefix != "" {
				addr = prefix + ".output." + name.String()
			}
			meta := planConfigMeta(addr, prefix, &body, c)
			if constant := expr.Get(constantValueKey); !constant.Exists() {
				block["value"] = partial.UnknownPlaceholder
				markUnknown(meta, "value")
			} else if constant.Type != gjson.Null {
				block["value"] = constant.Value()
			}
			block[ddMetaKey] = meta
			renameLine(lines, "expression", "value")
		}
		setLines(block, lines)
		out[key] = block
		return true
	})
}

// planModuleCallBlocks is module.<name>. A call made from inside a module is
// keyed by its call path, module.a.module.b. Arguments come from the call's
// expressions.
func planModuleCallBlocks(c *resourceChangeCorrelation) map[string]any {
	out := map[string]any{}
	if c.rootModuleCalls.IsObject() {
		c.rootModuleCalls.ForEach(func(name, call gjson.Result) bool {
			addPlanModuleCall(out, name.String(), "module."+name.String(), &call, c)
			return true
		})
	}
	for path, call := range c.nestedCalls {
		addPlanModuleCall(out, path, path, &call, c)
	}
	return withSectionLines(out, &c.rootModuleCalls)
}

func addPlanModuleCall(out map[string]any, key, address string, call *gjson.Result, c *resourceChangeCorrelation) {
	if key == linesKey || zeroInstances(call) {
		return
	}
	block := map[string]any{}
	lines := map[string]any{}
	exprs := call.Get("expressions")
	if exprs.IsObject() {
		meta := planConfigMeta(address, parentModulePath(address), &exprs, c)
		exprs.ForEach(func(attr, expr gjson.Result) bool {
			if attr.String() == linesKey {
				return true
			}
			if constant := expr.Get(constantValueKey); constant.Exists() && constant.Type != gjson.Null {
				block[attr.String()] = constant.Value()
			} else if !constant.Exists() && isExpression(&expr) {
				block[attr.String()] = partial.UnknownPlaceholder
				markUnknown(meta, attr.String())
			}
			return true
		})
		block[ddMetaKey] = meta
		lines = linesOf(&exprs)
	}
	callLines := linesOf(call)
	if source := call.Get("source"); source.Type == gjson.String && block["source"] == nil {
		block["source"] = source.String()
		copyLine(lines, callLines, "source", "source")
	}
	if version := call.Get("version_constraint"); version.Type == gjson.String && block["version"] == nil {
		block["version"] = version.String()
		copyLine(lines, callLines, "version_constraint", "version")
	}
	setLines(block, lines)
	out[key] = block
}

// planVariableBlocks is variable.<name>. A child module's variable is keyed
// by its call path. A plan does not carry a variable's type or validation, so
// type is unknown rather than absent: a rule must not report it missing.
func planVariableBlocks(c *resourceChangeCorrelation) map[string]any {
	out := map[string]any{}
	addPlanVariables(out, "", &c.rootVariables)
	for path, variables := range c.moduleVariables {
		addPlanVariables(out, path, &variables)
	}
	return withSectionLines(out, &c.rootVariables)
}

func addPlanVariables(out map[string]any, prefix string, variables *gjson.Result) {
	if !variables.IsObject() {
		return
	}
	variables.ForEach(func(name, variable gjson.Result) bool {
		if name.String() == linesKey {
			return true
		}
		key := name.String()
		if prefix != "" {
			key = prefix + "." + key
		}
		block := map[string]any{
			ddMetaKey: map[string]any{"unknown": map[string]any{"type": true}},
		}
		for _, k := range [...]string{"default", "description", "sensitive", "nullable"} {
			if v := variable.Get(k); v.Exists() && v.Type != gjson.Null {
				block[k] = v.Value()
			}
		}
		setLines(block, linesOf(&variable))
		out[key] = block
		return true
	})
}

// linesOf is a copy of the line table JSON line info attached to obj, empty
// when it has none.
func linesOf(obj *gjson.Result) map[string]any {
	lines, _ := obj.Get(linesKey).Value().(map[string]any)
	if lines == nil {
		lines = map[string]any{}
	}
	return lines
}

func setLines(block, lines map[string]any) {
	if len(lines) > 0 {
		block[linesKey] = lines
	}
}

// withSectionLines is section with the header lines of its blocks, read from
// config, the configuration object it was built from; nil when empty.
func withSectionLines(section map[string]any, config *gjson.Result) map[string]any {
	if len(section) == 0 {
		return nil
	}
	setLines(section, linesOf(config))
	return section
}

// renameLine moves the line of key from to key to.
func renameLine(lines map[string]any, from, to string) {
	if line, ok := lines["_dd_"+from]; ok {
		lines["_dd_"+to] = line
	}
}

// copyLine sets the line of key to in dst to the line of key from in src.
func copyLine(dst, src map[string]any, from, to string) {
	if line, ok := src["_dd_"+from]; ok {
		dst["_dd_"+to] = line
	}
}

// zeroInstances reports whether a module call's count or for_each is a
// constant that expands to no instance. A computed one is kept: the call may
// still have instances.
func zeroInstances(call *gjson.Result) bool {
	if count := call.Get("count_expression.constant_value"); count.Type == gjson.Number {
		return count.Int() == 0
	}
	switch forEach := call.Get("for_each_expression.constant_value"); {
	case forEach.IsArray():
		return len(forEach.Array()) == 0
	case forEach.IsObject():
		return len(forEach.Map()) == 0
	}
	return false
}

// markUnknown records in _dd_meta.unknown an attribute whose value the plan
// does not know.
func markUnknown(meta map[string]any, attr string) {
	unknown, _ := meta["unknown"].(map[string]any)
	if unknown == nil {
		unknown = map[string]any{}
		meta["unknown"] = unknown
	}
	unknown[attr] = true
}

// planConfigMeta resolves one configuration body of the block at address into
// a _dd_meta. scope is the config path of the module Terraform evaluates the
// body in: the declaring module for an output, the calling module for a
// module call's arguments.
func planConfigMeta(address, scope string, body *gjson.Result, c *resourceChangeCorrelation) map[string]any {
	meta := map[string]any{"address": address}
	reader := planReader{forEach: c.moduleForEach[canonicalConfigAddress(address)]}
	if inst := c.moduleInstances[canonicalConfigAddress(scope)]; len(inst) == 1 {
		reader.key = instanceKeyOf(inst[0])
		scope = inst[0]
	}
	refs, ambiguous := c.planReferencesIn(body, scope, &reader)
	// An empty references object is kept: the configuration was read and
	// nothing in it traced, which is different from no configuration at all.
	if refs != nil {
		meta["references"] = refs
	}
	if len(ambiguous) > 0 {
		meta["ambiguous"] = ambiguous
	}
	return meta
}

// managedSection returns the resource.<type> map a managed resource is
// recorded under, creating it when needed.
func (kp *TFPlan) managedSection(typ string) TFPlanResource {
	if kp.Resource[typ] == nil {
		kp.Resource[typ] = make(TFPlanResource)
	}
	return kp.Resource[typ]
}

// dataSection returns the data.<type> map a data source is recorded under,
// creating it when needed.
func (kp *TFPlan) dataSection(typ string) map[string]any {
	if kp.Data == nil {
		kp.Data = make(map[string]map[string]any)
	}
	if kp.Data[typ] == nil {
		kp.Data[typ] = make(map[string]any)
	}
	return kp.Data[typ]
}

// stateReader is how readModule reads one state tree: planned_values, or
// prior_state, from which only data sources the plan neither reads again nor
// deletes are taken. prior_state predates the plan's diff, so a data source
// this plan deletes is not part of the proposed infrastructure.
type stateReader struct {
	priorState    bool
	deleted       map[string]bool
	resourceLines map[string]int
	correlation   *resourceChangeCorrelation
}

// readModule recursively accumulates managed resources from every module into
// the flat resource.<type>.<name> map and data sources into the data map.
func (kp *TFPlan) readModule(module *hcl_plan.StateModule, r *stateReader) {
	if module == nil {
		return
	}
	for _, resource := range module.Resources {
		data := resource.Mode == hcl_plan.DataResourceMode
		if r.priorState && (!data || r.deleted[resource.Address]) {
			continue
		}
		// Module-prefixed so same-type-same-name resources in different
		// modules don't collide.
		resourceKey := resource.Name
		if module.Address != "" {
			resourceKey = module.Address + "." + resource.Name
		}
		if resource.Index != nil {
			resourceKey = formatResourceKeyWithIndex(resourceKey, resource.Index)
		}

		// Data sources are kept in the data namespace, separate from managed
		// resources of the same type and name: a read and a managed resource
		// sharing type and key are two different blocks.
		var section map[string]any
		if data {
			section = kp.dataSection(resource.Type)
		} else {
			section = kp.managedSection(resource.Type)
		}
		if _, planned := section[resourceKey]; planned {
			continue
		}

		unknown, configured := r.correlation.planValues(resource.Address, resource.AttributeValues)
		section[resourceKey] = withDDMeta(resource.AttributeValues, resource.Address, unknown, configured, r.correlation)

		if line, ok := r.resourceLines[resource.Address]; ok {
			ddLines, isMap := section[linesKey].(map[string]*model.LineObject)
			if !isMap {
				ddLines = make(map[string]*model.LineObject)
				section[linesKey] = ddLines
			}
			ddLines["_dd_"+resourceKey] = &model.LineObject{Line: line}
		}
	}

	for _, childModule := range module.ChildModules {
		kp.readModule(childModule, r)
	}
}

// deletedAddresses returns the set of addresses whose only planned action is
// deletion, e.g. a data source removed from config or dropped by count/for_each.
func deletedAddresses(resourceChanges []*hcl_plan.ResourceChange) map[string]bool {
	deleted := make(map[string]bool)
	for _, rc := range resourceChanges {
		if rc.Change != nil && rc.Change.Actions.Delete() {
			deleted[rc.Address] = true
		}
	}
	return deleted
}

// formatResourceKeyWithIndex appends a count/for_each index, e.g. "web[0]" or "bucket[\"prod\"]".
func formatResourceKeyWithIndex(baseName string, index any) string {
	switch idx := index.(type) {
	case float64:
		return fmt.Sprintf("%s[%d]", baseName, int(idx))
	case int:
		return fmt.Sprintf("%s[%d]", baseName, idx)
	case string:
		return fmt.Sprintf("%s[%q]", baseName, idx)
	default:
		return baseName
	}
}
