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

	ResourceChanges any `json:"resource_changes,omitempty"`
	Configuration   any `json:"configuration,omitempty"`
}

// TFPlanResource is keyed by resource name, plus a reserved "_dd_lines" key
// holding each resource's header line (see readModule).
type TFPlanResource map[string]any

type TFPlanNamedResource map[string]any

const ddMetaKey = "_dd_meta"

type resourceChangeCorrelation struct {
	afterUnknownByAddress map[string]any

	// configByAddress holds each config resource's raw expressions by
	// canonical address; moduleCalls and moduleOutputs are keyed by the child
	// module's config path.
	configByAddress map[string]gjson.Result
	moduleCalls     map[string]gjson.Result
	moduleOutputs   map[string]gjson.Result
	// instances and moduleInstances list the planned instance addresses by
	// canonical config address.
	instances       map[string][]string
	moduleInstances map[string][]string
	// resolved memoises resolveReferences by references list and module instance.
	resolved map[string][]string
}

func buildResourceChangeCorrelation(rawPlan []byte) resourceChangeCorrelation {
	c := resourceChangeCorrelation{
		afterUnknownByAddress: make(map[string]any),
		configByAddress:       make(map[string]gjson.Result),
		moduleCalls:           make(map[string]gjson.Result),
		moduleOutputs:         make(map[string]gjson.Result),
		resolved:              make(map[string][]string),
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
	module.Get("resources").ForEach(func(_, resource gjson.Result) bool {
		relativeAddress := resource.Get("address").String()
		if relativeAddress == "" {
			return true
		}
		absoluteAddress := relativeAddress
		if modulePath != "" {
			absoluteAddress = modulePath + "." + relativeAddress
		}
		if expressions := resource.Get("expressions"); expressions.Exists() {
			c.configByAddress[absoluteAddress] = expressions
		}
		return true
	})

	module.Get("module_calls").ForEach(func(callName, call gjson.Result) bool {
		childModule := call.Get("module")
		if !childModule.Exists() {
			return true
		}
		childPath := "module." + callName.String()
		if modulePath != "" {
			childPath = modulePath + "." + childPath
		}
		c.moduleCalls[childPath] = call.Get("expressions")
		c.moduleOutputs[childPath] = childModule.Get("outputs")
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
func withDDMeta(values map[string]any, addr string, unknown map[string]any, c *resourceChangeCorrelation) map[string]any {
	if values == nil {
		values = map[string]any{}
	}
	meta := map[string]any{"address": addr}
	if refs := c.referencesFor(addr); len(refs) > 0 {
		meta["references"] = refs
	}
	if len(unknown) > 0 {
		meta["unknown"] = unknown
	}
	values[ddMetaKey] = meta
	return values
}

func (c *resourceChangeCorrelation) referencesFor(addr string) map[string]interface{} {
	expressions, ok := c.configByAddress[canonicalConfigAddress(addr)]
	if !ok {
		return nil
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
// line, keyed by resource address. Addresses are unique across the whole
// plan, so planned_values and prior_state (resolved data sources) share one map.
func extractResourceHeaderLines(rawPlan []byte) map[string]int {
	lines := make(map[string]int)
	plannedRootModule := gjson.GetBytes(rawPlan, "planned_values.root_module")
	walkModule(&plannedRootModule, lines)
	priorStateRootModule := gjson.GetBytes(rawPlan, "prior_state.values.root_module")
	walkModule(&priorStateRootModule, lines)
	return lines
}

func walkModule(module *gjson.Result, lines map[string]int) {
	resources := module.Get("resources").Array()
	arr := module.Get("_dd_lines._dd_resources._dd_arr").Array()
	for i, resource := range resources {
		if i >= len(arr) {
			break
		}
		address := resource.Get("address").String()
		if line := arr[i].Get("_dd_values._dd_line").Int(); line > 0 {
			lines[address] = int(line)
		}
	}
	module.Get("child_modules").ForEach(func(_, child gjson.Result) bool {
		walkModule(&child, lines)
		return true
	})
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

	kp.readModule(plan.PlannedValues.RootModule, "", resourceLines, correlation)

	if plan.PriorState != nil && plan.PriorState.Values != nil {
		kp.readPriorStateData(plan.PriorState.Values.RootModule, "", resourceLines, deletedAddresses(plan.ResourceChanges), correlation)
	}

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

// readModule recursively accumulates managed resources from every module into
// the flat resource.<type>.<name> map and planned data sources into the data
// map. moduleAddress is "" for the root module.
func (kp *TFPlan) readModule(
	module *hcl_plan.StateModule,
	moduleAddress string,
	resourceLines map[string]int,
	correlation *resourceChangeCorrelation,
) {
	for _, resource := range module.Resources {
		// Module-prefixed so same-type-same-name resources in different
		// modules don't collide.
		resourceKey := resource.Name
		if moduleAddress != "" {
			resourceKey = moduleAddress + "." + resource.Name
		}

		if resource.Index != nil {
			resourceKey = formatResourceKeyWithIndex(resourceKey, resource.Index)
		}

		// Planned data sources are kept in the data namespace, separate from
		// managed resources of the same type and name: a planned read and a
		// managed resource sharing type and key are two different blocks.
		typeRes := kp.managedSection(resource.Type)
		if resource.Mode == hcl_plan.DataResourceMode {
			typeRes = kp.dataSection(resource.Type)
		}

		unknown := correlation.planValues(resource.Address, resource.AttributeValues)
		typeRes[resourceKey] = withDDMeta(resource.AttributeValues, resource.Address, unknown, correlation)

		if line, ok := resourceLines[resource.Address]; ok {
			ddLines, isMap := typeRes["_dd_lines"].(map[string]*model.LineObject)
			if !isMap {
				ddLines = make(map[string]*model.LineObject)
				typeRes["_dd_lines"] = ddLines
			}
			ddLines["_dd_"+resourceKey] = &model.LineObject{Line: line}
		}
	}

	for _, childModule := range module.ChildModules {
		kp.readModule(childModule, childModule.Address, resourceLines, correlation)
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

// readPriorStateData recursively merges resolved data sources into data.<type>.<name>.
// moduleAddress is "" for the root module. prior_state predates the plan's
// diff, so a data source being deleted by this plan is skipped rather than
// republished as if it were still part of the proposed infrastructure.
func (kp *TFPlan) readPriorStateData(
	module *hcl_plan.StateModule,
	moduleAddress string,
	resourceLines map[string]int,
	deleted map[string]bool,
	correlation *resourceChangeCorrelation,
) {
	if module == nil {
		return
	}

	for _, resource := range module.Resources {
		if resource.Mode != hcl_plan.DataResourceMode {
			continue
		}
		if deleted[resource.Address] {
			continue
		}

		if kp.Data == nil {
			kp.Data = make(map[string]map[string]any)
		}
		if kp.Data[resource.Type] == nil {
			kp.Data[resource.Type] = make(map[string]any)
		}

		// Module-prefixed and index-suffixed so same-type-same-name data
		// sources in different modules or for_each/count instances don't
		// collide, mirroring readModule's resourceKey construction.
		dataKey := resource.Name
		if moduleAddress != "" {
			dataKey = moduleAddress + "." + resource.Name
		}
		if resource.Index != nil {
			dataKey = formatResourceKeyWithIndex(dataKey, resource.Index)
		}

		typeData := kp.Data[resource.Type]
		// A data source the plan already resolved (planned_values) keeps its
		// values: prior state is the pre-plan snapshot, so it fills only the
		// entries the plan does not carry.
		if _, exists := typeData[dataKey]; !exists {
			unknown := correlation.planValues(resource.Address, resource.AttributeValues)
			typeData[dataKey] = withDDMeta(resource.AttributeValues, resource.Address, unknown, correlation)
		}

		if line, ok := resourceLines[resource.Address]; ok {
			ddLines, isMap := typeData["_dd_lines"].(map[string]*model.LineObject)
			if !isMap {
				ddLines = make(map[string]*model.LineObject)
				typeData["_dd_lines"] = ddLines
			}
			ddLines["_dd_"+dataKey] = &model.LineObject{Line: line}
		}
	}

	for _, childModule := range module.ChildModules {
		kp.readPriorStateData(childModule, childModule.Address, resourceLines, deleted, correlation)
	}
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
