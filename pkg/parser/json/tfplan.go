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
	hcl_plan "github.com/hashicorp/terraform-json"
	"github.com/tidwall/gjson"
)

// TFPlan is an auxiliary structure for parsing tfplans as a scanner Document
type TFPlan struct {
	Resource map[string]TFPlanResource `json:"resource"`
	Data     map[string]TFPlanResource `json:"data,omitempty"`
}

// TFPlanResource is an auxiliary structure for parsing tfplans as a scanner Document.
// Values are either a TFPlanNamedResource (keyed by resource name) or, under the
// reserved "_dd_lines" key, a map[string]*model.LineObject holding each sibling
// resource's header line (see readModule).
type TFPlanResource map[string]any

// TFPlanNamedResource is an auxiliary structure for parsing tfplans as a scanner Document
type TFPlanNamedResource map[string]any

// parseTFPlan unmarshals Document as a plan so it can be rebuilt with only
// the required information
func parseTFPlan(doc model.Document) (model.Document, error) {
	var plan *hcl_plan.Plan
	b, err := json.Marshal(doc)
	if err != nil {
		return model.Document{}, err
	}
	// Unmarshal our Document as a plan so we are able retrieve planned_values
	// in a easier way
	err = json.Unmarshal(b, &plan)
	if err != nil {
		// Consider as regular JSON and not tfplan
		return model.Document{}, err
	}

	// hcl_plan.Plan is a typed struct so unmarshaling drops the injected
	// _dd_lines keys along with each resource's "values" attribute line. Read
	// those lines back out of the raw bytes (via gjson, keyed by resource
	// address) before that information is lost.
	resourceLines := extractResourceHeaderLines(b)
	expressionLines := extractExpressionLines(b)
	valueAttributeLines := extractValueAttributeLines(b)

	parsedPlan := readPlan(plan, resourceLines, expressionLines, valueAttributeLines)
	return parsedPlan, nil
}

// extractResourceHeaderLines walks the raw plan JSON and returns, for every
// planned resource, the _dd_line of its "values" attribute (i.e. where the
// resource's own attribute block starts), keyed by resource address. Array
// elements don't carry their own _dd_lines sibling (see setSeqLines in
// json_line.go) — that information lives positionally in the parent module's
// "_dd_lines._dd_resources._dd_arr" instead.
func extractResourceHeaderLines(rawPlan []byte) map[string]int {
	lines := make(map[string]int)
	root_module := gjson.GetBytes(rawPlan, "planned_values.root_module")
	rootLines := root_module.Get("_dd_lines")
	walkModule(&root_module, &rootLines, lines)
	return lines
}

func walkModule(module, moduleLines *gjson.Result, lines map[string]int) {
	resources := module.Get("resources").Array()
	arr := moduleLines.Get("_dd_resources._dd_arr").Array()
	for i, resource := range resources {
		if i >= len(arr) {
			break
		}
		address := resource.Get("address").String()
		if line := arr[i].Get("_dd_values._dd_line").Int(); line > 0 {
			lines[address] = int(line)
		}
	}
	children := module.Get("child_modules").Array()
	childLines := moduleLines.Get("_dd_child_modules._dd_arr").Array()
	for i, child := range children {
		if i >= len(childLines) {
			break
		}
		walkModule(&child, &childLines[i], lines)
	}
}

func extractExpressionLines(rawPlan []byte) map[string]map[string]*model.LineObject {
	lines := make(map[string]map[string]*model.LineObject)
	rootModule := gjson.GetBytes(rawPlan, "configuration.root_module")
	walkConfigurationModule(&rootModule, lines)
	return lines
}

func extractValueAttributeLines(rawPlan []byte) map[string]map[string]*model.LineObject {
	lines := make(map[string]map[string]*model.LineObject)
	rootModule := gjson.GetBytes(rawPlan, "planned_values.root_module")
	walkPlannedValuesModule(&rootModule, lines)
	return lines
}

func walkPlannedValuesModule(module *gjson.Result, lines map[string]map[string]*model.LineObject) {
	for _, resource := range module.Get("resources").Array() {
		address := resource.Get("address").String()
		if address == "" {
			continue
		}
		attrs := map[string]*model.LineObject{}
		resource.Get("values._dd_lines").ForEach(func(key, val gjson.Result) bool {
			k := key.String()
			if k == "_dd__default" {
				return true
			}
			var attr model.LineObject
			if err := json.Unmarshal([]byte(val.Raw), &attr); err == nil && attr.Line > 0 {
				attrs[k] = &attr
			}
			return true
		})
		if len(attrs) > 0 {
			lines[address] = attrs
		}
	}
	module.Get("child_modules").ForEach(func(_, child gjson.Result) bool {
		walkPlannedValuesModule(&child, lines)
		return true
	})
}

func mergeAttributeLines(expressionLines, valueLines map[string]*model.LineObject) map[string]*model.LineObject {
	if len(expressionLines) == 0 && len(valueLines) == 0 {
		return nil
	}
	keys := make(map[string]struct{}, len(expressionLines)+len(valueLines))
	for k := range expressionLines {
		keys[k] = struct{}{}
	}
	for k := range valueLines {
		keys[k] = struct{}{}
	}
	merged := make(map[string]*model.LineObject, len(keys))
	for k := range keys {
		expr := expressionLines[k]
		val := valueLines[k]
		switch {
		case expr != nil && val != nil:
			// Planned values win for bare attribute paths (e.g. ["policy"]).
			// Configuration constant_value is kept for nested JSON-in-string
			// traversal (Statement, Action, Principal, …).
			nested := make(map[string]*model.LineObject, len(val.Map)+1)
			for key, line := range val.Map {
				nested[key] = line
			}
			nested["_dd_constant_value"] = &model.LineObject{Line: expr.Line}
			merged[k] = &model.LineObject{
				Line: val.Line,
				Arr:  val.Arr,
				Map:  nested,
			}
		case val != nil:
			merged[k] = val
		default:
			merged[k] = expr
		}
	}
	return merged
}

func walkConfigurationModule(module *gjson.Result, lines map[string]map[string]*model.LineObject) {
	for _, resource := range module.Get("resources").Array() {
		address := resource.Get("address").String()
		if address == "" {
			continue
		}
		expressions := map[string]*model.LineObject{}
		resource.Get("expressions").ForEach(func(key, expression gjson.Result) bool {
			if line := expression.Get("_dd_lines._dd_constant_value._dd_line").Int(); line > 0 {
				expressions["_dd_"+key.String()] = &model.LineObject{Line: int(line)}
			}
			return true
		})
		if len(expressions) > 0 {
			lines[address] = expressions
		}
	}
	module.Get("module_calls").ForEach(func(name, call gjson.Result) bool {
		child := call.Get("module")
		if child.Exists() {
			walkConfigurationModule(&child, lines)
		}
		return true
	})
}

// readPlan extracts the information needed from a Terraform plan and converts it to a scanner Document
func readPlan(
	plan *hcl_plan.Plan,
	resourceLines map[string]int,
	expressionLines, valueAttributeLines map[string]map[string]*model.LineObject,
) model.Document {
	kp := TFPlan{
		Resource: make(map[string]TFPlanResource),
		Data:     make(map[string]TFPlanResource),
	}

	kp.readModule(plan.PlannedValues.RootModule, "", resourceLines, expressionLines, valueAttributeLines)

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

// readModule recursively processes a module and its children, accumulating
// resources from every module into the same flat resource.<type>.<name> map
// without losing data across modules. moduleAddress is the full address of
// module (e.g. "module.staging"), or "" for the root module.
func (kp *TFPlan) readModule(
	module *hcl_plan.StateModule,
	moduleAddress string,
	resourceLines map[string]int,
	expressionLines, valueAttributeLines map[string]map[string]*model.LineObject,
) {
	// Process all resources in this module
	for _, resource := range module.Resources {
		resourcesByType := kp.Resource
		if resource.Mode == hcl_plan.DataResourceMode {
			resourcesByType = kp.Data
		}

		// Ensure the resource type map exists - accumulate, don't reinitialize!
		if resourcesByType[resource.Type] == nil {
			resourcesByType[resource.Type] = make(TFPlanResource)
		}
		typeRes := resourcesByType[resource.Type]

		// Root-module resources keep their plain name. Child-module resources
		// get their module address prefixed, so same-type-same-name resources
		// in different modules don't collide into one map entry (which would
		// silently drop a resource from evaluation).
		resourceKey := resource.Name
		if moduleAddress != "" {
			resourceKey = moduleAddress + "." + resource.Name
		}

		// Handle count and for_each: append the index to the resource key
		// This ensures each instance gets a unique key
		if resource.Index != nil {
			resourceKey = formatResourceKeyWithIndex(resourceKey, resource.Index)
		}

		// Accumulate the resource into the existing type map
		namedResource := TFPlanNamedResource(resource.AttributeValues)
		if namedResource == nil {
			namedResource = make(TFPlanNamedResource)
		}
		if moduleAddress != "" {
			namedResource["_dd_module_address"] = moduleAddress
		}
		if lines := mergeAttributeLines(expressionLines[resource.Address], valueAttributeLines[resource.Address]); lines != nil {
			namedResource["_dd_lines"] = lines
		}
		typeRes[resourceKey] = namedResource

		// Inject the resource's "values" attribute line as a sibling _dd_lines
		// entry at resource.<type>._dd_lines._dd_<name>._dd_line, matching the
		// gjson path GetLineBySearchLine builds for a bare resource searchKey.
		if line, ok := resourceLines[resource.Address]; ok {
			ddLines, isMap := typeRes["_dd_lines"].(map[string]*model.LineObject)
			if !isMap {
				ddLines = make(map[string]*model.LineObject)
				typeRes["_dd_lines"] = ddLines
			}
			ddLines["_dd_"+resourceKey] = &model.LineObject{Line: line}
		}
	}

	// Recursively process child modules, accumulating into the same map
	for _, childModule := range module.ChildModules {
		kp.readModule(childModule, childModule.Address, resourceLines, expressionLines, valueAttributeLines)
	}
}

// formatResourceKeyWithIndex formats a resource key to include count/for_each index
// Examples:
//   - count: "web" + 0 -> "web[0]"
//   - count: "web" + 2 -> "web[2]"
//   - for_each: "bucket" + "prod" -> "bucket[\"prod\"]"
//   - for_each: "bucket" + "staging" -> "bucket[\"staging\"]"
func formatResourceKeyWithIndex(baseName string, index interface{}) string {
	switch idx := index.(type) {
	case float64:
		// Count index (JSON numbers are float64)
		return fmt.Sprintf("%s[%d]", baseName, int(idx))
	case int:
		// Count index (in case it's already an int)
		return fmt.Sprintf("%s[%d]", baseName, idx)
	case string:
		// For_each index with string key
		return fmt.Sprintf("%s[%q]", baseName, idx)
	default:
		// Fallback: just use the base name if we don't recognize the index type
		return baseName
	}
}
