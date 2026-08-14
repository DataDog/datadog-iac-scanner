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

	// Raw (any), not typed hcl_plan structs, so after_unknown/configuration
	// pass through verbatim without a typed round-trip dropping data.
	ResourceChanges any `json:"resource_changes,omitempty"`
	Configuration   any `json:"configuration,omitempty"`
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

	parsedPlan := readPlan(plan, doc["resource_changes"], doc["configuration"], resourceLines)
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
	walkModule(&root_module, lines)
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

// readPlan extracts the information needed from a Terraform plan and converts it to a scanner Document.
// resourceChanges/configuration are raw values from the source document, passed through verbatim.
func readPlan(plan *hcl_plan.Plan, resourceChanges, configuration any, resourceLines map[string]int) model.Document {
	kp := TFPlan{
		Resource:        make(map[string]TFPlanResource),
		ResourceChanges: resourceChanges,
		Configuration:   configuration,
	}

	kp.readModule(plan.PlannedValues.RootModule, "", resourceLines)

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
func (kp *TFPlan) readModule(module *hcl_plan.StateModule, moduleAddress string, resourceLines map[string]int) {
	// Process all resources in this module
	for _, resource := range module.Resources {
		// Ensure the resource type map exists - accumulate, don't reinitialize!
		if kp.Resource[resource.Type] == nil {
			kp.Resource[resource.Type] = make(TFPlanResource)
		}
		typeRes := kp.Resource[resource.Type]

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
		typeRes[resourceKey] = TFPlanNamedResource(resource.AttributeValues)

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
		kp.readModule(childModule, childModule.Address, resourceLines)
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
