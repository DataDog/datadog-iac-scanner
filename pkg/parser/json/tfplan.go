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
)

// TFPlan is an auxiliary structure for parsing tfplans as a scanner Document
type TFPlan struct {
	Resource map[string]TFPlanResource `json:"resource"`
}

// TFPlanResource is an auxiliary structure for parsing tfplans as a scanner Document
type TFPlanResource map[string]TFPlanNamedResource

// TFPlanNamedResource is an auxiliary structure for parsing tfplans as a scanner Document
type TFPlanNamedResource map[string]interface{}

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

	parsedPlan := readPlan(plan)
	return parsedPlan, nil
}

// readPlan extracts the information needed from a Terraform plan and converts it to a scanner Document
func readPlan(plan *hcl_plan.Plan) model.Document {
	kp := TFPlan{
		Resource: make(map[string]TFPlanResource),
	}

	kp.readModule(plan.PlannedValues.RootModule)

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

// readModule will iterate over all planned_value getting the information required
// It recursively processes all modules and accumulates resources without losing data
func (kp *TFPlan) readModule(module *hcl_plan.StateModule) {
	kp.readModuleWithAddress(module, "")
}

// readModuleWithAddress recursively processes a module and its children with full address path
// to ensure unique resource identification across the module tree
func (kp *TFPlan) readModuleWithAddress(module *hcl_plan.StateModule, moduleAddress string) {
	// Process all resources in this module
	for _, resource := range module.Resources {
		// Ensure the resource type map exists - accumulate, don't reinitialize!
		if kp.Resource[resource.Type] == nil {
			kp.Resource[resource.Type] = make(map[string]TFPlanNamedResource)
		}

		// Build resource key with module path for child modules
		// Root module resources keep simple names for backward compatibility
		// Child module resources are prefixed with their module path
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
		kp.Resource[resource.Type][resourceKey] = resource.AttributeValues
	}

	// Recursively process child modules with their full address path
	for _, childModule := range module.ChildModules {
		// The childModule.Address already contains the full path from root
		// (e.g., "module.networking" or "module.networking.module.security")
		// So we pass it directly without combining with parent
		kp.readModuleWithAddress(childModule, childModule.Address)
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
