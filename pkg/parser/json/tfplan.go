/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"encoding/json"

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
func (kp *TFPlan) readModule(module *hcl_plan.StateModule) {
	// initialize all the types interfaces
	for _, resource := range module.Resources {
		convNamedRes := make(map[string]TFPlanNamedResource)
		kp.Resource[resource.Type] = convNamedRes
	}
	// fill in all the types interfaces
	for _, resource := range module.Resources {
		kp.Resource[resource.Type][resource.Name] = resource.AttributeValues
	}

	for _, childModule := range module.ChildModules {
		kp.readModule(childModule)
	}
}
