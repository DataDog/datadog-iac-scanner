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

	ResourceChanges any `json:"resource_changes,omitempty"`
	Configuration   any `json:"configuration,omitempty"`

	// TfplanMeta is a reserved top-level map, parallel to Resource (not
	// nested inside it), keyed exactly like Resource[type][flattened-key].
	TfplanMeta map[string]map[string]tfplanResourceMeta `json:"_dd_tfplan_meta,omitempty"`
}

// TFPlanResource is keyed by resource name, plus a reserved "_dd_lines" key
// holding each resource's header line (see readModule).
type TFPlanResource map[string]any

type TFPlanNamedResource map[string]any

// tfplanResourceMeta is the payload stored under
// _dd_tfplan_meta.<type>.<flattened-key>.
type tfplanResourceMeta struct {
	Address                  string `json:"address"`
	AfterUnknown             any    `json:"after_unknown,omitempty"`
	ConfigurationExpressions any    `json:"configuration_expressions,omitempty"`
}

type resourceChangeCorrelation struct {
	afterUnknownByAddress map[string]any
	expressionsByAddress  map[string]any
}

func buildResourceChangeCorrelation(rawPlan []byte) resourceChangeCorrelation {
	c := resourceChangeCorrelation{
		afterUnknownByAddress: make(map[string]any),
		expressionsByAddress:  make(map[string]any),
	}

	gjson.GetBytes(rawPlan, "resource_changes").ForEach(func(_, change gjson.Result) bool {
		address := change.Get("address").String()
		if address == "" {
			return true
		}
		if afterUnknown := change.Get("change.after_unknown"); afterUnknown.Exists() {
			c.afterUnknownByAddress[address] = afterUnknown.Value()
		}
		return true
	})

	rootConfigModule := gjson.GetBytes(rawPlan, "configuration.root_module")
	walkConfigModule(&rootConfigModule, "", &c)

	return c
}

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
			c.expressionsByAddress[absoluteAddress] = expressions.Value()
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

func resourceMetaFor(address string, c *resourceChangeCorrelation) tfplanResourceMeta {
	meta := tfplanResourceMeta{Address: address}
	if afterUnknown, ok := c.afterUnknownByAddress[address]; ok {
		meta.AfterUnknown = afterUnknown
	}
	if expressions, ok := c.expressionsByAddress[canonicalConfigAddress(address)]; ok {
		meta.ConfigurationExpressions = expressions
	}
	return meta
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
// line, keyed by resource address.
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

// readModule recursively accumulates resources from every module into the
// same flat resource.<type>.<name> map. moduleAddress is "" for the root module.
func (kp *TFPlan) readModule(
	module *hcl_plan.StateModule,
	moduleAddress string,
	resourceLines map[string]int,
	correlation *resourceChangeCorrelation,
) {
	for _, resource := range module.Resources {
		if kp.Resource[resource.Type] == nil {
			kp.Resource[resource.Type] = make(TFPlanResource)
		}
		typeRes := kp.Resource[resource.Type]

		// Module-prefixed so same-type-same-name resources in different
		// modules don't collide.
		resourceKey := resource.Name
		if moduleAddress != "" {
			resourceKey = moduleAddress + "." + resource.Name
		}

		if resource.Index != nil {
			resourceKey = formatResourceKeyWithIndex(resourceKey, resource.Index)
		}

		typeRes[resourceKey] = TFPlanNamedResource(resource.AttributeValues)

		if line, ok := resourceLines[resource.Address]; ok {
			ddLines, isMap := typeRes["_dd_lines"].(map[string]*model.LineObject)
			if !isMap {
				ddLines = make(map[string]*model.LineObject)
				typeRes["_dd_lines"] = ddLines
			}
			ddLines["_dd_"+resourceKey] = &model.LineObject{Line: line}
		}

		if kp.TfplanMeta[resource.Type] == nil {
			if kp.TfplanMeta == nil {
				kp.TfplanMeta = make(map[string]map[string]tfplanResourceMeta)
			}
			kp.TfplanMeta[resource.Type] = make(map[string]tfplanResourceMeta)
		}
		kp.TfplanMeta[resource.Type][resourceKey] = resourceMetaFor(resource.Address, correlation)
	}

	for _, childModule := range module.ChildModules {
		kp.readModule(childModule, childModule.Address, resourceLines, correlation)
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
