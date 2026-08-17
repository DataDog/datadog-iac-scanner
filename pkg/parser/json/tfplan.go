/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"encoding/json"
	"fmt"
	"regexp"

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
// Values are either a TFPlanNamedResource (keyed by resource name) or, under a
// reserved "_dd_*" key, scanner-owned metadata keyed like the sibling resource
// name (see readModule): "_dd_lines" holds each header line, "_dd_tfplan_meta"
// holds each resource's canonical address plus its correlated
// resource_changes/configuration entries.
type TFPlanResource map[string]any

// TFPlanNamedResource is an auxiliary structure for parsing tfplans as a scanner Document
type TFPlanNamedResource map[string]any

// tfplanResourceMeta is the payload stored under
// resource.<type>._dd_tfplan_meta._dd_<flattened-key>. It gives Rego a direct
// lookup for data that otherwise requires reconstructing the resource's
// canonical address and correlating it against the raw resource_changes/
// configuration structures.
type tfplanResourceMeta struct {
	// Address is the canonical (absolute) Terraform resource address, e.g.
	// "module.staging.aws_instance.web[0]".
	Address string `json:"address"`
	// AfterUnknown is resource_changes[].change.after_unknown for this
	// resource, verbatim, or nil if no matching change was found.
	AfterUnknown any `json:"after_unknown,omitempty"`
	// ConfigurationExpressions is configuration...resources[].expressions for
	// this resource, verbatim, or nil if no matching configuration was found.
	ConfigurationExpressions any `json:"configuration_expressions,omitempty"`
}

// indexBracketRE matches a single "[...]" instance-key suffix (count index or
// quoted for_each key) in a Terraform resource/module address segment.
var indexBracketRE = regexp.MustCompile(`\[[^\]]*\]`)

// resourceChangeCorrelation holds the two per-address lookups built once per
// plan (from the raw, untyped resource_changes/configuration) so readModule
// can attach correlated data to each resource without re-walking either
// structure per resource.
type resourceChangeCorrelation struct {
	afterUnknownByAddress map[string]any
	expressionsByAddress  map[string]any
}

// buildResourceChangeCorrelation indexes resource_changes by their (already
// absolute) address, and configuration by reconstructing each resource's
// absolute address from its module path, so both can be looked up by the same
// canonical address readModule already computes per resource. Raw gjson
// values are used (not the typed hcl_plan structs) so resource_changes/
// configuration data itself is never touched - only read.
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

// walkConfigModule recursively walks configuration.root_module (and its
// module_calls), reconstructing each resource's absolute address from
// modulePath so it can be looked up with the same canonical address as
// resource_changes and readModule's resourceLines/resourceKey.
func walkConfigModule(module *gjson.Result, modulePath string, c *resourceChangeCorrelation) {
	module.Get("resources").ForEach(func(_, resource gjson.Result) bool {
		// ConfigResource.Address is relative to its own module, e.g.
		// "aws_instance.web" - never index-suffixed, since configuration
		// describes the module definition, not a specific instance.
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

// canonicalConfigAddress strips every "[...]" instance-key suffix from an
// absolute resource address, e.g. "module.staging[\"prod\"].aws_instance.web[2]"
// becomes "module.staging.aws_instance.web" - the shape configuration
// addresses always have, since a module's configuration is shared by every
// instance of that module (for_each/count).
func canonicalConfigAddress(address string) string {
	return indexBracketRE.ReplaceAllString(address, "")
}

// resourceMetaFor builds the _dd_tfplan_meta payload for a single resource,
// correlating by its canonical (address) and configuration (index-stripped)
// addresses.
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

	// Built from the raw bytes (not the typed plan) so resource_changes/
	// configuration correlation sees exactly what's in the source document.
	correlation := buildResourceChangeCorrelation(b)

	parsedPlan := readPlan(plan, doc["resource_changes"], doc["configuration"], resourceLines, &correlation)
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

// readModule recursively processes a module and its children, accumulating
// resources from every module into the same flat resource.<type>.<name> map
// without losing data across modules. moduleAddress is the full address of
// module (e.g. "module.staging"), or "" for the root module.
func (kp *TFPlan) readModule(
	module *hcl_plan.StateModule,
	moduleAddress string,
	resourceLines map[string]int,
	correlation *resourceChangeCorrelation,
) {
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

		// Inject the resource's canonical address plus its correlated
		// resource_changes/configuration data as a sibling _dd_tfplan_meta
		// entry at resource.<type>._dd_tfplan_meta._dd_<name>, so Rego rules
		// can look this up directly instead of reconstructing the address and
		// re-walking resource_changes/configuration themselves.
		ddMeta, isMap := typeRes["_dd_tfplan_meta"].(map[string]tfplanResourceMeta)
		if !isMap {
			ddMeta = make(map[string]tfplanResourceMeta)
			typeRes["_dd_tfplan_meta"] = ddMeta
		}
		ddMeta["_dd_"+resourceKey] = resourceMetaFor(resource.Address, correlation)
	}

	// Recursively process child modules, accumulating into the same map
	for _, childModule := range module.ChildModules {
		kp.readModule(childModule, childModule.Address, resourceLines, correlation)
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
