/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/registry"
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
	Provisioners             any    `json:"provisioners,omitempty"`
}

type resourceChangeCorrelation struct {
	afterUnknownByAddress map[string]any
	expressionsByAddress  map[string]any
	provisionersByAddress map[string]any
}

func buildResourceChangeCorrelation(rawPlan []byte) resourceChangeCorrelation {
	c := resourceChangeCorrelation{
		afterUnknownByAddress: make(map[string]any),
		expressionsByAddress:  make(map[string]any),
		provisionersByAddress: make(map[string]any),
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
	walkConfigModule(&rootConfigModule, "", nil, &c)

	return c
}

// callSiteIdentity is a call site's stable identity: the module_calls block
// and argument name it was declared at. expression itself isn't part of the
// identity since a decoded JSON value (a map or slice) isn't comparable.
type callSiteIdentity struct {
	moduleAddress string
	argumentName  string
}

// callSiteRecord is one entry in a call_site_expressions chain.
type callSiteRecord struct {
	callSiteIdentity
	expression any
}

// callArgument is a call-site expression, never asserted as a resolved
// value (Terraform serializes var.x and base64encode(var.x) alike).
type callArgument struct {
	callSiteIdentity
	raw   gjson.Result
	chain []callSiteRecord
}

// record returns arg's own call site as a callSiteRecord.
func (arg *callArgument) record() callSiteRecord {
	return callSiteRecord{callSiteIdentity: arg.callSiteIdentity, expression: arg.raw.Value()}
}

// walkConfigModule indexes each resource's expressions/provisioners by
// absolute address, using callArgs to attach call-site provenance.
func walkConfigModule(module *gjson.Result, modulePath string, callArgs map[string]callArgument, c *resourceChangeCorrelation) {
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
			c.expressionsByAddress[absoluteAddress] = qualifyExpressionTree(&expressions, callArgs)
		}
		if provisioners := resource.Get("provisioners"); provisioners.Exists() {
			c.provisionersByAddress[absoluteAddress] = qualifyExpressionTree(&provisioners, callArgs)
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
		childArgs := make(map[string]callArgument)
		call.Get("expressions").ForEach(func(argName, argExpr gjson.Result) bool {
			// Resolve this call's own args against the parent so a chain of
			// var.x indirections resolves transitively, not just one hop.
			childArgs[argName.String()] = callArgument{
				callSiteIdentity: callSiteIdentity{moduleAddress: modulePath, argumentName: argName.String()},
				raw:              argExpr,
				chain:            callArgumentChain(&argExpr, callArgs),
			}
			return true
		})
		walkConfigModule(&childModule, childPath, childArgs, c)
		return true
	})
}

// qualifyExpressionTree walks an expressions/provisioners tree, attaching
// call-site provenance to reference leaves without modifying any field.
func qualifyExpressionTree(value *gjson.Result, callArgs map[string]callArgument) any {
	if len(callArgs) == 0 || !value.IsObject() && !value.IsArray() {
		return value.Value()
	}

	if value.Get("references").Exists() {
		return attachCallSiteExpressions(value, callArgs)
	}

	if value.IsArray() {
		items := value.Array()
		resolved := make([]any, len(items))
		for i, item := range items {
			resolved[i] = qualifyExpressionTree(&item, callArgs)
		}
		return resolved
	}

	resolved := make(map[string]any)
	value.ForEach(func(key, item gjson.Result) bool {
		resolved[key.String()] = qualifyExpressionTree(&item, callArgs)
		return true
	})
	return resolved
}

// attachCallSiteExpressions adds a "call_site_expressions" sidecar listing
// each matched var.<name> reference's call-site chain, never modifying expr.
func attachCallSiteExpressions(expr *gjson.Result, callArgs map[string]callArgument) any {
	chain := referencedArgumentChain(expr, callArgs)
	if len(chain) == 0 {
		return expr.Value()
	}

	value, ok := expr.Value().(map[string]any)
	if !ok {
		return expr.Value()
	}
	expressions := make([]any, len(chain))
	for i, rec := range chain {
		expressions[i] = rec.expression
	}
	value["call_site_expressions"] = expressions
	return value
}

// callArgumentChain builds expr's own provenance for a child call to use.
// Returns nil when callArgs is empty (see referencedArgumentChain).
func callArgumentChain(expr *gjson.Result, callArgs map[string]callArgument) []callSiteRecord {
	if len(callArgs) == 0 {
		return nil
	}
	return referencedArgumentChain(expr, callArgs)
}

// referencedArgumentChain flattens every ancestor call site a var.<name>
// reference resolves to, deduplicated by (module, argument) identity.
func referencedArgumentChain(expr *gjson.Result, callArgs map[string]callArgument) []callSiteRecord {
	refs := expr.Get("references")
	if !refs.IsArray() || len(refs.Array()) == 0 {
		return nil
	}

	rawRefs := make([]string, len(refs.Array()))
	for i, ref := range refs.Array() {
		rawRefs[i] = ref.String()
	}

	seen := make(map[callSiteIdentity]bool)
	var chain []callSiteRecord
	for i, ref := range refs.Array() {
		name, ok := varReferenceName(ref.String())
		if !ok {
			continue
		}
		if hasMoreSpecificTraversal(rawRefs, i, name) {
			continue
		}
		arg, ok := callArgs[name]
		if !ok {
			continue
		}
		chain = appendDedupRecord(chain, seen, arg.chain...)
		chain = appendDedupRecord(chain, seen, arg.record())
	}
	return chain
}

// appendDedupRecord appends each of recs to chain, skipping any whose
// identity is already in seen, and marks every appended identity as seen.
func appendDedupRecord(chain []callSiteRecord, seen map[callSiteIdentity]bool, recs ...callSiteRecord) []callSiteRecord {
	for _, rec := range recs {
		if seen[rec.callSiteIdentity] {
			continue
		}
		seen[rec.callSiteIdentity] = true
		chain = append(chain, rec)
	}
	return chain
}

// hasMoreSpecificTraversal reports whether rawRefs also contains a
// traversal into "var.<name>" (e.g. "var.settings.selected") at another index.
func hasMoreSpecificTraversal(rawRefs []string, self int, name string) bool {
	prefix := "var." + name
	for i, ref := range rawRefs {
		if i == self {
			continue
		}
		if !strings.HasPrefix(ref, prefix) {
			continue
		}
		rest := ref[len(prefix):]
		if strings.HasPrefix(rest, ".") || strings.HasPrefix(rest, "[") {
			return true
		}
	}
	return false
}

// varReferenceName reports whether ref is exactly a bare "var.<name>" root
// (not "var.settings.metric_name") and, if so, returns <name>.
func varReferenceName(ref string) (string, bool) {
	if !strings.HasPrefix(ref, "var.") {
		return "", false
	}
	name := strings.TrimPrefix(ref, "var.")
	if name == "" || strings.ContainsAny(name, ".[") {
		return "", false
	}
	return name, true
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
	configAddress := canonicalConfigAddress(address)
	if expressions, ok := c.expressionsByAddress[configAddress]; ok {
		meta.ConfigurationExpressions = expressions
	}
	if provisioners, ok := c.provisionersByAddress[configAddress]; ok {
		meta.Provisioners = provisioners
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
		kp.readPriorStateData(plan.PriorState.Values.RootModule, "", resourceLines, deletedAddresses(plan.ResourceChanges))
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

		// Build the full terraform address (type.name) and normalize away
		// count/for_each indices so it matches HCL-registered addresses.
		fullAddress := resource.Type + "." + resource.Name
		if moduleAddress != "" {
			fullAddress = moduleAddress + "." + resource.Type + "." + resource.Name
		}
		normalizedAddress := registry.NormalizeAddress(fullAddress)

		if resource.AttributeValues == nil {
			resource.AttributeValues = make(map[string]interface{})
		}
		resource.AttributeValues["_dd_tf_address"] = normalizedAddress

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
		typeData[dataKey] = resource.AttributeValues

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
		kp.readPriorStateData(childModule, childModule.Address, resourceLines, deleted)
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
