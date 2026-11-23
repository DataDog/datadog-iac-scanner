/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package json

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"
	"unsafe"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcl_plan "github.com/hashicorp/terraform-json"
	"github.com/tidwall/gjson"
)

// planAddressKey is the key of a resource's Terraform address in its metadata.
const planAddressKey = "address"

// planResourceKey is the section of a parsed plan holding its resources.
const planResourceKey = "resource"

// TfplanMetaKey is where the parser stores Terraform's own per-resource plan
// addresses, parallel to the resource sections in a parsed plan document.
const TfplanMetaKey = "_dd_tfplan_meta"

// PlanAddresses flattens parser metadata to a section/document-key lookup.
func PlanAddresses(doc model.Document) map[model.PlanResourceKey]string {
	raw, ok := doc[TfplanMetaKey].(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[model.PlanResourceKey]string)
	for section, entriesRaw := range raw {
		entries, ok := entriesRaw.(map[string]interface{})
		if !ok {
			continue
		}
		for key, entryRaw := range entries {
			entry, ok := entryRaw.(map[string]interface{})
			if !ok {
				continue
			}
			address, _ := entry["address"].(string)
			if address != "" {
				out[model.PlanResourceKey{Section: section, Key: key}] = address
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

type resourceChangeCorrelation struct {
	afterUnknownByAddress map[string]any
	expressionsByAddress  map[string]any
	provisionersByAddress map[string]any
}

// buildResourceChangeCorrelation uses the sections already decoded for the
// emitted document. Looking them up again in raw JSON would give gjson's first
// duplicate key instead of encoding/json's last value. Decoded values also own
// their strings, so sharing them here cannot retain the input buffer.
func buildResourceChangeCorrelation(resourceChanges, configuration any) resourceChangeCorrelation {
	c := resourceChangeCorrelation{
		afterUnknownByAddress: make(map[string]any),
		expressionsByAddress:  make(map[string]any),
		provisionersByAddress: make(map[string]any),
	}

	changes, _ := resourceChanges.([]any)
	for _, value := range changes {
		resource, _ := value.(map[string]any)
		address, _ := resource["address"].(string)
		if address == "" {
			continue
		}
		change, _ := resource["change"].(map[string]any)
		if afterUnknown, ok := change["after_unknown"]; ok {
			c.afterUnknownByAddress[address] = afterUnknown
		}
	}

	config, _ := configuration.(map[string]any)
	rootConfigModule, _ := config["root_module"].(map[string]any)
	walkConfigModule(rootConfigModule, "", nil, &c)

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
	expression any
	chain      []callSiteRecord
}

// record returns arg's own call site as a callSiteRecord.
func (arg *callArgument) record() callSiteRecord {
	return callSiteRecord{callSiteIdentity: arg.callSiteIdentity, expression: arg.expression}
}

// walkConfigModule indexes each resource's expressions/provisioners by
// absolute address, using callArgs to attach call-site provenance.
func walkConfigModule(module map[string]any, modulePath string, callArgs map[string]callArgument, c *resourceChangeCorrelation) {
	resources, _ := module["resources"].([]any)
	for _, value := range resources {
		resource, _ := value.(map[string]any)
		relativeAddress, _ := resource["address"].(string)
		if relativeAddress == "" {
			continue
		}
		absoluteAddress := relativeAddress
		if modulePath != "" {
			absoluteAddress = modulePath + "." + relativeAddress
		}
		if expressions, ok := resource["expressions"]; ok {
			c.expressionsByAddress[absoluteAddress] = qualifyExpressionTree(expressions, callArgs)
		}
		if provisioners, ok := resource["provisioners"]; ok {
			c.provisionersByAddress[absoluteAddress] = qualifyExpressionTree(provisioners, callArgs)
		}
	}

	calls, _ := module["module_calls"].(map[string]any)
	for callName, value := range calls {
		call, _ := value.(map[string]any)
		childModule, _ := call["module"].(map[string]any)
		if childModule == nil {
			continue
		}
		childPath := "module." + callName
		if modulePath != "" {
			childPath = modulePath + "." + childPath
		}
		childArgs := make(map[string]callArgument)
		expressions, _ := call["expressions"].(map[string]any)
		for argName, argExpr := range expressions {
			// Resolve this call's own args against the parent so a chain of
			// var.x indirections resolves transitively, not just one hop.
			childArgs[argName] = callArgument{
				callSiteIdentity: callSiteIdentity{moduleAddress: modulePath, argumentName: argName},
				expression:       argExpr,
				chain:            callArgumentChain(argExpr, callArgs),
			}
		}
		walkConfigModule(childModule, childPath, childArgs, c)
	}
}

// qualifyExpressionTree walks an expressions/provisioners tree, attaching
// call-site provenance to reference leaves without modifying any field.
func qualifyExpressionTree(value any, callArgs map[string]callArgument) any {
	if len(callArgs) == 0 {
		return value
	}

	switch value := value.(type) {
	case []any:
		resolved := make([]any, len(value))
		for i, item := range value {
			resolved[i] = qualifyExpressionTree(item, callArgs)
		}
		return resolved
	case map[string]any:
		if _, ok := value["references"]; ok {
			return attachCallSiteExpressions(value, callArgs)
		}
		resolved := make(map[string]any, len(value))
		for key, item := range value {
			resolved[key] = qualifyExpressionTree(item, callArgs)
		}
		return resolved
	default:
		return value
	}
}

// attachCallSiteExpressions adds a "call_site_expressions" sidecar listing
// each matched var.<name> reference's call-site chain, never modifying expr.
func attachCallSiteExpressions(expr map[string]any, callArgs map[string]callArgument) any {
	chain := referencedArgumentChain(expr, callArgs)
	if len(chain) == 0 {
		return expr
	}

	value := maps.Clone(expr)
	expressions := make([]any, len(chain))
	for i, rec := range chain {
		expressions[i] = rec.expression
	}
	value["call_site_expressions"] = expressions
	return value
}

// callArgumentChain builds expr's own provenance for a child call to use.
// Returns nil when callArgs is empty (see referencedArgumentChain).
func callArgumentChain(expr any, callArgs map[string]callArgument) []callSiteRecord {
	if len(callArgs) == 0 {
		return nil
	}
	return referencedArgumentChain(expr, callArgs)
}

// referencedArgumentChain flattens every ancestor call site a var.<name>
// reference resolves to, deduplicated by (module, argument) identity.
func referencedArgumentChain(expr any, callArgs map[string]callArgument) []callSiteRecord {
	value, _ := expr.(map[string]any)
	refs, _ := value["references"].([]any)
	if len(refs) == 0 {
		return nil
	}

	rawRefs := make([]string, len(refs))
	for i, ref := range refs {
		rawRefs[i], _ = ref.(string)
	}

	seen := make(map[callSiteIdentity]bool)
	var chain []callSiteRecord
	for i, ref := range rawRefs {
		name, ok := varReferenceName(ref)
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

// resourceMetaFor returns the _dd_tfplan_meta entry of the resource at address.
func resourceMetaFor(address string, c *resourceChangeCorrelation) map[string]interface{} {
	meta := map[string]interface{}{planAddressKey: address}
	if afterUnknown := c.afterUnknownByAddress[address]; afterUnknown != nil {
		meta["after_unknown"] = afterUnknown
	}
	configAddress := canonicalConfigAddress(address)
	if expressions := c.expressionsByAddress[configAddress]; expressions != nil {
		meta["configuration_expressions"] = expressions
	}
	if provisioners := c.provisionersByAddress[configAddress]; provisioners != nil {
		meta["provisioners"] = provisioners
	}
	return meta
}

// planView is the part of a plan that readPlan reads. Decoding the whole
// plan with terraform-json also decoded every value of resource_changes and
// of the managed resources in prior_state, which readPlan never reads. The
// format versions are validated as terraform-json validates them.
type planView struct {
	FormatVersion   string                `json:"format_version"`
	PlannedValues   *hcl_plan.StateValues `json:"planned_values"`
	PriorState      *priorStateView       `json:"prior_state"`
	ResourceChanges []resourceChangeView  `json:"-"`
}

type priorStateView struct {
	FormatVersion string `json:"format_version"`
	Values        *struct {
		RootModule *priorModuleView `json:"root_module"`
	} `json:"values"`
}

type priorModuleView struct {
	Address      string              `json:"address"`
	Resources    []priorResourceView `json:"resources"`
	ChildModules []*priorModuleView  `json:"child_modules"`
}

// priorResourceView keeps a resource's values encoded: readPriorStateData
// only reads those of data sources.
type priorResourceView struct {
	Address string                `json:"address"`
	Mode    hcl_plan.ResourceMode `json:"mode"`
	Type    string                `json:"type"`
	Name    string                `json:"name"`
	Index   any                   `json:"index"`
	Values  json.RawMessage       `json:"values"`
}

type resourceChangeView struct {
	Address string `json:"address"`
	Change  *struct {
		Actions hcl_plan.Actions `json:"actions"`
	} `json:"change"`
}

func decodePlanView(rawPlan []byte) (*planView, error) {
	var plan planView
	if err := json.Unmarshal(rawPlan, &plan); err != nil {
		return nil, err
	}
	if err := (&hcl_plan.Plan{FormatVersion: plan.FormatVersion}).Validate(); err != nil {
		return nil, err
	}
	if plan.PriorState != nil {
		if err := (&hcl_plan.State{FormatVersion: plan.PriorState.FormatVersion}).Validate(); err != nil {
			return nil, err
		}
	}
	return &plan, nil
}

// stateModule returns m with the values of its data sources decoded.
func (m *priorModuleView) stateModule() (*hcl_plan.StateModule, error) {
	if m == nil {
		return nil, nil
	}
	module := &hcl_plan.StateModule{Address: m.Address}
	for i := range m.Resources {
		r := &m.Resources[i]
		resource := &hcl_plan.StateResource{Address: r.Address, Mode: r.Mode, Type: r.Type, Name: r.Name, Index: r.Index}
		if r.Mode == hcl_plan.DataResourceMode && len(r.Values) > 0 {
			if err := json.Unmarshal(r.Values, &resource.AttributeValues); err != nil {
				return nil, err
			}
		}
		module.Resources = append(module.Resources, resource)
	}
	for _, child := range m.ChildModules {
		childModule, err := child.stateModule()
		if err != nil {
			return nil, err
		}
		module.ChildModules = append(module.ChildModules, childModule)
	}
	return module, nil
}

func parseTFPlan(doc model.Document) (model.Document, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return model.Document{}, err
	}
	return readPlanJSON(b, b)
}

// parseTFPlanContent parses the JSON content of a plan one top-level section
// at a time, without line markers, where parseTFPlan needs it decoded and
// line-annotated whole: scans that rebuild line info on demand never read
// the markers, and annotating the plan was most of its parse. ok is false
// when the content is not a plan this way can parse, which is then parsed
// whole.
func parseTFPlanContent(content []byte) (doc model.Document, ok bool) {
	sections, ok := topLevelSections(content)
	if !ok || !sections["planned_values"].IsObject() {
		return nil, false
	}
	doc, err := readPlanJSON(content, content)
	return doc, err == nil
}

// planSection is a top-level value of a plan, with the offset of its key.
type planSection struct {
	gjson.Result
	keyIndex int
}

// topLevelSections returns the top-level values of a JSON object by key.
// ok is false for invalid JSON, another root or a repeated key (decoding
// keeps its last value, gjson its first).
func topLevelSections(content []byte) (sections map[string]planSection, ok bool) {
	if len(content) == 0 || !json.Valid(content) {
		return nil, false
	}
	root := jsonView(content)
	if !root.IsObject() {
		return nil, false
	}
	sections = make(map[string]planSection)
	ok = true
	root.ForEach(func(key, value gjson.Result) bool {
		if _, seen := sections[key.String()]; seen {
			ok = false
			return false
		}
		sections[key.String()] = planSection{Result: value, keyIndex: key.Index}
		return true
	})
	return sections, ok
}

// jsonView parses content through a string view of it, so its values are
// not copied: they are only read while content is, and content is not
// modified.
func jsonView(content []byte) gjson.Result {
	return gjson.Parse(unsafe.String(unsafe.SliceData(content), len(content))) //nolint:gosec // read-only view
}

// annotatedSection decodes a top-level section of content with line markers
// counted from the start of content, its own being the line of its key. An
// array section is decoded as the value of its key, as it is in a whole plan,
// so the markers of its elements are the ones a whole parse gives them.
func annotatedSection(content []byte, key string, section *planSection) (interface{}, bool) {
	if section.Index <= 0 {
		return nil, false
	}
	valueLine := 1 + bytes.Count(content[:section.Index], []byte{'\n'})
	keyLine := 1 + bytes.Count(content[:section.keyIndex], []byte{'\n'})
	return annotatedSectionAt(content, key, section, valueLine, keyLine)
}

// annotatedSectionAt annotates a section whose source lines are already known.
func annotatedSectionAt(content []byte, key string, section *planSection, valueLine, keyLine int) (interface{}, bool) {
	if section.Index <= 0 {
		return nil, false
	}
	raw := content[section.Index : section.Index+len(section.Raw)]
	if section.IsArray() {
		wrapped := append(append(append([]byte(`{"`), key...), `":`...), raw...)
		wrapped = append(wrapped, '}')
		var values map[string]interface{}
		if err := json.Unmarshal(wrapped, &values); err != nil {
			return nil, false
		}
		initializeJSONLineAt(wrapped, valueLine).setLineInfo(values)
		return values[key], true
	}
	var values map[string]interface{}
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return nil, false
	}
	jLine := initializeJSONLineAt(raw, valueLine)
	values["_dd_lines"] = jLine.setLine(values, keyLine, "", false)
	return values, true
}

// readPlanJSON reads a plan from two JSON encodings: states holds its
// format_version, planned_values and prior_state with the line markers of
// setLineInfo, and changes its resource_changes and configuration, which
// are read as they are.
func readPlanJSON(states, changes []byte) (model.Document, error) {
	plan, err := decodePlanView(states)
	if err != nil {
		return model.Document{}, err
	}
	if plan.PlannedValues == nil || plan.PlannedValues.RootModule == nil {
		return model.Document{}, errors.New("terraform plan has no planned_values.root_module")
	}
	resourceChanges, err := decodeSection(changes, "resource_changes")
	if err != nil {
		return model.Document{}, err
	}
	if plan.ResourceChanges, err = decodeResourceChangeViews(changes); err != nil {
		return model.Document{}, err
	}
	var priorStateRoot *hcl_plan.StateModule
	if plan.PriorState != nil && plan.PriorState.Values != nil {
		if priorStateRoot, err = plan.PriorState.Values.RootModule.stateModule(); err != nil {
			return model.Document{}, err
		}
	}

	// planView is typed and drops the injected _dd_lines keys, so read
	// them back from the raw bytes before that information is lost.
	lines := extractResourceHeaderLines(states)
	configuration, err := decodeSection(changes, "configuration")
	if err != nil {
		return model.Document{}, err
	}

	correlation := buildResourceChangeCorrelation(resourceChanges, configuration)
	parsedPlan := readPlan(plan, priorStateRoot, resourceChanges, configuration, lines, &correlation)
	return parsedPlan, nil
}

// decodeResourceChangeViews decodes the addresses and actions of the
// resource_changes of a JSON-encoded plan.
func decodeResourceChangeViews(rawPlan []byte) ([]resourceChangeView, error) {
	var changes []resourceChangeView
	err := decodeSectionInto(rawPlan, "resource_changes", &changes)
	return changes, err
}

// decodeSection decodes the top-level key of a JSON-encoded plan, or returns
// nil when the plan has none.
func decodeSection(rawPlan []byte, key string) (any, error) {
	var value any
	err := decodeSectionInto(rawPlan, key, &value)
	return value, err
}

func decodeSectionInto(rawPlan []byte, key string, v any) error {
	section := jsonView(rawPlan).Get(key)
	if !section.Exists() {
		return nil
	}
	return json.Unmarshal(rawPlan[section.Index:section.Index+len(section.Raw)], v)
}

// lineInfoSections are the sections of a plan other than its resources that
// the line-info document holds, annotated: line detection resolves paths
// under "resource" (see the detector's terraformPlanPath) and
// "configuration" (outputs, variables). The change list, which only anchored
// search keys read, is a lazy section (see lazyLineInfoSections).
var lineInfoSections = []string{"configuration"}

// lazyLineInfoSections are the sections built only for the findings that need
// them: resource_changes and prior-state data are searched by deep anchored
// keys, while ordinary resource findings need neither.
var lazyLineInfoSections = []string{"resource_changes", "data"}

// parseTFPlanLineInfo builds the line-info document of a plan for line
// detection: the "resource" section of the parseTFPlan document, read from
// the line-annotated planned_values alone, and the annotated lineInfoSections.
// Line positions are keyed by their JSON path, so the lines found in a section
// on its own are those found in the whole plan. ok is false when
// planned_values cannot be read this way, and the caller then parses the
// whole plan.
func parseTFPlanLineInfo(content []byte) (doc model.Document, ok bool) {
	sections, ok := topLevelSections(content)
	plannedValues, formatVersion := sections["planned_values"], sections["format_version"]
	if !ok || !plannedValues.IsObject() || formatVersion.Type != gjson.String ||
		(&hcl_plan.Plan{FormatVersion: formatVersion.Str}).Validate() != nil {
		return nil, false
	}
	annotated, ok := annotatedSection(content, "planned_values", &plannedValues)
	if !ok {
		return nil, false
	}
	values, _ := annotated.(map[string]interface{})
	root, ok := values["root_module"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	rootLines, _ := root["_dd_lines"].(map[string]*model.LineObject)
	d := planDocument{resource: make(map[string]interface{}), meta: make(map[string]interface{})}
	if !d.readLineInfoModule(root, rootLines, "") {
		return nil, false
	}
	doc = model.Document{planResourceKey: d.resource}
	for _, name := range lineInfoSections {
		if section, ok := sections[name]; ok && (section.IsObject() || section.IsArray()) {
			if annotated, ok := annotatedSection(content, name, &section); ok {
				doc[name] = annotated
			}
		}
	}
	return doc, true
}

// parseTFPlanDataLineInfo restores the prior-state data section for anchored
// lookups without annotating managed resources or retaining prior_state itself.
func parseTFPlanDataLineInfo(content []byte, sections map[string]planSection) (interface{}, bool) {
	prior, exists := sections["prior_state"]
	if !exists || !prior.IsObject() ||
		(&hcl_plan.State{FormatVersion: prior.Get("format_version").String()}).Validate() != nil {
		return nil, false
	}
	changes, err := decodeResourceChangeViews(content)
	if err != nil {
		return nil, false
	}
	deleted := deletedAddresses(changes)
	root := prior.Get("values.root_module")
	if !root.IsObject() {
		return nil, false
	}

	entries := priorDataLineInfoEntries(&root, deleted)
	// Modules need not appear in any particular JSON field order. Annotate
	// selected values in source order, counting each intervening newline once.
	sort.Slice(entries, func(i, j int) bool { return entries[i].values.keyIndex < entries[j].values.keyIndex })
	offset, line := 0, 1
	lineAt := func(next int) int {
		line += bytes.Count(content[offset:next], []byte{'\n'})
		offset = next
		return line
	}
	d := planDocument{data: make(map[string]interface{}), meta: make(map[string]interface{})}
	for _, e := range entries {
		header := 0
		var values map[string]interface{}
		if e.values.keyIndex > 0 {
			header = lineAt(e.values.keyIndex)
			valueLine := lineAt(e.values.Index)
			if e.values.IsObject() {
				annotated, ok := annotatedSectionAt(content, "values", &e.values, valueLine, header)
				if !ok {
					return nil, false
				}
				values, _ = annotated.(map[string]interface{})
			} else if e.values.Raw != "null" {
				return nil, false
			}
		}
		d.add(d.data, e.typ, "data."+e.typ, e.key, values, header, nil)
	}
	return d.data, len(d.data) > 0
}

type priorDataLineInfoEntry struct {
	typ, key string
	values   planSection
}

// priorDataLineInfoEntries selects data resources using the same deletion,
// module and instance-key rules as readPriorStateData.
func priorDataLineInfoEntries(root *gjson.Result, deleted map[string]bool) []priorDataLineInfoEntry {
	var entries []priorDataLineInfoEntry
	modules := []gjson.Result{*root}
	for len(modules) > 0 {
		module := modules[len(modules)-1]
		modules = modules[:len(modules)-1]
		address := ""
		if module.Index != root.Index {
			address = module.Get("address").String()
		}
		module.Get("resources").ForEach(func(_, resource gjson.Result) bool {
			if resource.Get("mode").String() != string(hcl_plan.DataResourceMode) || deleted[resource.Get("address").String()] {
				return true
			}
			key := resource.Get("name").String()
			if address != "" {
				key = address + "." + key
			}
			if index := resource.Get("index"); index.Exists() {
				key = formatResourceKeyWithIndex(key, index.Value())
			}
			// gjson strings may reference the whole input buffer. The returned
			// tree must not retain that temporary copy of the plan.
			e := priorDataLineInfoEntry{typ: strings.Clone(resource.Get("type").String()), key: strings.Clone(key)}
			resource.ForEach(func(key, value gjson.Result) bool {
				if key.String() == "values" {
					e.values = planSection{Result: value, keyIndex: key.Index}
				}
				return true
			})
			entries = append(entries, e)
			return true
		})
		module.Get("child_modules").ForEach(func(_, child gjson.Result) bool {
			modules = append(modules, child)
			return true
		})
	}
	return entries
}

// resourceHeaderLines holds each resource's "values" attribute line, keyed
// by resource address, for each section the parsed plan reads values from.
// They are kept apart because an existing managed resource has the same
// address in planned_values and prior_state.
type resourceHeaderLines struct {
	planned    map[string]int
	priorState map[string]int
}

func extractResourceHeaderLines(rawPlan []byte) resourceHeaderLines {
	lines := resourceHeaderLines{planned: make(map[string]int), priorState: make(map[string]int)}
	for root, rootLines := range map[string]map[string]int{
		"planned_values.root_module":     lines.planned,
		"prior_state.values.root_module": lines.priorState,
	} {
		module := jsonView(rawPlan).Get(root)
		moduleLines := module.Get("_dd_lines")
		walkModule(&module, &moduleLines, rootLines)
	}
	return lines
}

// walkModule records the header lines of module's resources and of its child
// modules'. moduleLines is the module's line map: its own _dd_lines for a
// root module, and for a child module, an array element, the entry of its
// parent's _dd_child_modules array.
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
	childLines := moduleLines.Get("_dd_child_modules._dd_arr").Array()
	for i, child := range module.Get("child_modules").Array() {
		if i >= len(childLines) {
			break
		}
		walkModule(&child, &childLines[i], lines)
	}
}

func readPlan(
	plan *planView,
	priorStateRoot *hcl_plan.StateModule,
	resourceChanges, configuration any,
	lines resourceHeaderLines,
	correlation *resourceChangeCorrelation,
) model.Document {
	d := planDocument{
		resource: make(map[string]interface{}),
		data:     make(map[string]interface{}),
		meta:     make(map[string]interface{}),
	}
	d.readModule(plan.PlannedValues.RootModule, "", lines.planned, correlation)
	if plan.PriorState != nil && plan.PriorState.Values != nil {
		d.readPriorStateData(priorStateRoot, "", lines.priorState, deletedAddresses(plan.ResourceChanges))
	}

	doc := model.Document{planResourceKey: d.resource}
	if len(d.data) > 0 {
		doc["data"] = d.data
	}
	if resourceChanges != nil {
		doc["resource_changes"] = resourceChanges
	}
	if configuration != nil {
		doc["configuration"] = configuration
	}
	if len(d.meta) > 0 {
		doc[TfplanMetaKey] = d.meta
	}
	return doc
}

// planDocument holds the sections of a parsed plan document: resources
// under resource.<type>.<key> and data sources under data.<type>.<key> (the
// HCL parser's shape), each type also holding the header lines of its
// entries under "_dd_lines", and Terraform's addresses under
// _dd_tfplan_meta.<section>.<key>, a reserved map parallel to them.
type planDocument struct {
	resource, data, meta map[string]interface{}
}

// add stores the values of the entry key of type typ in section, with its
// header line (when line is positive) and its metadata.
func (d *planDocument) add(section map[string]interface{}, typ, metaSection, key string,
	values map[string]interface{}, line int, meta map[string]interface{}) {
	entries := childMap(section, typ)
	entries[key] = nil
	if values != nil {
		entries[key] = values
	}
	if line > 0 {
		childMap(entries, "_dd_lines")["_dd_"+key] = map[string]interface{}{"_dd_line": float64(line)}
	}
	childMap(d.meta, metaSection)[key] = meta
}

// childMap returns the map under key in parent, adding it when missing.
func childMap(parent map[string]interface{}, key string) map[string]interface{} {
	child, ok := parent[key].(map[string]interface{})
	if !ok {
		child = make(map[string]interface{})
		parent[key] = child
	}
	return child
}

// readModule recursively accumulates resources from every module into the
// same flat resource.<type>.<name> map. moduleAddress is "" for the root module.
func (d *planDocument) readModule(
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
		d.add(d.resource, resource.Type, resource.Type, resourceKey, resource.AttributeValues,
			resourceLines[resource.Address], resourceMetaFor(resource.Address, correlation))
	}

	for _, childModule := range module.ChildModules {
		d.readModule(childModule, childModule.Address, resourceLines, correlation)
	}
}

// readLineInfoModule is readModule for a line-annotated, decoded module.
// moduleLines is its line map (see walkModule). ok is false for a module
// that does not decode as a planned module.
func (d *planDocument) readLineInfoModule(module map[string]interface{}, moduleLines map[string]*model.LineObject,
	moduleAddress string) bool {
	resourceLines := lineArray(moduleLines, "_dd_resources")
	resources, _ := module["resources"].([]interface{})
	for i, r := range resources {
		resource, _ := r.(map[string]interface{})
		typ, typeOK := resource["type"].(string)
		name, nameOK := resource["name"].(string)
		values, valuesOK := resource["values"].(map[string]interface{})
		if !typeOK || !nameOK || (!valuesOK && resource["values"] != nil) {
			return false
		}
		key := name
		if moduleAddress != "" {
			key = moduleAddress + "." + name
		}
		if index, ok := resource["index"]; ok && index != nil {
			key = formatResourceKeyWithIndex(key, index)
		}
		line := 0
		if i < len(resourceLines) && resourceLines[i]["_dd_values"] != nil {
			line = resourceLines[i]["_dd_values"].Line
		}
		d.add(d.resource, typ, typ, key, values, line, nil)
	}
	childLines := lineArray(moduleLines, "_dd_child_modules")
	children, _ := module["child_modules"].([]interface{})
	for i, c := range children {
		child, _ := c.(map[string]interface{})
		address, ok := child["address"].(string)
		if !ok {
			return false
		}
		var lines map[string]*model.LineObject
		if i < len(childLines) {
			lines = childLines[i]
		}
		if !d.readLineInfoModule(child, lines, address) {
			return false
		}
	}
	return true
}

// lineArray returns the line maps of the elements of the array under key.
func lineArray(lines map[string]*model.LineObject, key string) []map[string]*model.LineObject {
	if line := lines[key]; line != nil {
		return line.Arr
	}
	return nil
}

// deletedAddresses returns the set of addresses whose only planned action is
// deletion, e.g. a data source removed from config or dropped by count/for_each.
func deletedAddresses(resourceChanges []resourceChangeView) map[string]bool {
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
func (d *planDocument) readPriorStateData(
	module *hcl_plan.StateModule,
	moduleAddress string,
	resourceLines map[string]int,
	deleted map[string]bool,
) {
	if module == nil {
		return
	}

	for _, resource := range module.Resources {
		if resource.Mode != hcl_plan.DataResourceMode || deleted[resource.Address] {
			continue
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
		// Keep plan-native addresses beside prior-state data values, just as
		// readModule does for planned resources. The scanner's flattened data
		// keys do not preserve Terraform's data. prefix or module path.
		d.add(d.data, resource.Type, "data."+resource.Type, dataKey, resource.AttributeValues,
			resourceLines[resource.Address], map[string]interface{}{planAddressKey: resource.Address})
	}

	for _, childModule := range module.ChildModules {
		d.readPriorStateData(childModule, childModule.Address, resourceLines, deleted)
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
