/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
)

const (
	// terraformVarsPathDirective is the inline comment prefix that overrides the tfvars path for a file.
	terraformVarsPathDirective = "kics_terraform_vars"
	blockTypeVariable          = "variable"
	blockTypeLocals            = "locals"
	// blockTypeLocalReference is the root name expressions read locals through.
	blockTypeLocalReference = "local"
)

var terraformVarsPathRegex = regexp.MustCompile(`(?m)^\s*// ` + terraformVarsPathDirective + `: ([\w/\\.:-]+)\r?\n`)

func mergeMaps(baseMap, newItems converter.VariableMap) {
	for key, value := range newItems {
		baseMap[key] = value
	}
}

func parseHCLBody(fsys vfs.FS, filename string) (*hclsyntax.Body, error) {
	src, err := fsys.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, err
	}

	parsedFile, diags := hclsyntax.ParseConfig(src, filename, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, diags
	}
	body, _ := parsedFile.Body.(*hclsyntax.Body)
	return body, nil
}

func getInputVariablesFromFile(fsys vfs.FS, filename string) (converter.VariableMap, error) {
	if tfpath.IsTFVarsJSON(filename) {
		return getInputVariablesFromJSONFile(fsys, filename)
	}
	body, err := parseHCLBody(fsys, filename)
	if err != nil {
		return nil, err
	}
	return extractInputVariables(body, filename), nil
}

func getInputVariablesFromJSONFile(fsys vfs.FS, filename string) (converter.VariableMap, error) {
	src, err := fsys.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, err
	}
	parsed, diags := hcljson.Parse(src, filename)
	if diags.HasErrors() {
		return nil, diags
	}
	attrs, _ := parsed.Body.JustAttributes()
	variables := make(converter.VariableMap, len(attrs))
	for name, attr := range attrs {
		val, diags := attr.Expr.Value(&hcl.EvalContext{})
		if !diags.HasErrors() && val.IsKnown() {
			variables[name] = val
		}
	}
	return variables, nil
}

// getInputVariablesAndLocalsFromFile parses filename once for both variables and locals.
func getInputVariablesAndLocalsFromFile(
	fsys vfs.FS, filename string,
) (vars, locals converter.VariableMap, err error) {
	if tfpath.IsJSONConfig(filename) {
		return extractVarsAndLocalsFromJSON(fsys, filename)
	}
	body, err := parseHCLBody(fsys, filename)
	if err != nil {
		return nil, nil, err
	}
	return extractInputVariables(body, filename), extractLocals(body), nil
}

// nolint:gocyclo
func extractInputVariables(body *hclsyntax.Body, filename string) converter.VariableMap {
	variables := make(converter.VariableMap)
	if body == nil {
		return variables
	}

	// Case 1: .tfvars-style assignments
	if filepath.Ext(filename) == ".tfvars" || strings.HasSuffix(filename, ".auto.tfvars") {
		for name, attr := range body.Attributes {
			val, diags := attr.Expr.Value(&hcl.EvalContext{})
			if !diags.HasErrors() && val.IsKnown() {
				variables[name] = val
			}
		}
		return variables
	}

	// Case 2: .tf variable "x" { default = ... }
	hasVariableBlock := false
	for _, block := range body.Blocks {
		if block.Type == blockTypeVariable && len(block.Labels) == 1 && block.Labels[0] != "" {
			hasVariableBlock = true
			varName := block.Labels[0]
			if defaultAttr, exists := block.Body.Attributes["default"]; exists {
				val, diags := defaultAttr.Expr.Value(&hcl.EvalContext{})
				if !diags.HasErrors() && val.IsKnown() {
					variables[varName] = val
					continue
				}
			}
			// Declared but unset: keep the attribute so try/can see unknown, not a missing key.
			variables[varName] = cty.UnknownVal(cty.DynamicPseudoType)
		}
	}

	// If no variable blocks found but has attributes, treat as .tfvars-style
	if !hasVariableBlock && len(body.Attributes) > 0 {
		for name, attr := range body.Attributes {
			val, diags := attr.Expr.Value(&hcl.EvalContext{})
			if !diags.HasErrors() && val.IsKnown() {
				variables[name] = val
			}
		}
	}

	return variables
}

func extractVarsAndLocalsFromJSON(fsys vfs.FS, filename string) (vars, locals converter.VariableMap, err error) {
	src, err := fsys.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, nil, err
	}
	parsed, diags := hcljson.Parse(src, filename)
	if diags.HasErrors() {
		return nil, nil, diags
	}
	content, _, diags := parsed.Body.PartialContent(jsonConfigSchema)
	if diags.HasErrors() && content == nil {
		return nil, nil, diags
	}

	vars, locals = varsAndLocalsFromJSONBlocks(content.Blocks)
	return vars, locals, nil
}

func varsAndLocalsFromJSONBlocks(blocks hcl.Blocks) (vars, locals converter.VariableMap) {
	vars = make(converter.VariableMap)
	locals = make(converter.VariableMap)
	evalCtx := &hcl.EvalContext{}
	for _, block := range blocks {
		switch block.Type {
		case blockTypeVariable:
			if len(block.Labels) != 1 || block.Labels[0] == "" {
				continue
			}
			vars[block.Labels[0]] = knownAttrOrUnknown(block.Body, "default", evalCtx)
		case blockTypeLocals:
			mergeKnownAttributes(locals, block.Body)
		}
	}
	return vars, locals
}

func knownAttrOrUnknown(body hcl.Body, name string, evalCtx *hcl.EvalContext) cty.Value {
	attrs, _ := body.JustAttributes()
	if def, ok := attrs[name]; ok {
		val, diags := def.Expr.Value(evalCtx)
		if !diags.HasErrors() && val.IsKnown() {
			return val
		}
	}
	return cty.UnknownVal(cty.DynamicPseudoType)
}

func mergeKnownAttributes(dst converter.VariableMap, body hcl.Body) {
	attrs, _ := body.JustAttributes()
	assignments := make([]localAssignment, 0, len(attrs))
	for name, attr := range attrs {
		assignments = append(assignments, localAssignment{name: name, expr: attr.Expr})
	}
	assignments = lastLocalAssignments(assignments)
	evalLocalPrePass(dst, assignments)
}

func extractLocals(body *hclsyntax.Body) converter.VariableMap {
	locals := make(converter.VariableMap)
	if body == nil {
		return locals
	}
	assignments := lastLocalAssignments(localAssignmentsFromBody(body))
	evalLocalPrePass(locals, assignments)
	return locals
}

// evalLocalPrePass resolves the locals a locals-only context can compute: an
// assignment waits until it reads only resolved locals, so try and can do not
// keep a fallback for a value that exists. Nulls are stored like other values.
func evalLocalPrePass(dst converter.VariableMap, assignments []localAssignment) {
	for pass := 0; pass < len(assignments)+1; pass++ {
		changed := false
		for _, item := range assignments {
			if _, ok := dst[item.name]; ok {
				continue
			}
			if !evaluableWithLocalsOnly(item.expr, dst) {
				continue
			}
			// The context holds the locals resolved so far, including ones
			// this pass resolved, so it is built per assignment.
			evalCtx := &hcl.EvalContext{
				Variables: map[string]cty.Value{"local": cty.ObjectVal(dst)},
				Functions: functions.TerraformFuncs,
			}
			val, diags := item.expr.Value(evalCtx)
			if !diags.HasErrors() && val.IsKnown() {
				dst[item.name] = val
				changed = true
			}
		}
		if !changed {
			break
		}
	}
}

// evaluableWithLocalsOnly reports whether expr reads nothing but locals that
// already hold a value in resolved. Whole-object reads (local[local.k]) may
// evaluate once the key they read resolves, except under try or can, which
// would keep a fallback for a key that appears later.
func evaluableWithLocalsOnly(expr hcl.Expression, resolved converter.VariableMap) bool {
	strict := usesTryOrCan(expr)
	for _, traversal := range expr.Variables() {
		if traversal.RootName() != blockTypeLocalReference {
			return false
		}
		name, ok := localTraversalName(traversal)
		if !ok {
			if strict {
				return false
			}
			continue
		}
		if _, done := resolved[name]; !done {
			return false
		}
	}
	return true
}

// usesTryOrCan reports whether expr calls try or can, which turn a missing
// local into a value instead of an error. An expression whose syntax tree
// cannot be inspected is treated as if it did.
func usesTryOrCan(expr hcl.Expression) bool {
	syntaxExpr, ok := expr.(hclsyntax.Expression)
	if !ok {
		return true
	}
	uses := false
	_ = hclsyntax.VisitAll(syntaxExpr, func(node hclsyntax.Node) hcl.Diagnostics {
		if call, ok := node.(*hclsyntax.FunctionCallExpr); ok && (call.Name == "try" || call.Name == "can") {
			uses = true
		}
		return nil
	})
	return uses
}

// localAssignment is a locals attribute, held back from the locals-only
// pre-pass while it reads more than resolved locals and evaluated again once
// data (or other) namespaces become available.
type localAssignment struct {
	name string
	expr hcl.Expression
}

func localAssignmentsFromBody(body *hclsyntax.Body) []localAssignment {
	var out []localAssignment
	for _, block := range body.Blocks {
		if block.Type != blockTypeLocals {
			continue
		}
		for name, attr := range block.Body.Attributes {
			out = append(out, localAssignment{name: name, expr: attr.Expr})
		}
	}
	return out
}

// lastLocalAssignments keeps the last declaration of each local name, in
// parse order: a later block, or a later file, wins.
func lastLocalAssignments(all []localAssignment) []localAssignment {
	last := make(map[string]int, len(all))
	for i, item := range all {
		last[item.name] = i
	}
	out := make([]localAssignment, 0, len(last))
	for i, item := range all {
		if last[item.name] == i {
			out = append(out, item)
		}
	}
	return out
}

// dataDependentLocals returns the locals that read data, directly or through
// other locals. A local declared in several files takes its last declaration,
// as the locals of the input variables do. Only these locals can change once
// data is rendered, so only these are worth re-evaluating: evaluating the
// others here, with variables and functions, would resolve them differently
// depending on whether the directory declares a policy document.
func dataDependentLocals(all []localAssignment) []localAssignment {
	last := make(map[string]int, len(all))
	for i, item := range all {
		last[item.name] = i
	}
	effective := make([]localAssignment, 0, len(last))
	reads := make([]localReads, 0, len(last))
	for i, item := range all {
		if last[item.name] == i {
			effective = append(effective, item)
			reads = append(reads, readsOf(item.expr))
		}
	}
	dependent := make(map[string]bool, len(effective))
	for changed := true; changed; {
		changed = false
		for i, item := range effective {
			if !dependent[item.name] && reads[i].dependsOn(dependent) {
				dependent[item.name] = true
				changed = true
			}
		}
	}
	var out []localAssignment
	for _, item := range effective {
		if dependent[item.name] {
			out = append(out, item)
		}
	}
	return out
}

// localReads is what a local expression reads besides variables.
type localReads struct {
	data   bool
	locals []string
	// anyLocal is set when the expression indexes local with a key that is not
	// a literal, so it may read any local.
	anyLocal bool
}

func readsOf(expr hcl.Expression) localReads {
	var r localReads
	for _, traversal := range expr.Variables() {
		switch traversal.RootName() {
		case terraformDataIdentifier:
			r.data = true
		case blockTypeLocalReference:
			if name, ok := localTraversalName(traversal); ok {
				r.locals = append(r.locals, name)
			} else {
				r.anyLocal = true
			}
		}
	}
	return r
}

// dependsOn reports whether the expression reads data or one of the locals in
// dependent, which read data themselves.
func (r localReads) dependsOn(dependent map[string]bool) bool {
	if r.data || (r.anyLocal && len(dependent) > 0) {
		return true
	}
	for _, name := range r.locals {
		if dependent[name] {
			return true
		}
	}
	return false
}

// localTraversalName returns the local a local.<name> or local["<name>"]
// traversal reads.
func localTraversalName(traversal hcl.Traversal) (string, bool) {
	if len(traversal) < 2 {
		return "", false
	}
	switch step := traversal[1].(type) {
	case hcl.TraverseAttr:
		return step.Name, true
	case hcl.TraverseIndex:
		if step.Key.IsKnown() && !step.Key.IsNull() && step.Key.Type() == cty.String {
			return step.Key.AsString(), true
		}
	}
	return "", false
}

// refreshLocals re-evaluates locals against vars (including data) so try /
// coalesce fallbacks that succeeded early can pick up chained data sources.
func refreshLocals(vars converter.VariableMap, assignments []localAssignment) bool {
	if len(assignments) == 0 {
		return false
	}
	current := objectValues(vars["local"])
	changed := false
	for pass := 0; pass < len(assignments)+1; pass++ {
		passChanged := false
		evalVars := cloneVariableMap(vars)
		evalVars["local"] = cty.ObjectVal(current)
		evalCtx := &hcl.EvalContext{Variables: evalVars, Functions: functions.TerraformFuncs}
		for _, item := range assignments {
			val, diags := item.expr.Value(evalCtx)
			if diags.HasErrors() || !val.IsKnown() {
				continue
			}
			if prev, ok := current[item.name]; ok && prev.RawEquals(val) {
				continue
			}
			current[item.name] = val
			passChanged = true
			changed = true
		}
		if !passChanged {
			break
		}
	}
	if changed {
		vars["local"] = cty.ObjectVal(current)
	}
	return changed
}

func objectValues(v cty.Value) converter.VariableMap {
	out := make(converter.VariableMap)
	if !v.IsKnown() || v.IsNull() || !v.CanIterateElements() || !v.Type().IsObjectType() {
		return out
	}
	for k, elem := range v.AsValueMap() {
		out[k] = elem
	}
	return out
}

func sanitizeCtyMap(in map[string]cty.Value) map[string]cty.Value {
	out := make(map[string]cty.Value)
	for k, v := range in {
		if v.IsNull() {
			out[k] = cty.NullVal(v.Type())
			continue
		}
		out[k] = v
	}
	return out
}

func getInputVariables(
	ctx context.Context, fsys vfs.FS, currentPath, fileContent, terraformVarsPath string,
	allow map[string]struct{}, keep string,
) converter.VariableMap {
	contextLogger := logger.FromContext(ctx)
	variablesMap := make(converter.VariableMap)
	localsMap := make(converter.VariableMap)

	tfFiles := hclConfigFiles(ctx, fsys, currentPath, allow, keep)

	// Parse all .tf/.tofu files for variables and locals
	for _, tfFile := range tfFiles {
		vars, locals, err := getInputVariablesAndLocalsFromFile(fsys, tfFile)
		if err != nil {
			// Non-fatal: a sibling may be unreadable (broken symlink, partial
			// MemFS push) or invalid HCL (testdata). Match getDataSourcePolicy.
			contextLogger.Debug().Err(err).Msgf("Skipping default values and locals from %s", tfFile)
			continue
		}
		mergeMaps(variablesMap, vars)
		mergeMaps(localsMap, locals)
	}

	for _, tfVarsFile := range autoloadedVarFiles(ctx, fsys, currentPath) {
		vars, errInput := getInputVariablesFromFile(fsys, tfVarsFile)
		if errInput != nil {
			contextLogger.Warn().Err(errInput).Msgf("Skipping values from %s", tfVarsFile)
			continue
		}
		mergeMaps(variablesMap, vars)
	}

	if terraformVarsPath == "" {
		match := terraformVarsPathRegex.FindStringSubmatch(fileContent)
		if match != nil {
			terraformVarsPath = filepath.FromSlash(strings.ReplaceAll(match[1], "\\", "/"))
			if !strings.Contains(match[1], ":") {
				terraformVarsPath = filepath.Join(currentPath, terraformVarsPath)
			}
		}
	}

	if terraformVarsPath != "" {
		if _, err := fsys.Stat(terraformVarsPath); err == nil {
			vars, errInput := getInputVariablesFromFile(fsys, terraformVarsPath)
			if errInput != nil {
				contextLogger.Error().Err(errInput).Msgf("Error getting values from %s", terraformVarsPath)
			} else {
				mergeMaps(variablesMap, vars)
			}
		} else {
			contextLogger.Trace().Msgf("%s file not found", terraformVarsPath)
		}
	}

	// Final sanitized maps
	cleanVars := sanitizeCtyMap(variablesMap)
	cleanLocals := sanitizeCtyMap(localsMap)

	result := make(converter.VariableMap)
	result["var"] = cty.ObjectVal(cleanVars)
	result["local"] = cty.ObjectVal(cleanLocals)
	return result
}

// autoloadedVarFiles lists the variable definitions files Terraform loads from
// dir on its own, in the order it applies them.
func autoloadedVarFiles(ctx context.Context, fsys vfs.FS, dir string) []string {
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Error().Msg("Error listing variable definitions files")
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	files := tfpath.AutoloadedVarFiles(names)
	for i, name := range files {
		files[i] = filepath.Join(dir, name)
	}
	return files
}

func hclConfigFiles(ctx context.Context, fsys vfs.FS, dir string, allow map[string]struct{}, keep string) []string {
	contextLogger := logger.FromContext(ctx)
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		contextLogger.Error().Msg("Error listing Terraform configuration files")
		return nil
	}
	names := tfmodules.SelectConfigNames(entries, dir, allow, keep)
	out := make([]string, len(names))
	for i, name := range names {
		out[i] = filepath.Join(dir, name)
	}
	return out
}
