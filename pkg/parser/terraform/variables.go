/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/vartype"
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
	// varReference is the root name expressions read input variables through.
	varReference = "var"
	// pathReference is the root name expressions read path.module, path.root
	// and path.cwd through.
	pathReference = "path"
)

var terraformVarsPathRegex = regexp.MustCompile(`(?m)^\s*// ` + terraformVarsPathDirective + `: ([\w/\\.:-]+)\r?\n`)

func mergeMaps(baseMap, newItems converter.VariableMap) {
	for key, value := range newItems {
		baseMap[key] = value
	}
}

func parseHCLBody(ctx context.Context, fsys vfs.FS, filename string) (*hclsyntax.Body, error) {
	src, err := tfmodules.ReadConfigFile(ctx, fsys, filename, "")
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

func getInputVariablesFromFile(ctx context.Context, fsys vfs.FS, filename string) (converter.VariableMap, error) {
	if tfpath.IsTFVarsJSON(filename) {
		return getInputVariablesFromJSONFile(ctx, fsys, filename)
	}
	body, err := parseHCLBody(ctx, fsys, filename)
	if err != nil {
		return nil, err
	}
	return extractInputVariables(body, filename), nil
}

func getInputVariablesFromJSONFile(ctx context.Context, fsys vfs.FS, filename string) (converter.VariableMap, error) {
	src, err := tfmodules.ReadConfigFile(ctx, fsys, filename, "")
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
		// JSON values are literal, as Terraform reads them: without an
		// evaluation context, "${0}" stays that string.
		val, diags := attr.Expr.Value(nil)
		if !diags.HasErrors() && val.IsKnown() {
			variables[name] = val
		}
	}
	return variables, nil
}

// getInputVariablesAndLocalsFromFile parses filename once for its variable
// declarations and locals assignments. A file declaring no variable may hold
// variable values as top-level attributes, which values returns.
func getInputVariablesAndLocalsFromFile(
	ctx context.Context, fsys vfs.FS, filename string,
) (decls []variableDeclaration, values converter.VariableMap, assignments []localAssignment, err error) {
	if tfpath.IsJSONConfig(filename) {
		return extractVarsAndLocalsFromJSON(ctx, fsys, filename)
	}
	body, err := parseHCLBody(ctx, fsys, filename)
	if err != nil {
		return nil, nil, nil, err
	}
	if body == nil {
		return nil, nil, nil, nil
	}
	for _, block := range body.Blocks {
		if block.Type != blockTypeVariable || len(block.Labels) != 1 || block.Labels[0] == "" {
			continue
		}
		attrs := block.Body.Attributes
		decls = append(decls, newVariableDeclaration(block.Labels[0], func(name string) (hcl.Expression, bool) {
			attr, ok := attrs[name]
			if !ok {
				return nil, false
			}
			return attr.Expr, true
		}))
	}
	if len(decls) == 0 {
		values = extractInputVariables(body, filename)
	}
	return decls, values, localAssignmentsFromBody(body), nil
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

func extractVarsAndLocalsFromJSON(
	ctx context.Context, fsys vfs.FS, filename string,
) (decls []variableDeclaration, values converter.VariableMap, assignments []localAssignment, err error) {
	src, err := tfmodules.ReadConfigFile(ctx, fsys, filename, "")
	if err != nil {
		return nil, nil, nil, err
	}
	parsed, diags := hcljson.Parse(src, filename)
	if diags.HasErrors() {
		return nil, nil, nil, diags
	}
	content, _, diags := parsed.Body.PartialContent(jsonConfigSchema)
	if diags.HasErrors() && content == nil {
		return nil, nil, nil, diags
	}

	decls, assignments = varsAndLocalsFromJSONBlocks(content.Blocks)
	return decls, nil, assignments, nil
}

func varsAndLocalsFromJSONBlocks(blocks hcl.Blocks) (decls []variableDeclaration, assignments []localAssignment) {
	for _, block := range blocks {
		switch block.Type {
		case blockTypeVariable:
			if len(block.Labels) != 1 || block.Labels[0] == "" {
				continue
			}
			attrs, _ := block.Body.JustAttributes()
			decls = append(decls, newVariableDeclaration(block.Labels[0], func(name string) (hcl.Expression, bool) {
				attr, ok := attrs[name]
				if !ok {
					return nil, false
				}
				return attr.Expr, true
			}))
		case blockTypeLocals:
			assignments = append(assignments, jsonLocalAssignments(block.Body)...)
		}
	}
	return decls, assignments
}

// jsonLocalAssignments returns the assignments of a JSON locals block, by name.
func jsonLocalAssignments(body hcl.Body) []localAssignment {
	attrs, _ := body.JustAttributes()
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)
	assignments := make([]localAssignment, 0, len(attrs))
	for _, name := range names {
		assignments = append(assignments, localAssignment{name: name, expr: attrs[name].Expr})
	}
	return assignments
}

// localAssignment is a locals attribute. getInputVariables evaluates the
// effective assignments of a directory once every variable value is known,
// and getDataSourcePolicy those reading data again once data is rendered.
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
// data is rendered, so only these are worth re-evaluating: getInputVariables
// already resolved the others with variables and functions, whether or not
// the directory declares a policy document.
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
			if name, ok := LocalTraversalName(traversal); ok {
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

// LocalTraversalName returns the local a local.<name> or local["<name>"]
// traversal reads.
func LocalTraversalName(traversal hcl.Traversal) (string, bool) {
	if traversal.RootName() != blockTypeLocalReference || len(traversal) < 2 {
		return "", false
	}
	return staticStepName(traversal[1])
}

// refreshLocals re-evaluates locals against vars (including data) so try /
// coalesce fallbacks that succeeded early can pick up chained data sources.
// They are evaluated with the functions and path of evalCtx, under the rules
// of the other locals: a local reading anything but var, path, data and
// declared locals, calling a function the scanner does not evaluate locals
// with, or reading a value that is not wholly known (an unrendered data
// document included) keeps its value, so try and can do not fall back past
// what the scanner cannot read. The locals of declared that vars does not
// hold are unknown while they are evaluated, and only resolved values are
// written back to vars.
func refreshLocals(
	vars converter.VariableMap, declared, assignments []localAssignment, evalCtx localEvalContext,
) bool {
	if len(assignments) == 0 {
		return false
	}
	resolved := objectValues(vars[blockTypeLocalReference])
	current := declaredLocals(resolved, declared)
	scope := map[string]cty.Value{varReference: vars[varReference], terraformDataIdentifier: vars[terraformDataIdentifier]}
	if evalCtx.path != cty.NilVal {
		scope[pathReference] = evalCtx.path
	}
	assignments = refreshableLocals(assignments, current, scope, evalCtx.funcs)
	changed := false
	for pass := 0; pass < len(assignments)+1; pass++ {
		passChanged := false
		evalVars := cloneVariableMap(vars)
		for name, value := range scope {
			evalVars[name] = value
		}
		evalVars[blockTypeLocalReference] = cty.ObjectVal(current)
		hclCtx := &hcl.EvalContext{Variables: evalVars, Functions: evalCtx.funcs}
		for _, item := range assignments {
			if !readsOnlyKnownValues(item.expr, evalVars) {
				continue
			}
			val, diags := item.expr.Value(hclCtx)
			if diags.HasErrors() || !val.IsWhollyKnown() {
				continue
			}
			if prev, ok := current[item.name]; ok && prev.RawEquals(val) {
				continue
			}
			current[item.name] = val
			resolved[item.name] = val
			passChanged = true
			changed = true
		}
		if !passChanged {
			break
		}
	}
	if changed {
		vars[blockTypeLocalReference] = cty.ObjectVal(resolved)
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
	fileValues := make(converter.VariableMap)

	tfFiles := hclConfigFiles(ctx, fsys, currentPath, allow, keep)
	var (
		locals    localDeclarations
		variables variableDeclarations
	)

	// Parse all .tf/.tofu files for variables and locals
	for _, tfFile := range tfFiles {
		decls, values, assignments, err := getInputVariablesAndLocalsFromFile(ctx, fsys, tfFile)
		if err != nil {
			// Non-fatal: a sibling may be unreadable (broken symlink, partial
			// MemFS push) or invalid HCL (testdata). Match getDataSourcePolicy.
			contextLogger.Debug().Err(err).Msgf("Skipping default values and locals from %s", tfFile)
			continue
		}
		variables.add(tfFile, decls)
		mergeMaps(fileValues, values)
		locals.add(tfFile, assignments)
	}

	// Values in increasing precedence: defaults, then variable definitions
	// files, then the explicit variables file.
	declared := variables.effective()
	variablesMap := make(converter.VariableMap, len(declared))
	for name, decl := range declared {
		variablesMap[name] = decl.defaultValue()
	}
	mergeMaps(variablesMap, fileValues)

	for _, tfVarsFile := range autoloadedVarFiles(ctx, fsys, currentPath) {
		vars, errInput := getInputVariablesFromFile(ctx, fsys, tfVarsFile)
		if errInput != nil {
			event := contextLogger.Warn()
			if errors.Is(errInput, tfmodules.ErrSkippedLinkPlaceholder) {
				event = contextLogger.Debug()
			}
			event.Err(errInput).Msgf("Skipping values from %s", tfVarsFile)
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
			vars, errInput := getInputVariablesFromFile(ctx, fsys, terraformVarsPath)
			if errInput != nil {
				event := contextLogger.Error()
				if errors.Is(errInput, tfmodules.ErrSkippedLinkPlaceholder) {
					event = contextLogger.Debug()
				}
				event.Err(errInput).Msgf("Error getting values from %s", terraformVarsPath)
			} else {
				mergeMaps(variablesMap, vars)
			}
		} else {
			contextLogger.Trace().Msgf("%s file not found", terraformVarsPath)
		}
	}

	for name, decl := range declared {
		variablesMap[name] = decl.conform(variablesMap[name])
	}

	// Final sanitized maps
	cleanVars := sanitizeCtyMap(variablesMap)
	evalCtx := newLocalEvalContext(fsys, currentPath)
	// Every variable value is now known, so each local is evaluated once, from
	// its declaration in the order Terraform applies files, as a direct var.x
	// in a resource already is. A local that does not resolve is missing, as
	// before (see resolveRootLocals).
	localsMap := resolveRootLocals(lastLocalAssignments(locals.all()), evalCtx.scope(cty.ObjectVal(cleanVars)), evalCtx.funcs)
	cleanLocals := sanitizeCtyMap(localsMap)

	result := make(converter.VariableMap)
	result[varReference] = cty.ObjectVal(cleanVars)
	result[blockTypeLocalReference] = cty.ObjectVal(cleanLocals)
	return result
}

// variableDeclaration is what one variable block sets. An argument the block
// does not set is nil, so an override file replaces only the arguments it
// sets, as Terraform merges it.
type variableDeclaration struct {
	name string
	// def is the default, unknown when it does not evaluate.
	def        *cty.Value
	constraint *vartype.Constraint
	nullable   *bool
}

// newVariableDeclaration reads a variable block through attr, which returns
// the expression of one of its arguments. The default is evaluated without an
// evaluation context, as Terraform does: a JSON default is a literal value,
// so "${0}" stays that string rather than a template.
func newVariableDeclaration(name string, attr func(string) (hcl.Expression, bool)) variableDeclaration {
	decl := variableDeclaration{name: name}
	if expr, ok := attr("default"); ok {
		v, diags := expr.Value(nil)
		if diags.HasErrors() || !v.IsKnown() {
			v = cty.DynamicVal
		}
		decl.def = &v
	}
	if expr, ok := attr("type"); ok {
		constraint, _ := vartype.Parse(expr)
		decl.constraint = &constraint
	}
	if expr, ok := attr("nullable"); ok {
		if v, diags := expr.Value(nil); !diags.HasErrors() && v.Type() == cty.Bool && ctyutil.Materialized(v) {
			nullable := v.True()
			decl.nullable = &nullable
		}
	}
	return decl
}

// defaultValue is the value of the variable before any variable definitions
// file: its default, or unknown without one, so try and can see a variable
// that exists.
func (d variableDeclaration) defaultValue() cty.Value {
	if d.def == nil {
		return cty.UnknownVal(cty.DynamicPseudoType)
	}
	return *d.def
}

// conform returns the value the configuration reads for the variable given v,
// as Terraform resolves it: a null given to a non-nullable variable takes the
// default, and the value is converted to the type, with the defaults of its
// optional attributes. A value Terraform rejects is unknown; module
// evaluation (tfeval) keeps such a value as given instead.
func (d variableDeclaration) conform(v cty.Value) cty.Value {
	if v.IsNull() && d.nullable != nil && !*d.nullable {
		v = d.defaultValue()
		if v.IsNull() {
			return cty.UnknownVal(cty.DynamicPseudoType)
		}
	}
	if d.constraint == nil || !v.IsWhollyKnown() {
		return v
	}
	conformed, err := d.constraint.Conform(v)
	if err != nil {
		return cty.UnknownVal(cty.DynamicPseudoType)
	}
	return conformed
}

// variableDeclarations collects the variable blocks of a directory in the
// order Terraform applies them: those of ordinary files, then those of
// override files, each in file order.
type variableDeclarations struct {
	ordinary, overrides []variableDeclaration
}

func (d *variableDeclarations) add(file string, decls []variableDeclaration) {
	if tfpath.IsOverride(file) {
		d.overrides = append(d.overrides, decls...)
		return
	}
	d.ordinary = append(d.ordinary, decls...)
}

// effective returns the declaration of each variable: its last ordinary
// block, with the arguments each override block sets replaced in turn. An
// override without a default keeps the inherited one.
func (d *variableDeclarations) effective() map[string]variableDeclaration {
	out := make(map[string]variableDeclaration, len(d.ordinary))
	for _, decl := range d.ordinary {
		out[decl.name] = decl
	}
	for _, override := range d.overrides {
		base, ok := out[override.name]
		if !ok {
			out[override.name] = override
			continue
		}
		if override.def != nil {
			base.def = override.def
		}
		if override.constraint != nil {
			base.constraint = override.constraint
		}
		if override.nullable != nil {
			base.nullable = override.nullable
		}
		out[override.name] = base
	}
	return out
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
