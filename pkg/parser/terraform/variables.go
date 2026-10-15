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

// localExprs maps local names to their unevaluated expressions. Locals are
// module-wide, so they are evaluated only once every file of the directory and
// every variable value is known (see resolveLocals).
type localExprs map[string]hcl.Expression

// getInputVariablesAndLocalsFromFile parses filename once for both variables and locals.
func getInputVariablesAndLocalsFromFile(
	fsys vfs.FS, filename string,
) (vars converter.VariableMap, locals localExprs, err error) {
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

func extractVarsAndLocalsFromJSON(fsys vfs.FS, filename string) (vars converter.VariableMap, locals localExprs, err error) {
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

func varsAndLocalsFromJSONBlocks(blocks hcl.Blocks) (vars converter.VariableMap, locals localExprs) {
	vars = make(converter.VariableMap)
	locals = make(localExprs)
	evalCtx := &hcl.EvalContext{}
	for _, block := range blocks {
		switch block.Type {
		case blockTypeVariable:
			if len(block.Labels) != 1 || block.Labels[0] == "" {
				continue
			}
			vars[block.Labels[0]] = knownAttrOrUnknown(block.Body, "default", evalCtx)
		case blockTypeLocals:
			attrs, _ := block.Body.JustAttributes()
			for name, attr := range attrs {
				locals[name] = attr.Expr
			}
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

func extractLocals(body *hclsyntax.Body) localExprs {
	locals := make(localExprs)
	if body == nil {
		return locals
	}
	for _, block := range body.Blocks {
		if block.Type != blockTypeLocals {
			continue
		}
		for name, attr := range block.Body.Attributes {
			locals[name] = attr.Expr
		}
	}
	return locals
}

// resolveLocals evaluates the locals of a whole module directory with var,
// local, path and the Terraform functions in scope, repeating until no further
// local resolves, so a local may use variables, functions, and locals declared
// in any file in any order.
func resolveLocals(
	exprs localExprs, vars converter.VariableMap, dir string, fsys vfs.FS,
) converter.VariableMap {
	locals := make(converter.VariableMap, len(exprs))
	variables := map[string]cty.Value{"var": cty.ObjectVal(vars)}
	for name, value := range functions.ContextVariables(dir, "") {
		variables[name] = value
	}
	evalCtx := &hcl.EvalContext{
		Variables: variables,
		Functions: functions.EvalFuncsWithRoot(dir, "", fsys),
	}
	for progress := true; progress && len(locals) < len(exprs); {
		progress = false
		variables["local"] = cty.ObjectVal(locals)
		for name, expr := range exprs {
			if _, ok := locals[name]; ok {
				continue
			}
			val, diags := expr.Value(evalCtx)
			if !diags.HasErrors() && val.IsKnown() {
				locals[name] = val
				progress = true
			}
		}
	}
	return locals
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
	localsExprs := make(localExprs)

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
		for name, expr := range locals {
			localsExprs[name] = expr
		}
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
	cleanLocals := sanitizeCtyMap(resolveLocals(localsExprs, cleanVars, currentPath, fsys))

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
