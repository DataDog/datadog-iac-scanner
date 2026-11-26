/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package terragrunt translates a Terragrunt unit (terragrunt.hcl) into the
// Terraform it means: a module call with the unit's source and values. Nothing
// is executed and no environment is read: values are evaluated statically and
// whatever cannot be known becomes partial.UnknownPlaceholder.
package terragrunt

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/hclexpr"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/hclcache"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	ctyconvert "github.com/zclconf/go-cty/cty/convert"
)

const (
	// VirtualFileName is the name of the translation, a virtual file in the
	// unit's directory.
	VirtualFileName = "terragrunt.generated.tf"
	// ModuleName is the name of the module block of a translation.
	ModuleName = "terragrunt"
)

// reservedArguments cannot be input names: Terraform uses them as meta-arguments.
var reservedArguments = map[string]bool{
	"source": true, "version": true, "count": true, "for_each": true,
	"providers": true, "depends_on": true, "lifecycle": true, "locals": true,
}

// Translate translates the unit file at path, whose content is src. fsys and
// repoRoot are used to read what the unit's directory and its local module
// provide (tfvars files); nothing outside repoRoot is read. An empty repoRoot
// confines reads to the unit's directory.
//
// It returns a nil translation, without error, for a unit that cannot be
// translated: no terraform.source, an unknown source, or unknown inputs as a
// whole. A syntax error in src is returned as an error.
func Translate(ctx context.Context, fsys vfs.FS, repoRoot, path string, src []byte) (*model.TerragruntTranslation, error) {
	if fsys == nil {
		fsys = vfs.DiskFS{}
	}
	body, diags := parseBody(ctx, src, path)
	if diags.HasErrors() {
		return nil, diags
	}
	if body == nil {
		return nil, nil
	}
	t := newTranslator(ctx, fsys, repoRoot, path)
	return t.translate(body)
}

// parseBody parses src as native HCL; the body is nil when it is not one.
func parseBody(ctx context.Context, src []byte, path string) (*hclsyntax.Body, hcl.Diagnostics) {
	file, diags := hclcache.ParseConfig(ctx, src, path)
	if diags.HasErrors() {
		return nil, diags
	}
	body, _ := file.Body.(*hclsyntax.Body)
	return body, nil
}

type translator struct {
	ctx      context.Context
	fsys     vfs.FS
	path     string
	unitDir  string
	root     string
	evalCtx  *hcl.EvalContext
	skipping func(format string, args ...any)
}

func newTranslator(ctx context.Context, fsys vfs.FS, repoRoot, path string) *translator {
	unitDir := filepath.Dir(path)
	absUnit := vfs.AbsOrClean(fsys, unitDir)
	root := absUnit
	if repoRoot != "" {
		root = vfs.AbsOrClean(fsys, repoRoot)
	}
	log := logger.FromContext(ctx)
	return &translator{
		ctx:     ctx,
		fsys:    fsys,
		path:    path,
		unitDir: unitDir,
		root:    root,
		evalCtx: &hcl.EvalContext{Functions: functions.EvalFuncsWithRoot(absUnit, root, fsys)},
		skipping: func(format string, args ...any) {
			log.Info().Msgf("terragrunt: "+format, args...)
		},
	}
}

// argument is one module argument and the item that sets it.
type argument struct {
	value cty.Value
	real  model.SourceLocation
}

func (t *translator) translate(body *hclsyntax.Body) (*model.TerragruntTranslation, error) {
	source, sourceRange, ok := t.source(body)
	if !ok {
		return nil, nil
	}
	args, ok := t.inputs(body)
	if !ok {
		return nil, nil
	}
	for name, a := range t.varFileValues(source) {
		args[name] = a
	}
	return render(source, sourceRange, args), nil
}

// source evaluates terraform.source.
func (t *translator) source(body *hclsyntax.Body) (string, model.SourceLocation, bool) {
	for _, block := range body.Blocks {
		if block.Type != "terraform" {
			continue
		}
		attr, has := block.Body.Attributes["source"]
		if !has {
			continue
		}
		val, diags := attr.Expr.Value(t.evalCtx)
		val, _ = val.UnmarkDeep()
		if diags.HasErrors() || !val.IsWhollyKnown() || val.IsNull() || val.Type() != cty.String || val.AsString() == "" {
			t.skipping("%s: terraform.source is not known, unit skipped", t.path)
			return "", model.SourceLocation{}, false
		}
		return val.AsString(), toRange(attr.SrcRange), true
	}
	t.skipping("%s: no terraform.source, unit skipped", t.path)
	return "", model.SourceLocation{}, false
}

// inputs evaluates the inputs attribute into per-name arguments.
func (t *translator) inputs(body *hclsyntax.Body) (map[string]argument, bool) {
	args := map[string]argument{}
	attr, has := body.Attributes["inputs"]
	if !has {
		return args, true
	}
	if obj, isObj := hclexpr.Unwrap(attr.Expr).(*hclsyntax.ObjectConsExpr); isObj {
		for _, item := range obj.Items {
			name, ok := t.keyName(item.KeyExpr)
			if !ok {
				t.skipping("%s: an input name is not known, input dropped", t.path)
				continue
			}
			args[name] = argument{
				value: evalPartial(item.ValueExpr, t.evalCtx),
				real:  toRange(hcl.RangeBetween(item.KeyExpr.Range(), item.ValueExpr.Range())),
			}
		}
		return args, true
	}
	val, diags := attr.Expr.Value(t.evalCtx)
	val, _ = val.UnmarkDeep()
	isMap := val.Type().IsObjectType() || val.Type().IsMapType()
	if diags.HasErrors() || !val.IsWhollyKnown() || val.IsNull() || !isMap {
		t.skipping("%s: inputs is not known, unit skipped", t.path)
		return nil, false
	}
	for name, v := range val.AsValueMap() {
		args[name] = argument{value: neutralize(v), real: toRange(attr.SrcRange)}
	}
	return args, true
}

func (t *translator) keyName(expr hclsyntax.Expression) (string, bool) {
	k, diags := expr.Value(t.evalCtx)
	return stringKey(k, diags)
}

func stringKey(k cty.Value, diags hcl.Diagnostics) (string, bool) {
	k, _ = k.UnmarkDeep()
	if diags.HasErrors() || !k.IsKnown() || k.IsNull() {
		return "", false
	}
	s, err := ctyconvert.Convert(k, cty.String)
	if err != nil {
		return "", false
	}
	return s.AsString(), true
}

func toRange(r hcl.Range) model.SourceLocation {
	return model.SourceLocation{
		Filename:    r.Filename,
		LineStart:   r.Start.Line,
		ColumnStart: r.Start.Column,
		LineEnd:     r.End.Line,
		ColumnEnd:   r.End.Column,
	}
}

// evalPartial evaluates expr. What cannot be evaluated becomes the
// placeholder, down to the item of an object or tuple constructor.
func evalPartial(expr hcl.Expression, ctx *hcl.EvalContext) cty.Value {
	val, diags := expr.Value(ctx)
	if !diags.HasErrors() {
		return neutralize(val)
	}
	switch e := expr.(type) {
	case *hclsyntax.ParenthesesExpr:
		return evalPartial(e.Expression, ctx)
	case *hclsyntax.ObjectConsExpr:
		attrs := make(map[string]cty.Value, len(e.Items))
		for _, item := range e.Items {
			k, kd := item.KeyExpr.Value(ctx)
			name, ok := stringKey(k, kd)
			if !ok {
				continue
			}
			attrs[name] = evalPartial(item.ValueExpr, ctx)
		}
		return cty.ObjectVal(attrs)
	case *hclsyntax.TupleConsExpr:
		elems := make([]cty.Value, 0, len(e.Exprs))
		for _, sub := range e.Exprs {
			elems = append(elems, evalPartial(sub, ctx))
		}
		return cty.TupleVal(elems)
	}
	return unknownValue()
}

func unknownValue() cty.Value { return cty.StringVal(partial.UnknownPlaceholder) }

// neutralize unmarks val and replaces its unknown parts with the placeholder.
func neutralize(val cty.Value) cty.Value {
	val, _ = val.UnmarkDeep()
	out, err := cty.Transform(val, func(_ cty.Path, v cty.Value) (cty.Value, error) {
		if !v.IsKnown() {
			return unknownValue(), nil
		}
		return v, nil
	})
	if err != nil {
		return unknownValue()
	}
	return out
}

// varFileValues returns the values of the tfvars files Terraform would load in
// the working copy Terragrunt builds: the local module's files overlaid by the
// unit directory's, a file of the unit replacing the module's of the same name.
func (t *translator) varFileValues(source string) map[string]argument {
	unitNames := t.fileNames(t.unitDir)
	moduleDir := t.localModuleDir(source)
	var moduleNames []string
	if moduleDir != "" {
		moduleNames = t.fileNames(moduleDir)
	}
	inUnit := make(map[string]bool, len(unitNames))
	names := append([]string(nil), unitNames...)
	for _, n := range unitNames {
		inUnit[n] = true
	}
	for _, n := range moduleNames {
		if !inUnit[n] {
			names = append(names, n)
		}
	}
	values := map[string]argument{}
	for _, name := range tfpath.AutoloadedVarFiles(names) {
		dir := moduleDir
		if inUnit[name] {
			dir = t.unitDir
		}
		for k, v := range t.readVarFile(filepath.Join(dir, name)) {
			values[k] = v
		}
	}
	return values
}

// localModuleDir is the directory of a local module source, resolved as the
// engine does, or "" when the source is remote or leaves the repository.
func (t *translator) localModuleDir(source string) string {
	if !isLocalSource(source) {
		return ""
	}
	if !strings.Contains(source, "/") { // "." and ".." need a separator to be local
		source += "/"
	}
	dir, _, err := tfmodules.LocalModuleDirWithContext(t.ctx, t.fsys, t.unitDir, source)
	if err != nil || dir == "" {
		return ""
	}
	if !t.confined(dir) {
		t.skipping("%s: module directory is outside the repository, its tfvars files are ignored", t.path)
		return ""
	}
	return dir
}

// isLocalSource tells whether a terraform.source is a local directory.
func isLocalSource(source string) bool {
	return tfmodules.LooksLikeLocalModuleSource(source) || source == "." || source == ".."
}

func (t *translator) confined(p string) bool {
	_, err := functions.ConfinePath(t.root, t.fsys, vfs.AbsOrClean(t.fsys, p))
	return err == nil
}

// fileNames lists the regular files of dir, none when it is not readable or
// leaves the repository.
func (t *translator) fileNames(dir string) []string {
	if !t.confined(dir) {
		return nil
	}
	entries, err := t.fsys.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}

func (t *translator) readVarFile(path string) map[string]argument {
	if !t.confined(path) {
		return nil
	}
	src, err := tfmodules.ReadConfigFile(t.ctx, t.fsys, path, "")
	if err != nil {
		t.skipping("%s: cannot read %s, ignored: %v", t.path, path, err)
		return nil
	}
	attrs := tfmodules.ParseVarsFile(src, path)
	values := make(map[string]argument, len(attrs))
	for name, attr := range attrs {
		values[name] = argument{value: evalPartial(attr.Expr, &hcl.EvalContext{}), real: toRange(attr.Range)}
	}
	return values
}

// render writes the module block and its line table.
func render(source string, sourceRange model.SourceLocation, args map[string]argument) *model.TerragruntTranslation {
	var b strings.Builder
	var table model.LineTable
	line := 1
	add := func(name string, real model.SourceLocation, text string) {
		n := strings.Count(text, "\n") + 1
		b.WriteString(text)
		b.WriteByte('\n')
		table = append(table, model.LineMapping{FromLine: line, ToLine: line + n - 1, Argument: name, Real: real})
		line += n
	}
	add("", sourceRange, fmt.Sprintf("module %q {", ModuleName))
	add("source", sourceRange, "  source = "+renderValue(cty.StringVal(source)))

	names := make([]string, 0, len(args))
	for name := range args {
		if reservedArguments[name] || !hclsyntax.ValidIdentifier(name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		a := args[name]
		text := renderValue(a.value)
		add(name, a.real, "  "+name+" = "+strings.ReplaceAll(text, "\n", "\n  "))
	}
	add("", sourceRange, "}")
	return &model.TerragruntTranslation{FileName: VirtualFileName, Text: b.String(), Lines: table}
}

// renderValue writes v as HCL. TokensForValue escapes the placeholder into a
// literal string; it is written back as a reference the evaluator cannot resolve.
func renderValue(v cty.Value) string {
	out := hclwrite.Format(hclwrite.TokensForValue(v).Bytes())
	text := strings.TrimSpace(string(out))
	return strings.ReplaceAll(text, "$"+partial.UnknownPlaceholder, partial.UnknownPlaceholder)
}
