/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terragrunt

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// stackDir is where terragrunt stack generate writes a stack's units.
const stackDir = ".terragrunt-stack"

// StackUnit is a unit a stack generates, evaluated where Terragrunt writes it.
// Its call is declared by the stack file: the generated directory is not part
// of the repository.
type StackUnit struct {
	// Name labels the call: the unit block's name, prefixed by the names of
	// the nested stacks it comes from.
	Name      string
	StackFile string
	// Block is the unit block, or the outermost stack block of a nested
	// stack's unit.
	Block hcl.Range
	// ValueRanges are where the stack file sets each value of the unit.
	ValueRanges map[string]hcl.Range
	Unit        *Unit
	// Files maps each generated file to the file it is copied from.
	Files map[string]string
	// SourceConfig is the unit's configuration in the repository.
	SourceConfig string

	evaluator *Evaluator
}

// stackBlock is an evaluated unit or stack block.
type stackBlock struct {
	name, source, path string
	values             cty.Value
	valueRanges        map[string]hcl.Range
	noDotStack         bool
	rng                hcl.Range
}

// ExpandStack evaluates a terragrunt.stack.hcl into the units it generates,
// following nested stacks. Only local unit and stack sources are expanded.
func (e *Evaluator) ExpandStack(ctx context.Context, stackFile string) ([]*StackUnit, error) {
	path, err := e.confine(e.repoRoot, stackFile)
	if err != nil {
		return nil, err
	}
	return e.expandStack(ctx, path, path, "", nil, 0)
}

func (e *Evaluator) expandStack(
	ctx context.Context, path, declaringFile, prefix string, outer *hcl.Range, depth int,
) ([]*StackUnit, error) {
	if depth >= maxReadDepth {
		return nil, errors.New("stacks are nested too deep")
	}
	units, stacks, err := e.evaluateStack(ctx, path)
	if err != nil {
		return nil, err
	}
	contextLogger := logger.FromContext(ctx)
	dir := filepath.Dir(path)
	var out []*StackUnit
	for i := range units {
		block := &units[i]
		unit, err := e.generateUnit(ctx, dir, block)
		if err != nil {
			contextLogger.Debug().Msgf("terragrunt: unit %q of %s: %v", block.name, path, err)
			continue
		}
		if unit == nil {
			continue
		}
		unit.Name, unit.StackFile = prefix+block.name, declaringFile
		if outer != nil {
			unit.Block, unit.ValueRanges = *outer, nil
		}
		out = append(out, unit)
	}
	for i := range stacks {
		block := &stacks[i]
		nested, err := e.generateStack(ctx, dir, block, declaringFile, prefix, outer, depth)
		if err != nil {
			contextLogger.Debug().Msgf("terragrunt: stack %q of %s: %v", block.name, path, err)
			continue
		}
		out = append(out, nested...)
	}
	return out, nil
}

// evaluateStack evaluates a stack file's locals, unit and stack blocks.
func (e *Evaluator) evaluateStack(ctx context.Context, path string) (units, stacks []stackBlock, err error) {
	src, err := e.fsys.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	file, diags := hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, nil, diags
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected body type %T", file.Body)
	}
	s := &scope{terragruntPath: path, originalPath: path, reading: map[string]bool{}}
	values := e.values
	if values == cty.NilVal {
		values = cty.DynamicVal
	}
	evalCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{"values": values},
		Functions: e.functions(ctx, s),
	}
	evalCtx.Variables[varLocal] = cty.ObjectVal(evaluateLocals(ctx, body, evalCtx))
	for _, block := range body.Blocks {
		if block.Type != "unit" && block.Type != "stack" || len(block.Labels) == 0 {
			continue
		}
		evaluated := evaluateStackBlock(ctx, block, evalCtx)
		if block.Type == "unit" {
			units = append(units, evaluated)
		} else {
			stacks = append(stacks, evaluated)
		}
	}
	return units, stacks, nil
}

func evaluateStackBlock(ctx context.Context, block *hclsyntax.Block, evalCtx *hcl.EvalContext) stackBlock {
	out := stackBlock{name: block.Labels[0], values: cty.EmptyObjectVal, rng: block.DefRange()}
	out.source, _ = knownString(attributeValue(block.Body, "source", evalCtx))
	out.path, _ = knownString(attributeValue(block.Body, "path", evalCtx))
	out.noDotStack = isKnownTrue(attributeValue(block.Body, "no_dot_terragrunt_stack", evalCtx))
	if attr, ok := block.Body.Attributes["values"]; ok {
		out.values = evalExpr(ctx, attr.Expr, evalCtx)
		out.valueRanges = map[string]hcl.Range{}
		for name := range valueMap(out.values) {
			if item, found := findItem(attr.Expr, name); found {
				out.valueRanges[name] = hcl.RangeBetween(item.KeyExpr.Range(), item.ValueExpr.Range())
			}
		}
	}
	return out
}

// generateUnit copies a unit block's source where Terragrunt generates it and
// evaluates it there with the block's values. It returns nil for a unit
// generated into the repository itself, which is scanned as a unit.
func (e *Evaluator) generateUnit(ctx context.Context, dir string, block *stackBlock) (*StackUnit, error) {
	source, target, err := e.generatedPaths(dir, block)
	if err != nil {
		return nil, err
	}
	config := filepath.Join(target, ConfigFileName)
	if block.noDotStack {
		if _, statErr := e.fsys.Stat(config); statErr == nil {
			return nil, nil
		}
	}
	files, contents, err := e.copyDir(source, target)
	if err != nil {
		return nil, err
	}
	if _, ok := files[config]; !ok {
		return nil, fmt.Errorf("%s has no %s", source, ConfigFileName)
	}
	evaluator := &Evaluator{
		fsys:     vfs.NewOverlay(e.fsys, contents),
		repoRoot: e.repoRoot,
		values:   block.values,
		outputs:  e.outputs,
	}
	unit, err := evaluator.EvaluateUnit(ctx, config)
	if err != nil {
		return nil, err
	}
	return &StackUnit{
		Block:        block.rng,
		ValueRanges:  block.valueRanges,
		Unit:         unit,
		Files:        files,
		SourceConfig: files[config],
		evaluator:    evaluator,
	}, nil
}

// generateStack copies a nested stack where Terragrunt generates it and
// expands it there with the block's values.
func (e *Evaluator) generateStack(
	ctx context.Context, dir string, block *stackBlock, declaringFile, prefix string, outer *hcl.Range, depth int,
) ([]*StackUnit, error) {
	source, target, err := e.generatedPaths(dir, block)
	if err != nil {
		return nil, err
	}
	_, contents, err := e.copyDir(source, target)
	if err != nil {
		return nil, err
	}
	nested := &Evaluator{
		fsys:     vfs.NewOverlay(e.fsys, contents),
		repoRoot: e.repoRoot,
		values:   block.values,
		outputs:  e.outputs,
	}
	if outer == nil {
		outer = &block.rng
	}
	return nested.expandStack(ctx, filepath.Join(target, StackFileName), declaringFile, prefix+block.name+"_", outer, depth+1)
}

// generatedPaths resolves a block's local source and where it is generated.
func (e *Evaluator) generatedPaths(dir string, block *stackBlock) (source, target string, err error) {
	if block.source == "" || block.path == "" {
		return "", "", errors.New("source and path must be known")
	}
	if !isLocalSource(block.source) {
		return "", "", fmt.Errorf("remote source %q is not expanded", block.source)
	}
	source, err = e.confine(dir, strings.ReplaceAll(block.source, "//", "/"))
	if err != nil {
		return "", "", err
	}
	base := filepath.Join(dir, stackDir)
	if block.noDotStack {
		base = dir
	}
	target, err = e.confine(base, block.path)
	if err != nil {
		return "", "", err
	}
	return source, target, nil
}

// copyDir lists the regular files of source by the path they are copied to
// under target, and their contents.
func (e *Evaluator) copyDir(source, target string) (files map[string]string, contents map[string][]byte, err error) {
	entries, err := e.fsys.ReadDir(source)
	if err != nil {
		return nil, nil, err
	}
	files = map[string]string{}
	contents = map[string][]byte{}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		from := filepath.Join(source, entry.Name())
		content, readErr := e.fsys.ReadFile(from)
		if readErr != nil {
			continue
		}
		to := filepath.Join(target, entry.Name())
		files[to], contents[to] = from, content
	}
	return files, contents, nil
}

// WithDependencyOutputs evaluates the unit again with dependency outputs.
func (s *StackUnit) WithDependencyOutputs(ctx context.Context, outputs map[string]cty.Value) (*StackUnit, error) {
	unit, err := s.evaluator.WithDependencyOutputs(outputs).EvaluateUnit(ctx, s.Unit.ConfigFile)
	if err != nil {
		return nil, err
	}
	again := *s
	again.Unit = unit
	return &again, nil
}

// Call is the unit's module call, declared by the stack file: relative
// sources resolve from the generated directory, and inputs passing a stack
// value as is are positioned where the stack file sets it.
func (s *StackUnit) Call() (call *Call, inputs map[string]cty.Value, ok bool) {
	call, inputs, ok = s.Unit.Call()
	if !ok {
		return nil, nil, false
	}
	body := &hclsyntax.Body{Attributes: hclsyntax.Attributes{}}
	for name, input := range s.Unit.Inputs {
		rng, set := s.ValueRanges[input.ValuesKey]
		if input.ValuesKey == "" || !set {
			continue
		}
		body.Attributes[name] = &hclsyntax.Attribute{
			Name:      name,
			Expr:      &hclsyntax.LiteralValueExpr{Val: input.Value, SrcRange: rng},
			SrcRange:  rng,
			NameRange: rng,
		}
	}
	call.Label = s.Name
	call.CallerFile = s.StackFile
	call.SourceDir = s.Unit.Dir
	call.Range = s.Block
	call.Body = body
	return call, inputs, true
}

func isLocalSource(source string) bool {
	return filepath.IsAbs(source) || strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../")
}
