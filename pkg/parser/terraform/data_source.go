/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"bytes"
	"context"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/instances"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/localdata"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
)

// jsonDataReference matches a read of the data namespace anywhere in JSON
// configuration, whatever spacing or wrapping the template expression uses. A
// false positive only costs an extra render pass.
var jsonDataReference = regexp.MustCompile(`\bdata\s*\.`)

// localDataMarkers are cheap content gates before parsing; the parser still
// matches block types exactly.
var localDataMarkers = func() [][]byte {
	types := localdata.Types()
	out := make([][]byte, len(types))
	for i, typ := range types {
		out[i] = []byte(typ)
	}
	return out
}()

// localDataBlock is a data block of a type localdata renders.
type localDataBlock struct {
	typ, name string
	source    localdata.Source
	body      hcl.Body
	src       []byte
	json      bool
	readsData bool
}

// getDataSourcePolicy renders the data sources of a directory that Terraform
// computes from configuration alone into the data variable, so the resources
// referencing their attributes read the rendered value.
func getDataSourcePolicy(
	ctx context.Context, fsys vfs.FS, currentPath string, inputVariables converter.VariableMap, allow map[string]struct{}, keep string,
) converter.VariableMap {
	contextLogger := logger.FromContext(ctx)
	var (
		blocks []localDataBlock
		locals []localAssignment
	)
	for _, tfFile := range hclConfigFiles(ctx, fsys, currentPath, allow, keep) {
		content, readErr := fsys.ReadFile(filepath.Clean(tfFile))
		if readErr != nil {
			contextLogger.Debug().Msgf("Error trying to read file %s for data source.", tfFile)
			continue
		}
		wantsData := fileMayDeclareLocalData(content)
		wantsLocals := bytes.Contains(content, localsMarker)
		if !wantsData && !wantsLocals {
			continue
		}
		fileBlocks, fileLocals := parseLocalDataFile(ctx, content, tfFile, wantsData, wantsLocals)
		blocks = append(blocks, fileBlocks...)
		locals = append(locals, fileLocals...)
	}
	if len(blocks) == 0 {
		return inputVariables
	}
	readsData := false
	for i := range blocks {
		readsData = readsData || blocks[i].readsData
	}
	// Locals that read data only resolve after a data pass, so keep their
	// expressions and refresh them when data grows.
	assignments := dataDependentLocals(locals)
	var rendered map[string]map[string]cty.Value
	// Each pass exposes one more link of a dependency chain through data or
	// locals, so a chain can be at most as long as the blocks plus locals.
	for pass := 0; pass <= len(blocks)+len(assignments); pass++ {
		next := renderLocalData(blocks, inputVariables)
		inputVariables["data"] = localDataValue(next)
		localsChanged := refreshLocals(inputVariables, assignments)
		if rendered != nil && localDataEqual(rendered, next) && !localsChanged {
			break
		}
		rendered = next
		if !readsData && !localsChanged {
			break
		}
	}
	return inputVariables
}

// localDataValue is the data variable: type, then name, then the attributes of
// the block, or its instances by index or key when it has count or for_each.
func localDataValue(rendered map[string]map[string]cty.Value) cty.Value {
	types := make(map[string]cty.Value, len(rendered))
	for typ, byName := range rendered {
		names := make(map[string]cty.Value, len(byName))
		for name, value := range byName {
			names[name] = value
		}
		types[typ] = cty.ObjectVal(names)
	}
	return cty.ObjectVal(types)
}

func localDataEqual(a, b map[string]map[string]cty.Value) bool {
	if len(a) != len(b) {
		return false
	}
	for typ, byName := range a {
		other, ok := b[typ]
		if !ok || len(other) != len(byName) {
			return false
		}
		for name, value := range byName {
			if o, ok := other[name]; !ok || !value.RawEquals(o) {
				return false
			}
		}
	}
	return true
}

func attributesValue(attrs map[string]string) cty.Value {
	if len(attrs) == 0 {
		return cty.MapValEmpty(cty.String)
	}
	values := make(map[string]cty.Value, len(attrs))
	for k, v := range attrs {
		values[k] = cty.StringVal(v)
	}
	return cty.MapVal(values)
}

func renderLocalData(
	blocks []localDataBlock, inputVariables converter.VariableMap,
) map[string]map[string]cty.Value {
	evalCtx := &hcl.EvalContext{Variables: inputVariables, Functions: functions.TerraformFuncs}
	out := map[string]map[string]cty.Value{}
	for i := range blocks {
		b := &blocks[i]
		value, ok := renderLocalDataBlock(b, evalCtx)
		if !ok {
			continue
		}
		if out[b.typ] == nil {
			out[b.typ] = map[string]cty.Value{}
		}
		out[b.typ][b.name] = value
	}
	return out
}

// renderLocalDataBlock renders one block. A block whose count or for_each
// resolves is rendered once per instance and read as a tuple by index or an
// object by key, as Terraform exposes it; any other block is rendered once.
func renderLocalDataBlock(b *localDataBlock, evalCtx *hcl.EvalContext) (cty.Value, bool) {
	render := func(ctx *hcl.EvalContext) (map[string]string, bool) {
		eval := (&partial.Renderer{Ctx: ctx, Source: partial.BytesSource(b.src)}).Render
		if b.json {
			eval = jsonEval(ctx, b.src)
		}
		attrs := b.source(b.body, eval)
		return attrs, attrs != nil
	}
	count, forEach := localDataInstanceAttributes(b)
	plan := instances.Resolve(count, forEach, evalCtx)
	if !plan.Expands() {
		attrs, ok := render(evalCtx)
		if !ok {
			return cty.NilVal, false
		}
		return attributesValue(attrs), true
	}
	byKey := map[string]cty.Value{}
	var list []cty.Value
	for _, item := range plan.Items {
		name, iteration := plan.Variable(item)
		child := evalCtx.NewChild()
		child.Variables = map[string]cty.Value{name: iteration}
		attrs, ok := render(child)
		if !ok {
			return cty.NilVal, false
		}
		if plan.Kind == instances.KindCount {
			list = append(list, attributesValue(attrs))
		} else {
			byKey[item.Key.AsString()] = attributesValue(attrs)
		}
	}
	if plan.Kind == instances.KindCount {
		return cty.TupleVal(list), true
	}
	return cty.ObjectVal(byKey), true
}

func localDataInstanceAttributes(b *localDataBlock) (count, forEach hcl.Expression) {
	if body, ok := b.body.(*hclsyntax.Body); ok {
		return instances.Attributes(body)
	}
	attrs, _ := b.body.JustAttributes()
	if attr, ok := attrs[instances.KindCount]; ok {
		count = attr.Expr
	}
	if attr, ok := attrs[instances.KindForEach]; ok {
		forEach = attr.Expr
	}
	return count, forEach
}

// jsonEval evaluates JSON configuration expressions, rendering what does not
// resolve from its source text.
func jsonEval(evalCtx *hcl.EvalContext, src []byte) localdata.EvalFunc {
	var eval localdata.EvalFunc
	eval = func(expr hcl.Expression) (cty.Value, bool) {
		if inner, vars, ok := partial.Unbind(expr); ok {
			return jsonEval(partial.Scope(evalCtx, vars), src)(inner)
		}
		v, diags := expr.Value(evalCtx)
		if !diags.HasErrors() && v.IsWhollyKnown() {
			return v, true
		}
		items, listDiags := hcl.ExprList(expr)
		if listDiags.HasErrors() {
			if rendered, ok := renderJSONTemplate(expr, evalCtx, src); ok {
				return rendered, true
			}
			return cty.StringVal(wrapJSONRange(expr.Range(), "", src)), true
		}
		if len(items) == 0 {
			return cty.EmptyTupleVal, true
		}
		elems := make([]cty.Value, len(items))
		for i, item := range items {
			elems[i], _ = eval(item)
		}
		return cty.TupleVal(elems), true
	}
	return eval
}

// renderJSONTemplate renders a JSON string holding a template, keeping the
// parts that do not resolve as text apart from those that do.
func renderJSONTemplate(expr hcl.Expression, evalCtx *hcl.EvalContext, src []byte) (cty.Value, bool) {
	r := expr.Range()
	if r.Start.Byte < 0 || r.End.Byte > len(src) || r.Start.Byte >= r.End.Byte {
		return cty.NilVal, false
	}
	unquoted, err := strconv.Unquote(strings.TrimSpace(string(src[r.Start.Byte:r.End.Byte])))
	if err != nil || !strings.Contains(unquoted, "${") {
		return cty.NilVal, false
	}
	quoted := []byte(strconv.Quote(unquoted))
	parsed, diags := hclsyntax.ParseExpression(quoted, "", hcl.InitialPos)
	if diags.HasErrors() {
		return cty.NilVal, false
	}
	return (&partial.Renderer{Ctx: evalCtx, Source: partial.BytesSource(quoted)}).Render(parsed)
}

// localsMarker is a cheap content gate before parsing for locals blocks.
var localsMarker = []byte(blockTypeLocals)

// parseLocalDataFile parses a configuration file once for the local data
// blocks it declares and the locals it assigns.
func parseLocalDataFile(
	ctx context.Context, content []byte, tfFile string, wantsData, wantsLocals bool,
) (blocks []localDataBlock, locals []localAssignment) {
	if tfpath.IsJSONConfig(tfFile) {
		return jsonLocalDataFile(ctx, content, tfFile, wantsData, wantsLocals)
	}
	parsedFile, diags := hclsyntax.ParseConfig(content, tfFile, hcl.InitialPos)
	if parsedFile == nil || diags.HasErrors() {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Debug().Msgf("Error trying to parse file %s for data source.", tfFile)
		return nil, nil
	}
	body, ok := parsedFile.Body.(*hclsyntax.Body)
	if !ok {
		return nil, nil
	}
	if wantsLocals {
		locals = localAssignmentsFromBody(body)
	}
	if !wantsData {
		return nil, locals
	}
	for _, block := range body.Blocks {
		if block.Type != terraformDataIdentifier || len(block.Labels) < 2 {
			continue
		}
		source, ok := localdata.Lookup(block.Labels[0])
		if !ok {
			continue
		}
		blocks = append(blocks, localDataBlock{
			typ:       block.Labels[0],
			name:      block.Labels[1],
			source:    source,
			body:      block.Body,
			src:       content,
			readsData: bodyReadsData(block.Body),
		})
	}
	return blocks, locals
}

func bodyReadsData(body *hclsyntax.Body) bool {
	reads := false
	_ = hclsyntax.VisitAll(body, func(node hclsyntax.Node) hcl.Diagnostics {
		if expr, ok := node.(*hclsyntax.ScopeTraversalExpr); ok && expr.Traversal.RootName() == terraformDataIdentifier {
			reads = true
		}
		return nil
	})
	return reads
}

func jsonLocalDataFile(
	ctx context.Context, src []byte, filename string, wantsData, wantsLocals bool,
) (blocks []localDataBlock, locals []localAssignment) {
	parsed, diags := hcljson.Parse(src, filename)
	if diags.HasErrors() {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Debug().Msgf("Error trying to parse file %s for data source.", filename)
		return nil, nil
	}
	content, _, _ := parsed.Body.PartialContent(jsonConfigSchema)
	if content == nil {
		return nil, nil
	}
	readsData := jsonDataReference.Match(src)
	for _, block := range content.Blocks {
		switch {
		case block.Type == blockTypeLocals && wantsLocals:
			attrs, _ := block.Body.JustAttributes()
			names := make([]string, 0, len(attrs))
			for name := range attrs {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				locals = append(locals, localAssignment{name: name, expr: attrs[name].Expr})
			}
		case block.Type == terraformDataIdentifier && wantsData && len(block.Labels) >= 2:
			source, ok := localdata.Lookup(block.Labels[0])
			if !ok {
				continue
			}
			blocks = append(blocks, localDataBlock{
				typ:       block.Labels[0],
				name:      block.Labels[1],
				source:    source,
				body:      block.Body,
				src:       src,
				json:      true,
				readsData: readsData,
			})
		}
	}
	return blocks, locals
}

// fileMayDeclareLocalData is a fast precheck before parsing. A literal
// substring match covers the common case; lexing handles block type labels
// spelled with escapes that do not appear verbatim in source bytes.
func fileMayDeclareLocalData(content []byte) bool {
	for _, marker := range localDataMarkers {
		if bytes.Contains(content, marker) {
			return true
		}
	}
	if !bytes.Contains(content, []byte(`\u`)) && !bytes.Contains(content, []byte(`\U`)) {
		return false
	}
	return scanForLocalDataBlock(content)
}

func scanForLocalDataBlock(content []byte) bool {
	tokens, diags := hclsyntax.LexConfig(content, "", hcl.InitialPos)
	if diags.HasErrors() {
		return false
	}
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Type != hclsyntax.TokenIdent || string(tokens[i].Bytes) != terraformDataIdentifier {
			continue
		}
		label, next := decodeQuotedBlockLabel(tokens, i+1)
		if _, ok := localdata.Lookup(label); ok {
			return true
		}
		i = next
	}
	return false
}

func decodeQuotedBlockLabel(tokens hclsyntax.Tokens, start int) (label string, next int) {
	for start < len(tokens) {
		switch tokens[start].Type {
		case hclsyntax.TokenNewline, hclsyntax.TokenComment:
			start++
		case hclsyntax.TokenOQuote:
			goto parseQuoted
		default:
			return "", start
		}
	}
	return "", start

parseQuoted:
	var b strings.Builder
	for j := start + 1; j < len(tokens); j++ {
		switch tokens[j].Type {
		case hclsyntax.TokenCQuote:
			return b.String(), j
		case hclsyntax.TokenQuotedLit:
			s, litDiags := hclsyntax.ParseStringLiteralToken(tokens[j])
			if litDiags.HasErrors() {
				return "", j
			}
			b.WriteString(s)
		default:
			return "", j
		}
	}
	return "", start
}
