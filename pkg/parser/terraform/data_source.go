/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"bytes"
	"context"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/localdata"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/partial"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
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
		content, readErr := tfmodules.ReadConfigFile(ctx, fsys, tfFile, "")
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
	// A block reading its own result has no value Terraform would compute,
	// and each pass would feed it its previous result: it is left unrendered.
	blocks = dropCyclicData(ctx, currentPath, blocks, locals)
	// Locals that read data only resolve after a data pass, so keep their
	// expressions and refresh them when data grows.
	assignments := dataDependentLocals(locals)
	var rendered map[string]map[string]map[string]string
	// Each pass exposes one more link of a dependency chain through data or
	// locals, so a chain can be at most as long as the blocks plus locals.
	for pass := 0; pass <= len(blocks)+len(assignments); pass++ {
		next := renderLocalData(blocks, inputVariables)
		data, err := gocty.ToCtyValue(next, cty.Map(cty.Map(cty.Map(cty.String))))
		if err != nil {
			contextLogger.Error().Msgf("Error trying to convert data sources to cty value: %s", err)
			return inputVariables
		}
		inputVariables["data"] = data
		localsChanged := refreshLocals(inputVariables, assignments)
		if rendered != nil && reflect.DeepEqual(rendered, next) && !localsChanged {
			break
		}
		rendered = next
		if !readsData && !localsChanged {
			break
		}
	}
	return inputVariables
}

// dropCyclicData returns blocks without those in a data reference cycle,
// which are then read as written.
func dropCyclicData(ctx context.Context, dir string, blocks []localDataBlock, locals []localAssignment) []localDataBlock {
	reads := make(map[string][]hcl.Traversal, len(blocks))
	for i := range blocks {
		key := DataKey(blocks[i].typ, blocks[i].name)
		reads[key] = append(reads[key], BodyTraversals(blocks[i].body)...)
	}
	localReads := make(map[string][]hcl.Traversal, len(locals))
	for _, local := range locals {
		localReads[local.name] = local.expr.Variables()
	}
	cyclic := DataCycles(reads, localReads)
	if len(cyclic) == 0 {
		return blocks
	}
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msgf("data reference cycle in %s; the blocks are read as written", dir)
	kept := blocks[:0:0]
	for i := range blocks {
		if !cyclic[DataKey(blocks[i].typ, blocks[i].name)] {
			kept = append(kept, blocks[i])
		}
	}
	return kept
}

// DataKey names a data block in the graph DataCycles reads.
func DataKey(typ, name string) string {
	return terraformDataIdentifier + "." + typ + "." + name
}

// DataCycles returns the data blocks, named by DataKey, that read their own
// result, directly or through other data blocks and locals. Terraform rejects
// such a cycle. Evaluating one anyway feeds the block its previous result on
// every pass, and a function such as jsonencode nests that result once more,
// so its size doubles with each pass. reads gives the traversals each block's
// configuration reads, locals those of each local. Only static
// data.<type>.<name> and local.<name> references are followed, as Terraform
// requires.
func DataCycles(reads, locals map[string][]hcl.Traversal) map[string]bool {
	edges := make(map[string][]string, len(reads)+len(locals))
	for key, traversals := range reads {
		edges[key] = dataEdges(traversals)
	}
	for name, traversals := range locals {
		edges["local."+name] = dataEdges(traversals)
	}
	var cyclic map[string]bool
	for key := range reads {
		if reachesItself(edges, key) {
			if cyclic == nil {
				cyclic = map[string]bool{}
			}
			cyclic[key] = true
		}
	}
	return cyclic
}

// BodyTraversals returns the traversals a block body reads: those of its
// attributes and nested blocks, or, for a JSON body, of its attributes, which
// hold its nested blocks as objects.
func BodyTraversals(body hcl.Body) []hcl.Traversal {
	if native, ok := body.(*hclsyntax.Body); ok {
		return nativeBodyTraversals(nil, native)
	}
	attrs, _ := body.JustAttributes()
	var out []hcl.Traversal
	for _, attr := range attrs {
		out = append(out, attr.Expr.Variables()...)
	}
	return out
}

func nativeBodyTraversals(out []hcl.Traversal, body *hclsyntax.Body) []hcl.Traversal {
	for _, attr := range body.Attributes {
		out = append(out, attr.Expr.Variables()...)
	}
	for _, block := range body.Blocks {
		out = nativeBodyTraversals(out, block.Body)
	}
	return out
}

// dataEdges returns the data blocks and locals the traversals name.
func dataEdges(traversals []hcl.Traversal) []string {
	var out []string
	for _, traversal := range traversals {
		if name, ok := LocalTraversalName(traversal); ok {
			out = append(out, "local."+name)
			continue
		}
		if traversal.RootName() != terraformDataIdentifier || len(traversal) < 3 {
			continue
		}
		typ, okType := traversal[1].(hcl.TraverseAttr)
		name, okName := traversal[2].(hcl.TraverseAttr)
		if okType && okName {
			out = append(out, DataKey(typ.Name, name.Name))
		}
	}
	return out
}

// reachesItself reports whether a path of at least one edge leads from start
// back to start.
func reachesItself(edges map[string][]string, start string) bool {
	seen := map[string]bool{}
	stack := append([]string(nil), edges[start]...)
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if node == start {
			return true
		}
		if seen[node] {
			continue
		}
		seen[node] = true
		stack = append(stack, edges[node]...)
	}
	return false
}

func renderLocalData(
	blocks []localDataBlock, inputVariables converter.VariableMap,
) map[string]map[string]map[string]string {
	evalCtx := &hcl.EvalContext{Variables: inputVariables, Functions: functions.TerraformFuncs}
	out := map[string]map[string]map[string]string{}
	for i := range blocks {
		b := &blocks[i]
		eval := (&partial.Renderer{Ctx: evalCtx, Source: partial.BytesSource(b.src)}).Render
		if b.json {
			eval = jsonEval(evalCtx, b.src)
		}
		attrs := b.source(b.body, eval)
		if attrs == nil {
			continue
		}
		if out[b.typ] == nil {
			out[b.typ] = map[string]map[string]string{}
		}
		out[b.typ][b.name] = attrs
	}
	return out
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
