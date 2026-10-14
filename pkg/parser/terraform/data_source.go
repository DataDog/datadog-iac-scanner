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
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/localdata"
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
	var blocks []localDataBlock
	for _, tfFile := range hclConfigFiles(ctx, fsys, currentPath, allow, keep) {
		content, readErr := fsys.ReadFile(filepath.Clean(tfFile))
		if readErr != nil {
			contextLogger.Debug().Msgf("Error trying to read file %s for data source.", tfFile)
			continue
		}
		if !fileMayDeclareLocalData(content) {
			continue
		}
		if tfpath.IsJSONConfig(tfFile) {
			blocks = append(blocks, jsonLocalDataBlocks(content, tfFile)...)
			continue
		}
		blocks = append(blocks, hclLocalDataBlocks(ctx, content, tfFile)...)
	}
	if len(blocks) == 0 {
		return inputVariables
	}
	readsData := false
	for i := range blocks {
		readsData = readsData || blocks[i].readsData
	}
	var rendered map[string]map[string]map[string]string
	// Each pass exposes one more link of a dependency chain, so a chain can be
	// at most as long as the number of blocks.
	for pass := 0; pass <= len(blocks); pass++ {
		next := renderLocalData(blocks, inputVariables)
		if rendered != nil && reflect.DeepEqual(rendered, next) {
			break
		}
		rendered = next
		data, err := gocty.ToCtyValue(rendered, cty.Map(cty.Map(cty.Map(cty.String))))
		if err != nil {
			contextLogger.Error().Msgf("Error trying to convert data sources to cty value: %s", err)
			return inputVariables
		}
		inputVariables["data"] = data
		if !readsData {
			break
		}
	}
	return inputVariables
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

func hclLocalDataBlocks(ctx context.Context, content []byte, tfFile string) []localDataBlock {
	parsedFile, diags := hclsyntax.ParseConfig(content, tfFile, hcl.InitialPos)
	if parsedFile == nil || diags.HasErrors() {
		contextLogger := logger.FromContext(ctx)
		contextLogger.Debug().Msgf("Error trying to parse file %s for data source.", tfFile)
		return nil
	}
	body, ok := parsedFile.Body.(*hclsyntax.Body)
	if !ok {
		return nil
	}
	var out []localDataBlock
	for _, block := range body.Blocks {
		if block.Type != terraformDataIdentifier || len(block.Labels) < 2 {
			continue
		}
		source, ok := localdata.Lookup(block.Labels[0])
		if !ok {
			continue
		}
		out = append(out, localDataBlock{
			typ:       block.Labels[0],
			name:      block.Labels[1],
			source:    source,
			body:      block.Body,
			src:       content,
			readsData: bodyReadsData(block.Body),
		})
	}
	return out
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

func jsonLocalDataBlocks(src []byte, filename string) []localDataBlock {
	parsed, diags := hcljson.Parse(src, filename)
	if diags.HasErrors() {
		return nil
	}
	content, _, _ := parsed.Body.PartialContent(jsonConfigSchema)
	if content == nil {
		return nil
	}
	readsData := jsonDataReference.Match(src)
	var out []localDataBlock
	for _, block := range content.Blocks {
		if block.Type != terraformDataIdentifier || len(block.Labels) < 2 {
			continue
		}
		source, ok := localdata.Lookup(block.Labels[0])
		if !ok {
			continue
		}
		out = append(out, localDataBlock{
			typ:       block.Labels[0],
			name:      block.Labels[1],
			source:    source,
			body:      block.Body,
			src:       src,
			json:      true,
			readsData: readsData,
		})
	}
	return out
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
