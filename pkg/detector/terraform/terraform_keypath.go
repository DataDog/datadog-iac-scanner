/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package terraform

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/dynamicblock"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// keyPart is one part of a search key below the block it names: a name, an
// optional bracketed index or map key, and an optional value anchor (name=value).
type keyPart struct {
	raw       string
	name      string
	index     string
	indexed   bool
	anchor    string
	hasAnchor bool
	repeated  repeatedBlocks
}

func newKeyPart(raw string, extracted [][]string, repeated repeatedBlocks) keyPart {
	part := raw
	for i, str := range extracted {
		part = strings.Replace(part, fmt.Sprintf("{{%d}}", i), str[0], 1)
	}
	p := keyPart{raw: raw, repeated: repeated}
	if eq := anchorStart(part); eq >= 0 {
		p.anchor, p.hasAnchor = part[eq+1:], true
		part = part[:eq]
	}
	p.name, p.index, p.indexed = splitIndexedPart(part)
	p.name = strings.TrimSuffix(strings.TrimPrefix(p.name, "{{"), "}}")
	return p
}

func (p *keyPart) withoutIndex() keyPart {
	q := *p
	q.raw, q.index, q.indexed, q.hasAnchor, q.anchor = q.name, "", false, false, ""
	return q
}

// anchorStart is the index of the "=" outside brackets, or -1.
func anchorStart(part string) int {
	depth := 0
	for i := 0; i < len(part); i++ {
		switch part[i] {
		case '[':
			depth++
		case ']':
			depth--
		case '=':
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// keyResolver resolves the parts of a search key in the syntax tree of the
// block the key names, the way a plan's line table is walked: a part names a
// key, never a value, and a part naming a repeated block without an index goes
// through every block in order. Only an expression the syntax tree does not
// structure (a heredoc, a function call) is matched as text, within the
// attribute holding it.
type keyResolver struct {
	ctx       context.Context
	detection *detector.DefaultDetectLineResponse
	extracted [][]string
	lines     []string
	kind      model.FileKind
	parse     func() (*hclsyntax.Body, error)
}

// lineIn is the line of the longest prefix of parts found in scope, or the
// line of scope itself. An index is a step of its own, as in a plan's path:
// without the element it names, a part stands for all of them.
func (r *keyResolver) lineIn(scope *hclsyntax.Block, parts []keyPart) int {
	for n := len(parts); n > 0; n-- {
		if line := r.inBlock(scope, parts[:n]); line > 0 {
			return line
		}
		if parts[n-1].indexed {
			prefix := make([]keyPart, n)
			copy(prefix, parts[:n-1])
			prefix[n-1] = parts[n-1].withoutIndex()
			if line := r.inBlock(scope, prefix); line > 0 {
				return line
			}
		}
	}
	return scope.TypeRange.Start.Line
}

// inBlock is the line of parts in block's body, or -1 when one is missing.
func (r *keyResolver) inBlock(block *hclsyntax.Block, parts []keyPart) int {
	body := blockContent(block)
	if body == nil {
		return -1
	}
	p := &parts[0]
	if attr, ok := body.Attributes[p.name]; ok {
		return r.step(attr, attr.Expr, attr.SrcRange.Start.Line, p, parts[1:])
	}
	candidates := blocksOfType(body, p.name)
	if p.indexed {
		if i, err := strconv.Atoi(p.index); err == nil {
			slots := repeatedBlockSlots(body, p.name, p.repeated)
			if i < 0 || i >= slots.len() {
				return -1
			}
			line := slots[i] + 1
			for _, block := range candidates {
				if block.TypeRange.Start.Line == line {
					return r.below(block, line, parts[1:])
				}
			}
			return -1
		}
		labeled := candidates[:0:0]
		for _, block := range candidates {
			if !dynamicblock.Is(block) && len(block.Labels) > 0 && block.Labels[0] == p.index {
				labeled = append(labeled, block)
			}
		}
		candidates = labeled
	}
	for _, block := range candidates {
		if line := r.below(block, block.TypeRange.Start.Line, parts[1:]); line > 0 {
			return line
		}
	}
	return -1
}

func (r *keyResolver) below(block *hclsyntax.Block, line int, rest []keyPart) int {
	if len(rest) == 0 {
		return line
	}
	return r.inBlock(block, rest)
}

// step applies p's index and anchor to expr, found at line, then resolves rest
// in what they select.
func (r *keyResolver) step(attr *hclsyntax.Attribute, expr hclsyntax.Expression, line int, p *keyPart, rest []keyPart) int {
	if p.indexed {
		element, elementLine, ok := indexExpr(expr, p.index)
		if !ok {
			if opaqueExpr(expr) {
				return r.text(attr, line, append([]keyPart{*p}, rest...))
			}
			return -1
		}
		expr, line = element, elementLine
	}
	if p.hasAnchor {
		if anchored := anchorLine(expr, p.anchor); anchored > 0 {
			line = anchored
		}
	}
	return r.inExpr(attr, expr, line, rest)
}

// inExpr is the line of parts inside expr, found at line, or -1 when one is
// missing.
func (r *keyResolver) inExpr(attr *hclsyntax.Attribute, expr hclsyntax.Expression, line int, parts []keyPart) int {
	if len(parts) == 0 {
		return line
	}
	switch e := unwrapExpr(expr).(type) {
	case *hclsyntax.ObjectConsExpr:
		item := objectItem(e, parts[0].name)
		if item == nil {
			return -1
		}
		return r.step(attr, item.ValueExpr, item.KeyExpr.Range().Start.Line, &parts[0], parts[1:])
	case *hclsyntax.TupleConsExpr:
		for _, element := range e.Exprs {
			if found := r.inExpr(attr, element, element.Range().Start.Line, parts); found > 0 {
				return found
			}
		}
		return -1
	case *hclsyntax.ConditionalExpr:
		for _, result := range []hclsyntax.Expression{e.TrueResult, e.FalseResult} {
			if found := r.inExpr(attr, result, line, parts); found > 0 {
				return found
			}
		}
		return -1
	case *hclsyntax.FunctionCallExpr:
		if e.Name == "merge" {
			for i := len(e.Args) - 1; i >= 0; i-- {
				if found := r.inExpr(attr, e.Args[i], line, parts); found > 0 {
					return found
				}
			}
		}
	}
	if opaqueExpr(expr) {
		return r.text(attr, line, parts)
	}
	return -1
}

// text matches parts as text from line, within attr, and returns the line of
// the last one found there.
func (r *keyResolver) text(attr *hclsyntax.Attribute, line int, parts []keyPart) int {
	end := attr.SrcRange.End.Line
	probe := *r.detection
	probe.CurrentLine = line - 1
	for i := range parts {
		p := &parts[i]
		s1, s2, idx := generateSubstrings(r.ctx, p.raw, r.extracted, r.lines, probe.CurrentLine, r.parse, p.repeated)
		if idx != 0 {
			if idx+1 < line || idx+1 > end {
				break
			}
			probe.CurrentLine = idx
			continue
		}
		before := probe.CurrentLine
		probe.DetectCurrentLine(s1, s2, 0, r.lines, r.kind)
		if probe.IsBreak || probe.CurrentLine >= end {
			probe.CurrentLine = before
			break
		}
	}
	return probe.CurrentLine + 1
}

// opaqueExpr is true for an expression whose keys the syntax tree does not
// hold: a string (a heredoc of JSON, say) or a function call.
func opaqueExpr(expr hclsyntax.Expression) bool {
	switch unwrapExpr(expr).(type) {
	case *hclsyntax.TemplateExpr, *hclsyntax.LiteralValueExpr, *hclsyntax.FunctionCallExpr:
		return true
	}
	return false
}

var transparentFunctions = map[string]bool{
	"jsonencode": true, "yamlencode": true, "tolist": true, "toset": true, "tomap": true,
}

// unwrapExpr is the expression expr's value is written as: parentheses,
// interpolation and encoding functions keep the keys of their argument.
func unwrapExpr(expr hclsyntax.Expression) hclsyntax.Expression {
	for {
		switch e := expr.(type) {
		case *hclsyntax.ParenthesesExpr:
			expr = e.Expression
		case *hclsyntax.TemplateWrapExpr:
			expr = e.Wrapped
		case *hclsyntax.FunctionCallExpr:
			if !transparentFunctions[e.Name] || len(e.Args) != 1 {
				return expr
			}
			expr = e.Args[0]
		default:
			return expr
		}
	}
}

// indexExpr is the element of a tuple, or the value of an object key, that
// index selects, with its line.
func indexExpr(expr hclsyntax.Expression, index string) (hclsyntax.Expression, int, bool) {
	switch e := unwrapExpr(expr).(type) {
	case *hclsyntax.TupleConsExpr:
		i, err := strconv.Atoi(index)
		if err != nil || i < 0 || i >= len(e.Exprs) {
			return nil, 0, false
		}
		return e.Exprs[i], e.Exprs[i].Range().Start.Line, true
	case *hclsyntax.ObjectConsExpr:
		if item := objectItem(e, index); item != nil {
			return item.ValueExpr, item.KeyExpr.Range().Start.Line, true
		}
	}
	return nil, 0, false
}

func objectItem(obj *hclsyntax.ObjectConsExpr, name string) *hclsyntax.ObjectConsItem {
	for i := range obj.Items {
		if key, ok := objectKey(obj.Items[i].KeyExpr); ok && key == name {
			return &obj.Items[i]
		}
	}
	return nil
}

// objectKey is the name of an object key written as an identifier or a
// constant string.
func objectKey(expr hclsyntax.Expression) (string, bool) {
	if key, ok := expr.(*hclsyntax.ObjectConsKeyExpr); ok {
		if !key.ForceNonLiteral {
			if name := hcl.ExprAsKeyword(key.Wrapped); name != "" {
				return name, true
			}
		}
		expr = key.Wrapped
	}
	value, diags := expr.Value(nil)
	if diags.HasErrors() || !value.IsKnown() || value.IsNull() || value.Type() != cty.String {
		return "", false
	}
	return value.AsString(), true
}

// anchorLine is the line of the element of a tuple equal to value, or 0.
func anchorLine(expr hclsyntax.Expression, value string) int {
	tuple, ok := unwrapExpr(expr).(*hclsyntax.TupleConsExpr)
	if !ok {
		return 0
	}
	for _, element := range tuple.Exprs {
		if text, ok := literalText(element); ok && text == value {
			return element.Range().Start.Line
		}
	}
	return 0
}

func literalText(expr hclsyntax.Expression) (string, bool) {
	value, diags := expr.Value(nil)
	if diags.HasErrors() || !value.IsKnown() || value.IsNull() {
		return "", false
	}
	switch value.Type() {
	case cty.String:
		return value.AsString(), true
	case cty.Number:
		return value.AsBigFloat().Text('f', -1), true
	case cty.Bool:
		return strconv.FormatBool(value.True()), true
	}
	return "", false
}

// blockContent is the body a block's children are written in: a dynamic
// block's content.
func blockContent(block *hclsyntax.Block) *hclsyntax.Body {
	if dynamicblock.Is(block) {
		return dynamicblock.Content(block)
	}
	return block.Body
}

// blocksOfType lists, in source order, the blocks of body that are or generate
// blocks of type typ.
func blocksOfType(body *hclsyntax.Body, typ string) []*hclsyntax.Block {
	var blocks []*hclsyntax.Block
	for _, block := range body.Blocks {
		if dynamicblock.Is(block) {
			if dynamicblock.GeneratedType(block) == typ {
				blocks = append(blocks, block)
			}
		} else if block.Type == typ {
			blocks = append(blocks, block)
		}
	}
	return blocks
}
