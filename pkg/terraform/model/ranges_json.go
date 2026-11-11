/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package model

import (
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Limits on the ranges recorded inside one JSON document: deeper values map
// to their deepest recorded ancestor.
const (
	maxDocDepth  = 16
	maxDocNodes  = 2048
	maxDocRanges = 8192
	maxDocBytes  = 1 << 20
)

// docNode is a JSON-shaped value with the source ranges of its parts.
type docNode struct {
	rng    hcl.Range
	object bool
	keys   []string
	// keyed holds, for each object member, the range from its key to the end
	// of its value.
	keyed []hcl.Range
	kids  []docNode
}

// recordDocRanges records the ranges of a jsonencode argument or of a string
// literal holding a JSON object or array under path, the path rules use for
// the decoded document. It reports whether expr is such a value.
func recordDocRanges(expr hcl.Expression, path string, ranges map[string]hcl.Range) bool {
	var doc docNode
	var ok bool
	switch e := expr.(type) {
	case *hclsyntax.FunctionCallExpr:
		if e.Name != jsonEncodeFunc || len(e.Args) != 1 {
			return false
		}
		n := 0
		doc, ok = exprDoc(e.Args[0], 0, &n)
	case *hclsyntax.TemplateExpr:
		doc, ok = templateDoc(e)
	default:
		return false
	}
	if !ok {
		return false
	}
	n := 0
	recordDoc(&doc, path, false, false, ranges, &n)
	return true
}

// recordDoc records the members and elements of doc under path. An object
// member's object value is also recorded under its ".0" path, for rules that
// read an object as a one-element list (an IAM Statement); that alias is made
// once per path, so the ranges stay linear in the depth.
func recordDoc(doc *docNode, path string, member, aliased bool, ranges map[string]hcl.Range, n *int) {
	if doc.object && member && !aliased {
		zero := joinPath(path, "0")
		if record(ranges, zero, doc.rng, n) {
			recordDoc(doc, zero, false, true, ranges, n)
		}
	}
	for i := range doc.kids {
		kid := &doc.kids[i]
		child := joinPath(path, strconv.Itoa(i))
		rng := kid.rng
		if doc.object {
			child = joinPath(path, doc.keys[i])
			rng = doc.keyed[i]
		}
		if !record(ranges, child, rng, n) {
			return
		}
		recordDoc(kid, child, doc.object, aliased, ranges, n)
	}
}

func record(ranges map[string]hcl.Range, path string, rng hcl.Range, n *int) bool {
	if *n >= maxDocRanges {
		return false
	}
	*n++
	ranges[path] = rng
	return true
}

// exprDoc reads the object and tuple constructors of a jsonencode argument;
// any other expression is a leaf.
func exprDoc(expr hcl.Expression, depth int, n *int) (docNode, bool) {
	*n++
	if *n > maxDocNodes {
		return docNode{}, false
	}
	doc := docNode{rng: expr.Range()}
	if depth >= maxDocDepth {
		return doc, true
	}
	switch e := expr.(type) {
	case *hclsyntax.ParenthesesExpr:
		inner, ok := exprDoc(e.Expression, depth, n)
		inner.rng = doc.rng
		return inner, ok
	case *hclsyntax.TupleConsExpr:
		for _, elem := range e.Exprs {
			kid, ok := exprDoc(elem, depth+1, n)
			if !ok {
				return docNode{}, false
			}
			doc.kids = append(doc.kids, kid)
		}
	case *hclsyntax.ObjectConsExpr:
		doc.object = true
		for _, item := range e.Items {
			name, ok := objectConsKeyName(item.KeyExpr)
			if !ok {
				continue
			}
			kid, ok := exprDoc(item.ValueExpr, depth+1, n)
			if !ok {
				return docNode{}, false
			}
			doc.keys = append(doc.keys, name)
			doc.keyed = append(doc.keyed, hcl.RangeBetween(item.KeyExpr.Range(), item.ValueExpr.Range()))
			doc.kids = append(doc.kids, kid)
		}
	}
	return doc, true
}

// docText is the text of a template with each interpolation replaced by a
// stand-in, and where each part of it starts in the source.
type docText struct {
	text     string
	filename string
	segs     []docSeg
}

type docSeg struct {
	off   int
	start hcl.Pos
	// lines is set when the newlines of the part's value are those of its
	// source, so offsets past a newline map to the next source line.
	lines   bool
	literal bool
}

// templateDoc parses a string template or heredoc as JSON. Interpolations
// stand for JSON string content, or else for whole JSON strings; a template
// that is JSON neither way is no document.
func templateDoc(e *hclsyntax.TemplateExpr) (docNode, bool) {
	if len(e.Parts) == 0 || !startsJSON(e.Parts) {
		return docNode{}, false
	}
	for _, standIn := range []string{"_", `"_"`} {
		t, ok := templateText(e, standIn)
		if !ok {
			return docNode{}, false
		}
		if doc, ok := t.parse(); ok {
			return doc, true
		}
	}
	return docNode{}, false
}

func startsJSON(parts []hclsyntax.Expression) bool {
	for _, p := range parts {
		s, ok := literalPart(p)
		if !ok {
			return false
		}
		if s = strings.TrimSpace(s); s != "" {
			return s[0] == '{' || s[0] == '['
		}
	}
	return false
}

func literalPart(expr hclsyntax.Expression) (string, bool) {
	lit, ok := expr.(*hclsyntax.LiteralValueExpr)
	if !ok || lit.Val.Type() != cty.String || !lit.Val.IsKnown() || lit.Val.IsNull() {
		return "", false
	}
	return lit.Val.AsString(), true
}

func templateText(e *hclsyntax.TemplateExpr, standIn string) (*docText, bool) {
	t := &docText{filename: e.SrcRange.Filename}
	var b strings.Builder
	for _, part := range e.Parts {
		rng := part.Range()
		seg := docSeg{off: b.Len(), start: rng.Start}
		if s, ok := literalPart(part); ok {
			seg.literal = true
			seg.lines = strings.Count(s, "\n") == rng.End.Line-rng.Start.Line
			b.WriteString(s)
		} else {
			b.WriteString(standIn)
		}
		if b.Len() > maxDocBytes {
			return nil, false
		}
		t.segs = append(t.segs, seg)
	}
	t.text = b.String()
	return t, true
}

// pos maps an offset of the text to a source position.
func (t *docText) pos(off int) hcl.Pos {
	i := sort.Search(len(t.segs), func(i int) bool { return t.segs[i].off > off }) - 1
	if i < 0 {
		i = 0
	}
	seg := t.segs[i]
	if !seg.literal {
		return seg.start
	}
	chunk := t.text[seg.off:min(off, len(t.text))]
	if !seg.lines {
		return seg.start
	}
	nl := strings.Count(chunk, "\n")
	if nl == 0 {
		return hcl.Pos{
			Line: seg.start.Line, Column: seg.start.Column + utf8.RuneCountInString(chunk), Byte: seg.start.Byte + len(chunk),
		}
	}
	last := strings.LastIndexByte(chunk, '\n')
	return hcl.Pos{Line: seg.start.Line + nl, Column: 1 + utf8.RuneCountInString(chunk[last+1:]), Byte: seg.start.Byte + len(chunk)}
}

func (t *docText) rangeOf(start, end int) hcl.Range {
	return hcl.Range{Filename: t.filename, Start: t.pos(start), End: t.pos(end)}
}

func (t *docText) parse() (docNode, bool) {
	p := &docParser{t: t, dec: json.NewDecoder(strings.NewReader(t.text))}
	p.dec.UseNumber()
	doc, ok := p.value(0)
	if !ok {
		return docNode{}, false
	}
	if _, err := p.dec.Token(); err != io.EOF {
		return docNode{}, false
	}
	return doc, true
}

type docParser struct {
	t     *docText
	dec   *json.Decoder
	nodes int
}

// next is the offset where the next token starts.
func (p *docParser) next() int {
	o := int(p.dec.InputOffset())
	for o < len(p.t.text) && strings.IndexByte(" \t\r\n,:", p.t.text[o]) >= 0 {
		o++
	}
	return o
}

func (p *docParser) value(depth int) (docNode, bool) {
	p.nodes++
	if p.nodes > maxDocNodes {
		return docNode{}, false
	}
	start := p.next()
	if depth >= maxDocDepth {
		var skip json.RawMessage
		if err := p.dec.Decode(&skip); err != nil {
			return docNode{}, false
		}
		return docNode{rng: p.t.rangeOf(start, int(p.dec.InputOffset()))}, true
	}
	tok, err := p.dec.Token()
	if err != nil {
		return docNode{}, false
	}
	var doc docNode
	switch tok {
	case json.Delim('{'):
		doc.object = true
		for p.dec.More() {
			keyStart := p.next()
			kt, err := p.dec.Token()
			key, ok := kt.(string)
			if err != nil || !ok {
				return docNode{}, false
			}
			kid, ok := p.value(depth + 1)
			if !ok {
				return docNode{}, false
			}
			doc.keys = append(doc.keys, key)
			doc.keyed = append(doc.keyed, hcl.Range{Filename: p.t.filename, Start: p.t.pos(keyStart), End: kid.rng.End})
			doc.kids = append(doc.kids, kid)
		}
		if _, err := p.dec.Token(); err != nil {
			return docNode{}, false
		}
	case json.Delim('['):
		for p.dec.More() {
			kid, ok := p.value(depth + 1)
			if !ok {
				return docNode{}, false
			}
			doc.kids = append(doc.kids, kid)
		}
		if _, err := p.dec.Token(); err != nil {
			return docNode{}, false
		}
	}
	doc.rng = p.t.rangeOf(start, int(p.dec.InputOffset()))
	return doc, true
}
