/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"fmt"
	"sort"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// DetectPath resolves written resource/data paths. Selecting a child of a
// computed expression requires provenance beyond this source-only capability.
func (d *DetectKindLine) DetectPath(
	ctx context.Context, file *model.FileMetadata, path model.SourcePath, output int,
) (model.VulnerabilityLines, error) {
	if err := ctx.Err(); err != nil {
		return model.VulnerabilityLines{}, err
	}
	if tfpath.IsJSONConfig(file.FilePath) {
		return model.VulnerabilityLines{}, fmt.Errorf("structured Terraform JSON locations unsupported")
	}
	if len(path) < 3 || path[0].IsIndex || path[1].IsIndex || path[2].IsIndex || (path[0].Key != "resource" && path[0].Key != "data") {
		return model.VulnerabilityLines{}, fmt.Errorf("expected written resource/data type and name")
	}
	body, err := d.cachedParseBody(file.OriginalData, file.FilePath)
	if err != nil {
		return model.VulnerabilityLines{}, err
	}
	blocks := d.blocksByName(body)[blockKey(path[0].Key, path[1].Key, path[2].Key)]
	if len(blocks) != 1 {
		return model.VulnerabilityLines{}, fmt.Errorf("source block is missing or ambiguous")
	}
	block := blocks[0]
	source, err := d.sourceBodyPath(block.Body, path[3:], block.DefRange())
	if err != nil {
		return model.VulnerabilityLines{}, err
	}
	lines := file.Lines()
	if source.Start.Line < 1 || source.End.Line > len(lines) {
		return model.VulnerabilityLines{}, fmt.Errorf("source location unavailable")
	}
	result := d.sourceVulnerabilityLines(block, source.Start.Line, lines)
	result.Line = source.Start.Line
	result.ResolvedFile = file.FilePath
	result.VulnerablilityLocation = model.ResourceLocation{Start: toResourceLine(source.Start), End: toResourceLine(source.End)}
	result.VulnLines = detector.GetAdjacentVulnLines(source.Start.Line-1, output, lines)
	result.FileSource = lines
	return result, nil
}

func (d *DetectKindLine) sourceBodyPath(body *hclsyntax.Body, path model.SourcePath, anchor hcl.Range) (hcl.Range, error) {
	if len(path) == 0 {
		return anchor, nil
	}
	first := path[0]
	if first.IsIndex {
		return hcl.Range{}, fmt.Errorf("array index applied to block body")
	}
	if attr, ok := body.Attributes[first.Key]; ok {
		return d.sourceExpressionPath(attr.Expr, path[1:], attr.Range())
	}
	group := d.indexSourceBody(body).groups[first.Key]
	if group == nil {
		if len(path) > 1 {
			return hcl.Range{}, fmt.Errorf("missing intermediate source property")
		}
		return anchor, nil
	}
	return d.sourceBlockPath(group, path[1:])
}

type sourceBlockGroup struct {
	first  *hclsyntax.Block
	labels map[string]*sourceBlockGroup
	blocks []*hclsyntax.Block
}

type sourceBodyIndex struct {
	groups  map[string]*sourceBlockGroup
	wrapped []*hclsyntax.Attribute
}

func (d *DetectKindLine) indexSourceBody(body *hclsyntax.Body) *sourceBodyIndex {
	if cached, ok := d.sourceBodies.Load(body); ok {
		return cached.(*sourceBodyIndex)
	}
	index := &sourceBodyIndex{groups: make(map[string]*sourceBlockGroup)}
	for _, block := range body.Blocks {
		group := index.groups[block.Type]
		if group == nil {
			group = &sourceBlockGroup{first: block}
			index.groups[block.Type] = group
		}
		for _, label := range block.Labels {
			if group.labels == nil {
				group.labels = make(map[string]*sourceBlockGroup)
			}
			child := group.labels[label]
			if child == nil {
				child = &sourceBlockGroup{first: block}
				group.labels[label] = child
			}
			group = child
		}
		group.blocks = append(group.blocks, block)
	}

	for _, attr := range body.Attributes {
		switch attr.Expr.(type) {
		case *hclsyntax.ObjectConsExpr, *hclsyntax.FunctionCallExpr:
			index.wrapped = append(index.wrapped, attr)
		}
	}
	sort.Slice(index.wrapped, func(i, j int) bool {
		return index.wrapped[i].SrcRange.Start.Byte < index.wrapped[j].SrcRange.Start.Byte
	})
	actual, _ := d.sourceBodies.LoadOrStore(body, index)
	return actual.(*sourceBodyIndex)
}

// Labels form object keys; only a repeated complete label path forms an array.
func (d *DetectKindLine) sourceBlockPath(group *sourceBlockGroup, path model.SourcePath) (hcl.Range, error) {
	anchor := group.first.DefRange()
	if len(path) == 0 {
		return anchor, nil
	}
	if len(group.labels) > 0 {
		if len(group.blocks) > 0 {
			return hcl.Range{}, fmt.Errorf("ambiguous source block label shape")
		}
		if path[0].IsIndex {
			return hcl.Range{}, fmt.Errorf("block label requires an object key")
		}
		child := group.labels[path[0].Key]
		if child == nil {
			if len(path) > 1 {
				return hcl.Range{}, fmt.Errorf("missing intermediate block label")
			}
			return anchor, nil
		}
		return d.sourceBlockPath(child, path[1:])
	}
	if len(group.blocks) == 1 {
		return d.sourceBodyPath(group.blocks[0].Body, path, anchor)
	}
	selector := path[0]
	if !selector.IsIndex || selector.Index < 0 || selector.Index >= len(group.blocks) {
		return hcl.Range{}, fmt.Errorf("repeated source block requires a valid index")
	}
	block := group.blocks[selector.Index]
	return d.sourceBodyPath(block.Body, path[1:], block.DefRange())
}

func (d *DetectKindLine) sourceExpressionPath(expr hclsyntax.Expression, path model.SourcePath, anchor hcl.Range) (hcl.Range, error) {
	if len(path) == 0 {
		return anchor, nil
	}
	switch value := expr.(type) {
	case *hclsyntax.ParenthesesExpr:
		return d.sourceExpressionPath(value.Expression, path, anchor)
	case *hclsyntax.ObjectConsExpr:
		if path[0].IsIndex {
			return hcl.Range{}, fmt.Errorf("array index applied to object expression")
		}
		return d.sourceObjectPath(value, path, anchor)
	case *hclsyntax.TupleConsExpr:
		index := path[0]
		if !index.IsIndex || index.Index < 0 || index.Index >= len(value.Exprs) {
			return hcl.Range{}, fmt.Errorf("tuple expression requires a valid index")
		}
		child := value.Exprs[index.Index]
		return d.sourceExpressionPath(child, path[1:], child.Range())
	case *hclsyntax.LiteralValueExpr, *hclsyntax.TemplateExpr, *hclsyntax.TemplateWrapExpr:
		return hcl.Range{}, fmt.Errorf("path continues through scalar expression")
	default:
		return hcl.Range{}, fmt.Errorf("structured children of computed expressions unsupported")
	}
}

type sourceObjectMember struct {
	item     hclsyntax.ObjectConsItem
	position int
}
type sourceObjectIndex struct {
	members       map[string]sourceObjectMember
	lastUncertain int
}

func (d *DetectKindLine) indexSourceObject(value *hclsyntax.ObjectConsExpr) *sourceObjectIndex {
	if cached, ok := d.sourceObjects.Load(value); ok {
		return cached.(*sourceObjectIndex)
	}
	index := &sourceObjectIndex{members: make(map[string]sourceObjectMember, len(value.Items)), lastUncertain: -1}
	for position, item := range value.Items {
		key, diags := item.KeyExpr.Value(nil)
		if diags.HasErrors() || !key.IsKnown() || key.IsNull() {
			index.lastUncertain = position
			continue
		}
		key, err := convert.Convert(key, cty.String)
		if err != nil {
			index.lastUncertain = position
			continue
		}
		index.members[key.AsString()] = sourceObjectMember{item: item, position: position}
	}
	actual, _ := d.sourceObjects.LoadOrStore(value, index)
	return actual.(*sourceObjectIndex)
}

func (d *DetectKindLine) sourceObjectPath(value *hclsyntax.ObjectConsExpr, path model.SourcePath, anchor hcl.Range) (hcl.Range, error) {
	index := d.indexSourceObject(value)
	member, found := index.members[path[0].Key]
	if index.lastUncertain >= 0 && (!found || index.lastUncertain > member.position) {
		return hcl.Range{}, fmt.Errorf("computed object key source unsupported")
	}
	if found {
		location := hcl.RangeBetween(member.item.KeyExpr.Range(), member.item.ValueExpr.Range())
		return d.sourceExpressionPath(member.item.ValueExpr, path[1:], location)
	}
	if len(path) > 1 {
		return hcl.Range{}, fmt.Errorf("missing intermediate object property")
	}
	return anchor, nil
}

// Source formatting reuses the legacy insertion math, with indexed containment
// and one shared source excerpt per written resource block.
type sourceInsertionKey struct {
	block *hclsyntax.Block
	line  int
}

func (d *DetectKindLine) sourceVulnerabilityLines(block *hclsyntax.Block, line int, lines []string) model.VulnerabilityLines {
	key := sourceInsertionKey{block: block, line: line}
	insertion, cached := d.sourceInsertions.Load(key)
	if !cached {
		at, col := calculateInsertionPointWith(block, line, lines, nil, d.sourceContainingStructure)
		insertion, _ = d.sourceInsertions.LoadOrStore(key, model.ResourceLine{Line: at, Col: col})
	}
	text, cached := d.sourceText.Load(block)
	if !cached {
		text, _ = d.sourceText.LoadOrStore(block, extractBlockSource(lines, block.TypeRange.Start.Line, block.Body.SrcRange.End.Line))
	}
	location := model.ResourceLocation{Start: toResourceLine(block.TypeRange.Start), End: toResourceLine(block.Body.SrcRange.End)}
	point := insertion.(model.ResourceLine)
	return model.VulnerabilityLines{
		BlockLocation: location, RemediationLocation: model.ResourceLocation{Start: point, End: point},
		LineWithVulnerability: lines[line-1], ResourceSource: text.(string),
	}
}

func (d *DetectKindLine) sourceContainingStructure(block *hclsyntax.Block, line int) (name string, start, end hcl.Pos, isAttr bool) {
	blocks := block.Body.Blocks
	// Sibling blocks are in source order. Searching by end line preserves the
	// legacy first-match behavior even for siblings sharing a physical line.
	index := sort.Search(len(blocks), func(i int) bool { return blocks[i].Body.SrcRange.End.Line >= line })
	if index < len(blocks) && blocks[index].TypeRange.Start.Line <= line {
		nested := blocks[index]
		if name, start, end, attr := d.sourceContainingStructure(nested, line); name != "" {
			return name, start, end, attr
		}
		return nested.Type, nested.TypeRange.Start, nested.Body.SrcRange.End, false
	}
	attributes := d.indexSourceBody(block.Body).wrapped
	index = sort.Search(len(attributes), func(i int) bool { return attributes[i].SrcRange.End.Line >= line })
	if index < len(attributes) && attributes[index].SrcRange.Start.Line <= line {
		attr := attributes[index]
		return attr.Name, attr.SrcRange.Start, attr.SrcRange.End, true
	}
	return "", hcl.Pos{}, hcl.Pos{}, false
}
