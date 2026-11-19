/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"fmt"

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
	source, err := sourceBodyPath(block.Body, path[3:], block.DefRange())
	if err != nil {
		return model.VulnerabilityLines{}, err
	}
	lines := file.Lines()
	if source.Start.Line < 1 || source.End.Line > len(lines) {
		return model.VulnerabilityLines{}, fmt.Errorf("source location unavailable")
	}
	result := vulnerabilityLinesFromBlock(block, source.Start.Line, lines, nil)
	result.Line = source.Start.Line
	result.ResolvedFile = file.FilePath
	result.VulnerablilityLocation = model.ResourceLocation{Start: toResourceLine(source.Start), End: toResourceLine(source.End)}
	result.VulnLines = detector.GetAdjacentVulnLines(source.Start.Line-1, output, lines)
	result.FileSource = lines
	return result, nil
}

func sourceBodyPath(body *hclsyntax.Body, path model.SourcePath, anchor hcl.Range) (hcl.Range, error) {
	if len(path) == 0 {
		return anchor, nil
	}
	first := path[0]
	if first.IsIndex {
		return hcl.Range{}, fmt.Errorf("array index applied to block body")
	}
	if attr, ok := body.Attributes[first.Key]; ok {
		return sourceExpressionPath(attr.Expr, path[1:], attr.Range())
	}
	var blocks []*hclsyntax.Block
	for _, block := range body.Blocks {
		if block.Type == first.Key {
			blocks = append(blocks, block)
		}
	}
	if len(blocks) == 0 {
		if len(path) > 1 {
			return hcl.Range{}, fmt.Errorf("missing intermediate source property")
		}
		return anchor, nil
	}
	if len(path) == 1 {
		return blocks[0].DefRange(), nil
	}
	// The parser exposes one unlabeled block as an object and repeated blocks
	// as an array. Source traversal must follow that same shape.
	if len(blocks) == 1 && len(blocks[0].Labels) == 0 {
		return sourceBodyPath(blocks[0].Body, path[1:], blocks[0].DefRange())
	}
	selector := path[1]
	if !selector.IsIndex || selector.Index < 0 || selector.Index >= len(blocks) {
		return hcl.Range{}, fmt.Errorf("nested source block requires a valid index")
	}
	block := blocks[selector.Index]
	return sourceBodyPath(block.Body, path[2:], block.DefRange())
}

func sourceExpressionPath(expr hclsyntax.Expression, path model.SourcePath, anchor hcl.Range) (hcl.Range, error) {
	if len(path) == 0 {
		return anchor, nil
	}
	switch value := expr.(type) {
	case *hclsyntax.ParenthesesExpr:
		return sourceExpressionPath(value.Expression, path, anchor)
	case *hclsyntax.ObjectConsExpr:
		if path[0].IsIndex {
			return hcl.Range{}, fmt.Errorf("array index applied to object expression")
		}
		return sourceObjectPath(value, path, anchor)
	case *hclsyntax.TupleConsExpr:
		index := path[0]
		if !index.IsIndex || index.Index < 0 || index.Index >= len(value.Exprs) {
			return hcl.Range{}, fmt.Errorf("tuple expression requires a valid index")
		}
		child := value.Exprs[index.Index]
		return sourceExpressionPath(child, path[1:], child.Range())
	case *hclsyntax.LiteralValueExpr, *hclsyntax.TemplateExpr, *hclsyntax.TemplateWrapExpr:
		return hcl.Range{}, fmt.Errorf("path continues through scalar expression")
	default:
		return hcl.Range{}, fmt.Errorf("structured children of computed expressions unsupported")
	}
}

func sourceObjectPath(value *hclsyntax.ObjectConsExpr, path model.SourcePath, anchor hcl.Range) (hcl.Range, error) {
	// Object constructors use the last value for duplicate keys. An unknown
	// later key can override any earlier one, so that selection is unsupported.
	for index := len(value.Items) - 1; index >= 0; index-- {
		item := value.Items[index]
		key, diags := item.KeyExpr.Value(nil)
		if diags.HasErrors() || !key.IsKnown() || key.IsNull() {
			return hcl.Range{}, fmt.Errorf("computed object key source unsupported")
		}
		key, err := convert.Convert(key, cty.String)
		if err != nil {
			return anchor, nil
		}
		if key.AsString() == path[0].Key {
			return sourceExpressionPath(item.ValueExpr, path[1:], hcl.RangeBetween(item.KeyExpr.Range(), item.ValueExpr.Range()))
		}
	}
	if len(path) > 1 {
		return hcl.Range{}, fmt.Errorf("missing intermediate object property")
	}
	return anchor, nil
}
