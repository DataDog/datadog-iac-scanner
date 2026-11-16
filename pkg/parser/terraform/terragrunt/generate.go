/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terragrunt

import (
	"context"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// GeneratedFile is a file a generate block writes into the module's working
// copy.
type GeneratedFile struct {
	Label    string
	Path     string
	Contents string
	// ContentsStart is where the contents' first line is written, in the file
	// declaring the block; for contents computed elsewhere, the attribute.
	ContentsStart hcl.Pos
	Filename      string
	IfExists      string
}

// RemoteState is a remote_state block: the backend Terragrunt configures.
type RemoteState struct {
	Backend string
	Config  cty.Value
	Range   hcl.Range
}

// evaluateGenerate evaluates the generate blocks whose contents are known and
// that are not disabled.
func evaluateGenerate(ctx context.Context, body *hclsyntax.Body, evalCtx *hcl.EvalContext) map[string]GeneratedFile {
	out := map[string]GeneratedFile{}
	for _, block := range blocksOfType(body, "generate") {
		if len(block.Labels) == 0 || isKnownTrue(attributeValue(block.Body, "disable", evalCtx)) {
			continue
		}
		path, ok := knownString(attributeValue(block.Body, "path", evalCtx))
		if !ok {
			continue
		}
		attr, ok := block.Body.Attributes["contents"]
		if !ok {
			continue
		}
		contents, ok := knownString(evalExpr(ctx, attr.Expr, evalCtx))
		if !ok {
			continue
		}
		ifExists, _ := knownString(attributeValue(block.Body, "if_exists", evalCtx))
		out[block.Labels[0]] = GeneratedFile{
			Label:         block.Labels[0],
			Path:          path,
			Contents:      contents,
			ContentsStart: contentsStart(attr),
			Filename:      attr.SrcRange.Filename,
			IfExists:      ifExists,
		}
	}
	return out
}

// contentsStart is where a literal or heredoc's text begins.
func contentsStart(attr *hclsyntax.Attribute) hcl.Pos {
	if template, ok := attr.Expr.(*hclsyntax.TemplateExpr); ok && len(template.Parts) > 0 {
		return template.Parts[0].Range().Start
	}
	return attr.Expr.Range().Start
}

// evaluateRemoteState evaluates the remote_state block, nil when there is
// none or its backend is unknown.
func evaluateRemoteState(body *hclsyntax.Body, evalCtx *hcl.EvalContext) *RemoteState {
	var out *RemoteState
	for _, block := range blocksOfType(body, "remote_state") {
		backend, ok := knownString(attributeValue(block.Body, "backend", evalCtx))
		if !ok || isKnownTrue(attributeValue(block.Body, "disable", evalCtx)) {
			continue
		}
		config := attributeValue(block.Body, "config", evalCtx)
		if config == cty.NilVal {
			config = cty.EmptyObjectVal
		}
		out = &RemoteState{Backend: backend, Config: config, Range: block.Range()}
	}
	return out
}
