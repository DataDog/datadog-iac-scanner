/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package parser

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
)

type lineInfoOnlyKey struct{}

// WithLineInfoOnly marks a parse as a reparse that only needs the document's
// line markers, so parsers may skip enrichment that only rules consume.
func WithLineInfoOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, lineInfoOnlyKey{}, true)
}

// IsLineInfoOnly reports whether ctx was marked with WithLineInfoOnly.
func IsLineInfoOnly(ctx context.Context) bool {
	v, _ := ctx.Value(lineInfoOnlyKey{}).(bool)
	return v
}

// lineInfoContextParser is an optional capability for recording parser-specific
// source metadata during the existing lazy reparse, without format branches in
// the runner.
type lineInfoContextParser interface {
	LineInfoContext(context.Context, *model.FileMetadata) context.Context
}

// LineInfoContext prepares a source-only parse and invokes the parser's optional
// metadata hook. Other parsers retain the same line-info behavior.
func (c *Parser) LineInfoContext(ctx context.Context, file *model.FileMetadata) context.Context {
	ctx = WithLineInfoOnly(ctx)
	if hook, ok := c.Parsers.(lineInfoContextParser); ok {
		ctx = hook.LineInfoContext(ctx, file)
	}
	return ctx
}

// PrepareContext invokes optional parser preparation once before routing and
// content exclusion. The derived context belongs to this file's dispatch only.
func (c *Parser) PrepareContext(ctx context.Context, path string, content []byte) (prepared context.Context, normalized []byte) {
	if hook, ok := c.Parsers.(interface {
		PrepareContext(context.Context, string, []byte) context.Context
	}); ok {
		// Match the bytes document parsing receives. Formats without this hook
		// retain their existing exclusion/classification input unchanged.
		content = utils.NormalizeSource(content)
		return hook.PrepareContext(ctx, path, content), content
	}
	return ctx, content
}

// SourceContext transfers optional immutable parser preparation into a later
// line-info request, preserving that request's cancellation and tracing context.
func (c *Parser) SourceContext(ctx context.Context) func(context.Context) context.Context {
	if hook, ok := c.Parsers.(interface {
		SourceContext(context.Context) func(context.Context) context.Context
	}); ok {
		return hook.SourceContext(ctx)
	}
	return nil
}

// FinishContext releases dispatch-only parser state after all source transfers,
// including excluded files and failed parses. Saved source contexts stay valid.
func (c *Parser) FinishContext(ctx context.Context) {
	if hook, ok := c.Parsers.(interface{ FinishContext(context.Context) }); ok {
		hook.FinishContext(ctx)
	}
}
