/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package lineinfo marks parses that only rebuild line markers. It imports no
// parser so every parser package can read the marks.
package lineinfo

import "context"

type onlyKey struct{}

// WithOnly marks a parse as a reparse that only needs the document's line
// markers, so parsers may skip enrichment that only rules consume.
func WithOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, onlyKey{}, true)
}

// IsOnly reports whether ctx was marked with WithOnly.
func IsOnly(ctx context.Context) bool {
	v, _ := ctx.Value(onlyKey{}).(bool)
	return v
}

type hclBodyKey struct{}

// WithHCLBody returns a context a parser can publish an HCL body on, and a
// function reading it back. The box is required for this parse: it is the
// only way the Terraform parser hands its body to the caller, which copies it
// onto ParsedDocument.HCLBody. Line detection reads ParsedDocument.HCLBody,
// not the box.
func WithHCLBody(parent context.Context) (ctx context.Context, body func() any) {
	box := new(any)
	ctx = context.WithValue(parent, hclBodyKey{}, box)
	body = func() any { return *box }
	return ctx, body
}

// SetHCLBody publishes body for the context from WithHCLBody. It does nothing
// on any other context, so a parse not started under WithHCLBody publishes no
// body onto ParsedDocument.HCLBody.
func SetHCLBody(ctx context.Context, body any) {
	if box, ok := ctx.Value(hclBodyKey{}).(*any); ok {
		*box = body
	}
}
