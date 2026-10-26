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
