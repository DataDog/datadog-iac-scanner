/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package parser

import "context"

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
