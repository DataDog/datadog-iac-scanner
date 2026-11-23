/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package parser

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// WithLineInfoOnly marks a parse as a reparse that only needs the document's
// line markers, so parsers may skip enrichment that only rules consume.
func WithLineInfoOnly(ctx context.Context) context.Context {
	return model.WithLineInfoOnly(ctx)
}

// IsLineInfoOnly reports whether ctx was marked with WithLineInfoOnly.
func IsLineInfoOnly(ctx context.Context) bool {
	return model.IsLineInfoOnly(ctx)
}

type lineInfoExportKey struct{}

// WithLineInfoExport marks a line-info reparse whose documents are exported
// whole as the line-info payload (see model.FileMetadatas.Combine), so
// parsers must not reduce them to the part line detection reads.
func WithLineInfoExport(ctx context.Context) context.Context {
	return context.WithValue(ctx, lineInfoExportKey{}, true)
}

// IsLineInfoExport reports whether ctx was marked with WithLineInfoExport.
func IsLineInfoExport(ctx context.Context) bool {
	v, _ := ctx.Value(lineInfoExportKey{}).(bool)
	return v
}

// WithLazyLineInfo marks a parse whose documents' line markers are never
// read, because line info is rebuilt on demand by a line-info reparse (see
// WithLineInfoOnly), so parsers may leave the markers out.
func WithLazyLineInfo(ctx context.Context) context.Context {
	return model.WithLazyLineInfo(ctx)
}

// IsLazyLineInfo reports whether ctx was marked with WithLazyLineInfo.
func IsLazyLineInfo(ctx context.Context) bool {
	return model.IsLazyLineInfo(ctx)
}
