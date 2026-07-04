/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package pulumi

import "context"

type contextKey struct{}

// FileSymbols holds statically extracted exported symbols from a single source file.
// Only literal-valued exports (strings, numbers, bools, plain maps, plain slices)
// are stored; dynamic or computed values are omitted.
type FileSymbols struct {
	Values map[string]interface{}
}

// ProjectIndex maps absolute (slash-separated) file paths to their exported symbols.
// It is built once from the full file inventory before individual files are parsed,
// allowing parsers to resolve cross-file constants without a second repo walk.
type ProjectIndex struct {
	ByFile map[string]*FileSymbols
}

// Lookup returns the FileSymbols for absPath, or nil if not indexed.
func (idx *ProjectIndex) Lookup(absPath string) *FileSymbols {
	if idx == nil {
		return nil
	}
	return idx.ByFile[absPath]
}

// WithProjectIndex attaches idx to ctx so all language parsers can resolve
// cross-file constants without changing the kindParser interface.
func WithProjectIndex(ctx context.Context, idx *ProjectIndex) context.Context {
	return context.WithValue(ctx, contextKey{}, idx)
}

// ProjectIndexFromContext returns the *ProjectIndex attached to ctx, or nil.
func ProjectIndexFromContext(ctx context.Context) *ProjectIndex {
	v, _ := ctx.Value(contextKey{}).(*ProjectIndex)
	return v
}
