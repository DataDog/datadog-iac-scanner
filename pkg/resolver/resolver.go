/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// Preprocessor expands composed IaC (Helm, Kustomize, …) into files for parsing.
type Preprocessor interface {
	Resolve(ctx context.Context, rootDir string) (model.ResolvedFiles, error)
	SupportedTypes() []model.FileKind
	Name() string
	Detect(path string) (model.FileKind, bool)
}

// Resolver dispatches to preprocessors by file kind.
type Resolver struct {
	byKind  map[model.FileKind]Preprocessor
	ordered []Preprocessor
}

// Builder constructs a Resolver from preprocessors.
type Builder struct {
	preprocessors []Preprocessor
}

// NewBuilder creates a new Builder.
func NewBuilder() *Builder {
	return &Builder{}
}

// Add registers a preprocessor (call order is preserved for GetType detection).
func (b *Builder) Add(ctx context.Context, p Preprocessor) *Builder {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msgf("resolver.Add(%s)", p.Name())
	b.preprocessors = append(b.preprocessors, p)
	return b
}

// Build creates the Resolver. Later preprocessors overwrite byKind for the same FileKind.
func (b *Builder) Build(ctx context.Context) (*Resolver, error) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("resolver.Build()")

	byKind := make(map[model.FileKind]Preprocessor)
	for _, p := range b.preprocessors {
		for _, t := range p.SupportedTypes() {
			byKind[t] = p
		}
	}

	return &Resolver{
		byKind:  byKind,
		ordered: append([]Preprocessor(nil), b.preprocessors...),
	}, nil
}

// Resolve runs the preprocessor for the given kind.
func (r *Resolver) Resolve(ctx context.Context, filePath string, kind model.FileKind) (model.ResolvedFiles, error) {
	contextLogger := logger.FromContext(ctx)
	if p, ok := r.byKind[kind]; ok {
		obj, err := p.Resolve(ctx, filePath)
		if err != nil {
			return model.ResolvedFiles{}, err
		}
		contextLogger.Debug().Msgf("resolver.Resolve() rendered file: %s", filePath)
		return obj, nil
	}
	return model.ResolvedFiles{}, nil
}

// GetType picks a preprocessor for a directory; registration order matters (Helm before Kustomize for Chart.yaml dirs).
func (r *Resolver) GetType(filePath string) model.FileKind {
	for _, p := range r.ordered {
		if k, ok := p.Detect(filePath); ok {
			return k
		}
	}
	return model.KindCOMMON
}
