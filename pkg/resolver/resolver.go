/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"gopkg.in/yaml.v3"
)

// kindResolver is a type of resolver interface (ex: helm resolver)
// Resolve will render file/template
// SupportedTypes will return the file kinds that the resolver supports
type kindResolver interface {
	Resolve(ctx context.Context, filePath string) (model.ResolvedFiles, error)
	SupportedTypes() []model.FileKind
}

// Resolver is a struct containing the resolvers by file kind
type Resolver struct {
	resolvers map[model.FileKind]kindResolver
}

// Builder is a struct used to create a new resolver
type Builder struct {
	resolvers []kindResolver
}

// NewBuilder creates a new Builder's reference
func NewBuilder() *Builder {
	return &Builder{}
}

// Add will add kindResolvers for building the resolver
func (b *Builder) Add(ctx context.Context, p kindResolver) *Builder {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msgf("resolver.Add()")
	b.resolvers = append(b.resolvers, p)
	return b
}

// Build will create a new instance of a resolver
func (b *Builder) Build(ctx context.Context) (*Resolver, error) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("resolver.Build()")

	resolvers := make(map[model.FileKind]kindResolver, len(b.resolvers))
	for _, resolver := range b.resolvers {
		for _, typeRes := range resolver.SupportedTypes() {
			resolvers[typeRes] = resolver
		}
	}

	return &Resolver{
		resolvers: resolvers,
	}, nil
}

// Resolve will resolve the files according to its type
func (r *Resolver) Resolve(ctx context.Context, filePath string, kind model.FileKind) (model.ResolvedFiles, error) {
	contextLogger := logger.FromContext(ctx)
	if r, ok := r.resolvers[kind]; ok {
		obj, err := r.Resolve(ctx, filePath)
		if err != nil {
			return model.ResolvedFiles{}, err
		}
		contextLogger.Debug().Msgf("resolver.Resolve() rendered file: %s", filePath)
		return obj, nil
	}
	// need to log here
	return model.ResolvedFiles{}, nil
}

// GetType will analyze the filepath to determine which resolver to use
func (r *Resolver) GetType(filePath string) model.FileKind {
	chartYAML := filepath.Join(filePath, "Chart.yaml")
	if _, err := os.Stat(chartYAML); err == nil {
		if !isLibraryChart(chartYAML) {
			return model.KindHELM
		}
	}
	return model.KindCOMMON
}

// isLibraryChart returns true if the Chart.yaml at the given path declares type: library.
// Library charts are not installable and should not be processed by the Helm renderer.
func isLibraryChart(chartYAMLPath string) bool {
	data, err := os.ReadFile(chartYAMLPath)
	if err != nil {
		return false
	}
	var meta struct {
		Type string `yaml:"type"`
	}
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return false
	}
	return meta.Type == "library"
}
