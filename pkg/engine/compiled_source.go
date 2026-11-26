/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com) Copyright 2026 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	"github.com/DataDog/datadog-iac-scanner/pkg/detector"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
)

type opaSourceValue struct{ value ast.Value }

func (v opaSourceValue) Kind() reflect.Kind {
	switch v.value.(type) {
	case ast.Object:
		return reflect.Map
	case *ast.Array:
		return reflect.Slice
	default:
		return reflect.Invalid
	}
}
func (v opaSourceValue) Field(key string) (detector.SourceValue, bool) {
	object, ok := v.value.(ast.Object)
	if !ok {
		return nil, false
	}
	term := object.Get(ast.StringTerm(key))
	if term == nil {
		return nil, false
	}
	return opaSourceValue{term.Value}, true
}
func (v opaSourceValue) Keys() []string {
	object, ok := v.value.(ast.Object)
	if !ok {
		return nil
	}
	keys := make([]string, 0, object.Len())
	for _, term := range object.Keys() {
		if key, ok := term.Value.(ast.String); ok {
			keys = append(keys, string(key))
		}
	}
	sort.Strings(keys)
	return keys
}
func (v opaSourceValue) Element(index int) detector.SourceValue {
	return opaSourceValue{v.value.(*ast.Array).Elem(index).Value}
}
func (v opaSourceValue) Length() int { return v.value.(*ast.Array).Len() }
func (v opaSourceValue) Text() string {
	if text, ok := v.value.(ast.String); ok {
		return string(text)
	}
	if v.Kind() == reflect.Invalid {
		return v.value.String()
	}
	return ""
}
func (v opaSourceValue) Identity() detector.SourceIdentity {
	if v.Kind() == reflect.Map || v.Kind() == reflect.Slice {
		return detector.SourceIdentity{Pointer: reflect.ValueOf(v.value).Pointer()}
	}
	return detector.SourceIdentity{}
}

// compiledSourceValue borrows the same immutable OPA document evaluated by the
// rule. It remains available when the scanner releases the native document map.
func (q *QueryContext) compiledSourceValue(file *model.FileMetadata) (detector.SourceValue, error) {
	if value := q.compiledSources[file.ID]; value != nil {
		return opaSourceValue{value}, nil
	}

	if file.Document != nil {
		document := file.Document
		if file.DocumentDialect == model.GitLabDialect {
			document = file.RuleInputDocument(document)
		}
		return detector.NativeSourceValue{Value: document}, nil
	}
	return nil, fmt.Errorf("compiled source document unavailable")
}

type compiledLocation struct {
	file *model.FileMetadata
	line int
	path model.SourcePath
}

// Source selectors search written configuration, never the analysis envelope.
type gitlabSourceRoot struct{ detector.SourceValue }

func (v gitlabSourceRoot) Keys() []string { return []string{model.GitLabInputKey} }
func (v gitlabSourceRoot) Field(key string) (detector.SourceValue, bool) {
	if key != model.GitLabInputKey {
		return nil, false
	}
	child, ok := v.SourceValue.Field(key)
	if !ok {
		return nil, false
	}
	return detector.WrittenSourceValue(child), true
}

// One concrete address drives source reporting and inventory association.
func (q *QueryContext) compiledFindingLocation(
	ctx context.Context, document *model.FileMetadata, path model.SourcePath, writtenKey string,
) (compiledLocation, error) {
	if len(document.SourceFiles) == 0 {
		return compiledLocation{}, nil
	}
	if path == nil && writtenKey == "" {
		return compiledRootLocation(document)
	}
	value, err := q.compiledSourceValue(document)
	if err != nil {
		return compiledLocation{}, err
	}
	var concrete model.SourcePath
	if path != nil {
		concrete, err = detector.ResolveSourcePath(value, path)
	} else {
		if document.DocumentDialect == model.GitLabDialect {
			value = gitlabSourceRoot{value}
		}
		concrete, err = detector.ResolveLegacySourcePath(ctx, value, writtenKey)
	}
	if err != nil {
		return compiledLocation{}, err
	}
	if document.DocumentDialect == model.GitLabDialect && len(concrete) > 0 {
		if concrete[0].IsIndex || concrete[0].Key != model.GitLabInputKey {
			return compiledLocation{}, fmt.Errorf("finding path must address GitLab configuration")
		}
		concrete = concrete[1:]
	}
	file, line, found := document.FindingSourceAt(concrete.Components())
	if !found {
		return compiledLocation{}, fmt.Errorf("compiled field source unavailable")
	}
	_, ignored := file.Commands["ignore"]
	if file.SourceExcluded || ignored {
		return compiledLocation{}, ErrNoResult
	}
	return compiledLocation{file: file, line: line, path: concrete}, nil
}

func compiledRootLocation(document *model.FileMetadata) (compiledLocation, error) {
	if _, ignored := document.Commands["ignore"]; ignored {
		return compiledLocation{}, ErrNoResult
	}
	return compiledLocation{file: document, line: 1}, nil
}
