/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	ctyConvert "github.com/zclconf/go-cty/cty/convert"
)

// Engine contains the conditions of rules and comments positions
type Engine struct {
}

// ExpToString converts an expression into a string
func (e *Engine) ExpToString(ctx context.Context, expr hclsyntax.Expression) (string, error) {
	contextLogger := logger.FromContext(ctx)
	switch t := expr.(type) {
	case *hclsyntax.LiteralValueExpr:
		s, err := ctyConvert.Convert(t.Val, cty.String)
		if err != nil {
			return "", err
		}
		return s.AsString(), nil
	case *hclsyntax.TemplateExpr:
		if t.IsStringLiteral() {
			v, err := t.Value(nil)
			if err != nil {
				return "", err
			}
			return v.AsString(), nil
		}
		builderString, err := e.buildString(ctx, t.Parts)
		if err != nil {
			return "", err
		}

		return builderString, nil
	case *hclsyntax.TemplateWrapExpr:
		return e.ExpToString(ctx, t.Wrapped)
	case *hclsyntax.ObjectConsKeyExpr:
		return e.ExpToString(ctx, t.Wrapped)
	case *hclsyntax.ScopeTraversalExpr:
		items := evaluateScopeTraversalExpr(t.Traversal)
		return strings.Join(items, "."), nil
	}
	err := fmt.Errorf("can't convert expression %T to string", expr)
	contextLogger.Error().Msg(err.Error())
	return "", err
}

func (e *Engine) buildString(ctx context.Context, parts []hclsyntax.Expression) (string, error) {
	builder := &strings.Builder{}

	for _, part := range parts {
		s, err := e.ExpToString(ctx, part)
		if err != nil {
			return "", err
		}
		builder.WriteString(s)
	}

	s := builder.String()

	builder.Reset()
	builder = nil

	return s, nil
}

func evaluateScopeTraversalExpr(t hcl.Traversal) []string {
	items := make([]string, 0)
	for _, part := range t {
		switch tt := part.(type) {
		case hcl.TraverseAttr:
			items = append(items, tt.Name)
		case hcl.TraverseRoot:
			items = append(items, tt.Name)
		case hcl.TraverseIndex:
			switch tt.Key.Type() {
			case cty.Number:
				items = append(items, tt.Key.AsBigFloat().String())
			case cty.String:
				items = append(items, tt.Key.AsString())
			}
		}
	}
	return items
}
