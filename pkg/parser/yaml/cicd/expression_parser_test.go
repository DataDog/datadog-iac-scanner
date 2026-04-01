package cicd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpressionParser_ExtractExpressions(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "single expression",
			input:    "echo ${{ toJSON(secrets) }}",
			expected: 1,
		},
		{
			name:     "multiple expressions",
			input:    "${{ github.ref }} and ${{ secrets.TOKEN }}",
			expected: 2,
		},
		{
			name:     "no expressions",
			input:    "just plain text",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := extractExpressionsFromString(tt.input)
			assert.Len(t, matches, tt.expected)
		})
	}
}

func TestExpressionParser_ParseSecretsExpansion(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name                 string
		expression           ExpressionMatch
		wantSecretsExpansion bool
		wantDynamicSecret    bool
	}{
		{
			name:                 "toJSON(secrets)",
			expression:           ExpressionMatch{Expression: "toJSON(secrets)", Full: "${{ toJSON(secrets) }}"},
			wantSecretsExpansion: true,
			wantDynamicSecret:    false,
		},
		{
			name:                 "secrets with literal key",
			expression:           ExpressionMatch{Expression: "secrets['MY_SECRET']", Full: "${{ secrets['MY_SECRET'] }}"},
			wantSecretsExpansion: false,
			wantDynamicSecret:    false,
		},
		{
			name:                 "secrets with dynamic key",
			expression:           ExpressionMatch{Expression: "secrets[matrix.env]", Full: "${{ secrets[matrix.env] }}"},
			wantSecretsExpansion: false,
			wantDynamicSecret:    true,
		},
		{
			name:                 "secrets with format",
			expression:           ExpressionMatch{Expression: "secrets[format('PAT_{0}', matrix.env)]", Full: "${{ secrets[format('PAT_{0}', matrix.env)] }}"},
			wantSecretsExpansion: false,
			wantDynamicSecret:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseExpression(ctx, tt.expression)
			assert.True(t, result.ParseOK, "parsing should succeed")
			assert.Equal(t, tt.wantSecretsExpansion, result.HasSecretsExpansion)
			assert.Equal(t, tt.wantDynamicSecret, result.HasDynamicSecretKey)
		})
	}
}

func TestExpressionParser_ConstantReducible(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name             string
		expression       ExpressionMatch
		wantConstant     bool
		wantConstantSubs bool
	}{
		{
			name:             "string literal",
			expression:       ExpressionMatch{Expression: "'foo'", Full: "${{ 'foo' }}"},
			wantConstant:     true,
			wantConstantSubs: false,
		},
		{
			name:             "variable reference",
			expression:       ExpressionMatch{Expression: "github.ref", Full: "${{ github.ref }}"},
			wantConstant:     false,
			wantConstantSubs: false,
		},
		{
			name:             "mixed expression",
			expression:       ExpressionMatch{Expression: "github.ref == 'main' && 1 + 2 > 0", Full: "${{ github.ref == 'main' && 1 + 2 > 0 }}"},
			wantConstant:     false,
			wantConstantSubs: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseExpression(ctx, tt.expression)
			assert.True(t, result.ParseOK, "parsing should succeed")
			assert.Equal(t, tt.wantConstant, result.ConstantReducible)
			if tt.wantConstantSubs {
				assert.NotEmpty(t, result.ConstantSubexprs)
			}
		})
	}
}
