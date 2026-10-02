package runner

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsExpectedHelmRenderError_UndefinedNames(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want bool
	}{
		{"missing helper template", `template: c/templates/a.yaml:3:5: executing "c/templates/a.yaml" at <include "lib.name" .>: error calling include: template: no template "lib.name" associated with template "gotpl"`, true},
		{"undefined named template", `template: c/templates/a.yaml:3:5: template "lib.name" not defined`, true},
		{"misspelled function", `template: c/templates/a.yaml:3: function "tpll" not defined`, false},
		{"required value", `execution error at (c/templates/a.yaml:3:5): value is required`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isExpectedHelmRenderError(errors.New(tt.msg)))
		})
	}
}

func TestHasTemplateSyntax(t *testing.T) {
	require.True(t, hasTemplateSyntax([]byte("name: {{ .Values.name }}\n")))
	require.True(t, hasTemplateSyntax([]byte("# header\n{{- if .Values.on }}\nkind: A\n")))
	require.False(t, hasTemplateSyntax([]byte("# render with {{ values }}\nkind: A\n")))
	require.False(t, hasTemplateSyntax([]byte("kind: A\n  # {{ note }}\n")))
	require.False(t, hasTemplateSyntax([]byte("kind: A\n")))
}
