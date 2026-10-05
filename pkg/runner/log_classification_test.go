package runner

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
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

func TestLogParseFailure(t *testing.T) {
	chart := t.TempDir()
	tests := []struct {
		name, file, content, wantLevel string
	}{
		{"raw template of a failed chart", filepath.Join(chart, "templates", "a.yaml"), "kind: A\n", "debug"},
		{"other file of a failed chart", filepath.Join(chart, "values.yaml"), "kind: A\n", "error"},
		{"test fixture", "repo/testdata/bad.yaml", "kind: A\n", "debug"},
		{"templated YAML", "deploy.yaml", "name: {{ .Values.name }}\n", "debug"},
		{"GitHub Actions expression", ".github/workflows/ci.yaml", "run: echo ${{ secrets.X }}\n", "error"},
		{"quoted Ansible Jinja", "playbook.yaml", "msg: \"{{ foo }}\"\n", "error"},
		{"CloudFormation dynamic reference", "stack.yaml", "Password: '{{resolve:ssm:/p}}'\n", "error"},
		{"template in a trailing comment", "deploy.yaml", "kind: A # {{ x }}\n", "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			ctx := zerolog.New(&logs).WithContext(context.Background())
			s := &Service{}
			s.recordFailedHelmChart(chart)

			s.logParseFailure(ctx, tt.file, []byte(tt.content), errors.New("bad"))

			require.Contains(t, logs.String(), `"level":"`+tt.wantLevel+`"`)
		})
	}
}
