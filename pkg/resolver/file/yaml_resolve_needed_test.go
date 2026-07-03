package file

import "testing"

func TestYamlResolveNeeded(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{name: "plain k8s single doc", content: "apiVersion: v1\nkind: Pod\n", want: false},
		{name: "multi doc", content: "apiVersion: v1\nkind: Pod\n---\napiVersion: v1\nkind: Service\n", want: true},
		{name: "openapi ref", content: "responses:\n  err:\n    $ref: '#/components/schemas/Error'\n", want: true},
		{name: "ansible include", content: "tasks:\n  - include_vars: vars.yml\n", want: true},
		{name: "helm template", content: "metadata:\n  name: {{ .Values.name }}\n", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := yamlResolveNeeded([]byte(tt.content), false); got != tt.want {
				t.Errorf("yamlResolveNeeded() = %v, want %v", got, tt.want)
			}
		})
	}
}
