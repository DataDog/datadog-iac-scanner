/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package utils

import "testing"

func TestHasYAMLBreakingTemplate(t *testing.T) {
	tests := map[string]bool{
		"metadata:\n  name: {{ .Values.name }}\n":   true,
		"{{- if .Values.enabled }}\nkind: A\n":      true,
		"items:\n  - {{ .Values.item }}\n":          true,
		"steps:\n  - run: echo ${{ secrets.X }}\n":  false,
		"- debug: msg=\"{{ foo }}\"\n":              false,
		"Password: '{{resolve:ssm:/p}}'\n":          false,
		"kind: A # {{ x }}\n":                       false,
		"# render with {{ values }}\nkind: A\n":     false,
		"if: ${{ github.event_name == 'push' }}\n":  false,
		"image: \"{{ .Values.image }}\"\nkind: A\n": false,
	}
	for content, want := range tests {
		if got := HasYAMLBreakingTemplate([]byte(content)); got != want {
			t.Errorf("HasYAMLBreakingTemplate(%q) = %v, want %v", content, got, want)
		}
	}
}
