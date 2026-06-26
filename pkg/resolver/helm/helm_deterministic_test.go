package helm

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyDeterministicSubstitutions(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string // substring that must appear in output
		absent   string // substring that must NOT appear in output (optional)
	}{
		{
			name:     "randAlphaNum replaced with ddscan stub",
			input:    "name: {{ randAlphaNum 8 | lower }}\n",
			contains: `"ddscan0001"`,
			absent:   "randAlphaNum",
		},
		{
			name:     "randAlpha replaced with ddscan stub",
			input:    "name: {{ randAlpha 5 }}\n",
			contains: `"ddscan0001"`,
			absent:   "randAlpha",
		},
		{
			name:     "randAscii replaced with ddscan stub",
			input:    "apiVersion: v1\nname: {{ randAscii 6 }}\n",
			contains: `"ddscan0002"`,
			absent:   "randAscii",
		},
		{
			name:     "randNumeric replaced with digit-only stub",
			input:    "port-seed: {{ randNumeric 4 }}\n",
			contains: `"00000001"`,
			absent:   "randNumeric",
		},
		{
			name:     "uuidv4 replaced with UUID-shaped stub",
			input:    "scan-id: {{ uuidv4 }}\n",
			contains: `"00000000-0000-0000-0001-000000000001"`,
			absent:   "uuidv4",
		},
		{
			name:     "now replaced with static toDate call",
			input:    "created: {{ now | htmlDate }}\n",
			contains: `(toDate "2006-01-02" "2000-01-01")`,
			absent:   "now",
		},
		{
			name:     "$now variable should NOT be substituted",
			input:    "name: {{ $now }}\n",
			contains: "$now",
			absent:   "$(toDate",
		},
		{
			name:     ".Values.now field should NOT be substituted",
			input:    "value: {{ .Values.now }}\n",
			contains: ".Values.now",
			absent:   "toDate",
		},
		{
			name:     "no match leaves template unchanged",
			input:    "name: {{ .Values.myName }}\nport: 80\n",
			contains: "name: {{ .Values.myName }}\nport: 80\n",
		},
		{
			name:     "randAlphaNum outside action block",
			input:    "data:\n  script: randAlphaNum 8\n",
			contains: "randAlphaNum 8",
			absent:   "ddscan",
		},
		{
			name:     "uuidv4 as template-include string arg",
			input:    `{{ include "uuidv4" . }}`,
			contains: `"uuidv4"`,
			absent:   "00000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := string(applyDeterministicSubstitutions([]byte(tt.input)))
			require.Contains(t, out, tt.contains)
			if tt.absent != "" {
				require.NotContains(t, out, tt.absent)
			}
		})
	}
}

func TestApplyDeterministicSubstitutions_TwoCallsDifferentLines(t *testing.T) {
	// Two randAlphaNum calls on different lines must produce different stubs.
	input := "line1: {{ randAlphaNum 8 }}\nline2: {{ randAlphaNum 8 }}\n"
	out := string(applyDeterministicSubstitutions([]byte(input)))
	require.Contains(t, out, `"ddscan0001"`, "first call should embed line 1")
	require.Contains(t, out, `"ddscan0002"`, "second call should embed line 2")
	require.NotContains(t, out, "randAlphaNum")
}

func TestHelm_DeterministicRendering(t *testing.T) {
	res := &Resolver{}
	ctx := context.Background()

	fixturePath := filepath.FromSlash("../../../test/fixtures/test_helm_nondeterministic")

	first, err := res.Resolve(ctx, fixturePath)
	require.NoError(t, err)
	require.NotEmpty(t, first.File, "first render must produce at least one file")

	second, err := res.Resolve(ctx, fixturePath)
	require.NoError(t, err)

	require.Equal(t, first.File, second.File, "helm rendering must be deterministic")
}
