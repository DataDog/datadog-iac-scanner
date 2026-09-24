/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package dockercompose

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInterpolate(t *testing.T) {
	env := map[string]string{
		"TAG":   "1.25",
		"EMPTY": "",
	}
	lookup := func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	}

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no dollar", "nginx:latest", "nginx:latest"},
		{"braced set", "nginx:${TAG}", "nginx:1.25"},
		{"bare set", "nginx:$TAG", "nginx:1.25"},
		{"bare unset stays literal", "nginx:$MISSING", "nginx:$MISSING"},
		{"bare unset stops at non-name", "$MISSING-x", "$MISSING-x"},
		{"default when unset", "${TAG2:-nginx}", "nginx"},
		{"default when unset no colon", "${TAG2-nginx}", "nginx"},
		{"default when empty", "${EMPTY:-nginx}", "nginx"},
		{"no default when empty dash only", "${EMPTY-nginx}", ""},
		{"set value wins over default", "${TAG:-nginx}", "1.25"},
		{"default containing colon", "${MISSING:-nginx:1.27}", "nginx:1.27"},
		{"alt when set", "${TAG:+prod}", "prod"},
		{"alt unset stays literal", "${MISSING:+prod}", "${MISSING:+prod}"},
		{"alt when empty stays literal", "${EMPTY:+prod}", "${EMPTY:+prod}"},
		{"alt when set no colon", "${TAG+prod}", "prod"},
		{"required unset stays literal", "${MISSING:?required}", "${MISSING:?required}"},
		{"required empty expands empty", "${EMPTY:?required}", ""},
		{"required when set", "${TAG:?required}", "1.25"},
		{"nested default resolves", "${IMAGE:-${FALLBACK:-nginx}}", "nginx"},
		{"nested default outer set", "${TAG:-${FALLBACK:-nginx}}", "1.25"},
		{"nested default inner set", "${MISSING:-${TAG:-nginx}}", "1.25"},
		{"nested default unresolvable stays", "${MISSING:-${ALSO_MISSING}}", "${ALSO_MISSING}"},
		{"nested alternate resolves", "${TAG:+${FALLBACK:-prod}}", "prod"},
		{"nested deep", "${A:-${B:-${C:-deep}}}", "deep"},
		{"escaped dollar", "cost: $$5", "cost: $5"},
		{"escaped dollar then var", "$$${TAG}", "$1.25"},
		{"adjacent refs", "${TAG}${TAG}", "1.251.25"},
		{"lone dollar", "a $ b", "a $ b"},
		{"dollar at end", "abc$", "abc$"},
		{"unterminated brace", "a ${TAG b", "a ${TAG b"},
		{"malformed operator stays literal", "${TAG~x}", "${TAG~x}"},
		{"empty braces stays literal", "${}", "${}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, Interpolate(tt.in, lookup))
		})
	}
}

func TestInterpolateNoDollarShortCircuit(t *testing.T) {
	calls := 0
	lookup := func(name string) (string, bool) {
		calls++
		return "x", true
	}
	require.Equal(t, "plain", Interpolate("plain", lookup))
	require.Zero(t, calls)
}

func TestParseEnvFile(t *testing.T) {
	content := []byte(`
# comment
TAG=1.25
EMPTY=
export EXPORTED=yes
SPACED = trimmed
QUOTED="hello world"
SINGLE='literal $TAG'
NEWLINE="line1\nline2"
TAB="a\tb"
ESC="back\\slash"
MALFORMED
=noname
   # indented comment
UNQUOTED=plain value
`)
	env := ParseEnvFile(content)
	require.Equal(t, map[string]string{
		"TAG":      "1.25",
		"EMPTY":    "",
		"EXPORTED": "yes",
		"SPACED":   "trimmed",
		"QUOTED":   "hello world",
		"SINGLE":   "literal $TAG",
		"NEWLINE":  "line1\nline2",
		"TAB":      "a\tb",
		"ESC":      "back\\slash",
		"UNQUOTED": "plain value",
	}, env)
}
