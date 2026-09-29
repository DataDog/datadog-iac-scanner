package yaml

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	yamlv3 "gopkg.in/yaml.v3"
)

func TestParseDecoderDiagnostics(t *testing.T) {
	for _, tt := range []struct {
		name, content string
		unknownAnchor bool
	}{
		{"unknown anchor", "password: *FakeSecret123\n", true},
		{"unclosed flow", "kind: ConfigMap\nmetadata: [\n", false},
		{"invalid escape", "kind: ConfigMap\nmetadata: \"FakeSecret123\\q\"\n", false},
		{"undefined tag", "kind: ConfigMap\nmetadata: !FakeSecret123!tag value\n", false},
		{"duplicate directive", "%YAML 1.1\n%YAML 1.1\n---\nkind: ConfigMap\n", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var node yamlv3.Node
			originalErr := yamlv3.NewDecoder(strings.NewReader(tt.content)).Decode(&node)
			require.Error(t, originalErr)
			_, docs, _, _, err := Parse(context.Background(), []byte(tt.content), "test.yaml", false, 15)
			require.Error(t, err)
			require.Empty(t, docs)
			require.Contains(t, err.Error(), "YAML document 1")
			require.NotContains(t, err.Error(), "FakeSecret123")
			if tt.unknownAnchor {
				require.Contains(t, originalErr.Error(), "FakeSecret123")
				require.Contains(t, err.Error(), "unknown anchor referenced")
			} else {
				require.Contains(t, originalErr.Error(), "line ")
				require.ErrorContains(t, err, originalErr.Error(), "source-free syntax diagnostics retain their location and reason")
			}
		})
	}
}

func TestParseEmptyAndMalformedStreams(t *testing.T) {
	for _, tt := range []struct {
		name, content string
		docs          int
		wantErr       bool
	}{
		{"empty", "", 0, false},
		{"comments CRLF", " \r\n# comment\r\n", 0, false},
		{"empty documents", "---\n---\n# end\n", 0, false},
		{"null documents", "null\n---\n~\n---\n!!null \"\"\n", 0, false},
		{"empty around real documents", "---\n---\nkind: ConfigMap\n---\nnull\n---\nkind: Secret\n---\n", 2, false},
		{"malformed first", "kind: [\n", 0, true},
		{"malformed after empty", "---\n---\nkind: [\n", 0, true},
		{"malformed tail", "kind: ConfigMap\n---\nkind: [\n", 1, true},
		{"unsupported scalar", "just a scalar\n", 0, true},
		{"empty integer scalar", "!!int \"\"\n", 0, true},
		{"empty double quoted string", "\"\"\n", 0, false},
		{"empty single quoted string", "''\n", 0, false},
		{"empty string scalar", "!!str \"\"\n", 0, false},
		{"empty tagged string", "!!str\n", 0, false},
		{"empty string stream", "\"\"\n---\n''\n---\n!!str \"\"\n", 0, false},
		{"empty strings around real documents", "''\n---\nkind: ConfigMap\n---\n!!str \"\"\n---\nkind: Secret\n---\n\"\"\n", 2, false},
		{"empty string before malformed", "''\n---\nkind: [\n", 0, true},
		{"empty string in partial stream", "kind: ConfigMap\n---\n''\n---\n!!int \"\"\n", 1, true},
		{"nonempty string scalar", "!!str value\n", 0, true},
		{"empty custom scalar", "!custom \"\"\n", 0, true},
		{"invalid null scalar", "!!null invalid\n", 0, true},
		{"unsupported middle", "kind: ConfigMap\n---\njust a scalar\n---\nkind: Secret\n", 2, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, docs, _, _, err := Parse(context.Background(), []byte(tt.content), "test.yaml", false, 15)
			require.Len(t, docs, tt.docs)
			if tt.wantErr {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "no documents found")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
