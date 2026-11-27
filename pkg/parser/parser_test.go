/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package parser

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	jsonParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	terraformParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform"
	yamlParser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/default"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

// TestParser_Parse tests the functions [Parse()] and all the methods called by them
func TestParser_Parse(t *testing.T) {
	p := initilizeBuilder()

	ctx := context.Background()
	for _, parser := range p {
		if _, ok := parser.extensions[".json"]; !ok {
			continue
		}
		docs, err := parser.Parse(ctx, "../../test/fixtures/test_extension/test.json", []byte(`
{
	"martin": {
		"name": "CxBraga"
	}
}
`), true, false, 15)
		require.NoError(t, err)
		require.Len(t, docs.Docs, 1)
		require.Contains(t, docs.Docs[0], "martin")
		require.Equal(t, model.KindJSON, docs.Kind)
	}

	for _, parser := range p {
		if _, ok := parser.extensions[".yaml"]; !ok {
			continue
		}
		docs, err := parser.Parse(ctx, "../../test/fixtures/test_extension/test.yaml", []byte(`
martin:
  name: CxBraga
`), true, false, 15)
		require.NoError(t, err)
		require.Len(t, docs.Docs, 1)
		require.Contains(t, docs.Docs[0], "martin")
		require.Equal(t, model.KindYAML, docs.Kind)
	}
}

// TestParser_Empty tests the functions [Parse()] and all the methods called by them (tests an empty parser)
func TestParser_Empty(t *testing.T) {
	ctx := context.Background()
	p, err := NewBuilder(ctx).
		Build([]string{""}, []string{""})
	if err != nil {
		t.Errorf("Error building parser: %s", err)
	}
	for _, parser := range p {
		docs, err := parser.Parse(ctx, "test.json", nil, true, false, 15)
		require.Nil(t, docs.Docs)
		require.Equal(t, model.FileKind(""), docs.Kind)
		require.Error(t, err)
		require.Equal(t, ErrNotSupportedFile, err)
	}
}

func TestParser_ParseContentIgnoresExtension(t *testing.T) {
	ctx := context.Background()
	parsers, err := NewBuilder(ctx).
		Add(&yamlParser.Parser{}).
		Build([]string{"kubernetes"}, nil)
	require.NoError(t, err)
	require.Len(t, parsers, 1)

	documents, err := parsers[0].ParseContent(
		ctx,
		"chart/crds/widget.json",
		[]byte(`{"apiVersion":"v1","kind":"ConfigMap"}`),
		false,
		false,
		15,
	)
	require.NoError(t, err)
	require.Len(t, documents.Docs, 1)
	require.Equal(t, "chart/crds/widget.json", documents.Docs[0]["_path"])
	require.Equal(t, "ConfigMap", documents.Docs[0]["kind"])
}

// TestParser_SupportedExtensions tests the functions [SupportedExtensions()] and all the methods called by them
func TestParser_SupportedExtensions(t *testing.T) {
	p := initilizeBuilder()
	extensions := make(map[string]struct{})

	for _, parser := range p {
		got := parser.SupportedExtensions()
		for key := range got {
			extensions[key] = struct{}{}
		}
	}
	require.NotNil(t, extensions)
	require.Contains(t, extensions, ".json")
	require.Contains(t, extensions, ".tf")
	require.Contains(t, extensions, ".yaml")
}

func initilizeBuilder() []*Parser {
	ctx := context.Background()
	bd, _ := NewBuilder(ctx).
		Add(&jsonParser.Parser{}).
		Add(&yamlParser.Parser{}).
		Add(terraformParser.NewDefault()).
		Build([]string{""}, []string{""})
	return bd
}

func TestIsValidExtension(t *testing.T) {
	ctx := context.Background()
	parser, _ := NewBuilder(ctx).
		Add(&jsonParser.Parser{}).
		Build([]string{""}, []string{""})
	require.True(t, parser[0].isValidExtension(ctx, "../../test/fixtures/test_extension/test.json"), "test.json should be a valid extension")
	require.False(t, parser[0].isValidExtension(ctx, "../../test/fixtures/test_extension/test.xml"), "test.xml should not be a valid extension")
}

func TestParser_Contains(t *testing.T) {
	type args struct {
		types          []string
		supportedTypes map[string]bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "test contains",
			args: args{
				types:          []string{"cloudformation"},
				supportedTypes: map[string]bool{"cloudformation": true, "terraform": true},
			},
			want: true,
		},
		{
			name: "empty types returns false (no platform selected)",
			args: args{
				types:          []string{},
				supportedTypes: map[string]bool{"terraform": true},
			},
			want: false,
		},
		{
			name: "single empty string returns true (no filter)",
			args: args{
				types:          []string{""},
				supportedTypes: map[string]bool{"terraform": true},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contains(tt.args.types, tt.args.supportedTypes)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestBuild_PlatformIsIntersectedWithRequestedTypes verifies that Parser.Platform
// contains only the platforms that were explicitly requested, not every platform
// the underlying parser supports. This prevents Docker Compose (or any other
// opt-in platform) queries from executing when a different YAML platform is
// requested — the regression described in datadog-iac-scanner#363.
func TestBuild_PlatformIsIntersectedWithRequestedTypes(t *testing.T) {
	ctx := context.Background()

	// Request only Kubernetes; the default YAML parser also supports dockercompose,
	// ansible, cloudformation, and several others.
	parsers, err := NewBuilder(ctx).
		Add(&yamlParser.Parser{}).
		Build([]string{"kubernetes"}, nil)
	require.NoError(t, err)
	require.Len(t, parsers, 1)
	require.Equal(t, []string{"kubernetes"}, parsers[0].Platform,
		"Parser.Platform must contain only the requested platform, not all supported types")

	// The wildcard request ("") must still include every supported type.
	allParsers, err := NewBuilder(ctx).
		Add(&yamlParser.Parser{}).
		Build([]string{""}, nil)
	require.NoError(t, err)
	require.Len(t, allParsers, 1)
	require.Greater(t, len(allParsers[0].Platform), 1,
		"wildcard Build should include all supported types")
}

func TestReferenceFilesystemAuthority(t *testing.T) {
	for _, ext := range []string{"json", "yaml"} {
		t.Run(ext, func(t *testing.T) {
			dir := t.TempDir()
			mainPath := filepath.Join(dir, "main."+ext)
			assetPath := filepath.Join(dir, "asset."+ext)
			main := `{"openapi":"3.0.0","info":{"title":"test","version":"1"},"paths":{},"definition":{"marker":"internal"},"internal":{"$ref":"#/definition"},"value":{"$ref":"./asset.json"},"scalar":"./asset.json"}`
			nestedPath := filepath.Join(dir, "nested."+ext)
			nested := `{"$ref":"./nested.json"}`
			owned, host := `{"marker":"owned"}`, `{"marker":"host"}`
			if ext == "yaml" {
				main = "openapi: 3.0.0\ninfo: {title: test, version: '1'}\npaths: {}\ndefinition: {marker: internal}\ninternal: {$ref: '#/definition'}\nvalue: {$ref: './asset.yaml'}\nscalar: ./asset.yaml\n"
				owned, host = "marker: owned\n", "marker: host\n"
				nested = "$ref: ./nested.yaml\n"
			}
			require.NoError(t, os.WriteFile(assetPath, []byte(host), 0600))
			for _, tc := range []struct {
				name     string
				fsys     vfs.FS
				want     string
				resolved int
			}{
				{"owned", vfs.NewMemFS(map[string][]byte{assetPath: []byte(owned)}), "owned", 1},
				{"missing", vfs.NewMemFS(nil), "", 0},
				{"nested", vfs.NewMemFS(map[string][]byte{assetPath: []byte(nested), nestedPath: []byte(owned)}), "owned", 2},
				{"malformed", vfs.NewMemFS(map[string][]byte{assetPath: []byte("[")}), "", 0},
				{"disk-default", nil, "host", 1},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var specific KindParser = &jsonParser.Parser{FS: tc.fsys}
					if ext == "yaml" {
						specific = &yamlParser.Parser{FS: tc.fsys}
					}
					ps, err := NewBuilder(t.Context()).WithFS(tc.fsys).Add(specific).Build([]string{""}, []string{""})
					require.NoError(t, err)
					for range 2 {
						parsed, err := ps[0].Parse(t.Context(), mainPath, []byte(main), true, false, 15)
						require.NoError(t, err)
						require.Len(t, parsed.ResolvedFiles, tc.resolved+1) // Includes the internal reference to mainPath.
						if tc.want == "" {
							require.Equal(t, "./asset."+ext, parsed.Docs[0]["scalar"])
						} else {
							// Each occurrence must resolve; one cannot satisfy the other's assertion.
							for _, field := range []string{"value", "scalar"} {
								resolved, _ := parsed.Docs[0][field].(map[string]any)
								require.Equal(t, tc.want, resolved["marker"], field)
							}
						}
						encoded, err := json.Marshal(parsed.Docs)
						require.NoError(t, err)
						require.Contains(t, string(encoded), `"internal":{`)
						require.GreaterOrEqual(t, strings.Count(string(encoded), `"marker":"internal"`), 2)
						if tc.want == "" {
							require.Contains(t, string(encoded), "$ref")
							require.NotContains(t, string(encoded), "host")
						}
					}
				})
			}
		})
	}
}
