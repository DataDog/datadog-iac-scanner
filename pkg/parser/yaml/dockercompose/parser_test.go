/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package dockercompose

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestParser_Metadata(t *testing.T) {
	p := NewDefaultWithFS(nil)
	require.Equal(t, []string{".yaml", ".yml"}, p.SupportedExtensions())
	require.Equal(t, map[string]bool{"dockercompose": true}, p.SupportedTypes())
	require.Equal(t, model.KindYAML, p.GetKind())
	require.Equal(t, "#", p.GetCommentToken())
}

func TestParser_Parse_Interpolation(t *testing.T) {
	compose := `
services:
  web:
    image: nginx:${TAG:-latest}
    environment:
      - PASSWORD=${DB_PASSWORD}
    ports:
      - "${PORT}:80"
`
	other := `
services:
  api:
    image: nginx:1.27
`
	tests := []struct {
		name       string
		compose    string
		envContent string
		envPath    string
		want       string
	}{
		{
			name:       "env file next to compose",
			compose:    compose,
			envContent: "TAG=1.27\nDB_PASSWORD=hunter2\nPORT=8080\n",
			envPath:    "compose.yaml",
			want:       `{"services":{"web":{"environment":["PASSWORD=hunter2"],"image":"nginx:1.27","ports":["8080:80"]}}}`,
		},
		{
			name:       "no env file, unresolvable refs stay literal",
			compose:    compose,
			envContent: "",
			envPath:    "other-dir/compose.yaml",
			want:       `{"services":{"web":{"environment":["PASSWORD=${DB_PASSWORD}"],"image":"nginx:latest","ports":["${PORT}:80"]}}}`,
		},
		{
			name:    "no dollar signs: passthrough",
			compose: other,
			want:    `{"services":{"api":{"image":"nginx:1.27"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			composePath := filepath.Join(dir, tt.envPath)
			require.NoError(t, os.MkdirAll(filepath.Dir(composePath), 0o755))
			if tt.envContent != "" {
				require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(composePath), ".env"), []byte(tt.envContent), 0o600))
			}
			p := NewDefaultWithFS(nil)
			_, docs, _, _, err := p.Parse(context.Background(), []byte(tt.compose), composePath, true, 15)
			require.NoError(t, err)
			require.Len(t, docs, 1)
			// Strip the line-tracking metadata so the JSON comparison stays
			// focused on the interpolated values.
			clean := stripLineInfo(docs[0])
			j, err := json.Marshal(clean)
			require.NoError(t, err)
			require.JSONEq(t, tt.want, string(j))
		})
	}
}

func TestParser_Parse_LineTrackingSurvivesInterpolation(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"), []byte("TAG=1.27\n"), 0o600))
	compose := `services:
  web:
    image: nginx:${TAG}
`
	p := NewDefaultWithFS(nil)
	_, docs, _, _, err := p.Parse(context.Background(), []byte(compose), filepath.Join(dir, "compose.yaml"), true, 15)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	web := asMap(docs[0]["services"])["web"]
	require.Equal(t, "nginx:1.27", asMap(web)["image"])

	lines := asMap(web)["_dd_lines"].(map[string]*model.LineObject)["_dd_image"]
	require.Equal(t, 3, lines.Line, "interpolated value must keep its declaration line")
}

func TestParser_Parse_NoEnvLoadedKeepsDefaults(t *testing.T) {
	dir := t.TempDir()
	compose := "services:\n  web:\n    image: nginx:${TAG:-pinned}\n"
	p := NewDefaultWithFS(nil)
	_, docs, _, _, err := p.Parse(context.Background(), []byte(compose), filepath.Join(dir, "compose.yaml"), true, 15)
	require.NoError(t, err)
	web := asMap(docs[0]["services"])["web"]
	require.Equal(t, "nginx:pinned", asMap(web)["image"])
}

func asMap(v interface{}) map[string]interface{} {
	switch t := v.(type) {
	case model.Document:
		m := map[string]interface{}{}
		for k, val := range t {
			m[k] = val
		}
		return m
	case map[string]interface{}:
		return t
	}
	return nil
}

func stripLineInfo(doc model.Document) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range doc {
		if k == "_dd_lines" || k == "_path" {
			continue
		}
		out[k] = stripValue(v)
	}
	return out
}

func stripValue(v interface{}) interface{} {
	switch t := v.(type) {
	case model.Document:
		return stripLineInfo(t)
	case map[string]interface{}:
		out := map[string]interface{}{}
		for k, val := range t {
			if k == "_dd_lines" {
				continue
			}
			out[k] = stripValue(val)
		}
		return out
	case []interface{}:
		for i, val := range t {
			t[i] = stripValue(val)
		}
		return t
	}
	return v
}
