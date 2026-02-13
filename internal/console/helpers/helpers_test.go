/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package helpers

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/test"
	"github.com/stretchr/testify/require"
)

func TestFileAnalyzer(t *testing.T) {
	if err := test.ChangeCurrentDir("kics"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		arg     string
		want    string
		wantErr bool
	}{
		{
			name:    "file_analyzer_json",
			arg:     "test/fixtures/config_test/kics.json",
			want:    "json",
			wantErr: false,
		},
		{
			name:    "file_analyzer_json_no_extension",
			arg:     "test/fixtures/config_test/kics.config_json",
			want:    "json",
			wantErr: false,
		},
		{
			name:    "file_analyzer_yaml",
			arg:     "test/fixtures/config_test/kics.yaml",
			want:    "yaml",
			wantErr: false,
		},
		{
			name:    "file_analyzer_yaml_no_extension",
			arg:     "test/fixtures/config_test/kics.config_yaml",
			want:    "yaml",
			wantErr: false,
		},
		{
			name:    "file_analyzer_hcl",
			arg:     "test/fixtures/config_test/kics.hcl",
			want:    "hcl",
			wantErr: false,
		},
		{
			name:    "file_analyzer_hcl_no_extension",
			arg:     "test/fixtures/config_test/kics.config_hcl",
			want:    "hcl",
			wantErr: false,
		},
		{
			name:    "file_analyzer_toml",
			arg:     "test/fixtures/config_test/kics.toml",
			want:    "toml",
			wantErr: false,
		},
		{
			name:    "file_analyzer_toml_no_extension",
			arg:     "test/fixtures/config_test/kics.config_toml",
			want:    "toml",
			wantErr: false,
		},
		{
			name:    "file_analyzer_js_incorrect",
			arg:     "test/fixtures/config_test/kics.config_js",
			want:    "",
			wantErr: true,
		},
		{
			name:    "file_analyzer_js_no_extension_incorrect",
			arg:     "test/fixtures/config_test/kics.js",
			want:    "",
			wantErr: true,
		},
		{
			name:    "file_analyzer_js_wrong_extension",
			arg:     "test/fixtures/config_test/kics_wrong.js",
			want:    "yaml",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FileAnalyzer(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("FileAnalyzer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FileAnalyzer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFileAnalyzer_Error_File(t *testing.T) {
	_, err := FileAnalyzer(filepath.FromSlash("test/fixtures/config_test/kicsNoFileExists.js"))
	require.Error(t, err)
}

func TestHelpers_GenerateReport(t *testing.T) {
	type args struct {
		path     string
		filename string
		body     interface{}
		formats  []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		remove  []string
	}{
		{
			name: "test_generate_report",
			args: args{
				path:     ".",
				filename: "result",
				body:     "",
				formats:  []string{"json"},
			},
			wantErr: false,
			remove:  []string{"result.json"},
		},
		{
			name: "test_generate_report_error",
			args: args{
				path:     ".",
				filename: "result",
				body:     "",
				formats:  []string{"html"},
			},
			wantErr: true,
			remove:  []string{"result.html"},
		},
		{
			name: "test_generate_report_error",
			args: args{
				path:     ".",
				filename: "result",
				body:     "",
				formats:  []string{"sarif"},
			},
			wantErr: false,
			remove:  []string{"result.sarif"},
		},
		{
			name: "test_generate_report_error",
			args: args{
				path:     ".",
				filename: "result",
				body:     "",
				formats:  []string{"glsast"},
			},
			wantErr: false,
			remove:  []string{"gl-sast-result.json"},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := GenerateReport(ctx, tt.args.path, tt.args.filename, tt.args.body, tt.args.formats, &model.SCIInfo{})
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateReport() = %v, wantErr = %v", err, tt.wantErr)
			}
			for _, file := range tt.remove {
				err := os.Remove(filepath.Join(tt.args.path, file))
				require.NoError(t, err)
			}
		})
	}
}

func TestHelpers_GetDefaultQueryPath(t *testing.T) {
	if err := test.ChangeCurrentDir("kics"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		queriesPath string
		wantErr     bool
	}{
		{
			name:        "test_get_default_query_path",
			queriesPath: filepath.FromSlash("assets/queries"),
			wantErr:     false,
		},
		{
			// GetDefaultQueryPath should NOT fail for non-existent paths because
			// queries are embedded in the binary and loaded via assets.GetEmbeddedQueryDirs().
			// The path is only used for logging/display purposes.
			name:        "test_get_default_query_path_nonexistent",
			queriesPath: filepath.FromSlash("nonexistent/path"),
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetDefaultQueryPath(tt.queriesPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDefaultQueryPath() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr && got == "" {
				t.Errorf("GetDefaultQueryPath() returned empty path, expected non-empty")
			}
		})
	}
}

func TestHelpers_GetNumCPU(t *testing.T) {
	cpu := GetNumCPU()
	require.NotEqual(t, cpu, nil)
}
