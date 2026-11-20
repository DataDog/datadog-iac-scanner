/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/require"
	"reflect"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type mockkindDetectLine struct {
}

type mockDefaultDetector struct {
}

func (m mockkindDetectLine) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string, outputLines int) model.VulnerabilityLines {
	return model.VulnerabilityLines{
		Line: 1,
	}
}

func (m mockDefaultDetector) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string, outputLines int) model.VulnerabilityLines {
	return model.VulnerabilityLines{
		Line: 5,
	}
}

func TestDetector_SetupLogs(t *testing.T) {
	det := initDetector()
	type args struct {
		log zerolog.Logger
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "test_setup_logs",
			args: args{
				log: log.With().
					Str("scanID", "Test").
					Str("fileName", "Test_file_name").
					Str("queryName", "Test_Query_name").
					Logger(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			det.SetupLogs(&tt.args.log)
			got := det.logWithFields
			if !reflect.DeepEqual(*got, tt.args.log) {
				t.Errorf("SetupLogs() = %v, want = %v", got, tt.args.log)
			}
		})
	}
}

func TestDetector_DetectLine(t *testing.T) {
	ctx := context.Background()
	var mock mockkindDetectLine
	var defaultmock mockDefaultDetector
	det := initDetector().Add(mock, model.KindCOMMON)
	det.defaultDetector = defaultmock

	type args struct {
		file      *model.FileMetadata
		searchKey string
	}
	tests := []struct {
		name string
		args args
		want model.VulnerabilityLines
	}{
		{
			name: "test_kind_detect_line",
			args: args{
				file: &model.FileMetadata{
					Kind: model.KindCOMMON,
				},
				searchKey: "",
			},
			want: model.VulnerabilityLines{
				Line: 1,
			},
		},
		{
			name: "test_default_detect_line",
			args: args{
				file: &model.FileMetadata{
					Kind: model.KindTerraform,
				},
				searchKey: "",
			},
			want: model.VulnerabilityLines{
				Line: 5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := det.DetectLine(ctx, tt.args.file, tt.args.searchKey)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DetectLine() = %v, want = %v", got, tt.want)
			}
		})
	}
}

var OriginalData0 = `resource "aws_s3_bucket" "b" {
	bucket = "my-tf-test-bucket"
	acl    = "authenticated-read"
	}`

func initDetector() *DetectLine {
	return NewDetectLine(3)
}

func TestStructuredSourceContexts(t *testing.T) {
	ctx := context.Background()
	parent := NewDetectLine(2)
	first, second := parent.ForkSourceResolver(), parent.ForkSourceResolver()
	file := func(content string) *model.FileMetadata {
		lines := strings.Split(content, "\n")
		return &model.FileMetadata{Kind: model.KindYAML, LinesOriginalData: &lines}
	}
	a, b := file("first:\n  value: true\n"), file("second: false\n")
	path := model.SourcePath{{Key: "first"}, {Key: "value"}}
	got, err := first.DetectPath(ctx, a, path)
	require.NoError(t, err)
	require.Equal(t, 2, got.Line)
	root := first.source.documents[0]
	_, err = second.DetectPath(ctx, b, model.SourcePath{{Key: "second"}})
	require.NoError(t, err)
	for range 3 {
		_, err = first.DetectPath(ctx, a, path)
		require.NoError(t, err)
		require.Same(t, root, first.source.documents[0])
	}
	require.Nil(t, parent.source.documents, "legacy detector must not acquire a source tree")
	// Each context keeps only its current source; returning to another snapshot
	// can reparse without affecting other concurrent decode contexts.
	_, err = first.DetectPath(ctx, b, model.SourcePath{{Key: "second"}})
	require.NoError(t, err)
	require.NotSame(t, root, first.source.documents[0])
	previous := first.source.documents[0]
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = first.DetectPath(canceled, a, path)
	require.ErrorIs(t, err, context.Canceled)
	require.Same(t, previous, first.source.documents[0], "cancellation must not replace the cached source")
}

func TestStructuredSourceMappingIndex(t *testing.T) {
	ctx := context.Background()
	var source strings.Builder
	for index := range 128 {
		fmt.Fprintf(&source, "property_%d: %d\n", index, index)
	}
	lines := strings.Split(source.String(), "\n")
	file := &model.FileMetadata{Kind: model.KindYAML, LinesOriginalData: &lines}
	d := NewDetectLine(2)
	for index := range 128 {
		got, err := d.DetectPath(ctx, file, model.SourcePath{{Key: fmt.Sprintf("property_%d", index)}})
		require.NoError(t, err)
		require.Equal(t, index+1, got.Line)
		if index == 0 {
			require.Len(t, d.source.mappings, 1)
		}
	}
	root := d.source.documents[0]
	cached := d.source.mappings[root]
	require.Len(t, cached.members, 128)
	_, err := d.DetectPath(ctx, file, model.SourcePath{{Key: "property_0"}})
	require.NoError(t, err)
	require.Same(t, cached, d.source.mappings[root], "all property lookups reuse one index of borrowed source nodes")
}
