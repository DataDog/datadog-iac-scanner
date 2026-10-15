/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package storage

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// TestMemoryStorage_SaveFile tests the functions [SaveFile()]
func TestMemoryStorage_SaveFile(t *testing.T) {
	type fields struct {
		vulnerabilities []model.Vulnerability
		allFiles        model.FileMetadatas
	}
	type args struct {
		in0      context.Context
		metadata *model.FileMetadata
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "SaveFile",
			fields: fields{
				vulnerabilities: []model.Vulnerability{},
				allFiles:        model.FileMetadatas{},
			},
			args: args{
				in0: nil,
				metadata: &model.FileMetadata{
					ID:           "id",
					ScanID:       "scan_id",
					OriginalData: "orig_data",
					FilePath:     "file_name",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MemoryStorage{
				vulnerabilities: tt.fields.vulnerabilities,
				allFiles:        tt.fields.allFiles,
			}
			if err := m.SaveFile(tt.args.in0, tt.args.metadata); (err != nil) != tt.wantErr {
				t.Errorf("MemoryStorage.SaveFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			require.Equal(t, tt.args.metadata, m.allFiles[0])
		})
	}
}

// TestMemoryStorage_SaveFile tests the functions [GetFiles(), GetVulnerabilities()]
func TestMemoryStorage(t *testing.T) { //nolint
	type fields struct {
		vulnerabilities []model.Vulnerability
		allFiles        model.FileMetadatas
	}
	type args struct {
		in0 context.Context
		in1 string
		in2 []string
	}
	type want struct {
		metadata        model.FileMetadatas
		vulnerabilities []model.Vulnerability
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    want
		wantErr bool
	}{
		{
			name: "test_case",
			fields: fields{
				vulnerabilities: []model.Vulnerability{
					{
						ID:               0,
						ScanID:           "scan_id",
						FileID:           "file_id",
						FileName:         "file_name",
						QueryID:          "query_id",
						QueryName:        "query_name",
						Line:             1,
						SearchKey:        "search_key",
					},
				},
				allFiles: model.FileMetadatas{
					&model.FileMetadata{
						ID:           "id",
						ScanID:       "scan_id",
						OriginalData: "orig_data",
						FilePath:     "file_name",
					},
				},
			},
			args: args{
				in0: nil,
				in1: "",
				in2: []string{},
			},
			wantErr: false,
			want: want{
				metadata: model.FileMetadatas{
					&model.FileMetadata{
						ID:           "id",
						ScanID:       "scan_id",
						OriginalData: "orig_data",
						FilePath:     "file_name",
					},
				},
				vulnerabilities: []model.Vulnerability{
					{
						ID:               0,
						ScanID:           "scan_id",
						FileID:           "file_id",
						FileName:         "file_name",
						QueryID:          "query_id",
						QueryName:        "query_name",
						Line:             1,
						SearchKey:        "search_key",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		m := &MemoryStorage{
			vulnerabilities: tt.fields.vulnerabilities,
			allFiles:        tt.fields.allFiles,
		}
		t.Run(fmt.Sprintf("%s", tt.name+"_GetFiles"), func(t *testing.T) {
			got, err := m.GetFiles(tt.args.in0, tt.args.in1)
			if (err != nil) != tt.wantErr {
				t.Errorf("MemoryStorage.GetFiles() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want.metadata) {
				t.Errorf("MemoryStorage.GetFiles() = %v, want %v", got, tt.want)
			}
		})
		t.Run(fmt.Sprintf("%s", tt.name+"_GetVulnerabilities"), func(t *testing.T) {
			got, err := m.GetVulnerabilities(tt.args.in0, tt.args.in1)
			if (err != nil) != tt.wantErr {
				t.Errorf("MemoryStorage.GetVulnerabilities() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want.vulnerabilities) {
				t.Errorf("MemoryStorage.GetVulnerabilities() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMemoryStorage_SaveVulnerabilities tests the functions [SaveVulnerabilities()]
func TestMemoryStorage_SaveVulnerabilities(t *testing.T) {
	type fields struct {
		vulnerabilities []model.Vulnerability
		allFiles        model.FileMetadatas
	}
	type args struct {
		in0             context.Context
		vulnerabilities []model.Vulnerability
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "SaveVulnerabilities",
			fields: fields{
				vulnerabilities: []model.Vulnerability{},
				allFiles:        model.FileMetadatas{},
			},
			args: args{
				in0: nil,
				vulnerabilities: []model.Vulnerability{
					{
						ID:               0,
						ScanID:           "scan_id",
						FileID:           "file_id",
						FileName:         "file_name",
						QueryID:          "query_id",
						QueryName:        "query_name",
						Line:             1,
						SearchKey:        "search_key",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MemoryStorage{
				vulnerabilities: tt.fields.vulnerabilities,
				allFiles:        tt.fields.allFiles,
			}
			if err := m.SaveVulnerabilities(tt.args.in0, tt.args.vulnerabilities); (err != nil) != tt.wantErr {
				t.Errorf("MemoryStorage.SaveVulnerabilities() error = %v, wantErr %v", err, tt.wantErr)
			}
			require.Equal(t, tt.args.vulnerabilities, m.vulnerabilities)
		})
	}
}

// Findings of different files of packaged dependencies are all reported at one
// declaration line; they stay distinct by where they were detected.
func TestMemoryStorage_ReportedFindingsAreNotMerged(t *testing.T) {
	declaration := &model.ReportedLocation{Path: "app/Chart.yaml", Line: 5, LineText: "- name: pkg"}
	storage := NewMemoryStorage()
	var saved []model.Vulnerability
	for _, detected := range []string{"app/charts/a/templates/pod.yaml", "app/charts/b/templates/pod.yaml"} {
		v := model.Vulnerability{
			FileName: detected, QueryID: "q", Platform: "Kubernetes", ResourceType: "Pod",
			ResourceName: "release", LineWithVulnerability: "privileged: true",
		}
		declaration.Apply(&v)
		saved = append(saved, v)
	}
	require.NoError(t, storage.SaveVulnerabilities(context.Background(), saved))
	got, err := storage.GetVulnerabilities(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, got, 2)

	require.NoError(t, storage.SaveVulnerabilities(context.Background(), saved[:1]))
	got, err = storage.GetVulnerabilities(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, got, 2, "the same finding saved twice is still one")
}

// Two resources that share a fingerprint collapse into one finding; an ignore
// comment on one of them must not hide the other's.
func TestMemoryStorage_SuppressedDuplicateDoesNotHideActiveFinding(t *testing.T) {
	finding := func(line int, suppressed bool) model.Vulnerability {
		return model.Vulnerability{
			FileName: "main.tf", QueryID: "q", Platform: "Terraform", ResourceType: "aws_security_group",
			ResourceName: "allow_tls", Line: line, IsSuppressed: suppressed,
		}
	}
	for name, saved := range map[string][]model.Vulnerability{
		"suppressed last":  {finding(4, false), finding(15, true)},
		"suppressed first": {finding(15, true), finding(4, false)},
	} {
		t.Run(name, func(t *testing.T) {
			storage := NewMemoryStorage()
			require.NoError(t, storage.SaveVulnerabilities(context.Background(), saved))
			got, err := storage.GetVulnerabilities(context.Background(), "")
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.False(t, got[0].IsSuppressed)
			require.Equal(t, 4, got[0].Line)
		})
	}

	storage := NewMemoryStorage()
	require.NoError(t, storage.SaveVulnerabilities(context.Background(), []model.Vulnerability{finding(4, true), finding(15, true)}))
	got, err := storage.GetVulnerabilities(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.True(t, got[0].IsSuppressed, "a group whose findings are all suppressed stays suppressed")
}

// Queries save their findings in whatever order they finish; the findings
// must come back in the same order regardless.
func TestMemoryStorage_GetVulnerabilitiesIsOrdered(t *testing.T) {
	var saved []model.Vulnerability
	for _, file := range []string{"b.tf", "a.tf"} {
		for _, query := range []string{"q2", "q1"} {
			for _, line := range []int{9, 3} {
				saved = append(saved, model.Vulnerability{
					FileName: file, QueryID: query, Platform: "Terraform", ResourceType: "aws_s3_bucket",
					ResourceName: fmt.Sprintf("%s-%d", query, line), Line: line,
				})
			}
		}
	}
	storage := NewMemoryStorage()
	require.NoError(t, storage.SaveVulnerabilities(context.Background(), saved))
	first, err := storage.GetVulnerabilities(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, first, len(saved))
	require.Equal(t, "a.tf", first[0].FileName)
	require.Equal(t, 3, first[0].Line)
	require.Equal(t, "q1", first[0].QueryID)
	require.Equal(t, "b.tf", first[len(first)-1].FileName)
	require.Equal(t, 9, first[len(first)-1].Line)
	require.Equal(t, "q2", first[len(first)-1].QueryID)
	for range 20 {
		again, err := storage.GetVulnerabilities(context.Background(), "")
		require.NoError(t, err)
		require.Equal(t, first, again)
	}
}

// TestNewMemoryStorage tests the functions [NewMemoryStorage()]
func TestNewMemoryStorage(t *testing.T) {
	tests := []struct {
		name string
		want *MemoryStorage
	}{
		{
			name: "new_memory_storage",
			want: &MemoryStorage{
				allFiles:        make(model.FileMetadatas, 0),
				vulnerabilities: make([]model.Vulnerability, 0),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewMemoryStorage(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewMemoryStorage() = %v, want %v", got, tt.want)
			}
		})
	}
}
