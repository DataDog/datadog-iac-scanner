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
						ID:        0,
						ScanID:    "scan_id",
						FileID:    "file_id",
						FileName:  "file_name",
						QueryID:   "query_id",
						QueryName: "query_name",
						Line:      1,
						SearchKey: "search_key",
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
						ID:        0,
						ScanID:    "scan_id",
						FileID:    "file_id",
						FileName:  "file_name",
						QueryID:   "query_id",
						QueryName: "query_name",
						Line:      1,
						SearchKey: "search_key",
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
						ID:        0,
						ScanID:    "scan_id",
						FileID:    "file_id",
						FileName:  "file_name",
						QueryID:   "query_id",
						QueryName: "query_name",
						Line:      1,
						SearchKey: "search_key",
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

// Instances of one Terraform block share a file, a line, a call chain and, when
// a rule names the block, a resource name, but they are distinct resources:
// each is kept. The same finding of one instance saved twice is still one.
func TestMemoryStorage_TerraformInstancesAreNotMerged(t *testing.T) {
	storage := NewMemoryStorage()
	var saved []model.Vulnerability
	for _, docID := range []string{"mod\x00r/main.tf|module.m[0]\x000", "mod\x00r/main.tf|module.m[0]\x001", "root\x00\x000"} {
		saved = append(saved, model.Vulnerability{
			FileID: docID, FileName: "modules/m/main.tf", QueryID: "q", Platform: "Terraform",
			ResourceType: "aws_s3_bucket", ResourceName: "b", Line: 3, ModuleCallChain: "r/main.tf|module.m[0]",
		})
	}
	require.NoError(t, storage.SaveVulnerabilities(context.Background(), saved))
	require.NoError(t, storage.SaveVulnerabilities(context.Background(), saved[:1]))
	got, err := storage.GetVulnerabilities(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, got, 3)

	// Findings of a file scanned as written keep merging by fingerprint.
	plain := NewMemoryStorage()
	dup := model.Vulnerability{FileID: "f1", FileName: "main.tf", QueryID: "q", Platform: "Terraform", ResourceName: "b", Line: 3}
	require.NoError(t, plain.SaveVulnerabilities(context.Background(), []model.Vulnerability{dup, dup}))
	got, err = plain.GetVulnerabilities(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, got, 1)
}

// Of findings saved under one key, the last is kept, and the kept findings
// stay in the order they were saved, however often they are read.
func TestMemoryStorage_UniqueFindingsKeepLastInOrder(t *testing.T) {
	finding := func(name, searchKey string) model.Vulnerability {
		return model.Vulnerability{
			FileID: "f1", FileName: "main.tf", QueryID: "q", Platform: "Terraform",
			ResourceName: name, Line: 3, SearchKey: searchKey,
		}
	}
	storage := NewMemoryStorage()
	require.NoError(t, storage.SaveVulnerabilities(context.Background(), []model.Vulnerability{
		finding("a", "first"), finding("b", "only"), finding("a", "second"), finding("c", "only"), finding("a", "third"),
	}))
	searchKeys := func(vs []model.Vulnerability) []string {
		var out []string
		for i := range vs {
			out = append(out, vs[i].ResourceName+"="+vs[i].SearchKey)
		}
		return out
	}
	want := []string{"b=only", "c=only", "a=third"}
	for range 2 {
		got, err := storage.GetVulnerabilities(context.Background(), "")
		require.NoError(t, err)
		require.Equal(t, want, searchKeys(got))
	}

	require.NoError(t, storage.SaveVulnerabilities(context.Background(), []model.Vulnerability{finding("b", "again")}))
	got, err := storage.GetVulnerabilities(context.Background(), "")
	require.NoError(t, err)
	require.Equal(t, []string{"c=only", "a=third", "b=again"}, searchKeys(got))
}

// The first findings saved are kept without a copy, and saving more never
// writes past them into the slice they came in.
func TestMemoryStorage_FirstSaveIsNotCopied(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	first := make([]model.Vulnerability, 1, 3)
	first[0] = model.Vulnerability{FileName: "a.tf", QueryID: "q", ResourceName: "a"}
	require.NoError(t, storage.SaveVulnerabilities(ctx, first))
	require.NoError(t, storage.SaveVulnerabilities(ctx, []model.Vulnerability{{FileName: "b.tf", QueryID: "q", ResourceName: "b"}}))
	require.Empty(t, first[:2][1].FileName)
	got, err := storage.GetVulnerabilities(ctx, "")
	require.NoError(t, err)
	require.Len(t, got, 2)

	empty := NewMemoryStorage()
	require.NoError(t, empty.SaveVulnerabilities(ctx, nil))
	got, err = empty.GetVulnerabilities(ctx, "")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Empty(t, got)
}
