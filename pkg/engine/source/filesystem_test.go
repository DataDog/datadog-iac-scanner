/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package source

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/test"
)

// TestFilesystemSource_GetQueryLibrary tests the functions [GetQueryLibrary()] and all the methods called by them
func TestFilesystemSource_GetQueryLibrary(t *testing.T) { //nolint
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		t.Fatal(err)
	}
	type fields struct {
		Source              []string
		Library             string
		ExperimentalQueries bool
	}
	type args struct {
		platform string
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		contains string
		wantErr  bool
	}{
		{
			name: "get_generic_query_terraform",
			fields: fields{
				Source:              []string{"./assets/queries/template"},
				Library:             "./assets/libraries",
				ExperimentalQueries: true,
			},
			args: args{
				platform: "terraform",
			},
			contains: "generic.terraform",
			wantErr:  false,
		},
		{
			name: "get_generic_query_common",
			fields: fields{
				Source:              []string{"./assets/queries/template"},
				Library:             "./assets/libraries",
				ExperimentalQueries: true,
			},
			args: args{
				platform: "common",
			},
			contains: "generic.common",
			wantErr:  false,
		},
		{
			name: "get_generic_query_cloudformation",
			fields: fields{
				Source:              []string{"./assets/queries/template"},
				Library:             "./assets/libraries",
				ExperimentalQueries: true,
			},
			args: args{
				platform: "cloudFormation",
			},
			contains: "generic.cloudformation",
			wantErr:  false,
		},
		{
			name: "get_generic_query_ansible",
			fields: fields{
				Source:              []string{"./assets/queries/template"},
				Library:             "./assets/libraries",
				ExperimentalQueries: true,
			},
			args: args{
				platform: "ansible",
			},
			contains: "generic.ansible",
			wantErr:  false,
		},
		{
			name: "get_generic_query_k8s",
			fields: fields{
				Source:              []string{"./assets/queries/template"},
				Library:             "./assets/libraries",
				ExperimentalQueries: true,
			},
			args: args{
				platform: "k8s",
			},
			contains: "generic.k8s",
			wantErr:  false,
		},
		{
			name: "get_generic_query_cicd",
			fields: fields{
				Source:              []string{"./assets/queries/template"},
				Library:             "./assets/libraries",
				ExperimentalQueries: true,
			},
			args: args{
				platform: "cicd",
			},
			contains: "generic.cicd",
			wantErr:  false,
		},
		{
			name: "get_generic_query_unknown",
			fields: fields{
				Source:              []string{"./assets/queries/template"},
				Library:             "./assets/libraries",
				ExperimentalQueries: true,
			},
			args: args{
				platform: "unknown",
			},
			contains: "",
			wantErr:  true,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewFilesystemSource(ctx, tt.fields.Source, []string{""}, []string{""}, tt.fields.Library, tt.fields.ExperimentalQueries)

			got, err := s.GetQueryLibrary(ctx, tt.args.platform)
			if (err != nil) != tt.wantErr {
				t.Errorf("FilesystemSource.GetQueryLibrary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !strings.Contains(got.LibraryCode, tt.contains) {
				t.Errorf("FilesystemSource.GetQueryLibrary() = %v, doesn't contains %v", got, tt.contains)
			}
		})
	}
}

// Test_getPlatform tests the functions [getPlatform()] and all the methods called by them
func Test_getPlatform(t *testing.T) {
	type args struct {
		PlatformInMetadata string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "get_platform_common",
			args: args{
				PlatformInMetadata: "Common",
			},
			want: "common",
		},
		{
			name: "get_platform_ansible",
			args: args{
				PlatformInMetadata: "Ansible",
			},
			want: "ansible",
		},
		{
			name: "get_platform_cloudFormation",
			args: args{
				PlatformInMetadata: "CloudFormation",
			},
			want: "cloudFormation",
		},
		{
			name: "get_platform_cicd",
			args: args{
				PlatformInMetadata: "CICD",
			},
			want: "cicd",
		},
		{
			name: "get_platform_k8s",
			args: args{
				PlatformInMetadata: "Kubernetes",
			},
			want: "k8s",
		},
		{
			name: "get_platform_open_api",
			args: args{
				PlatformInMetadata: "OpenAPI",
			},
			want: "openAPI",
		},
		{
			name: "get_platform_terraform",
			args: args{
				PlatformInMetadata: "Terraform",
			},
			want: "terraform",
		},
		{
			name: "get_platform_AzureResourceManager",
			args: args{
				PlatformInMetadata: "AzureResourceManager",
			},
			want: "azureResourceManager",
		},
		{
			name: "get_platform_unknown",
			args: args{
				PlatformInMetadata: "Unknown",
			},
			want: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getPlatform(tt.args.PlatformInMetadata); got != tt.want {
				t.Errorf("getPlatform() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSource_validateMetadata(t *testing.T) {
	tests := []struct {
		name         string
		metadata     map[string]interface{}
		wantValid    bool
		wantInvField string
	}{
		{
			name: "valid metadata test case",
			metadata: map[string]interface{}{
				"id":       "1234",
				"platform": "terraform",
			},
			wantValid:    true,
			wantInvField: "platform",
		},
		{
			name: "invalid metadata platform test case",
			metadata: map[string]interface{}{
				"id": "1234",
			},
			wantValid:    false,
			wantInvField: "platform",
		},
		{
			name: "invalid metadata id test case",
			metadata: map[string]interface{}{
				"platform": "terraform",
			},
			wantValid:    false,
			wantInvField: "id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, invField := validateMetadata(tt.metadata)
			require.Equal(t, tt.wantValid, valid)
			require.Equal(t, tt.wantInvField, invField)
		})
	}
}

func TestSource_getLibraryInDir(t *testing.T) {
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		t.Fatal(err)
	}

	type args struct {
		platform       string
		libraryDirPath string
	}

	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test get library in dir for terraform",
			args: args{
				platform:       "terraform",
				libraryDirPath: filepath.FromSlash("./assets/libraries"),
			},
			want: filepath.FromSlash("assets/libraries/terraform.rego"),
		},
		{
			name: "test get library in dir error",
			args: args{
				platform:       "",
				libraryDirPath: filepath.FromSlash("./assets/libraries"),
			},
			want: "",
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getLibraryInDir(ctx, tt.args.platform, tt.args.libraryDirPath)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFilesystemSource_ReadLocalFile(t *testing.T) {
	dir := t.TempDir()
	queryPath := filepath.Join(dir, "my_query")
	require.NoError(t, os.Mkdir(queryPath, 0700))
	metadata := `{
  "id": "wonderful-query",
  "queryName": "My Wonderful Query",
  "severity": "HIGH",
  "category": "AVAILABILITY",
  "descriptionText": "This is my query",
  "descriptionUrl": "https://example.com",
  "descriptionId": "12345678",
  "platform": "dockerfile",
  "cwe": ""
}
`
	require.NoError(t, os.WriteFile(filepath.Join(queryPath, "metadata.json"), []byte(metadata), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(queryPath, "query.rego"), []byte("rule"), 0644))

	query, err := ReadQueryFile(t.Context(), queryPath)
	assert.NoError(t, err)
	assert.Equal(t, query.Metadata["id"], "wonderful-query")
}

// TestCheckQueryExcludeWithLegacyId tests the checkQueryExclude function with both new ID and legacy ID
func TestCheckQueryExcludeWithLegacyId(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		metadata       map[string]any
		excludeIDs     []string
		expectedResult bool
		description    string
	}{
		{
			name: "exclude_by_new_id",
			metadata: map[string]any{
				"id":       "terraform-aws-s3-bucket-public",
				"legacyId": "abc-123-def-456",
				"category": "Security",
				"severity": "HIGH",
			},
			excludeIDs:     []string{"terraform-aws-s3-bucket-public"},
			expectedResult: true,
			description:    "Should exclude when new ID matches",
		},
		{
			name: "exclude_by_legacy_id",
			metadata: map[string]any{
				"id":       "terraform-aws-s3-bucket-public",
				"legacyId": "abc-123-def-456",
				"category": "Security",
				"severity": "HIGH",
			},
			excludeIDs:     []string{"abc-123-def-456"},
			expectedResult: true,
			description:    "Should exclude when legacy ID matches",
		},
		{
			name: "exclude_by_either_id",
			metadata: map[string]any{
				"id":       "terraform-aws-s3-bucket-public",
				"legacyId": "abc-123-def-456",
				"category": "Security",
				"severity": "HIGH",
			},
			excludeIDs:     []string{"different-id", "abc-123-def-456", "another-id"},
			expectedResult: true,
			description:    "Should exclude when legacy ID is in the list",
		},
		{
			name: "no_exclude_when_no_match",
			metadata: map[string]any{
				"id":       "terraform-aws-s3-bucket-public",
				"legacyId": "abc-123-def-456",
				"category": "Security",
				"severity": "HIGH",
			},
			excludeIDs:     []string{"different-id", "another-different-id"},
			expectedResult: false,
			description:    "Should not exclude when neither ID matches",
		},
		{
			name: "no_exclude_with_empty_list",
			metadata: map[string]any{
				"id":       "terraform-aws-s3-bucket-public",
				"legacyId": "abc-123-def-456",
				"category": "Security",
				"severity": "HIGH",
			},
			excludeIDs:     []string{},
			expectedResult: false,
			description:    "Should not exclude when exclude list is empty",
		},
		{
			name: "exclude_case_insensitive_new_id",
			metadata: map[string]any{
				"id":       "terraform-aws-s3-bucket-public",
				"legacyId": "abc-123-def-456",
				"category": "Security",
				"severity": "HIGH",
			},
			excludeIDs:     []string{"TERRAFORM-AWS-S3-BUCKET-PUBLIC"},
			expectedResult: true,
			description:    "Should exclude with case-insensitive match on new ID",
		},
		{
			name: "exclude_case_insensitive_legacy_id",
			metadata: map[string]any{
				"id":       "terraform-aws-s3-bucket-public",
				"legacyId": "abc-123-def-456",
				"category": "Security",
				"severity": "HIGH",
			},
			excludeIDs:     []string{"ABC-123-DEF-456"},
			expectedResult: true,
			description:    "Should exclude with case-insensitive match on legacy ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queryParams := &QueryInspectorParameters{
				ExcludeQueries: QueryFilter{
					ByIDs: tt.excludeIDs,
				},
			}
			result := checkQueryExclude(ctx, tt.metadata, queryParams)
			assert.Equal(t, tt.expectedResult, result, tt.description)
		})
	}
}

// TestCheckQueryIncludeWithLegacyId tests the checkQueryInclude function with both new ID and legacy ID
func TestCheckQueryIncludeWithLegacyId(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		metadata       map[string]any
		includeIDs     []string
		expectedResult bool
		description    string
	}{
		{
			name: "include_by_new_id",
			metadata: map[string]any{
				"id":       "terraform-aws-s3-bucket-public",
				"legacyId": "abc-123-def-456",
				"category": "Security",
				"severity": "HIGH",
			},
			includeIDs:     []string{"terraform-aws-s3-bucket-public"},
			expectedResult: true,
			description:    "Should include when new ID matches",
		},
		{
			name: "include_by_legacy_id",
			metadata: map[string]any{
				"id":       "terraform-aws-s3-bucket-public",
				"legacyId": "abc-123-def-456",
				"category": "Security",
				"severity": "HIGH",
			},
			includeIDs:     []string{"abc-123-def-456"},
			expectedResult: true,
			description:    "Should include when legacy ID matches",
		},
		{
			name: "include_by_either_id_in_list",
			metadata: map[string]any{
				"id":       "terraform-aws-s3-bucket-public",
				"legacyId": "abc-123-def-456",
				"category": "Security",
				"severity": "HIGH",
			},
			includeIDs:     []string{"different-id", "terraform-aws-s3-bucket-public", "another-id"},
			expectedResult: true,
			description:    "Should include when new ID is in the list",
		},
		{
			name: "include_by_legacy_id_in_list",
			metadata: map[string]any{
				"id":       "terraform-aws-s3-bucket-public",
				"legacyId": "abc-123-def-456",
				"category": "Security",
				"severity": "HIGH",
			},
			includeIDs:     []string{"different-id", "abc-123-def-456", "another-id"},
			expectedResult: true,
			description:    "Should include when legacy ID is in the list",
		},
		{
			name: "no_include_when_no_match",
			metadata: map[string]any{
				"id":       "terraform-aws-s3-bucket-public",
				"legacyId": "abc-123-def-456",
				"category": "Security",
				"severity": "HIGH",
			},
			includeIDs:     []string{"different-id", "another-different-id"},
			expectedResult: false,
			description:    "Should not include when neither ID matches",
		},
		{
			name: "include_all_with_empty_list",
			metadata: map[string]any{
				"id":       "terraform-aws-s3-bucket-public",
				"legacyId": "abc-123-def-456",
				"category": "Security",
				"severity": "HIGH",
			},
			includeIDs:     []string{},
			expectedResult: true,
			description:    "Should include all when include list is empty",
		},
		{
			name: "include_case_insensitive_new_id",
			metadata: map[string]any{
				"id":       "terraform-aws-s3-bucket-public",
				"legacyId": "abc-123-def-456",
				"category": "Security",
				"severity": "HIGH",
			},
			includeIDs:     []string{"TERRAFORM-AWS-S3-BUCKET-PUBLIC"},
			expectedResult: true,
			description:    "Should include with case-insensitive match on new ID",
		},
		{
			name: "include_case_insensitive_legacy_id",
			metadata: map[string]any{
				"id":       "terraform-aws-s3-bucket-public",
				"legacyId": "abc-123-def-456",
				"category": "Security",
				"severity": "HIGH",
			},
			includeIDs:     []string{"ABC-123-DEF-456"},
			expectedResult: true,
			description:    "Should include with case-insensitive match on legacy ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queryParams := &QueryInspectorParameters{
				IncludeQueries: QueryFilter{
					ByIDs: tt.includeIDs,
				},
			}
			result := checkQueryInclude(ctx, tt.metadata, queryParams)
			assert.Equal(t, tt.expectedResult, result, tt.description)
		})
	}
}
