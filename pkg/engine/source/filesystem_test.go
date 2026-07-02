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

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFilesystemSource_GetQueryLibrary verifies that GetQueryLibrary reads library files from disk.
func TestFilesystemSource_GetQueryLibrary(t *testing.T) { //nolint
	libDir := t.TempDir()
	for _, platform := range []string{"terraform", "common", "cloudformation", "ansible", "k8s", "cicd"} {
		content := []byte("package generic." + platform + "\n")
		require.NoError(t, os.WriteFile(filepath.Join(libDir, platform+".rego"), content, 0600))
	}

	ctx := context.Background()
	for _, platform := range []string{"terraform", "common", "cloudFormation", "ansible", "k8s", "cicd"} {
		t.Run("get_generic_query_"+strings.ToLower(platform), func(t *testing.T) {
			s := NewFilesystemSource(ctx, []string{"."}, []string{""}, []string{""}, libDir, false)
			got, err := s.GetQueryLibrary(ctx, platform)
			require.NoError(t, err)
			assert.Contains(t, got.LibraryCode, "generic."+strings.ToLower(platform))
		})
	}

	t.Run("get_generic_query_unknown", func(t *testing.T) {
		s := NewFilesystemSource(ctx, []string{"."}, []string{""}, []string{""}, libDir, false)
		_, err := s.GetQueryLibrary(ctx, "unknown")
		require.Error(t, err)
	})
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
	libDir := t.TempDir()
	regoPath := filepath.Join(libDir, "terraform.rego")
	require.NoError(t, os.WriteFile(regoPath, []byte("package generic.terraform\n"), 0600))

	ctx := context.Background()

	t.Run("test get library in dir for terraform", func(t *testing.T) {
		got := getLibraryInDir(ctx, "terraform", libDir)
		require.Equal(t, regoPath, got)
	})

	t.Run("test get library in dir error", func(t *testing.T) {
		got := getLibraryInDir(ctx, "", libDir)
		require.Equal(t, "", got)
	})
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

func TestFilesystemSource_localQueryDirs(t *testing.T) {
	ctx := context.Background()

	normalizePaths := func(t *testing.T, paths []string) []string {
		t.Helper()
		out := make([]string, 0, len(paths))
		for _, path := range paths {
			evaluated, err := filepath.EvalSymlinks(path)
			require.NoError(t, err)
			out = append(out, evaluated)
		}
		return out
	}

	createQueryDir := func(t *testing.T, root, name string) string {
		t.Helper()

		queryDir := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(queryDir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(queryDir, QueryFileName), []byte("package test"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(queryDir, MetadataFileName), []byte(`{"id":"test","platform":"terraform"}`), 0o600))

		return queryDir
	}

	tests := []struct {
		name string
		set  func(t *testing.T, root string) (source []string, want []string, err error)
	}{
		{
			name: "valid dir",
			set: func(t *testing.T, root string) ([]string, []string, error) {
				queryDir := createQueryDir(t, root, "valid_query")
				return []string{root}, []string{queryDir}, nil
			},
		},
		{
			name: "non-existent path",
			set: func(t *testing.T, root string) ([]string, []string, error) {
				return []string{filepath.Join(root, "missing")}, nil, errors.New("unable to evaluate path")
			},
		},
		{
			name: "path is a file",
			set: func(t *testing.T, root string) ([]string, []string, error) {
				filePath := filepath.Join(root, "queries.rego")
				require.NoError(t, os.WriteFile(filePath, []byte("package test"), 0o600))
				return []string{filePath}, nil, errors.New("no valid query directories found")
			},
		},
		{
			name: "symlink to dir",
			set: func(t *testing.T, root string) ([]string, []string, error) {
				target := filepath.Join(root, "target")
				queryDir := createQueryDir(t, target, "linked_query")

				link := filepath.Join(root, "queries-link")
				require.NoError(t, os.Symlink(target, link))

				return []string{link}, []string{queryDir}, nil
			},
		},
		{
			name: "recursive search",
			set: func(t *testing.T, root string) ([]string, []string, error) {
				recdir := filepath.Join(root, "recursive")
				require.NoError(t, os.MkdirAll(recdir, 0o700))
				queryDir := createQueryDir(t, recdir, "recursive_query")
				queryDir2 := createQueryDir(t, recdir, "recursive_query2")
				queryDir3 := createQueryDir(t, recdir, "recursive_query3")

				return []string{root}, []string{queryDir, queryDir2, queryDir3}, nil
			},
		},
		{
			name: "error in one of multiple paths",
			set: func(t *testing.T, root string) ([]string, []string, error) {
				createQueryDir(t, root, "not_returned_valid_query_dir")
				return []string{root, "non_existent_path"}, nil, errors.New("unable to evaluate path")
			},
		},
		{
			name: "no valid query directories",
			set: func(t *testing.T, root string) ([]string, []string, error) {
				return []string{root}, nil, errors.New("no valid query directories found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			src, want, wantErr := tt.set(t, root)

			source := NewFilesystemSource(ctx, src, []string{""}, []string{""}, "", true)

			got, err := source.localQueryDirs(ctx)
			assert.ElementsMatch(t, normalizePaths(t, want), got)
			if wantErr != nil {
				require.ErrorContains(t, err, wantErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
