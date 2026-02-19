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
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/test"
)

// BenchmarkFilesystemSource_GetQueries benchmarks getQueries to see improvements
func BenchmarkFilesystemSource_GetQueries(b *testing.B) {
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		b.Fatal(err)
	}
	type fields struct {
		Source              []string
		Types               []string
		CloudProviders      []string
		Library             string
		ExperimentalQueries bool
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "testing_all_paths",
			fields: fields{
				Source:              []string{""},
				Types:               []string{""},
				CloudProviders:      []string{""},
				Library:             "./assets/libraries",
				ExperimentalQueries: true,
			},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			s := NewFilesystemSource(ctx, tt.fields.Source, tt.fields.Types, tt.fields.CloudProviders, tt.fields.Library, tt.fields.ExperimentalQueries)
			for n := 0; n < b.N; n++ {
				filter := QueryInspectorParameters{
					IncludeQueries: IncludeQueries{ByIDs: []string{}},
					ExcludeQueries: ExcludeQueries{ByIDs: []string{}, ByCategories: []string{}},
					InputDataPath:  "",
				}
				if _, err := s.GetQueries(ctx, &filter); err != nil {
					b.Errorf("Error: %s", err)
				}
			}
		})
	}
}

// TestFilesystemSource_GetQueriesWithExclude test the function GetQuery with QuerySelectionFilter set for Exclude queries
func TestFilesystemSource_GetQueriesWithExclude(t *testing.T) { //nolint
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		t.Fatal(err)
	}
	contentByte, err := os.ReadFile(filepath.FromSlash("./assets/queries/terraform/aws/alb_deletion_protection_disabled/query.rego"))
	require.NoError(t, err)
	type fields struct {
		Source              []string
		Types               []string
		CloudProviders      []string
		Library             string
		ExperimentalQueries bool
	}
	tests := []struct {
		name              string
		fields            fields
		includeIDs        []string
		excludeIDs        []string
		excludeCategory   []string
		excludeSeverities []string
		want              []model.QueryMetadata
		wantErr           bool
	}{
		{
			name: "get_queries_with_exclude_result_1",
			fields: fields{
				Source: []string{""}, Types: []string{""},
				CloudProviders: []string{""}, Library: "./assets/libraries",
				ExperimentalQueries: true,
			},
			includeIDs:        []string{"afecd1f1-6378-4f7e-bb3b-60c35801fdd4"},
			excludeCategory:   []string{},
			excludeSeverities: []string{},
			excludeIDs:        []string{"afecd1f1-6378-4f7e-bb3b-60c35801fdd5"},
			want: []model.QueryMetadata{
				{
					Query:     "alb_deletion_protection_disabled",
					Content:   string(contentByte),
					InputData: "{}",
					Metadata: map[string]interface{}{
						"id":                 "afecd1f1-6378-4f7e-bb3b-60c35801fdd4",
						"queryName":          "ALB deletion protection disabled",
						"severity":           "MEDIUM",
						"category":           "Insecure Configurations",
						"descriptionText":    "Enabling deletion protection for an Application Load Balancer (ALB) helps prevent accidental or unauthorized deletion of the ALB resource, which could cause significant downtime or impact application availability. If the `enable_deletion_protection` attribute is set to `false`, as shown below, malicious or inadvertent actions could destroy the ALB and disrupt traffic flow to critical applications:\n\n```\nresource \"aws_alb\" \"example\" {\n  name                      = \"test-lb-tf\"\n  internal                  = false\n  load_balancer_type        = \"network\"\n  subnets                   = aws_subnet.public.*.id\n\n  enable_deletion_protection = true\n\n  tags = {\n    Environment = \"production\"\n  }\n}\n```\n\nEnabling this setting minimizes the risk of outages by requiring an extra step to delete the load balancer, thereby safeguarding essential network infrastructure.",
						"descriptionUrl":     "https://docs.datadoghq.com/security/code_security/iac_security/iac_rules/terraform/aws/alb_deletion_protection_disabled",
						"platform":           "Terraform",
						"descriptionID":      "224b3c6f",
						"cloudProvider":      "aws",
						"cwe":                "693",
						"oldSeverity":        "LOW",
						"oldDescriptionText": "Application Load Balancer should have deletion protection enabled",
						"providerUrl":        "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb#enable_deletion_protection",
					},
					Platform:     "terraform",
					Aggregation:  1,
					Experimental: false,
				},
			},
			wantErr: false,
		},
		{
			name: "get_queries_with_exclude_severity_no_result",
			fields: fields{
				Source: []string{""}, Types: []string{""},
				CloudProviders: []string{""}, Library: "./assets/libraries",
			},
			excludeCategory:   []string{"Insecure Configurations", "Access Control", "Networking and Firewall", "Observability", "Encryption", "Build Process", "Resource Management", "Secret Management", "Supply-Chain"},
			excludeIDs:        []string{},
			excludeSeverities: []string{"critical", "high", "medium", "low", "info"},
			want:              []model.QueryMetadata{},
			wantErr:           false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewFilesystemSource(ctx, tt.fields.Source, []string{""}, []string{""}, tt.fields.Library, tt.fields.ExperimentalQueries)
			filter := QueryInspectorParameters{
				IncludeQueries: IncludeQueries{ByIDs: tt.includeIDs},
				ExcludeQueries: ExcludeQueries{ByIDs: tt.excludeIDs, ByCategories: tt.excludeCategory, BySeverities: tt.excludeSeverities},
				InputDataPath:  "",
			}
			got, err := s.GetQueries(ctx, &filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("FilesystemSource.GetQueries() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			wantStr, err := test.StringifyStruct(tt.want)
			require.Nil(t, err)
			gotStr, err := test.StringifyStruct(got)
			require.Nil(t, err)
			require.Equal(t, tt.want, got, "want = %s\ngot = %s", wantStr, gotStr)
		})
	}
}

// TestFilesystemSource_GetQueriesWithInclude test the function GetQuery with QuerySelectionFilter set for include queries
func TestFilesystemSource_GetQueriesWithInclude(t *testing.T) {
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		t.Fatal(err)
	}

	contentByte, err := os.ReadFile(filepath.FromSlash("./assets/queries/terraform/aws/alb_deletion_protection_disabled/query.rego"))
	require.NoError(t, err)

	type fields struct {
		Source              []string
		Types               []string
		CloudProviders      []string
		Library             string
		ExperimentalQueries bool
	}
	tests := []struct {
		name       string
		fields     fields
		includeIDs []string
		want       []model.QueryMetadata
		wantErr    bool
	}{
		{
			name: "get_queries_with_include_result_1",
			fields: fields{
				Source: []string{""}, Types: []string{""}, CloudProviders: []string{""},
				Library:             "./assets/libraries",
				ExperimentalQueries: true,
			},
			includeIDs: []string{"afecd1f1-6378-4f7e-bb3b-60c35801fdd4"},
			want: []model.QueryMetadata{
				{
					Query:     "alb_deletion_protection_disabled",
					Content:   string(contentByte),
					InputData: "{}",
					Metadata: map[string]interface{}{
						"id":                 "afecd1f1-6378-4f7e-bb3b-60c35801fdd4",
						"queryName":          "ALB deletion protection disabled",
						"severity":           "MEDIUM",
						"category":           "Insecure Configurations",
						"descriptionText":    "Enabling deletion protection for an Application Load Balancer (ALB) helps prevent accidental or unauthorized deletion of the ALB resource, which could cause significant downtime or impact application availability. If the `enable_deletion_protection` attribute is set to `false`, as shown below, malicious or inadvertent actions could destroy the ALB and disrupt traffic flow to critical applications:\n\n```\nresource \"aws_alb\" \"example\" {\n  name                      = \"test-lb-tf\"\n  internal                  = false\n  load_balancer_type        = \"network\"\n  subnets                   = aws_subnet.public.*.id\n\n  enable_deletion_protection = true\n\n  tags = {\n    Environment = \"production\"\n  }\n}\n```\n\nEnabling this setting minimizes the risk of outages by requiring an extra step to delete the load balancer, thereby safeguarding essential network infrastructure.",
						"descriptionUrl":     "https://docs.datadoghq.com/security/code_security/iac_security/iac_rules/terraform/aws/alb_deletion_protection_disabled",
						"platform":           "Terraform",
						"descriptionID":      "224b3c6f",
						"cloudProvider":      "aws",
						"cwe":                "693",
						"oldSeverity":        "LOW",
						"oldDescriptionText": "Application Load Balancer should have deletion protection enabled",
						"providerUrl":        "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb#enable_deletion_protection",
					},
					Platform:     "terraform",
					Aggregation:  1,
					Experimental: false,
				},
			},
			wantErr: false,
		},
		{
			name: "get_queries_with_include_no_result_1",
			fields: fields{
				Source: []string{""}, Types: []string{""}, CloudProviders: []string{""}, Library: "./assets/libraries",
			},
			includeIDs: []string{"57b9893d-33b1-4419-bcea-xxxxxxx"},
			want:       []model.QueryMetadata{},
			wantErr:    false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewFilesystemSource(ctx, tt.fields.Source, []string{""}, []string{""}, tt.fields.Library, tt.fields.ExperimentalQueries)
			filter := QueryInspectorParameters{
				IncludeQueries: IncludeQueries{
					ByIDs: tt.includeIDs,
				},
				ExcludeQueries: ExcludeQueries{
					ByIDs:        []string{},
					ByCategories: []string{},
				},
				InputDataPath: "",
			}

			got, err := s.GetQueries(ctx, &filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("FilesystemSource.GetQueries() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			wantStr, err := test.StringifyStruct(tt.want)
			require.Nil(t, err)
			gotStr, err := test.StringifyStruct(got)
			require.Nil(t, err)

			require.Equal(t, tt.want, got, "want = %s\ngot = %s", wantStr, gotStr)
		})
	}
}

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

// TestFilesystemSource_GetQueries tests the functions [GetQueries()] and all the methods called by them
func TestFilesystemSource_GetQueries(t *testing.T) {
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		t.Fatal(err)
	}

	contentByte, err := os.ReadFile(filepath.FromSlash("./assets/queries/terraform/aws/alb_deletion_protection_disabled/query.rego"))
	require.NoError(t, err)

	type fields struct {
		Source              []string
		Types               []string
		CloudProviders      []string
		IncludeIDs          []string
		Library             string
		ExperimentalQueries bool
	}
	tests := []struct {
		name    string
		fields  fields
		want    []model.QueryMetadata
		wantErr bool
	}{
		{
			name: "get_queries_1",
			fields: fields{
				Source: []string{""}, Types: []string{""}, CloudProviders: []string{""},
				IncludeIDs:          []string{"afecd1f1-6378-4f7e-bb3b-60c35801fdd4"},
				Library:             "./assets/libraries",
				ExperimentalQueries: false,
			},
			want: []model.QueryMetadata{
				{
					Query:     "alb_deletion_protection_disabled",
					Content:   string(contentByte),
					InputData: "{}",
					Metadata: map[string]interface{}{
						"id":                 "afecd1f1-6378-4f7e-bb3b-60c35801fdd4",
						"queryName":          "ALB deletion protection disabled",
						"severity":           "MEDIUM",
						"category":           "Insecure Configurations",
						"descriptionText":    "Enabling deletion protection for an Application Load Balancer (ALB) helps prevent accidental or unauthorized deletion of the ALB resource, which could cause significant downtime or impact application availability. If the `enable_deletion_protection` attribute is set to `false`, as shown below, malicious or inadvertent actions could destroy the ALB and disrupt traffic flow to critical applications:\n\n```\nresource \"aws_alb\" \"example\" {\n  name                      = \"test-lb-tf\"\n  internal                  = false\n  load_balancer_type        = \"network\"\n  subnets                   = aws_subnet.public.*.id\n\n  enable_deletion_protection = true\n\n  tags = {\n    Environment = \"production\"\n  }\n}\n```\n\nEnabling this setting minimizes the risk of outages by requiring an extra step to delete the load balancer, thereby safeguarding essential network infrastructure.",
						"descriptionUrl":     "https://docs.datadoghq.com/security/code_security/iac_security/iac_rules/terraform/aws/alb_deletion_protection_disabled",
						"platform":           "Terraform",
						"descriptionID":      "224b3c6f",
						"cloudProvider":      "aws",
						"cwe":                "693",
						"oldSeverity":        "LOW",
						"oldDescriptionText": "Application Load Balancer should have deletion protection enabled",
						"providerUrl":        "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb#enable_deletion_protection",
					},
					Platform:     "terraform",
					Aggregation:  1,
					Experimental: false,
				},
			},
			wantErr: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewFilesystemSource(ctx, tt.fields.Source, []string{""}, []string{""}, tt.fields.Library, tt.fields.ExperimentalQueries)
			filter := QueryInspectorParameters{
				IncludeQueries: IncludeQueries{
					ByIDs: tt.fields.IncludeIDs},
				ExcludeQueries: ExcludeQueries{
					ByIDs:        []string{},
					ByCategories: []string{},
				},
				ExperimentalQueries: tt.fields.ExperimentalQueries,
				InputDataPath:       "",
			}
			got, err := s.GetQueries(ctx, &filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("FilesystemSource.GetQueries() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			wantStr, err := test.StringifyStruct(tt.want)
			require.Nil(t, err)
			gotStr, err := test.StringifyStruct(got)
			require.Nil(t, err)

			require.Equal(t, tt.want, got, "want = %s\ngot = %s", wantStr, gotStr)
		})
	}
}

// Test_ReadMetadata tests the functions [ReadMetadata()] and all the methods called by them
func Test_ReadMetadata(t *testing.T) {
	if err := test.ChangeCurrentDir("datadog-iac-scanner"); err != nil {
		t.Fatal(err)
	}
	type args struct {
		queryDir string
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]interface{}
		wantErr bool
	}{
		{
			name: "read_metadata_error",
			args: args{
				queryDir: "error-path",
			},
			want:    nil,
			wantErr: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := ReadMetadata(ctx, tt.args.queryDir); !reflect.DeepEqual(got, tt.want) {
				require.Equal(t, tt.wantErr, (err != nil))
				gotStr, err := test.StringifyStruct(got)
				require.Nil(t, err)
				wantStr, err := test.StringifyStruct(tt.want)
				require.Nil(t, err)
				t.Errorf("readMetadata()\ngot = %v\nwant = %v", gotStr, wantStr)
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
