/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/registry"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/stretchr/testify/require"
)

var (
	have = `
resource "aws_s3_bucket" "b" {
  bucket = "S3B_541"
  // dd-iac-scan ignore-line
  acl    = "public-read"
  // regular comment
  // dd-iac-scan ignore-block
  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}
`
	count = `
   resource "aws_instance" "server" {
	count = true == true ? 0 : 1

	subnet_id     = var.subnet_ids[count.index]

	ami           = "ami-a1b2c3d4"
	instance_type = "t2.micro"

  }

  resource "aws_instance" "server1" {
	count = length(var.subnet_ids)

	ami           = "ami-a1b2c3d4"
	instance_type = "t2.micro"
	subnet_id     = var.subnet_ids[count.index]

  }`

	parentheses = `
variable "default" {
		type    = "string"
		default = "default_var_file"
}

data "aws_ami" "example" {
		most_recent = true

		owners = ["self"]
		tags = {
		  Name   = "app-server"
		  Tested = "true"
		  ("Tag/${var.default}") = "test"
		}
}
  `
	namelessResource = `resource "aws_lb" {
  name               = "test-lb-tf-1"
  internal           = false
  load_balancer_type = "network"
  subnets            = [for subnet in aws_subnet.public : subnet.id]
  enable_deletion_protection = true
}

resource "aws_lb" {
  name               = "test-lb-tf-2"
  internal           = false
  load_balancer_type = "network"
  subnets            = [for subnet in aws_subnet.public : subnet.id]
  enable_deletion_protection = true
}
`
	conditionalValResource = `resource "aws_secretsmanager_secret_version" "example" {
  count         = 1
  secret_id     = aws_secretsmanager_secret.rds_db_secrets[0].id
  secret_string = <<EOF
{
  "password":"${var.create_db_instance ? 123456 : null}"
}
EOF
}
`
)

type fileTest struct {
	name                    string
	filename                string
	shouldReplaceDataSource bool
	want                    string
	wantErr                 bool
}

// TestParser_GetKind tests the functions [GetKind()] and all the methods called by them
func TestParser_GetKind(t *testing.T) {
	p := &Parser{}
	require.Equal(t, model.KindTerraform, p.GetKind())
}

// TestParser_GetKind tests the functions [SupportedTypes()] and all the methods called by them
func TestParser_SupportedTypes(t *testing.T) {
	p := &Parser{}
	require.Equal(t, map[string]bool{"terraform": true}, p.SupportedTypes())
}

// TestParser_SupportedExtensions tests the functions [SupportedExtensions()] and all the methods called by them
func TestParser_SupportedExtensions(t *testing.T) {
	p := &Parser{}
	require.Equal(t, []string{".tf", ".tfvars"}, p.SupportedExtensions())
}

// Test_Parser tests the functions [Parser()] and all the methods called by them
func Test_Parser(t *testing.T) {
	ctx := context.Background()
	parser := NewDefault()
	_, document, linesToIgnore, _, err := parser.Parse(ctx, []byte(have), "test.tf", true, 15)

	require.Equal(t, []int{8, 9, 10, 11, 5, 4, 6}, linesToIgnore)
	require.NoError(t, err)
	require.Len(t, document, 1)
	require.Contains(t, document[0], "resource")
	require.Contains(t, document[0]["resource"], "aws_s3_bucket")

	// case where we fail to parse the file and a fatal error is thrown caught with recover
	_, document, linesToIgnore, _, err = parser.Parse(ctx, []byte(conditionalValResource), "test.tf", true, 15)
	require.NoError(t, err)
	require.Len(t, document, 0)
	require.Len(t, linesToIgnore, 0)

}

// Test_Count tests resources with count set to 0
func Test_Count(t *testing.T) {
	ctx := context.Background()
	parser := NewDefault()
	_, document, _, _, err := parser.Parse(ctx, []byte(count), "count.tf", true, 15)
	require.NoError(t, err)
	require.Len(t, document, 1)
	require.Contains(t, document[0], "resource")
	require.Contains(t, document[0]["resource"].(model.Document)["aws_instance"], "server1")
	require.NotContains(t, document[0]["resource"].(model.Document)["aws_instance"], "server")
}

// Test_Parentheses_Expr tests if parentheses expr is well parsed
func Test_Parentheses_Expr(t *testing.T) {
	ctx := context.Background()
	parser := NewDefault()
	// Call Resolve first to set up input variables
	fullPath := filepath.FromSlash("../../../test/fixtures/test-tf-parentheses/parentheses.tf")
	_, _, err := parser.Resolve(ctx, []byte(parentheses), fullPath, false, 0)
	require.NoError(t, err)
	_, document, _, _, err := parser.Parse(ctx, []byte(parentheses), fullPath, true, 15)
	require.NoError(t, err)
	require.Len(t, document, 1)
	require.Contains(t, document[0], "data")
	ami := document[0]["data"].(model.Document)["aws_ami"].(model.Document)["example"]
	require.Contains(t, ami.(model.Document)["tags"], "Tag/default_var_file")
}

// Test_namelessResource tests the case of the nameless resource where the resource name is not specified and model.Document resource is a list
func Test_namelessResource(t *testing.T) {
	ctx := context.Background()
	parser := NewDefault()
	_, document, _, _, err := parser.Parse(ctx, []byte(namelessResource), "namelessResource.tf", true, 15)
	require.NoError(t, err)
	require.Len(t, document, 1)
	require.Contains(t, document[0], "resource")
	require.Len(t, document[0]["resource"].(model.Document)["aws_lb"].([]interface{}), 2)
	require.Equal(t, document[0]["resource"].(model.Document)["aws_lb"].([]interface{})[0].(model.Document)["name"],
		"test-lb-tf-1")
	require.Equal(t, document[0]["resource"].(model.Document)["aws_lb"].([]interface{})[1].(model.Document)["name"],
		"test-lb-tf-2")
}

// Test_Resolve tests the functions [Resolve()] and all the methods called by them
func Test_Resolve(t *testing.T) {
	ctx := context.Background()
	parser := NewDefault()

	resolved, _, err := parser.Resolve(ctx, []byte(have), "test.tf", true, 15)
	require.NoError(t, err)
	require.Equal(t, []byte(have), resolved)
}

func TestTerraform_ProcessContent(t *testing.T) {
	type args struct {
		elements model.Document
		content  string
		path     string
	}

	tests := []struct {
		name string
		args args
		want map[string]interface{}
	}{
		{
			name: "test_process_content",
			args: args{
				elements: model.Document{},
				content:  filepath.Join("..", "..", "..", "test", "fixtures", "test_certificate", "certificate.pem"),
				path:     filepath.Join("..", "..", "test", "fixtures", "test_certificate", "certificate.pem"),
			},
			want: map[string]interface{}{
				"expiration_date": [3]int{2022, 3, 27},
				"file":            filepath.Join("..", "..", "..", "test", "fixtures", "test_certificate", "certificate.pem"),
				"rsa_key_bytes":   512,
			},
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processContent(ctx, tt.args.elements, tt.args.content, tt.args.path)
			require.Equal(t, tt.want, tt.args.elements["certificate_body"])
		})
	}
}

// Test_GetCommentToken must get the token that represents a comment
func Test_GetCommentToken(t *testing.T) {
	parser := &Parser{}
	require.Equal(t, "#", parser.GetCommentToken())
}

func TestTerraform_StringifyContent(t *testing.T) {
	type fields struct {
		parser *Parser
	}
	type args struct {
		content []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "test stringify content",
			fields: fields{
				parser: &Parser{},
			},
			args: args{
				content: []byte(`
resource "aws_s3_bucket" "b" {
	bucket = "S3B_541"
	acl    = "public-read"

	tags = {
		Name        = "My bucket"
		Environment = "Dev"
	}
}
`),
			},
			want: `
resource "aws_s3_bucket" "b" {
	bucket = "S3B_541"
	acl    = "public-read"

	tags = {
		Name        = "My bucket"
		Environment = "Dev"
	}
}
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.fields.parser.StringifyContent(tt.args.content)
			require.Equal(t, tt.wantErr, err != nil)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestParseFile(t *testing.T) {
	tests := []fileTest{
		{
			name:     "Should parse variable file",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_variables", "terraform.tfvars"),
			want: `test_terraform = "terraform.tfvars"
`,
			shouldReplaceDataSource: false,
			wantErr:                 false,
		},
		{
			name:     "Should parse terraform file",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_variables", "test.tf"),
			want: `variable "local_default_var" {
  type    = "string"
  default = "local_default"
}

variable "" {
  type    = "string"
  default = "invalid_block"
}

variable "invalid_attr" {
}

resource "test" "test1" {
  test_map        = var.map2
  test_bool       = var.test1
  test_list       = var.test2
  test_neted_map  = var.map2[var.map1["map1key1"]]

  test_block {
    terraform_var = var.test_terraform
  }

  test_default_local = var.local_default_var
  test_default       = var.default_var
}
`,
			shouldReplaceDataSource: false,
			wantErr:                 false,
		},
		{
			name:                    "Should get error when trying to parse inexistent file",
			filename:                filepath.Join(".", "not_found.tf"),
			shouldReplaceDataSource: false,
			want:                    "",
			wantErr:                 true,
		},
		{
			name:     "Should parse data source file without errors",
			filename: filepath.Join("..", "..", "..", "test", "fixtures", "test_terraform_data_source", "data_source_1.tf"),
			want: `resource "aws_cloudwatch_log_destination_policy" "test_destination_policy" {
  destination_name = aws_cloudwatch_log_destination.test_destination.name
  access_policy    = "data.aws_iam_policy_document.test_destination_policy.json"
}

data "aws_iam_policy_document" "test_destination_policy" {
  statement {
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "data.aws_caller_identity.current.id",
      ]
    }

    actions = [
      "logs:*",
    ]

  }
}

`,
			shouldReplaceDataSource: true,
			wantErr:                 false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedFile, err := readAndParseFile(vfs.DiskFS{}, tt.filename, tt.shouldReplaceDataSource)
			if tt.wantErr {
				require.NotNil(t, err)
				require.Nil(t, parsedFile)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, strings.ReplaceAll(string(parsedFile.Bytes), "\r", ""))
			}
		})
	}
}

func TestParseFileReplacesOnlyRootDataTraversals(t *testing.T) {
	source := []byte(`
resource "test" "test" {
  root_data    = data.aws_s3_bucket.selected.arn
  nested_var   = var.data.resource_arn
  nested_local = local.data.resource_arn
  nested_each  = each.value.data.resource_arn
  literal      = "data.aws_s3_bucket.selected.arn"
  template     = "arn:${data.aws_partition.current.partition}:s3:::example"
}
`)
	path := filepath.Join(t.TempDir(), "data_references.tf")
	require.NoError(t, os.WriteFile(path, source, 0o600))

	parsedFile, err := readAndParseFile(vfs.DiskFS{}, path, true)
	require.NoError(t, err)
	got := string(parsedFile.Bytes)
	require.Contains(t, got, `root_data    = "data.aws_s3_bucket.selected.arn"`)
	require.Contains(t, got, `nested_var   = var.data.resource_arn`)
	require.Contains(t, got, `nested_local = local.data.resource_arn`)
	require.Contains(t, got, `nested_each  = each.value.data.resource_arn`)
	require.Contains(t, got, `literal      = "data.aws_s3_bucket.selected.arn"`)
	require.Contains(t, got, `template     = "arn:${"data.aws_partition.current.partition"}:s3:::example"`)
}

func TestParseFileReturnsDiagnostics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.tf")
	require.NoError(t, os.WriteFile(path, []byte(`resource "test" "test" {
  value = aws_s3_bucket.selected.
}`), 0o600))

	parsedFile, err := readAndParseFile(vfs.DiskFS{}, path, true)
	require.Nil(t, parsedFile)
	require.ErrorContains(t, err, "Invalid attribute name")
}

func readAndParseFile(fsys vfs.FS, filename string, shouldReplaceDataSource bool) (*hcl.File, error) {
	content, err := fsys.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, err
	}
	file, diags := parseFileContent(content, filename, shouldReplaceDataSource)
	if diags.HasErrors() {
		return nil, diags
	}
	return file, nil
}

// TestParser_ConcurrentSameDir guards the per-directory variable cache: the
// converter adds per-file keys to the variable map during evaluation, so the
// cached map must never be shared across the files parsed concurrently in the
// same directory (doing so caused "concurrent map writes" crashes). Run under
// -race to catch regressions.
func TestParser_ConcurrentSameDir(t *testing.T) {
	dir := t.TempDir()
	const numFiles = 32
	for i := 0; i < numFiles; i++ {
		// format() over an unknown variable forces the converter's evalFunction
		// fallback, which writes the unknown root key into the variable map.
		content := fmt.Sprintf(`
resource "aws_s3_bucket" "b%d" {
  bucket = format("%%s-%%s", unknown_input_%d, another_unknown_%d)
}
`, i, i, i)
		path := filepath.Join(dir, fmt.Sprintf("file_%d.tf", i))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}

	p := NewDefault()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < numFiles; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := filepath.Join(dir, fmt.Sprintf("file_%d.tf", i))
			content, err := os.ReadFile(path) //nolint:gosec
			require.NoError(t, err)
			_, _, _, _, parseErr := p.Parse(ctx, content, path, false, 0)
			require.NoError(t, parseErr)
		}(i)
	}
	wg.Wait()
}

// TestExtractAndRegisterAddresses_VariableBlocks verifies that variable blocks in .tf files
// are registered under the "var.<name>" key so the tfplan detector can resolve module_default
// findings to the variable's default line.
func TestExtractAndRegisterAddresses_VariableBlocks(t *testing.T) {
	tmpDir := t.TempDir()
	variablesTF := filepath.Join(tmpDir, "variables.tf")
	content := `variable "publicly_accessible" {
  description = "Whether publicly accessible."
  type        = bool
  default     = true
}

variable "storage_encrypted" {
  type    = bool
  default = false
}
`
	err := os.WriteFile(variablesTF, []byte(content), 0644)
	require.NoError(t, err)

	reg := registry.New()
	ctx := context.Background()
	parser := New(reg)

	_, _, _, _, parseErr := parser.Parse(ctx, []byte(content), variablesTF, false, 1)
	require.NoError(t, parseErr)

	// var.publicly_accessible should be registered at line 1
	loc, found := reg.LookupWithScope("var.publicly_accessible", variablesTF)
	require.True(t, found, "var.publicly_accessible should be in the registry")
	require.Equal(t, variablesTF, loc.FilePath)
	require.Equal(t, 1, loc.Line)

	// var.storage_encrypted should be registered at line 7
	loc2, found2 := reg.LookupWithScope("var.storage_encrypted", variablesTF)
	require.True(t, found2, "var.storage_encrypted should be in the registry")
	require.Equal(t, variablesTF, loc2.FilePath)
	require.Equal(t, 7, loc2.Line)
}
