/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/hclcache"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
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
	name     string
	filename string
	want     string
	wantErr  bool
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
	require.Equal(t, []string{".tf", ".tofu", ".tf.json", ".tofu.json", ".tfvars"}, p.SupportedExtensions())
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

	_, document, _, _, err = parser.Parse(ctx, []byte(conditionalValResource), "test.tf", true, 15)
	require.NoError(t, err)
	require.Len(t, document, 1)
	secret := document[0]["resource"].(model.Document)["aws_secretsmanager_secret_version"].(model.Document)["example"].(model.Document)
	require.Contains(t, secret["secret_string"], "${null}")

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

func Test_Parser_Tofu(t *testing.T) {
	ctx := context.Background()
	parser := NewDefault()
	require.Equal(t, model.KindTerraform, parser.GetKind())
	require.Contains(t, parser.SupportedExtensions(), ".tofu")

	_, document, _, _, err := parser.Parse(ctx, []byte(have), "test.tofu", true, 15)
	require.NoError(t, err)
	require.Len(t, document, 1)
	require.Contains(t, document[0], "resource")
	require.Contains(t, document[0]["resource"], "aws_s3_bucket")
}

func Test_Parser_InventoriedTwinsKeepOwnVars(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "main.tf")
	tofu := filepath.Join(dir, "main.tofu")
	require.NoError(t, os.WriteFile(tf, []byte(`
variable "name" { default = "from-tf" }
resource "aws_s3_bucket" "b" { bucket = var.name }
`), 0o600))
	require.NoError(t, os.WriteFile(tofu, []byte(`
variable "name" { default = "from-tofu" }
resource "aws_s3_bucket" "b" { bucket = var.name }
`), 0o600))

	parser := NewDefault()
	parser.SetMergeAllow([]string{tf, tofu})

	_, tfDoc, _, _, err := parser.Parse(context.Background(), []byte(`
variable "name" { default = "from-tf" }
resource "aws_s3_bucket" "b" { bucket = var.name }
`), tf, true, 15)
	require.NoError(t, err)
	tfBucket := fmt.Sprint(tfDoc[0]["resource"].(model.Document)["aws_s3_bucket"].(model.Document)["b"].(model.Document)["bucket"])
	require.Contains(t, tfBucket, "from-tf")
	require.NotContains(t, tfBucket, "from-tofu")

	_, tofuDoc, _, _, err := parser.Parse(context.Background(), []byte(`
variable "name" { default = "from-tofu" }
resource "aws_s3_bucket" "b" { bucket = var.name }
`), tofu, true, 15)
	require.NoError(t, err)
	tofuBucket := fmt.Sprint(tofuDoc[0]["resource"].(model.Document)["aws_s3_bucket"].(model.Document)["b"].(model.Document)["bucket"])
	require.Contains(t, tofuBucket, "from-tofu")
	require.NotContains(t, tofuBucket, "from-tf")
}

func Test_Parser_SharesDirectoryVarsCacheAcrossSiblingFiles(t *testing.T) {
	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "main.tf"),
		filepath.Join(dir, "variables.tf"),
		filepath.Join(dir, "outputs.tf"),
	}
	for _, path := range paths {
		require.NoError(t, os.WriteFile(path, []byte(`variable "name" { default = "shared" }`), 0o600))
	}

	parser := NewDefault()
	parser.SetMergeAllow(paths)
	for _, path := range paths {
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		_, _, _, _, err = parser.Parse(t.Context(), content, path, true, 15)
		require.NoError(t, err)
	}

	cacheEntries := 0
	parser.dirVarsCache.Range(func(_, _ any) bool {
		cacheEntries++
		return true
	})
	require.Equal(t, 1, cacheEntries)
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
			NewDefault().processContent(ctx, tt.args.elements, tt.args.content, tt.args.path)
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
			wantErr: false,
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
			wantErr: false,
		},
		{
			name:     "Should get error when trying to parse inexistent file",
			filename: filepath.Join(".", "not_found.tf"),
			want:     "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedFile, err := readAndParseFile(vfs.DiskFS{}, tt.filename)
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

func TestParseFileReturnsDiagnostics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.tf")
	require.NoError(t, os.WriteFile(path, []byte(`resource "test" "test" {
  value = aws_s3_bucket.selected.
}`), 0o600))

	parsedFile, err := readAndParseFile(vfs.DiskFS{}, path)
	require.Nil(t, parsedFile)
	require.ErrorContains(t, err, "Invalid attribute name")
}

func readAndParseFile(fsys vfs.FS, filename string) (*hcl.File, error) {
	content, err := fsys.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, err
	}
	file, diags := hclsyntax.ParseConfig(content, filename, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, diags
	}
	return file, nil
}

// TestParser_ConcurrentSameDir guards the per-directory variable cache: the
// cached map must never be written while the files of one directory are parsed
// concurrently (doing so caused "concurrent map writes" crashes). Run under
// -race to catch regressions.
func TestParser_ConcurrentSameDir(t *testing.T) {
	dir := t.TempDir()
	const numFiles = 32
	for i := 0; i < numFiles; i++ {
		// format() over unknown variables renders them as text.
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

func TestParser_EvaluatesFileFunction(t *testing.T) {
	for _, backend := range []string{"disk", "memory"} {
		t.Run(backend, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "note.txt"), []byte("host"), 0600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "host-only.txt"), []byte("host-only"), 0600))
			src := []byte(`resource "t" "x" {
 n=file("note.txt")
 absent=try(file("host-only.txt"),"caught")
}`)
			tf := filepath.Join(dir, "main.tf")
			var fsys vfs.FS = vfs.DiskFS{}
			want, absent := "host", "host-only"
			if backend == "memory" {
				fsys = vfs.NewMemFS(map[string][]byte{tf: src, filepath.Join(dir, "note.txt"): []byte("owned")})
				want, absent = "owned", "caught"
			}
			parser := NewDefaultWithParams(fsys, "", model.SCIInfo{})
			_, docs, _, _, err := parser.Parse(context.Background(), src, tf, false, 0)
			require.NoError(t, err)
			require.Len(t, docs, 1)
			values := docs[0]["resource"].(model.Document)["t"].(model.Document)["x"].(model.Document)
			for name, expected := range map[string]string{"n": want, "absent": absent} {
				actual := values[name].(ctyjson.SimpleJSONValue)
				require.True(t, actual.Value.RawEquals(cty.StringVal(expected)))
			}
		})
	}
}

func TestParser_WrapsEscapingFileFunction(t *testing.T) {
	dir := t.TempDir()
	src := []byte(`resource "t" "x" { n = file("../secret") }`)
	tf := filepath.Join(dir, "main.tf")
	parser := NewDefault()
	_, docs, _, _, err := parser.Parse(context.Background(), src, tf, false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)
	n := docs[0]["resource"].(model.Document)["t"].(model.Document)["x"].(model.Document)["n"]
	require.Equal(t, `${file("../secret")}`, n)
}

func TestParseUnavailableJSONLinkPlaceholder(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, "main.tf.json")
	placeholder := []byte("./missing.tf")
	require.NoError(t, os.WriteFile(path, placeholder, 0o644))
	var logs bytes.Buffer
	log := zerolog.New(&logs).Level(zerolog.DebugLevel)
	_, docs, _, _, err := NewDefault().Parse(log.WithContext(t.Context()), placeholder, path, false, 0)
	require.NoError(t, err)
	require.Empty(t, docs)
	require.Contains(t, logs.String(), `"level":"debug"`)
}

func TestParser_CertificateFilesystem(t *testing.T) {
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "fixtures", "test_certificate", "certificate.pem"))
	require.NoError(t, err)
	for _, format := range []struct {
		name, source string
	}{
		{"main.tf", `resource "aws_acm_certificate" "cert" {certificate_body="certificate.pem"}`},
		{"main.tf.json", `{"resource":{"aws_acm_certificate":{"cert":{"certificate_body":"certificate.pem"}}}}`},
	} {
		t.Run(format.name, func(t *testing.T) {
			dir := t.TempDir()
			cert := filepath.Join(dir, "certificate.pem")
			require.NoError(t, os.WriteFile(cert, []byte("conflicting invalid host certificate"), 0600))
			path := filepath.Join(dir, format.name)
			source := []byte(format.source)
			p := NewDefaultWithParams(vfs.NewMemFS(map[string][]byte{path: source, cert: pem}), "", model.SCIInfo{})
			for range 2 {
				_, docs, _, _, err := p.Parse(t.Context(), source, path, false, 0)
				require.NoError(t, err)
				require.Len(t, docs, 1)
				body := docs[0]["resource"].(model.Document)["aws_acm_certificate"].(model.Document)["cert"].(model.Document)["certificate_body"]
				require.IsType(t, map[string]interface{}{}, body)
				info := body.(map[string]interface{})
				require.Equal(t, cert, info["file"])
				require.Contains(t, info, "expiration_date")
			}
		})
	}
}

func TestParser_HCLCacheReusesDirectoryParsesAndMatchesUncached(t *testing.T) {
	dir := "/repo/env/prod"
	files := map[string][]byte{
		filepath.Join(dir, "variables.tf"): []byte(`
variable "env" {
  type    = string
  default = "prod"
}
`),
		filepath.Join(dir, "locals.tf"): []byte(`
locals {
  bucket_name = "app-${var.env}-logs"
  policy_sid  = "AllowRead-${var.env}"
}
`),
		filepath.Join(dir, "iam.tf"): []byte(`
locals {
  effect = "Allow"
}
data "aws_iam_policy_document" "read" {
  statement {
    sid       = local.policy_sid
    effect    = local.effect
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${local.bucket_name}/*"]
  }
}
resource "aws_iam_policy" "read" {
  name   = local.policy_sid
  policy = data.aws_iam_policy_document.read.json
}
`),
		filepath.Join(dir, "main.tf"): []byte(`
resource "aws_s3_bucket" "logs" {
  bucket = local.bucket_name
}
`),
		filepath.Join(dir, "terraform.tfvars"): []byte(`env = "staging"`),
	}
	order := []string{
		filepath.Join(dir, "variables.tf"),
		filepath.Join(dir, "locals.tf"),
		filepath.Join(dir, "iam.tf"),
		filepath.Join(dir, "main.tf"),
		filepath.Join(dir, "terraform.tfvars"),
	}

	parseAll := func(ctx context.Context) map[string][]byte {
		p := NewDefaultWithParams(vfs.NewMemFS(files), "", model.SCIInfo{})
		out := make(map[string][]byte, len(order))
		for _, path := range order {
			_, docs, _, _, err := p.Parse(ctx, files[path], path, false, 0)
			require.NoError(t, err, path)
			b, err := json.Marshal(docs)
			require.NoError(t, err)
			out[path] = b
		}
		return out
	}

	uncached := parseAll(context.Background())

	cache := hclcache.New(0)
	defer cache.Close()
	cached := parseAll(hclcache.WithCache(context.Background(), cache))

	// Output must be identical with vs without hclcache.
	require.Equal(t, uncached, cached)

	// Every file in the directory is parsed at most once instead of 2-3x across
	// variables.go, data_source.go, and terraform.go.
	stats := cache.Stats()
	require.Equal(t, int64(len(order)), stats.Misses, "expected each file to be parsed once")
	require.GreaterOrEqual(t, stats.Hits, int64(6), "expected cache hits across variables, data sources, and resource parses")
}

func BenchmarkParseDirectoryWithHCLCache(b *testing.B) {
	dir := "/repo/env/prod"
	files := map[string][]byte{
		filepath.Join(dir, "variables.tf"): []byte(`
variable "env" { default = "prod" }
variable "region" { default = "us-east-1" }
variable "owner" { default = "platform" }
`),
		filepath.Join(dir, "locals.tf"): []byte(`
locals {
  bucket_name = "${var.owner}-${var.env}-${var.region}-logs"
  policy_sid  = "AllowRead-${var.env}"
  common_tags = { Env = var.env, Owner = var.owner, Region = var.region }
}
`),
		filepath.Join(dir, "iam.tf"): []byte(`
locals {
  effect = "Allow"
}
data "aws_iam_policy_document" "read" {
  statement {
    sid       = local.policy_sid
    effect    = local.effect
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::${local.bucket_name}/*"]
  }
}
resource "aws_iam_policy" "read" {
  name   = local.policy_sid
  policy = data.aws_iam_policy_document.read.json
}
`),
		filepath.Join(dir, "main.tf"): []byte(`
resource "aws_s3_bucket" "logs" {
  bucket = local.bucket_name
  tags   = local.common_tags
}
`),
		filepath.Join(dir, "terraform.tfvars"): []byte(`env = "staging"`),
	}
	order := []string{
		filepath.Join(dir, "variables.tf"),
		filepath.Join(dir, "locals.tf"),
		filepath.Join(dir, "iam.tf"),
		filepath.Join(dir, "main.tf"),
		filepath.Join(dir, "terraform.tfvars"),
	}
	memfs := vfs.NewMemFS(files)

	b.Run("Uncached", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			p := NewDefaultWithParams(memfs, "", model.SCIInfo{})
			for _, path := range order {
				if _, _, _, _, err := p.Parse(context.Background(), files[path], path, false, 0); err != nil {
					b.Fatal(err)
				}
			}
		}
	})

	b.Run("WithHCLCache", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			cache := hclcache.New(0)
			ctx := hclcache.WithCache(context.Background(), cache)
			p := NewDefaultWithParams(memfs, "", model.SCIInfo{})
			for _, path := range order {
				if _, _, _, _, err := p.Parse(ctx, files[path], path, false, 0); err != nil {
					b.Fatal(err)
				}
			}
			cache.Close()
		}
	})
}
