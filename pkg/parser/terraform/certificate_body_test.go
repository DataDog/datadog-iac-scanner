package terraform

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/rs/zerolog"
)

func TestCertificateBodyNonStringDoesNotPanicDuringResourceProcessing(t *testing.T) {
	t.Run("literal bool", func(t *testing.T) {
		content := `resource "aws_api_gateway_domain_name" "example" {
  certificate_body = true
  domain_name      = "api.example.com"
}`
		assertNoRecoveredPanic(t, content, "main.tf")
	})

	t.Run("variable resolved to bool via tfvars", func(t *testing.T) {
		dir := t.TempDir()
		mainTF := `variable "cert" {
  type    = bool
  default = true
}
resource "aws_acm_certificate" "example" {
  certificate_body = var.cert
}`
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(mainTF), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "terraform.tfvars"), []byte("cert = true\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		var logBuf bytes.Buffer
		ctx := zerolog.New(&logBuf).WithContext(context.Background())
		parser := NewDefaultWithParams(vfs.DiskFS{}, "", model.SCIInfo{})
		path := filepath.Join(dir, "main.tf")
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		_, _, _, _, err = parser.Parse(ctx, content, path, true, 15)
		if err != nil {
			t.Fatalf("parse returned error: %v", err)
		}
		if bytes.Contains(logBuf.Bytes(), []byte("Recovered from panic")) {
			t.Fatalf("unexpected recovered panic in logs: %q", logBuf.String())
		}
	})
}

func assertNoRecoveredPanic(t *testing.T, content, path string) {
	t.Helper()

	var logBuf bytes.Buffer
	ctx := zerolog.New(&logBuf).WithContext(context.Background())
	parser := NewDefault()

	_, _, _, _, err := parser.Parse(ctx, []byte(content), path, true, 15)
	if err != nil {
		t.Fatalf("parse returned error: %v", err)
	}
	if bytes.Contains(logBuf.Bytes(), []byte("Recovered from panic")) {
		t.Fatalf("unexpected recovered panic in logs: %q", logBuf.String())
	}
}
