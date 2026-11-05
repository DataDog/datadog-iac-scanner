/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	stdjson "encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	jsonparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/json"
	"github.com/stretchr/testify/require"
)

// A certificate body is what is read of the certificate, whether the HCL
// parser read the file it names, evaluation rendered the file or a plan holds
// the certificate.
func TestCertificateBodyIsTheSameForHCLAndPlan(t *testing.T) {
	certPEM, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "test_certificate", "certificate.pem"))
	require.NoError(t, err)
	want := map[string]interface{}{"expiration_date": []interface{}{2022.0, 3.0, 27.0}, "rsa_key_bytes": 512.0}

	files, instantiated := resolveRepo(t, map[string]string{
		"main.tf": `
resource "aws_iam_server_certificate" "root" {
  certificate_body = file("cert.pem")
}

module "m" {
  source = "./m"
}
`,
		"cert.pem":  string(certPEM),
		"m/main.tf": `resource "aws_iam_server_certificate" "child" { certificate_body = file("${path.module}/../cert.pem") }`,
		"unevaluated/main.tf": `
resource "aws_iam_server_certificate" "written" {
  certificate_body = file("../cert.pem")
  name             = var.missing
}
`,
	}, nil)

	var pemJSON stdjson.RawMessage
	pemJSON, err = stdjson.Marshal(string(certPEM))
	require.NoError(t, err)
	plan := `{"format_version":"1.2","terraform_version":"1.9.0",
"planned_values":{"root_module":{"resources":[{"address":"aws_iam_server_certificate.root","mode":"managed","type":"aws_iam_server_certificate","name":"root","values":{"certificate_body":` + string(pemJSON) + `}}]}},
"resource_changes":[],
"configuration":{"root_module":{"resources":[{"address":"aws_iam_server_certificate.root","mode":"managed","type":"aws_iam_server_certificate","name":"root","expressions":{"certificate_body":{}}}]}}}`
	_, planDocs, _, _, err := (&jsonparser.Parser{}).Parse(context.Background(), []byte(plan), "plan.json", false, 0)
	require.NoError(t, err)
	planFile := &model.FileMetadata{Kind: model.KindTerraformPlan, Document: planDocs[0]}

	var written model.FileMetadatas
	for _, f := range files {
		written = append(written, f)
	}
	parseTerraformValues(context.Background(), append(written, planFile), instantiated)

	body := func(doc model.Document, typ, name string) interface{} {
		var out interface{}
		raw, err := stdjson.Marshal(docAsMap(docAsMap(docAsMap(doc["resource"])[typ])[name])[certificateBodyKey])
		require.NoError(t, err)
		require.NoError(t, stdjson.Unmarshal(raw, &out))
		return out
	}
	require.Equal(t, want, body(planFile.Document, "aws_iam_server_certificate", "root"), "plan")
	require.Equal(t, want, body(files["main.tf"].Document, "aws_iam_server_certificate", "root"), "evaluated root block")
	require.Len(t, instantiated, 1)
	require.Equal(t, want, body(instantiated[0], "aws_iam_server_certificate", "child"), "module instance")
	require.Equal(t, want, body(files["unevaluated/main.tf"].Document, "aws_iam_server_certificate", "written"),
		"a file evaluation cannot read is read next to the document's file")
	require.Equal(t, map[string]interface{}{"name": true},
		metaOf(t, files["unevaluated/main.tf"].Document, "resource", "aws_iam_server_certificate", "written")[unknownKey],
		"a certificate read is known")
}

func TestCertificateBodyThatIsNotACertificateIsKept(t *testing.T) {
	doc := model.Document{"resource": map[string]interface{}{"aws_acm_certificate": map[string]interface{}{
		"flag":    map[string]interface{}{certificateBodyKey: true},
		"text":    map[string]interface{}{certificateBodyKey: "not a certificate"},
		"missing": map[string]interface{}{certificateBodyKey: `${file("missing.pem")}`},
	}}}
	parseCertificateBodies(context.Background(), doc, filepath.Join(t.TempDir(), "main.tf"))
	require.Equal(t, map[string]interface{}{
		"flag":    map[string]interface{}{certificateBodyKey: true},
		"text":    map[string]interface{}{certificateBodyKey: "not a certificate"},
		"missing": map[string]interface{}{certificateBodyKey: `${file("missing.pem")}`},
	}, doc["resource"].(map[string]interface{})["aws_acm_certificate"])
}
