/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

func TestParseJSONConfigResource(t *testing.T) {
	src := []byte(`{
  "resource": {
    "aws_s3_bucket": {
      "b": {
        "bucket": "S3B_541",
        "acl": "public-read",
        "versioning": {
          "enabled": true
        }
      }
    }
  }
}`)
	doc, err := parseJSONConfig(src, "main.tf.json", nil)
	require.NoError(t, err)

	bucket := doc["resource"].(model.Document)["aws_s3_bucket"].(model.Document)["b"].(model.Document)
	require.Equal(t, "public-read", bucket["acl"].(ctyjson.SimpleJSONValue).AsString())
	require.Equal(t, "S3B_541", bucket["bucket"].(ctyjson.SimpleJSONValue).AsString())
	require.Equal(t, true, bucket["versioning"].(model.Document)["enabled"].(ctyjson.SimpleJSONValue).True())

	lines := bucket["_dd_lines"].(map[string]model.LineObject)
	require.Equal(t, 6, lines["_dd_acl"].Line)
}

func TestParseJSONConfigCountZeroSkipped(t *testing.T) {
	src := []byte(`{
  "resource": {
    "aws_instance": {
      "gone": { "count": 0, "ami": "ami-123" },
      "kept": { "ami": "ami-123" }
    }
  }
}`)
	doc, err := parseJSONConfig(src, "main.tf.json", nil)
	require.NoError(t, err)
	instances := doc["resource"].(model.Document)["aws_instance"].(model.Document)
	_, gone := instances["gone"]
	require.False(t, gone)
	_, kept := instances["kept"]
	require.True(t, kept)
}

func TestParser_JSONConfigAndTofuJSON(t *testing.T) {
	ctx := context.Background()
	parser := NewDefault()
	src := []byte(`{"resource":{"aws_s3_bucket":{"b":{"acl":"public-read"}}}}`)

	for _, name := range []string{"main.tf.json", "main.tofu.json"} {
		_, document, ignore, _, err := parser.Parse(ctx, src, name, true, 15)
		require.NoError(t, err, name)
		require.Empty(t, ignore, name)
		require.Len(t, document, 1, name)
		require.Contains(t, document[0]["resource"], "aws_s3_bucket", name)
	}
}

func TestParser_JSONConfigUsesIAMPolicyDocument(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "main.tf.json")
	src := []byte(`{
  "data": {
    "aws_iam_policy_document": {
      "doc": {
        "statement": [{
          "sid": "1",
          "actions": ["s3:GetObject"],
          "resources": ["arn:aws:s3:::example/*"]
        }]
      }
    }
  },
  "resource": {
    "aws_iam_policy": {
      "p": {
        "policy": "${data.aws_iam_policy_document.doc.json}"
      }
    }
  }
}`)
	require.NoError(t, os.WriteFile(main, src, 0o600))

	_, document, _, _, err := NewDefault().Parse(context.Background(), src, main, true, 15)
	require.NoError(t, err)
	policy := document[0]["resource"].(model.Document)["aws_iam_policy"].(model.Document)["p"].(model.Document)["policy"]
	require.Contains(t, stringifyValue(policy), "s3:GetObject")
	require.Contains(t, stringifyValue(policy), "arn:aws:s3:::example/*")
}

func TestParser_JSONConfigUsesSiblingVariableDefaults(t *testing.T) {
	dir := t.TempDir()
	vars := filepath.Join(dir, "variables.tf")
	main := filepath.Join(dir, "main.tf.json")
	require.NoError(t, os.WriteFile(vars, []byte(`
variable "acl" { default = "public-read" }
`), 0o600))
	src := []byte(`{"resource":{"aws_s3_bucket":{"b":{"acl":"${var.acl}"}}}}`)
	require.NoError(t, os.WriteFile(main, src, 0o600))

	_, document, _, _, err := NewDefault().Parse(context.Background(), src, main, true, 15)
	require.NoError(t, err)
	bucket := document[0]["resource"].(model.Document)["aws_s3_bucket"].(model.Document)["b"].(model.Document)
	require.Equal(t, "public-read", bucket["acl"].(ctyjson.SimpleJSONValue).AsString())
}

func TestParser_JSONConfigUsesSiblingJSONVariables(t *testing.T) {
	dir := t.TempDir()
	vars := filepath.Join(dir, "variables.tf.json")
	main := filepath.Join(dir, "main.tf.json")
	require.NoError(t, os.WriteFile(vars, []byte(`{"variable":{"acl":{"default":"public-read"}}}`), 0o600))
	src := []byte(`{"resource":{"aws_s3_bucket":{"b":{"acl":"${var.acl}"}}}}`)
	require.NoError(t, os.WriteFile(main, src, 0o600))

	_, document, _, _, err := NewDefault().Parse(context.Background(), src, main, true, 15)
	require.NoError(t, err)
	bucket := document[0]["resource"].(model.Document)["aws_s3_bucket"].(model.Document)["b"].(model.Document)
	require.Equal(t, "public-read", bucket["acl"].(ctyjson.SimpleJSONValue).AsString())
}

func TestParseJSONConfigKeepsKnownNestedSiblings(t *testing.T) {
	src := []byte(`{
  "resource": {
    "aws_s3_bucket": {
      "b": {
        "tags": {
          "Environment": "prod",
          "Name": "${var.missing}"
        }
      }
    }
  }
}`)
	doc, err := parseJSONConfig(src, "main.tf.json", nil)
	require.NoError(t, err)
	tags := doc["resource"].(model.Document)["aws_s3_bucket"].(model.Document)["b"].(model.Document)["tags"].(model.Document)
	require.Equal(t, "prod", tags["Environment"].(ctyjson.SimpleJSONValue).AsString())
	require.Equal(t, "${var.missing}", tags["Name"])
}

func TestParseJSONConfigWrapsUnresolvedExprFromValue(t *testing.T) {
	src := []byte(`{
  "resource": {
    "aws_s3_bucket": {
      "b": {
        "acl": "${var.missing}"
      }
    }
  }
}`)
	doc, err := parseJSONConfig(src, "main.tf.json", nil)
	require.NoError(t, err)
	bucket := doc["resource"].(model.Document)["aws_s3_bucket"].(model.Document)["b"].(model.Document)
	require.Equal(t, "${var.missing}", bucket["acl"])
}

func TestParseJSONConfigPreservesPartialTemplate(t *testing.T) {
	src := []byte(`{
  "resource": {
    "aws_s3_bucket": {
      "b": {
        "arn": "arn:aws:s3:::${var.missing}/*"
      }
    }
  }
}`)
	doc, err := parseJSONConfig(src, "main.tf.json", nil)
	require.NoError(t, err)
	bucket := doc["resource"].(model.Document)["aws_s3_bucket"].(model.Document)["b"].(model.Document)
	require.Equal(t, "arn:aws:s3:::${var.missing}/*", bucket["arn"])
}

func TestParser_JSONConfigDoesNotTreatResourcesAsVars(t *testing.T) {
	dir := t.TempDir()
	vars := filepath.Join(dir, "variables.tf.json")
	main := filepath.Join(dir, "main.tf.json")
	require.NoError(t, os.WriteFile(vars, []byte(`{"variable":{"resource":{"default":"from-var"}}}`), 0o600))
	src := []byte(`{"resource":{"aws_s3_bucket":{"b":{"bucket":"${var.resource}"}}}}`)
	require.NoError(t, os.WriteFile(main, src, 0o600))

	_, document, _, _, err := NewDefault().Parse(context.Background(), src, main, true, 15)
	require.NoError(t, err)
	bucket := document[0]["resource"].(model.Document)["aws_s3_bucket"].(model.Document)["b"].(model.Document)
	require.Equal(t, "from-var", bucket["bucket"].(ctyjson.SimpleJSONValue).AsString())
}

func TestParser_JSONLocalsResolveAcrossPasses(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "main.tf.json")
	src := []byte(`{
  "locals": {
    "b": "${local.a}",
    "a": "resolved"
  },
  "resource": {
    "aws_s3_bucket": {
      "b": { "bucket": "${local.b}" }
    }
  }
}`)
	require.NoError(t, os.WriteFile(main, src, 0o600))

	_, document, _, _, err := NewDefault().Parse(context.Background(), src, main, true, 15)
	require.NoError(t, err)
	bucket := document[0]["resource"].(model.Document)["aws_s3_bucket"].(model.Document)["b"].(model.Document)
	require.Equal(t, "resolved", bucket["bucket"].(ctyjson.SimpleJSONValue).AsString())
}

func TestParser_JSONTwinsKeepOwnVars(t *testing.T) {
	dir := t.TempDir()
	tfJSON := filepath.Join(dir, "main.tf.json")
	tofuJSON := filepath.Join(dir, "main.tofu.json")
	tfSrc := []byte(`{"variable":{"name":{"default":"from-tf"}},"resource":{"aws_s3_bucket":{"b":{"bucket":"${var.name}"}}}}`)
	tofuSrc := []byte(`{"variable":{"name":{"default":"from-tofu"}},"resource":{"aws_s3_bucket":{"b":{"bucket":"${var.name}"}}}}`)
	require.NoError(t, os.WriteFile(tfJSON, tfSrc, 0o600))
	require.NoError(t, os.WriteFile(tofuJSON, tofuSrc, 0o600))

	parser := NewDefault()
	parser.SetMergeAllow([]string{tfJSON, tofuJSON})

	_, tfDoc, _, _, err := parser.Parse(context.Background(), tfSrc, tfJSON, true, 15)
	require.NoError(t, err)
	tfBucket := fmtSprintBucket(tfDoc)
	require.Contains(t, tfBucket, "from-tf")
	require.NotContains(t, tfBucket, "from-tofu")

	_, tofuDoc, _, _, err := parser.Parse(context.Background(), tofuSrc, tofuJSON, true, 15)
	require.NoError(t, err)
	tofuBucket := fmtSprintBucket(tofuDoc)
	require.Contains(t, tofuBucket, "from-tofu")
	require.NotContains(t, tofuBucket, "from-tf")
}

func fmtSprintBucket(doc []model.Document) string {
	return stringifyValue(doc[0]["resource"].(model.Document)["aws_s3_bucket"].(model.Document)["b"].(model.Document)["bucket"])
}

func stringifyValue(v interface{}) string {
	switch t := v.(type) {
	case ctyjson.SimpleJSONValue:
		return t.AsString()
	case string:
		return t
	default:
		return ""
	}
}
