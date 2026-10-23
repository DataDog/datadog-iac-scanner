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
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
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

func jsonBucket(layer model.Document, name string) model.Document {
	byType, _ := layer["resource"].(model.Document)["aws_s3_bucket"].(model.Document)
	bucket, _ := byType[name].(model.Document)
	return bucket
}

func TestParseJSONConfigExpandsCountAndForEachIntoDocuments(t *testing.T) {
	src := []byte(`{
  "variable": {"buckets": {"default": {"a": {"enc": false}, "b": {"enc": true}}}},
  "resource": {
    "aws_s3_bucket": {
      "fe": {
        "for_each": "${var.buckets}",
        "bucket": "${each.key}",
        "versioned": "${each.value.enc}"
      },
      "cnt": {"count": 2, "bucket": "b-${count.index}"},
      "same": {"count": 3, "bucket": "same"},
      "none": {"for_each": {}, "bucket": "x"},
      "zero": {"count": 0, "bucket": "x"}
    }
  }
}`)
	vars := converter.VariableMap{"var": cty.ObjectVal(map[string]cty.Value{
		"buckets": cty.ObjectVal(map[string]cty.Value{
			"a": cty.ObjectVal(map[string]cty.Value{"enc": cty.False}),
			"b": cty.ObjectVal(map[string]cty.Value{"enc": cty.True}),
		}),
	})}
	layers, err := parseJSONConfigLayers(src, "main.tf.json", vars)
	require.NoError(t, err)
	require.Len(t, layers, 2)

	require.Equal(t, "a", jsonBucket(layers[0], "fe")["bucket"].(ctyjson.SimpleJSONValue).AsString())
	require.Equal(t, "b", jsonBucket(layers[1], "fe")["bucket"].(ctyjson.SimpleJSONValue).AsString())
	require.False(t, jsonBucket(layers[0], "fe")["versioned"].(ctyjson.SimpleJSONValue).True())
	require.True(t, jsonBucket(layers[1], "fe")["versioned"].(ctyjson.SimpleJSONValue).True())
	require.Equal(t, "b-0", jsonBucket(layers[0], "cnt")["bucket"].(ctyjson.SimpleJSONValue).AsString())
	require.Equal(t, "b-1", jsonBucket(layers[1], "cnt")["bucket"].(ctyjson.SimpleJSONValue).AsString())

	require.NotNil(t, jsonBucket(layers[0], "same"))
	require.Equal(t, jsonBucket(layers[0], "same"), jsonBucket(layers[1], "same"),
		"instances that read the same are one instance, in every document")
	for _, name := range []string{"none", "zero"} {
		require.Nil(t, jsonBucket(layers[0], name), name)
		require.Nil(t, jsonBucket(layers[1], name), name)
	}
}

func TestParser_ParseReturnsOneDocumentPerExpandedInstance(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "main.tf")
	src := []byte(`
resource "aws_s3_bucket" "b" {
  count  = 2
  bucket = "b-${count.index}"
}
`)
	require.NoError(t, os.WriteFile(main, src, 0o600))
	_, documents, _, _, err := NewDefault().Parse(context.Background(), src, main, true, 15)
	require.NoError(t, err)
	require.Len(t, documents, 2)
	for i, document := range documents {
		bucket := document["resource"].(model.Document)["aws_s3_bucket"].(model.Document)["b"].(model.Document)
		require.Equal(t, fmt.Sprintf("b-%d", i), bucket["bucket"])
	}
}

func parseJSONConfig(src []byte, filename string, inputVars converter.VariableMap) (model.Document, error) {
	layers, err := parseJSONConfigLayers(src, filename, inputVars)
	if err != nil || len(layers) == 0 {
		return nil, err
	}
	return layers[0], nil
}

func TestParseJSONConfigExpandsDynamicBlocks(t *testing.T) {
	src := []byte(`{
  "resource": {
    "aws_security_group": {
      "sg": {
        "name": "sg",
        "ingress": {"from_port": 22},
        "dynamic": {
          "ingress": {
            "for_each": ["80", "443"],
            "content": {"from_port": "${ingress.value}"}
          }
        }
      },
      "unresolved": {
        "dynamic": {
          "ingress": {
            "for_each": "${var.ports}",
            "content": {"from_port": "${ingress.value}"}
          }
        }
      }
    }
  }
}`)
	doc, err := parseJSONConfig(src, "main.tf.json", nil)
	require.NoError(t, err)

	groups := doc["resource"].(model.Document)["aws_security_group"].(model.Document)
	sg := groups["sg"].(model.Document)
	require.NotContains(t, sg, "dynamic")
	ingress := sg["ingress"].([]interface{})
	require.Len(t, ingress, 3)
	require.Equal(t, "443", fmt.Sprint(ingress[2].(model.Document)["from_port"].(ctyjson.SimpleJSONValue).AsString()))

	require.Contains(t, groups["unresolved"].(model.Document), "dynamic")
}

func TestParseJSONConfigExpandsModuleCalls(t *testing.T) {
	src := []byte(`{
  "module": {
    "m": {"for_each": {"a": "x", "b": "y"}, "source": "./mods/${each.key}"}
  }
}`)
	docs, err := parseJSONConfigLayers(src, "main.tf.json", nil)
	require.NoError(t, err)
	require.Len(t, docs, 2)
}
