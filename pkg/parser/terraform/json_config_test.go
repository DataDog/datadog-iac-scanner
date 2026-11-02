/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
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
	doc, err := parseJSONConfig(src, "main.tf.json")
	require.NoError(t, err)

	bucket := doc["resource"].(model.Document)["aws_s3_bucket"].(model.Document)["b"].(model.Document)
	require.Equal(t, "public-read", bucket["acl"].(ctyjson.SimpleJSONValue).AsString())
	require.Equal(t, "S3B_541", bucket["bucket"].(ctyjson.SimpleJSONValue).AsString())
	require.Equal(t, true, bucket["versioning"].(model.Document)["enabled"].(ctyjson.SimpleJSONValue).True())

	lines := bucket["_dd_lines"].(map[string]model.LineObject)
	require.Equal(t, 6, lines["_dd_acl"].Line)
}

func TestParseJSONConfigCountZeroKept(t *testing.T) {
	src := []byte(`{
  "resource": {
    "aws_instance": {
      "gone": { "count": 0, "ami": "ami-123" },
      "kept": { "ami": "ami-123" }
    }
  }
}`)
	doc, err := parseJSONConfig(src, "main.tf.json")
	require.NoError(t, err)
	instances := doc["resource"].(model.Document)["aws_instance"].(model.Document)
	gone, ok := instances["gone"].(model.Document)
	require.True(t, ok)
	require.True(t, gone["count"].(ctyjson.SimpleJSONValue).Equals(cty.NumberIntVal(0)).True())
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
	doc, err := parseJSONConfig(src, "main.tf.json")
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
	doc, err := parseJSONConfig(src, "main.tf.json")
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
	doc, err := parseJSONConfig(src, "main.tf.json")
	require.NoError(t, err)
	bucket := doc["resource"].(model.Document)["aws_s3_bucket"].(model.Document)["b"].(model.Document)
	require.Equal(t, "arn:aws:s3:::${var.missing}/*", bucket["arn"])
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

// Values a .tf.json fallback cannot evaluate are listed in _dd_meta.unknown;
// meta-arguments never are.
func TestParseJSONConfigUnknown(t *testing.T) {
	src := []byte(`{
  "resource": {
    "aws_s3_bucket": {
      "b": {
        "count": "${var.n}",
        "bucket": "${var.x}",
        "acl": "private",
        "tags": { "a": "a", "b": "${var.b}" },
        "rules": ["r", "${var.r}"]
      },
      "k": { "acl": "private" }
    }
  },
  "module": { "m": { "source": "${var.s}" } }
}`)
	doc, err := parseJSONConfig(src, "main.tf.json")
	require.NoError(t, err)
	buckets := doc["resource"].(model.Document)["aws_s3_bucket"].(model.Document)
	require.Equal(t, map[string]interface{}{"unknown": map[string]interface{}{
		"bucket": true,
		"tags":   map[string]interface{}{"b": true},
		"rules":  []interface{}{false, true},
	}}, buckets["b"].(model.Document)["_dd_meta"])
	require.NotContains(t, buckets["k"], "_dd_meta")
	require.NotContains(t, doc["module"].(model.Document)["m"], "_dd_meta")
}
