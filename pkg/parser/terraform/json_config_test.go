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

func TestParseJSONConfigCountZeroLeftOut(t *testing.T) {
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
	require.NotContains(t, instances, "gone")
	require.Contains(t, instances, "kept")
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

// Values a .tf.json fallback cannot evaluate are listed in _dd_meta.unknown,
// an unknown count as count; meta-arguments and nulls are not in the body.
func TestParseJSONConfigUnknown(t *testing.T) {
	src := []byte(`{
  "resource": {
    "aws_s3_bucket": {
      "b": {
        "count": "${var.n}",
        "provider": "aws.west",
        "depends_on": ["aws_x.y"],
        "key": null,
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
	b := buckets["b"].(model.Document)
	for _, key := range []string{"count", "provider", "depends_on", "key"} {
		require.NotContains(t, b, key)
	}
	require.Equal(t, map[string]interface{}{
		"provider":   "aws.west",
		"configured": map[string]interface{}{"acl": true, "bucket": true, "rules": true, "tags": true},
		"unknown": map[string]interface{}{
			"count":  true,
			"bucket": true,
			"tags":   map[string]interface{}{"b": true},
			"rules":  []interface{}{false, true},
		},
	}, b["_dd_meta"])
	require.NotContains(t, buckets["k"].(model.Document)["_dd_meta"], "unknown")
	require.Equal(t, map[string]interface{}{"unknown": map[string]interface{}{"source": true}},
		doc["module"].(model.Document)["m"].(model.Document)["_dd_meta"])
}

func TestParseJSONConfigProviderIsAList(t *testing.T) {
	doc, err := parseJSONConfig([]byte(`{"provider": {"aws": {"region": "us-east-1"}}}`), "main.tf.json")
	require.NoError(t, err)
	require.Len(t, doc["provider"].(model.Document)["aws"], 1)
}

func TestParseJSONConfigOutputDependsOnIsHidden(t *testing.T) {
	doc, err := parseJSONConfig([]byte(`{
  "output": {
    "o": {
      "value": "x",
      "depends_on": ["aws_x.a"]
    }
  }
}`), "main.tf.json")
	require.NoError(t, err)
	o := doc["output"].(model.Document)["o"].(model.Document)
	require.NotContains(t, o, "depends_on")
	require.Contains(t, o, "value")
}
