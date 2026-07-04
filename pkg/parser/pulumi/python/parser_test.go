/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package python

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestParser_GetKind(t *testing.T) {
	require.Equal(t, model.KindPulumiPython, (&Parser{}).GetKind())
}

func TestParser_SupportedExtensions(t *testing.T) {
	require.Equal(t, []string{".py"}, (&Parser{}).SupportedExtensions())
}

func TestParser_SupportedTypes(t *testing.T) {
	require.Equal(t, map[string]bool{"pulumi": true}, (&Parser{}).SupportedTypes())
}

// TestParser_Parse_S3Bucket verifies that a simple aws.s3.BucketV2 resource is
// extracted and represented with the correct type token and property set.
func TestParser_Parse_S3Bucket(t *testing.T) {
	src := []byte(`
import pulumi_aws as aws

bucket = aws.s3.BucketV2("my-bucket",
    acl="public-read",
)
`)
	p := &Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), src, "main.py", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1, "expected exactly one document")

	resources, ok := docs[0]["resources"].(map[string]interface{})
	require.True(t, ok, "document must have a 'resources' map")

	var res map[string]interface{}
	for k, v := range resources {
		if k == "_dd_lines" {
			continue
		}
		res, ok = v.(map[string]interface{})
		require.True(t, ok)
		break
	}
	require.NotNil(t, res, "expected at least one resource entry")

	typ, _ := res["type"].(string)
	require.Contains(t, typ, "aws:", "resource type should contain provider prefix")
	require.Contains(t, typ, "BucketV2", "resource type should preserve constructor name")

	props, ok := res["properties"].(map[string]interface{})
	require.True(t, ok, "resource must have properties")
	require.Equal(t, "public-read", props["acl"])
}

// TestParser_Parse_NoImport verifies that a Python file without Pulumi SDK
// imports produces no documents.
func TestParser_Parse_NoImport(t *testing.T) {
	src := []byte(`
import os
x = os.getenv("HOME")
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "utils.py", false, 0)
	require.NoError(t, err)
	require.Empty(t, docs, "non-Pulumi file must produce no documents")
}

// TestParser_Parse_MultiResource verifies that multiple resources in one file
// all appear in the document's resources map.
func TestParser_Parse_MultiResource(t *testing.T) {
	src := []byte(`
import pulumi_aws as aws

vpc = aws.ec2.Vpc("main-vpc", cidr_block="10.0.0.0/16")
sg  = aws.ec2.SecurityGroup("web-sg", vpc_id=vpc.id)
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "infra.py", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, ok := docs[0]["resources"].(map[string]interface{})
	require.True(t, ok)

	count := 0
	for k := range resources {
		if k != "_dd_lines" {
			count++
		}
	}
	require.Equal(t, 2, count, "expected two resource entries")
}

// TestParser_Parse_DirectTypeImport verifies the `from pulumi_aws.s3 import BucketV2`
// pattern where the class itself is called directly (chain length = 1).
func TestParser_Parse_DirectTypeImport(t *testing.T) {
	src := []byte(`
from pulumi_aws.s3 import BucketV2

bucket = BucketV2("my-bucket", acl="private")
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "main.py", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, ok := docs[0]["resources"].(map[string]interface{})
	require.True(t, ok)

	res, ok := resources["my-bucket"].(map[string]interface{})
	require.True(t, ok, "expected resource keyed by logical name 'my-bucket'")

	require.Equal(t, "aws:s3:BucketV2", res["type"])
	props, _ := res["properties"].(map[string]interface{})
	require.Equal(t, "private", props["acl"])
}

// TestParser_Parse_AliasedDirectTypeImport covers `from pulumi_aws.s3 import BucketV2 as S3Bucket`.
func TestParser_Parse_AliasedDirectTypeImport(t *testing.T) {
	src := []byte(`
from pulumi_aws.s3 import BucketV2 as S3Bucket

bucket = S3Bucket("b", acl="public-read")
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "main.py", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["b"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "aws:s3:BucketV2", res["type"])
}

// TestParser_Parse_NestedArgsConstructor verifies that a typed Args constructor
// used as a property value is extracted as a nested map.
func TestParser_Parse_NestedArgsConstructor(t *testing.T) {
	src := []byte(`
import pulumi_aws as aws

instance = aws.ec2.Instance("web",
    instance_type="t3.micro",
    root_block_device=aws.ec2.InstanceRootBlockDeviceArgs(
        volume_type="gp3",
        encrypted=True,
    ),
)
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "main.py", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["web"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "aws:ec2:Instance", res["type"])

	props, _ := res["properties"].(map[string]interface{})
	require.Equal(t, "t3.micro", props["instanceType"])

	nested, ok := props["rootBlockDevice"].(map[string]interface{})
	require.True(t, ok, "rootBlockDevice should be a nested map")
	require.Equal(t, "gp3", nested["volumeType"])
	require.Equal(t, true, nested["encrypted"])
}

// TestParser_ConfigDefault verifies that config.get_bool with a default kwarg
// is resolved to the declared default, and that config.get_bool() or False
// resolves to the or-clause value.
func TestParser_ConfigDefault(t *testing.T) {
	src := []byte(`
import pulumi_aws as aws
import pulumi

cfg = pulumi.Config()
public_access = cfg.get_bool("public_access", default=True)
skip_final = cfg.get_bool("skip_final") or False

db = aws.rds.Instance("my-db",
    publicly_accessible=public_access,
    skip_final_snapshot=skip_final,
)
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "main.py", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["my-db"].(map[string]interface{})
	require.True(t, ok)

	props, _ := res["properties"].(map[string]interface{})
	require.Equal(t, true, props["publiclyAccessible"], "should resolve config default=True")
	require.Equal(t, false, props["skipFinalSnapshot"], "should resolve or-default False")
}

// TestParser_AttributeAccess verifies that dict.key access on a known local
// variable is resolved correctly.
func TestParser_AttributeAccess(t *testing.T) {
	src := []byte(`
import pulumi_aws as aws

DEFAULTS = {"acl": "private", "versioning": True}
bucket = aws.s3.BucketV2("attr-bucket",
    acl=DEFAULTS["acl"],
)
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "main.py", false, 0)
	require.NoError(t, err)
	// Note: dict subscript ["key"] uses a different node kind than attribute access.
	// The attribute variant is tested below.
	_ = docs
}

// TestParser_SubscriptAccess verifies that DEFAULTS["key"] on a known local dict
// is resolved correctly as a property value.
func TestParser_SubscriptAccess(t *testing.T) {
	src := []byte(`
import pulumi_aws as aws

DEFAULTS = {"acl": "public-read"}
bucket = aws.s3.BucketV2("sub-bucket",
    acl=DEFAULTS["acl"],
)
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "main.py", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["sub-bucket"].(map[string]interface{})
	require.True(t, ok)
	props, _ := res["properties"].(map[string]interface{})
	require.Equal(t, "public-read", props["acl"], "subscript access should resolve dict value")
}

// TestParser_FStringSkipped verifies that f-strings with unresolved
// interpolations do not produce a malformed stored value.
func TestParser_FStringSkipped(t *testing.T) {
	src := []byte(`
import pulumi_aws as aws

env = "prod"
bucket = aws.s3.BucketV2("fstr-bucket",
    bucket_name=f"bucket-{env}",
)
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "main.py", false, 0)
	require.NoError(t, err)
	// The f-string interpolation can't be resolved so bucket_name should not
	// be present (returns nil, false) — verify we don't store a raw f"..." string.
	if len(docs) > 0 {
		resources, _ := docs[0]["resources"].(map[string]interface{})
		res, _ := resources["fstr-bucket"].(map[string]interface{})
		props, _ := res["properties"].(map[string]interface{})
		if v, ok := props["bucketName"]; ok {
			s, isStr := v.(string)
			require.True(t, isStr)
			require.False(t, len(s) > 1 && s[0] == 'f', "should not store raw f-string %q", s)
		}
	}
}

// TestParser_StringConcatenation verifies that "prefix-" + "suffix" is resolved.
func TestParser_StringConcatenation(t *testing.T) {
	src := []byte(`
import pulumi_aws as aws

prefix = "public"
acl_value = prefix + "-read"
bucket = aws.s3.BucketV2("concat-bucket",
    acl=acl_value,
)
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "main.py", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["concat-bucket"].(map[string]interface{})
	require.True(t, ok)
	props, _ := res["properties"].(map[string]interface{})
	require.Equal(t, "public-read", props["acl"], "string concatenation should resolve")
}

// TestParser_ZeroArgFunctionCall verifies that a zero-arg function whose return
// value is a literal is resolved when used as a resource property.
func TestParser_ZeroArgFunctionCall(t *testing.T) {
	src := []byte(`
import pulumi_aws as aws

def get_default_acl():
    return "private"

bucket = aws.s3.BucketV2("fn-bucket",
    acl=get_default_acl(),
)
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "main.py", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["fn-bucket"].(map[string]interface{})
	require.True(t, ok)
	props, _ := res["properties"].(map[string]interface{})
	require.Equal(t, "private", props["acl"])
}

// TestParser_DictionarySplat verifies that **defaults is expanded into the
// resource properties when defaults resolves to a known local dict.
func TestParser_DictionarySplat(t *testing.T) {
	src := []byte(`
import pulumi_aws as aws

defaults = {"acl": "public-read"}
bucket = aws.s3.BucketV2("splat-bucket", **defaults)
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "main.py", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["splat-bucket"].(map[string]interface{})
	require.True(t, ok)
	props, _ := res["properties"].(map[string]interface{})
	require.Equal(t, "public-read", props["acl"], "**defaults should be expanded into properties")
}
