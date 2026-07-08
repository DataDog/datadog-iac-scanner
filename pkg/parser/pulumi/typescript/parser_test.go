/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package typescript

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestParser_GetKind(t *testing.T) {
	require.Equal(t, model.KindPulumiTypeScript, (&Parser{}).GetKind())
}

func TestParser_SupportedExtensions(t *testing.T) {
	require.Equal(t, []string{".ts"}, (&Parser{}).SupportedExtensions())
}

func TestParser_SupportedTypes(t *testing.T) {
	require.Equal(t, map[string]bool{"pulumi": true}, (&Parser{}).SupportedTypes())
}

// TestParser_Parse_S3Bucket verifies that a new aws.s3.BucketV2 call is
// extracted and represented with the correct type token and properties.
func TestParser_Parse_S3Bucket(t *testing.T) {
	src := []byte(`
import * as aws from "@pulumi/aws";

const bucket = new aws.s3.BucketV2("my-bucket", {
    acl: "public-read",
});
`)
	p := &Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), src, "index.ts", false, 0)
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

// TestParser_Parse_NoImport verifies that a TypeScript file without Pulumi SDK
// imports produces no documents.
func TestParser_Parse_NoImport(t *testing.T) {
	src := []byte(`
import * as fs from "fs";
const data = fs.readFileSync("file.txt");
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "util.ts", false, 0)
	require.NoError(t, err)
	require.Empty(t, docs, "non-Pulumi file must produce no documents")
}

// TestParser_Parse_MultiResource verifies that multiple new Resource() calls
// in a single file all appear in the extracted document.
func TestParser_Parse_MultiResource(t *testing.T) {
	src := []byte(`
import * as aws from "@pulumi/aws";

const vpc = new aws.ec2.Vpc("main-vpc", { cidrBlock: "10.0.0.0/16" });
const sg  = new aws.ec2.SecurityGroup("web-sg", { vpcId: vpc.id });
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "infra.ts", false, 0)
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

// TestParser_Parse_RequireImport verifies CommonJS require() style imports.
func TestParser_Parse_RequireImport(t *testing.T) {
	src := []byte(`
const aws = require("@pulumi/aws");
const bucket = new aws.s3.BucketV2("my-bucket", { acl: "private" });
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "index.ts", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["my-bucket"].(map[string]interface{})
	require.True(t, ok, "expected resource keyed by 'my-bucket'")
	require.Equal(t, "aws:s3:BucketV2", res["type"])
}

// TestParser_Parse_RequireDestructure verifies `const { s3 } = require("@pulumi/aws")`.
func TestParser_Parse_RequireDestructure(t *testing.T) {
	src := []byte(`
const { s3 } = require("@pulumi/aws");
const bucket = new s3.BucketV2("b", { acl: "public-read" });
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "index.ts", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["b"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "aws:s3:BucketV2", res["type"])
}

// TestParser_Parse_SpreadProps verifies that spread elements resolved from local
// vars contribute their properties to the resource.
func TestParser_Parse_SpreadProps(t *testing.T) {
	src := []byte(`
import * as aws from "@pulumi/aws";
const defaults = { acl: "private" };
const bucket = new aws.s3.BucketV2("b", { ...defaults, versioning: true });
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "index.ts", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["b"].(map[string]interface{})
	require.True(t, ok)
	props, _ := res["properties"].(map[string]interface{})
	require.Equal(t, "private", props["acl"], "spread property should be present")
	require.Equal(t, true, props["versioning"], "explicit property should still be present")
}

// TestParser_ConfigDefault verifies that config.getBoolean() ?? false and
// config.get() are resolved to their nullish-coalescing defaults.
func TestParser_ConfigDefault(t *testing.T) {
	src := []byte(`
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
const config = new pulumi.Config();
const publicAccess = config.getBoolean("publicAccess") ?? true;
const region = config.get("region") ?? "us-east-1";
const db = new aws.rds.Instance("my-db", {
    publiclyAccessible: publicAccess,
    availabilityZone: region,
});
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "index.ts", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["my-db"].(map[string]interface{})
	require.True(t, ok)
	props, _ := res["properties"].(map[string]interface{})
	require.Equal(t, true, props["publiclyAccessible"], "should resolve ?? true")
	require.Equal(t, "us-east-1", props["availabilityZone"], "should resolve ?? string default")
}

// TestParser_AsTypeAssertion verifies that TypeScript `as` type assertions on
// the logical name, property values, and the whole args object are unwrapped.
func TestParser_AsTypeAssertion(t *testing.T) {
	src := []byte(`
import * as aws from "@pulumi/aws";

const acl = "private" as string;
const bucket = new aws.s3.BucketV2("as-bucket" as string, {
    acl: "public-read" as aws.s3.CannedAcl,
});
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "index.ts", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["as-bucket"].(map[string]interface{})
	require.True(t, ok, "resource should be found by unwrapped name")
	props, _ := res["properties"].(map[string]interface{})
	require.Equal(t, "public-read", props["acl"], "property value should be unwrapped from as-expression")
}

// TestParser_AsTypeAssertionArgsObject verifies that a whole args object wrapped
// in `as` is correctly unwrapped and its properties are extracted.
func TestParser_AsTypeAssertionArgsObject(t *testing.T) {
	src := []byte(`
import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";

const bucket = new aws.s3.BucketV2("b2", { acl: "private" } as pulumi.Inputs);
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "index.ts", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["b2"].(map[string]interface{})
	require.True(t, ok)
	props, _ := res["properties"].(map[string]interface{})
	require.Equal(t, "private", props["acl"])
}

// TestParser_TypeAssertionPrefix verifies that the older <Type>expr prefix
// assertion is correctly unwrapped so the inner value is used.
func TestParser_TypeAssertionPrefix(t *testing.T) {
	src := []byte(`
import * as aws from "@pulumi/aws";

const bucket = new aws.s3.BucketV2(<string>"type-assert-bucket", {
    acl: <string>"public-read",
});
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "index.ts", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["type-assert-bucket"].(map[string]interface{})
	require.True(t, ok, "resource should be found with unwrapped name")
	props, _ := res["properties"].(map[string]interface{})
	require.Equal(t, "public-read", props["acl"])
}

// TestParser_ZeroArgFunctionCall verifies that a zero-arg function whose return
// value is a literal is resolved when used as a resource property.
func TestParser_ZeroArgFunctionCall(t *testing.T) {
	src := []byte(`
import * as aws from "@pulumi/aws";

function getDefaultAcl() {
    return "private";
}

const bucket = new aws.s3.BucketV2("fn-bucket", {
    acl: getDefaultAcl(),
});
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "index.ts", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["fn-bucket"].(map[string]interface{})
	require.True(t, ok)
	props, _ := res["properties"].(map[string]interface{})
	require.Equal(t, "private", props["acl"])
}

// TestParser_ZeroArgArrowCall verifies that a zero-arg arrow function constant
// is resolved when called as a resource property value.
func TestParser_ZeroArgArrowCall(t *testing.T) {
	src := []byte(`
import * as aws from "@pulumi/aws";

const getRegion = () => "us-east-1";

const bucket = new aws.s3.BucketV2("arrow-bucket", {
    region: getRegion(),
});
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "index.ts", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["arrow-bucket"].(map[string]interface{})
	require.True(t, ok)
	props, _ := res["properties"].(map[string]interface{})
	require.Equal(t, "us-east-1", props["region"])
}

// TestParser_ArgsIdentifierVariable verifies that an identifier resolving to a
// local object variable is expanded as the resource's properties.
func TestParser_ArgsIdentifierVariable(t *testing.T) {
	src := []byte(`
import * as aws from "@pulumi/aws";

const bucketArgs = { acl: "public-read", versioning: true };
const bucket = new aws.s3.BucketV2("id-bucket", bucketArgs);
`)
	_, docs, _, _, err := (&Parser{}).Parse(context.Background(), src, "index.ts", false, 0)
	require.NoError(t, err)
	require.Len(t, docs, 1)

	resources, _ := docs[0]["resources"].(map[string]interface{})
	res, ok := resources["id-bucket"].(map[string]interface{})
	require.True(t, ok)
	props, _ := res["properties"].(map[string]interface{})
	require.Equal(t, "public-read", props["acl"])
}
