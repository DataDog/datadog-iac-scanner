/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package javascript_test

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi/javascript"
)

func TestJavaScriptParser_RequireImport(t *testing.T) {
	src := []byte(`
const aws = require("@pulumi/aws");
const bucket = new aws.s3.BucketV2("my-bucket", {
    acl: "public-read",
});
`)
	p := &javascript.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), src, "index.js", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("expected 1 document, got %d", len(docs))
	}

	resources, ok := docs[0]["resources"].(map[string]interface{})
	if !ok {
		t.Fatal("expected resources map")
	}
	res, ok := resources["my-bucket"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected my-bucket resource, got keys: %v", resourceKeys(resources))
	}
	typ, _ := res["type"].(string)
	if typ != "aws:s3:BucketV2" {
		t.Errorf("unexpected type: %v", typ)
	}
}

func TestJavaScriptParser_ESMImport(t *testing.T) {
	src := []byte(`
import * as aws from "@pulumi/aws";
const bucket = new aws.s3.BucketV2("esm-bucket", {
    acl: "private",
});
`)
	p := &javascript.Parser{}
	_, docs, _, _, err := p.Parse(context.Background(), src, "index.js", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("expected 1 document, got %d", len(docs))
	}
}

func resourceKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
