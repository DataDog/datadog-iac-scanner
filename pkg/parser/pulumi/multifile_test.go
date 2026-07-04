/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package pulumi_test

import (
	"context"
	"testing"

	pulumi "github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi"
	pulumiGo "github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi/golang"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi/javascript"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi/projectindex"
	pulumiPy "github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi/python"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi/typescript"
)

// ── TypeScript ────────────────────────────────────────────────────────────────

// TestMultiFile_TS_NamedImport verifies that a named export from a sibling .ts
// file is resolved and injected as a resource property.
func TestMultiFile_TS_NamedImport(t *testing.T) {
	configSrc := []byte(`
export const defaultAcl = "public-read";
export const skipFinalSnapshot = false;
`)

	mainSrc := []byte(`
import * as aws from "@pulumi/aws";
import { defaultAcl, skipFinalSnapshot } from "./config";

const bucket = new aws.s3.BucketV2("my-bucket", {
    acl: defaultAcl,
});
`)

	cache := map[string][]byte{
		"/repo/config.ts": configSrc,
		"/repo/index.ts":  mainSrc,
	}
	idx := projectindex.Build([]string{"/repo/config.ts", "/repo/index.ts"}, cache)
	ctx := pulumi.WithProjectIndex(context.Background(), idx)

	_, docs, _, _, err := (&typescript.Parser{}).Parse(ctx, mainSrc, "/repo/index.ts", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("expected at least one document")
	}

	resources := resourcesMap(t, docs[0])
	res := resourceEntry(t, resources, "my-bucket")
	props := propsMap(t, res)
	assertProp(t, props, "acl", "public-read")
}

// TestMultiFile_TS_NamespaceImport verifies that a namespace import resolves
// member expressions like cfg.defaultAcl.
func TestMultiFile_TS_NamespaceImport(t *testing.T) {
	configSrc := []byte(`
export const defaultAcl = "private";
`)
	mainSrc := []byte(`
import * as aws from "@pulumi/aws";
import * as cfg from "./config";

const bucket = new aws.s3.BucketV2("ns-bucket", {
    acl: cfg.defaultAcl,
});
`)

	cache := map[string][]byte{
		"/repo/config.ts":  configSrc,
		"/repo/index2.ts":  mainSrc,
	}
	idx := projectindex.Build([]string{"/repo/config.ts", "/repo/index2.ts"}, cache)
	ctx := pulumi.WithProjectIndex(context.Background(), idx)

	_, docs, _, _, err := (&typescript.Parser{}).Parse(ctx, mainSrc, "/repo/index2.ts", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("expected at least one document")
	}
	resources := resourcesMap(t, docs[0])
	res := resourceEntry(t, resources, "ns-bucket")
	props := propsMap(t, res)
	assertProp(t, props, "acl", "private")
}

// TestMultiFile_TS_Spread verifies that spreading a namespace import merges all
// exported values into the resource properties.
func TestMultiFile_TS_Spread(t *testing.T) {
	configSrc := []byte(`
export const defaults = { acl: "public-read", region: "us-east-1" };
`)
	mainSrc := []byte(`
import * as aws from "@pulumi/aws";
import { defaults } from "./config";

const bucket = new aws.s3.BucketV2("spread-bucket", { ...defaults });
`)

	cache := map[string][]byte{
		"/repo/config.ts":  configSrc,
		"/repo/spread.ts":  mainSrc,
	}
	idx := projectindex.Build([]string{"/repo/config.ts", "/repo/spread.ts"}, cache)
	ctx := pulumi.WithProjectIndex(context.Background(), idx)

	_, docs, _, _, err := (&typescript.Parser{}).Parse(ctx, mainSrc, "/repo/spread.ts", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("expected at least one document")
	}
	resources := resourcesMap(t, docs[0])
	res := resourceEntry(t, resources, "spread-bucket")
	props := propsMap(t, res)
	assertProp(t, props, "acl", "public-read")
}

// TestMultiFile_JS_Require verifies CommonJS require of a local module.
func TestMultiFile_JS_Require(t *testing.T) {
	configSrc := []byte(`
module.exports = {
    acl: "private",
};
`)
	mainSrc := []byte(`
const aws = require("@pulumi/aws");
const cfg = require("./config");

const bucket = new aws.s3.BucketV2("js-bucket", {
    acl: cfg.acl,
});
`)

	cache := map[string][]byte{
		"/repo/config.js": configSrc,
		"/repo/index.js":  mainSrc,
	}
	idx := projectindex.Build([]string{"/repo/config.js", "/repo/index.js"}, cache)
	ctx := pulumi.WithProjectIndex(context.Background(), idx)

	_, docs, _, _, err := (&javascript.Parser{}).Parse(ctx, mainSrc, "/repo/index.js", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("expected at least one document")
	}
	resources := resourcesMap(t, docs[0])
	res := resourceEntry(t, resources, "js-bucket")
	props := propsMap(t, res)
	assertProp(t, props, "acl", "private")
}

// ── Python ────────────────────────────────────────────────────────────────────

func TestMultiFile_Python_FromImport(t *testing.T) {
	configSrc := []byte(`
DEFAULT_ACL = "public-read"
SKIP_FINAL = True
`)
	mainSrc := []byte(`
import pulumi_aws as aws
from config import DEFAULT_ACL, SKIP_FINAL

bucket = aws.s3.BucketV2("py-bucket",
    acl=DEFAULT_ACL,
    skip_final_snapshot=SKIP_FINAL,
)
`)

	cache := map[string][]byte{
		"/repo/config.py": configSrc,
		"/repo/main.py":   mainSrc,
	}
	idx := projectindex.Build([]string{"/repo/config.py", "/repo/main.py"}, cache)
	ctx := pulumi.WithProjectIndex(context.Background(), idx)

	_, docs, _, _, err := (&pulumiPy.Parser{}).Parse(ctx, mainSrc, "/repo/main.py", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("expected at least one document")
	}
	resources := resourcesMap(t, docs[0])
	res := resourceEntry(t, resources, "py-bucket")
	props := propsMap(t, res)
	assertProp(t, props, "acl", "public-read")
	assertProp(t, props, "skipFinalSnapshot", true)
}

// ── Go ────────────────────────────────────────────────────────────────────────

func TestMultiFile_Go_SiblingConst(t *testing.T) {
	configSrc := []byte(`package main

const defaultACL = "public-read"
`)
	mainSrc := []byte(`package main

import (
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := s3.NewBucketV2(ctx, "go-bucket", &s3.BucketV2Args{
			Acl: pulumi.String(defaultACL),
		})
		return err
	})
}
`)

	cache := map[string][]byte{
		"/repo/config.go": configSrc,
		"/repo/main.go":   mainSrc,
	}
	idx := projectindex.Build([]string{"/repo/config.go", "/repo/main.go"}, cache)
	ctx := pulumi.WithProjectIndex(context.Background(), idx)

	_, docs, _, _, err := (&pulumiGo.Parser{}).Parse(ctx, mainSrc, "/repo/main.go", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("expected at least one document")
	}
	resources := resourcesMap(t, docs[0])
	res := resourceEntry(t, resources, "go-bucket")
	props := propsMap(t, res)
	assertProp(t, props, "acl", "public-read")
}

// TestMultiFile_Go_IdentifierLogicalName verifies that logical names that are
// identifiers resolved via pkgSyms (cross-file constants) work correctly.
func TestMultiFile_Go_IdentifierLogicalName(t *testing.T) {
	configSrc := []byte(`package main

const bucketName = "named-bucket"
`)
	mainSrc := []byte(`package main

import (
	s3 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := s3.NewBucketV2(ctx, bucketName, &s3.BucketV2Args{
			Acl: pulumi.String("private"),
		})
		return err
	})
}
`)

	cache := map[string][]byte{
		"/repo/config.go": configSrc,
		"/repo/main.go":   mainSrc,
	}
	idx := projectindex.Build([]string{"/repo/config.go", "/repo/main.go"}, cache)
	ctx := pulumi.WithProjectIndex(context.Background(), idx)

	_, docs, _, _, err := (&pulumiGo.Parser{}).Parse(ctx, mainSrc, "/repo/main.go", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("expected at least one document")
	}
	resources := resourcesMap(t, docs[0])
	res := resourceEntry(t, resources, "named-bucket")
	props := propsMap(t, res)
	assertProp(t, props, "acl", "private")
}

// TestMultiFile_Go_Arg2Identifier verifies that when arg[2] of a constructor is
// a package-level variable identifier, its properties are resolved via pkgSyms.
func TestMultiFile_Go_Arg2Identifier(t *testing.T) {
	configSrc := []byte(`package main

import (
	s3 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

var defaultBucketArgs = s3.BucketV2Args{
	Acl: pulumi.String("public-read"),
}
`)
	mainSrc := []byte(`package main

import (
	s3 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := s3.NewBucketV2(ctx, "arg2-bucket", &defaultBucketArgs)
		return err
	})
}
`)
	cache := map[string][]byte{
		"/repo/config.go": configSrc,
		"/repo/main.go":   mainSrc,
	}
	idx := projectindex.Build([]string{"/repo/config.go", "/repo/main.go"}, cache)
	ctx := pulumi.WithProjectIndex(context.Background(), idx)

	_, docs, _, _, err := (&pulumiGo.Parser{}).Parse(ctx, mainSrc, "/repo/main.go", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("expected at least one document")
	}
	resources := resourcesMap(t, docs[0])
	res := resourceEntry(t, resources, "arg2-bucket")
	props := propsMap(t, res)
	assertProp(t, props, "acl", "public-read")
}

// TestMultiFile_Go_StringConcat verifies that "a" + "b" property values are resolved.
func TestMultiFile_Go_StringConcat(t *testing.T) {
	src := []byte(`package main

import (
	s3 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := s3.NewBucketV2(ctx, "concat-bucket", &s3.BucketV2Args{
			Acl: pulumi.String("public" + "-read"),
		})
		return err
	})
}
`)
	_, docs, _, _, err := (&pulumiGo.Parser{}).Parse(context.Background(), src, "/repo/main.go", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("expected at least one document")
	}
	resources := resourcesMap(t, docs[0])
	res := resourceEntry(t, resources, "concat-bucket")
	props := propsMap(t, res)
	assertProp(t, props, "acl", "public-read")
}

// TestMultiFile_Go_MultiResultHelper verifies that a package-level var holding
// a composite literal is indexed and resolved as arg[2] via pkgSyms.
func TestMultiFile_Go_MultiResultHelper(t *testing.T) {
	helperSrc := []byte(`package main

import (
	s3 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

var defaultBucketArgs = &s3.BucketV2Args{Acl: pulumi.String("public-read")}
`)
	mainSrc := []byte(`package main

import (
	s3 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := s3.NewBucketV2(ctx, "helper-bucket", defaultBucketArgs)
		return err
	})
}
`)
	cache := map[string][]byte{
		"/repo/helpers.go": helperSrc,
		"/repo/main.go":    mainSrc,
	}
	idx := projectindex.Build([]string{"/repo/helpers.go", "/repo/main.go"}, cache)
	ctx := pulumi.WithProjectIndex(context.Background(), idx)

	_, docs, _, _, err := (&pulumiGo.Parser{}).Parse(ctx, mainSrc, "/repo/main.go", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("expected at least one document")
	}
	resources := resourcesMap(t, docs[0])
	res := resourceEntry(t, resources, "helper-bucket")
	props := propsMap(t, res)
	assertProp(t, props, "acl", "public-read")
}

// TestMultiFile_Go_ZeroArgFunctionCall verifies that a zero-arg helper function
// exported from a sibling file is resolved when called as a property value.
func TestMultiFile_Go_ZeroArgFunctionCall(t *testing.T) {
	helperSrc := []byte(`package main

func getDefaultRegion() string {
	return "us-east-1"
}
`)
	mainSrc := []byte(`package main

import (
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		_, err := s3.NewBucketV2(ctx, "fn-bucket", &s3.BucketV2Args{
			Region: pulumi.String(getDefaultRegion()),
		})
		return err
	})
}
`)

	cache := map[string][]byte{
		"/repo/helper.go": helperSrc,
		"/repo/main.go":   mainSrc,
	}
	idx := projectindex.Build([]string{"/repo/helper.go", "/repo/main.go"}, cache)
	ctx := pulumi.WithProjectIndex(context.Background(), idx)

	_, docs, _, _, err := (&pulumiGo.Parser{}).Parse(ctx, mainSrc, "/repo/main.go", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("expected at least one document")
	}
	resources := resourcesMap(t, docs[0])
	res := resourceEntry(t, resources, "fn-bucket")
	props := propsMap(t, res)
	assertProp(t, props, "region", "us-east-1")
}

// TestMultiFile_NoContext verifies that parsers still work when no ProjectIndex
// is attached to the context (backward compatibility).
func TestMultiFile_NoContext(t *testing.T) {
	src := []byte(`
import * as aws from "@pulumi/aws";
const bucket = new aws.s3.BucketV2("no-ctx-bucket", { acl: "private" });
`)
	_, docs, _, _, err := (&typescript.Parser{}).Parse(context.Background(), src, "/repo/index.ts", false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(docs) == 0 {
		t.Fatal("expected document even without context")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func resourcesMap(t *testing.T, doc map[string]interface{}) map[string]interface{} {
	t.Helper()
	m, ok := doc["resources"].(map[string]interface{})
	if !ok {
		t.Fatalf("document has no resources map; doc keys: %v", mapKeys(doc))
	}
	return m
}

func resourceEntry(t *testing.T, resources map[string]interface{}, name string) map[string]interface{} {
	t.Helper()
	v, ok := resources[name]
	if !ok {
		t.Fatalf("resource %q not found; available: %v", name, mapKeys(resources))
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		t.Fatalf("resource %q is not a map", name)
	}
	return m
}

func propsMap(t *testing.T, res map[string]interface{}) map[string]interface{} {
	t.Helper()
	m, ok := res["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("resource has no properties map")
	}
	return m
}

func assertProp(t *testing.T, props map[string]interface{}, key string, want interface{}) {
	t.Helper()
	got, ok := props[key]
	if !ok {
		t.Errorf("property %q not found; available: %v", key, mapKeys(props))
		return
	}
	if got != want {
		t.Errorf("property %q: got %v (%T), want %v (%T)", key, got, got, want, want)
	}
}

func mapKeys(m map[string]interface{}) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
