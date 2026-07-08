/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package projectindex_test

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/pulumi/projectindex"
)

func TestBuild_TypeScript(t *testing.T) {
	src := []byte(`
export const defaultAcl = "public-read";
export const skipFinal = false;
export const count = 3;
export const tags = { env: "prod", team: "infra" };
export function getRegion() { return "us-east-1"; }
`)
	paths := []string{"/repo/config.ts"}
	cache := map[string][]byte{"/repo/config.ts": src}

	idx := projectindex.Build(paths, cache)
	if idx == nil {
		t.Fatal("expected non-nil index")
	}
	syms := idx.Lookup("/repo/config.ts")
	if syms == nil {
		t.Fatal("expected symbols for config.ts")
	}

	assertVal(t, syms.Values, "defaultAcl", "public-read")
	assertVal(t, syms.Values, "skipFinal", false)
	assertVal(t, syms.Values, "count", float64(3))
	assertVal(t, syms.Values, "getRegion", "us-east-1")

	tags, ok := syms.Values["tags"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected tags to be a map, got %T", syms.Values["tags"])
	}
	assertVal(t, tags, "env", "prod")
}

func TestBuild_JavaScript_ModuleExports(t *testing.T) {
	src := []byte(`
module.exports = {
  acl: "private",
  region: "eu-west-1",
};
module.exports.extra = "value";
`)
	paths := []string{"/repo/config.js"}
	cache := map[string][]byte{"/repo/config.js": src}

	idx := projectindex.Build(paths, cache)
	syms := idx.Lookup("/repo/config.js")
	if syms == nil {
		t.Fatal("expected symbols for config.js")
	}
	assertVal(t, syms.Values, "acl", "private")
	assertVal(t, syms.Values, "region", "eu-west-1")
	assertVal(t, syms.Values, "extra", "value")
}

func TestBuild_Python(t *testing.T) {
	src := []byte(`
DEFAULT_ACL = "private"
SKIP_FINAL = True
TAGS = {"env": "prod"}

def get_region():
    return "ap-southeast-1"
`)
	paths := []string{"/repo/config.py"}
	cache := map[string][]byte{"/repo/config.py": src}

	idx := projectindex.Build(paths, cache)
	syms := idx.Lookup("/repo/config.py")
	if syms == nil {
		t.Fatal("expected symbols for config.py")
	}
	assertVal(t, syms.Values, "DEFAULT_ACL", "private")
	assertVal(t, syms.Values, "SKIP_FINAL", true)
	assertVal(t, syms.Values, "get_region", "ap-southeast-1")
}

func TestBuild_Go(t *testing.T) {
	src := []byte(`
package main

const defaultACL = "private"
var skipFinal = false

func getRegion() string { return "us-east-1" }
`)
	paths := []string{"/repo/main.go"}
	cache := map[string][]byte{"/repo/main.go": src}

	idx := projectindex.Build(paths, cache)
	syms := idx.Lookup("/repo/main.go")
	if syms == nil {
		t.Fatal("expected symbols for main.go")
	}
	assertVal(t, syms.Values, "defaultACL", "private")
	assertVal(t, syms.Values, "skipFinal", false)
	assertVal(t, syms.Values, "getRegion", "us-east-1")
}

func TestBuild_Go_HelperFunctionMultiStatement(t *testing.T) {
	src := []byte(`package main

import (
	"fmt"
	s3 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func defaultBucketArgs() *s3.BucketV2Args {
	fmt.Println("building args") // non-return statement
	return &s3.BucketV2Args{Acl: pulumi.String("public-read")}
}
`)
	paths := []string{"/repo/helpers.go"}
	cache := map[string][]byte{"/repo/helpers.go": src}

	idx := projectindex.Build(paths, cache)
	syms := idx.Lookup("/repo/helpers.go")
	if syms == nil {
		t.Fatal("expected symbols for helpers.go")
	}
	v, ok := syms.Values["defaultBucketArgs"]
	if !ok {
		t.Fatalf("defaultBucketArgs not found; keys: %v", keys(syms.Values))
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", v)
	}
	// The index preserves Go PascalCase keys; normalization happens in the parser.
	if m["Acl"] != "public-read" {
		t.Errorf("Acl: got %v, want public-read", m["Acl"])
	}
}

func TestBuild_Go_CrossFile(t *testing.T) {
	configSrc := []byte(`package main
const defaultACL = "public-read"
`)
	mainSrc := []byte(`package main
import s3 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/s3"
`)
	paths := []string{"/repo/config.go", "/repo/main.go"}
	cache := map[string][]byte{
		"/repo/config.go": configSrc,
		"/repo/main.go":   mainSrc,
	}

	idx := projectindex.Build(paths, cache)

	// Both files in the same dir should have access to each other's package symbols.
	for _, p := range paths {
		syms := idx.Lookup(p)
		if syms == nil {
			t.Fatalf("expected symbols for %s", p)
		}
		assertVal(t, syms.Values, "defaultACL", "public-read")
	}
}

func TestBuild_TS_ArrowFunctionExport(t *testing.T) {
	src := []byte(`
export const getRegion = () => "us-east-1";
export const getAcl = () => { return "public-read"; };
export const nested = () => ({ acl: "private" });
`)
	idx := projectindex.Build([]string{"/repo/config.ts"}, map[string][]byte{"/repo/config.ts": src})
	syms := idx.Lookup("/repo/config.ts")
	if syms == nil {
		t.Fatal("expected symbols")
	}
	assertVal(t, syms.Values, "getRegion", "us-east-1")
	assertVal(t, syms.Values, "getAcl", "public-read")
}

func TestBuild_TS_ExportDefault(t *testing.T) {
	src := []byte(`export default "us-east-1";`)
	idx := projectindex.Build([]string{"/repo/config.ts"}, map[string][]byte{"/repo/config.ts": src})
	syms := idx.Lookup("/repo/config.ts")
	if syms == nil {
		t.Fatal("expected symbols")
	}
	assertVal(t, syms.Values, "default", "us-east-1")
}

func TestBuild_Go_MapStringKeys(t *testing.T) {
	src := []byte(`package main

var tags = map[string]string{"Environment": "prod", "Team": "platform"}
`)
	idx := projectindex.Build([]string{"/repo/main.go"}, map[string][]byte{"/repo/main.go": src})
	syms := idx.Lookup("/repo/main.go")
	if syms == nil {
		t.Fatal("expected symbols")
	}
	v, ok := syms.Values["tags"]
	if !ok {
		t.Fatalf("tags not found; keys: %v", keys(syms.Values))
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", v)
	}
	if m["Environment"] != "prod" {
		t.Errorf("Environment: got %v, want prod", m["Environment"])
	}
}

func TestBuild_Go_MultiResultReturn(t *testing.T) {
	src := []byte(`package main

import (
	s3 "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func getArgs() (*s3.BucketV2Args, error) {
	return &s3.BucketV2Args{Acl: pulumi.String("private")}, nil
}
`)
	idx := projectindex.Build([]string{"/repo/main.go"}, map[string][]byte{"/repo/main.go": src})
	syms := idx.Lookup("/repo/main.go")
	if syms == nil {
		t.Fatal("expected symbols")
	}
	v, ok := syms.Values["getArgs"]
	if !ok {
		t.Fatalf("getArgs not found; keys: %v", keys(syms.Values))
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", v)
	}
	if m["Acl"] != "private" {
		t.Errorf("Acl: got %v, want private", m["Acl"])
	}
}

func TestBuild_Go_StringConcatenation(t *testing.T) {
	src := []byte(`package main

const prefix = "us-"
const region = prefix + "east-1"
`)
	idx := projectindex.Build([]string{"/repo/main.go"}, map[string][]byte{"/repo/main.go": src})
	syms := idx.Lookup("/repo/main.go")
	if syms == nil {
		t.Fatal("expected symbols")
	}
	assertVal(t, syms.Values, "region", "us-east-1")
}

func TestBuild_Py_StringConcatenation(t *testing.T) {
	src := []byte(`
DEFAULT_ACL = "public" + "-read"
`)
	idx := projectindex.Build([]string{"/repo/config.py"}, map[string][]byte{"/repo/config.py": src})
	syms := idx.Lookup("/repo/config.py")
	if syms == nil {
		t.Fatal("expected symbols")
	}
	assertVal(t, syms.Values, "DEFAULT_ACL", "public-read")
}

func TestBuild_Py_FStringSkipped(t *testing.T) {
	src := []byte(`
env = "prod"
name = f"bucket-{env}"
static = f"just-static"
`)
	idx := projectindex.Build([]string{"/repo/config.py"}, map[string][]byte{"/repo/config.py": src})
	syms := idx.Lookup("/repo/config.py")
	if syms == nil {
		t.Fatal("expected symbols")
	}
	if _, ok := syms.Values["name"]; ok {
		t.Error("f-string with interpolation should not be indexed")
	}
}

func TestBuild_TS_MultiStatementFunction(t *testing.T) {
	src := []byte(`
export function getRegion() {
  const prefix = "us";
  return "us-east-1";
}
`)
	idx := projectindex.Build([]string{"/repo/config.ts"}, map[string][]byte{"/repo/config.ts": src})
	syms := idx.Lookup("/repo/config.ts")
	if syms == nil {
		t.Fatal("expected symbols")
	}
	assertVal(t, syms.Values, "getRegion", "us-east-1")
}

func TestBuild_TS_TemplateString(t *testing.T) {
	src := []byte("export const prefix = `my-project`;")
	idx := projectindex.Build([]string{"/repo/config.ts"}, map[string][]byte{"/repo/config.ts": src})
	syms := idx.Lookup("/repo/config.ts")
	if syms == nil {
		t.Fatal("expected symbols")
	}
	assertVal(t, syms.Values, "prefix", "my-project")
}

func TestBuild_Py_MultiStatementFunction(t *testing.T) {
	src := []byte(`
def get_region():
    print("fetching region")
    return "eu-west-1"
`)
	idx := projectindex.Build([]string{"/repo/config.py"}, map[string][]byte{"/repo/config.py": src})
	syms := idx.Lookup("/repo/config.py")
	if syms == nil {
		t.Fatal("expected symbols")
	}
	assertVal(t, syms.Values, "get_region", "eu-west-1")
}

func TestBuild_Go_SliceCompositeLit(t *testing.T) {
	src := []byte(`package main

var regions = []string{"us-east-1", "eu-west-1"}
`)
	idx := projectindex.Build([]string{"/repo/main.go"}, map[string][]byte{"/repo/main.go": src})
	syms := idx.Lookup("/repo/main.go")
	if syms == nil {
		t.Fatal("expected symbols")
	}
	v, ok := syms.Values["regions"]
	if !ok {
		t.Fatalf("regions not found; keys: %v", keys(syms.Values))
	}
	arr, ok := v.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", v)
	}
	if len(arr) != 2 || arr[0] != "us-east-1" {
		t.Errorf("regions: got %v, want [us-east-1 eu-west-1]", arr)
	}
}

func assertVal(t *testing.T, m map[string]interface{}, key string, want interface{}) {
	t.Helper()
	got, ok := m[key]
	if !ok {
		t.Errorf("key %q not found in symbols; keys: %v", key, keys(m))
		return
	}
	if got != want {
		t.Errorf("key %q: got %v (%T), want %v (%T)", key, got, got, want, want)
	}
}

func keys(m map[string]interface{}) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
