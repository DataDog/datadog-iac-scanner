/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestStringPredicates(t *testing.T) {
	t.Parallel()

	got, err := StartsWithFunc.Call([]cty.Value{cty.StringVal("hello"), cty.StringVal("he")})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.True) {
		t.Fatalf("startswith = %#v", got)
	}

	got, err = EndsWithFunc.Call([]cty.Value{cty.StringVal("hello"), cty.StringVal("lo")})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.True) {
		t.Fatalf("endswith = %#v", got)
	}

	got, err = StrContainsFunc.Call([]cty.Value{cty.StringVal("hello"), cty.StringVal("ell")})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.True) {
		t.Fatalf("strcontains = %#v", got)
	}
}

func TestAllTrueAnyTrue(t *testing.T) {
	t.Parallel()

	got, err := AllTrueFunc.Call([]cty.Value{cty.ListValEmpty(cty.Bool)})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.True) {
		t.Fatalf("alltrue empty = %#v", got)
	}

	got, err = AnyTrueFunc.Call([]cty.Value{cty.ListValEmpty(cty.Bool)})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.False) {
		t.Fatalf("anytrue empty = %#v", got)
	}

	got, err = AllTrueFunc.Call([]cty.Value{cty.ListVal([]cty.Value{cty.True, cty.False})})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.False) {
		t.Fatalf("alltrue mixed = %#v", got)
	}

	got, err = AnyTrueFunc.Call([]cty.Value{cty.ListVal([]cty.Value{cty.False, cty.True})})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.True) {
		t.Fatalf("anytrue mixed = %#v", got)
	}

	got, err = AllTrueFunc.Call([]cty.Value{cty.ListVal([]cty.Value{cty.UnknownVal(cty.Bool), cty.False})})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.False) {
		t.Fatalf("alltrue unknown then false = %#v", got)
	}
}

func TestSumAndOne(t *testing.T) {
	t.Parallel()

	got, err := SumFunc.Call([]cty.Value{cty.TupleVal([]cty.Value{
		cty.NumberIntVal(1),
		cty.NumberIntVal(2),
		cty.NumberIntVal(3),
	})})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.NumberIntVal(6)) {
		t.Fatalf("sum = %#v", got)
	}

	got, err = OneFunc.Call([]cty.Value{cty.TupleVal([]cty.Value{cty.StringVal("only")})})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("only")) {
		t.Fatalf("one = %#v", got)
	}

	got, err = OneFunc.Call([]cty.Value{cty.ListValEmpty(cty.String)})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.NullVal(cty.String)) {
		t.Fatalf("one empty = %#v", got)
	}
}

func TestMatchkeysAndTranspose(t *testing.T) {
	t.Parallel()

	got, err := MatchkeysFunc.Call([]cty.Value{
		cty.ListVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b"), cty.StringVal("c")}),
		cty.ListVal([]cty.Value{cty.StringVal("x"), cty.StringVal("y"), cty.StringVal("z")}),
		cty.ListVal([]cty.Value{cty.StringVal("y")}),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := cty.ListVal([]cty.Value{cty.StringVal("b")})
	if !got.RawEquals(want) {
		t.Fatalf("matchkeys = %#v, want %#v", got, want)
	}

	got, err = TransposeFunc.Call([]cty.Value{cty.MapVal(map[string]cty.Value{
		"a": cty.ListVal([]cty.Value{cty.StringVal("1"), cty.StringVal("2")}),
		"b": cty.ListVal([]cty.Value{cty.StringVal("2")}),
	})})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Type().IsMapType() {
		t.Fatalf("transpose type = %s", got.Type().FriendlyName())
	}
	if got.LengthInt() != 2 {
		t.Fatalf("transpose length = %d", got.LengthInt())
	}
}

func TestEncodeAndHash(t *testing.T) {
	t.Parallel()

	encoded, err := Base64EncodeFunc.Call([]cty.Value{cty.StringVal("hello")})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Base64DecodeFunc.Call([]cty.Value{encoded})
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.RawEquals(cty.StringVal("hello")) {
		t.Fatalf("base64 roundtrip = %#v", decoded)
	}

	got, err := URLEncodeFunc.Call([]cty.Value{cty.StringVal("a b")})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("a+b")) {
		t.Fatalf("urlencode = %#v", got)
	}

	_, err = Base64DecodeFunc.Call([]cty.Value{cty.StringVal("/w==")})
	if err == nil {
		t.Fatal("base64decode invalid UTF-8: expected error")
	}

	got, err = Md5Func.Call([]cty.Value{cty.StringVal("hello")})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("5d41402abc4b2a76b9719d911017c592")) {
		t.Fatalf("md5 = %#v", got)
	}

	got, err = Base64Sha256Func.Call([]cty.Value{cty.StringVal("hello")})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=")) {
		t.Fatalf("base64sha256 = %#v", got)
	}

	encoded, err = TextEncodeBase64Func.Call([]cty.Value{cty.StringVal("hello!"), cty.StringVal("UTF-16LE")})
	if err != nil {
		t.Fatal(err)
	}
	if !encoded.RawEquals(cty.StringVal("aABlAGwAbABvACEA")) {
		t.Fatalf("textencodebase64 = %#v", encoded)
	}
	decoded, err = TextDecodeBase64Func.Call([]cty.Value{encoded, cty.StringVal("UTF-16LE")})
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.RawEquals(cty.StringVal("hello!")) {
		t.Fatalf("textdecodebase64 = %#v", decoded)
	}

	gzipped, err := Base64GzipFunc.Call([]cty.Value{cty.StringVal("hello")})
	if err != nil {
		t.Fatal(err)
	}
	if gzipped.AsString() == "" {
		t.Fatal("base64gzip empty")
	}
	again, err := Base64GzipFunc.Call([]cty.Value{cty.StringVal("hello")})
	if err != nil {
		t.Fatal(err)
	}
	if !gzipped.RawEquals(again) {
		t.Fatal("base64gzip is not deterministic")
	}
}

func TestCidrFunctions(t *testing.T) {
	t.Parallel()

	got, err := CidrHostFunc.Call([]cty.Value{cty.StringVal("10.12.127.0/20"), cty.NumberIntVal(16)})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("10.12.112.16")) {
		t.Fatalf("cidrhost = %#v", got)
	}

	got, err = CidrHostFunc.Call([]cty.Value{cty.StringVal("10.12.127.0/20"), cty.NumberIntVal(-16)})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("10.12.127.240")) {
		t.Fatalf("cidrhost negative = %#v", got)
	}

	got, err = CidrNetmaskFunc.Call([]cty.Value{cty.StringVal("10.0.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("255.255.0.0")) {
		t.Fatalf("cidrnetmask = %#v", got)
	}

	got, err = CidrSubnetFunc.Call([]cty.Value{
		cty.StringVal("172.16.0.0/12"),
		cty.NumberIntVal(4),
		cty.NumberIntVal(2),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("172.18.0.0/16")) {
		t.Fatalf("cidrsubnet = %#v", got)
	}

	got, err = CidrSubnetsFunc.Call([]cty.Value{
		cty.StringVal("10.1.0.0/16"),
		cty.NumberIntVal(4),
		cty.NumberIntVal(4),
		cty.NumberIntVal(8),
		cty.NumberIntVal(4),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := cty.ListVal([]cty.Value{
		cty.StringVal("10.1.0.0/20"),
		cty.StringVal("10.1.16.0/20"),
		cty.StringVal("10.1.32.0/24"),
		cty.StringVal("10.1.48.0/20"),
	})
	if !got.RawEquals(want) {
		t.Fatalf("cidrsubnets = %#v, want %#v", got, want)
	}

	got, err = CidrSubnetFunc.Call([]cty.Value{
		cty.StringVal("::/0"),
		cty.NumberIntVal(64),
		cty.MustParseNumberVal("9223372036854775808"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("8000::/64")) {
		t.Fatalf("cidrsubnet ipv6 = %#v", got)
	}
}

func TestPathTimeUUID(t *testing.T) {
	t.Parallel()

	got, err := BasenameFunc.Call([]cty.Value{cty.StringVal("/foo/bar.txt")})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("bar.txt")) {
		t.Fatalf("basename = %#v", got)
	}

	got, err = DirnameFunc.Call([]cty.Value{cty.StringVal("/foo/bar.txt")})
	if err != nil {
		t.Fatal(err)
	}
	if got.AsString() == "" {
		t.Fatal("dirname empty")
	}

	got, err = PathExpandFunc.Call([]cty.Value{cty.StringVal("relative")})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("relative")) {
		t.Fatalf("pathexpand relative = %#v", got)
	}

	got, err = TimeCmpFunc.Call([]cty.Value{
		cty.StringVal("2017-11-22T00:00:00Z"),
		cty.StringVal("2017-11-22T00:00:00Z"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.NumberIntVal(0)) {
		t.Fatalf("timecmp equal = %#v", got)
	}

	got, err = TimeCmpFunc.Call([]cty.Value{
		cty.StringVal("2017-11-22T00:00:00Z"),
		cty.StringVal("2017-11-23T00:00:00Z"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.NumberIntVal(-1)) {
		t.Fatalf("timecmp before = %#v", got)
	}

	got, err = UUIDV5Func.Call([]cty.Value{cty.StringVal("dns"), cty.StringVal("www.terraform.io")})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("a5008fae-b28c-5ba5-96cd-82b4c53552d6")) {
		t.Fatalf("uuidv5 = %#v", got)
	}
}

func TestTemplateString(t *testing.T) {
	t.Parallel()

	got, err := TerraformFuncs["templatestring"].Call([]cty.Value{
		cty.StringVal("hello ${name}"),
		cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal("world")}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RawEquals(cty.StringVal("hello world")) {
		t.Fatalf("templatestring = %#v", got)
	}
}
