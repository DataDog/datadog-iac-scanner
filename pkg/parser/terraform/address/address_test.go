/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package address

import (
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestFormatKey(t *testing.T) {
	tests := []struct {
		name   string
		key    cty.Value
		want   string
		wantOK bool
	}{
		{name: "int", key: cty.NumberIntVal(0), want: "[0]", wantOK: true},
		{name: "large int", key: cty.NumberIntVal(123), want: "[123]", wantOK: true},
		{name: "string", key: cty.StringVal("prod"), want: `["prod"]`, wantOK: true},
		{name: "empty string", key: cty.StringVal(""), want: `[""]`, wantOK: true},
		{name: "quote", key: cty.StringVal(`say "hi"`), want: `["say \"hi\""]`, wantOK: true},
		{name: "backslash", key: cty.StringVal(`a\b`), want: `["a\\b"]`, wantOK: true},
		{name: "both", key: cty.StringVal(`\"`), want: `["\\\""]`, wantOK: true},
		{name: "comma", key: cty.StringVal("a,b"), want: `["a,b"]`, wantOK: true},
		{name: "unknown", key: cty.UnknownVal(cty.String), want: "", wantOK: false},
		{name: "null", key: cty.NullVal(cty.String), want: "", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := FormatKey(tt.key)
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("FormatKey(%v) = %q, %v; want %q, %v", tt.key, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestResource(t *testing.T) {
	type testCase struct {
		name       string
		modulePath string
		mode       Mode
		resType    string
		resName    string
		key        cty.Value
		want       string
	}
	tests := []testCase{
		{name: "root resource no meta", mode: ModeManaged, resType: "aws_s3_bucket", resName: "b", key: cty.NilVal,
			want: "aws_s3_bucket.b"},
		{name: "root count", mode: ModeManaged, resType: "aws_instance", resName: "a", key: cty.NumberIntVal(2),
			want: "aws_instance.a[2]"},
		{name: "root for_each", mode: ModeManaged, resType: "aws_s3_bucket", resName: "b", key: cty.StringVal("prod"),
			want: `aws_s3_bucket.b["prod"]`},
		{name: "data for_each", mode: ModeData, resType: "aws_iam_policy_document", resName: "p", key: cty.StringVal("k"),
			want: `data.aws_iam_policy_document.p["k"]`},
		{name: "module path", modulePath: `module.net["eu"]`, mode: ModeManaged, resType: "aws_s3_bucket", resName: "b",
			key: cty.StringVal("prod"), want: `module.net["eu"].aws_s3_bucket.b["prod"]`},
		{name: "nested modules", modulePath: `module.a["x"].module.b[0]`, mode: ModeManaged, resType: "aws_instance",
			resName: "c", key: cty.NumberIntVal(1), want: `module.a["x"].module.b[0].aws_instance.c[1]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Resource(tt.modulePath, tt.mode, tt.resType, tt.resName, tt.key)
			if got != tt.want {
				t.Fatalf("Resource = %q; want %q", got, tt.want)
			}
		})
	}
}
