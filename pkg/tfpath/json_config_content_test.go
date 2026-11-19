/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfpath

import "testing"

func TestIsPlainJSON(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "positive5.json", want: true},
		{path: "dir/stack.json", want: true},
		{path: "main.tf.json", want: false},
		{path: "main.tofu.json", want: false},
		{path: "terraform.tfvars.json", want: false},
		{path: "main.tf", want: false},
		{path: "package.json", want: true},
	}
	for _, tt := range tests {
		if got := IsPlainJSON(tt.path); got != tt.want {
			t.Errorf("IsPlainJSON(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestLooksLikeJSONConfig(t *testing.T) {
	cdktf := []byte(`{
  "//": {"metadata": {"stackName": "cdktf-test", "version": "0.9.0"}},
  "provider": {"aws": [{"region": "us-east-1"}]},
  "resource": {"aws_instance": {"cdktf-test": {"ami": "ami-1", "monitoring": false}}},
  "terraform": {"required_providers": {"aws": {"source": "aws"}}}
}`)
	tests := []struct {
		name    string
		content []byte
		want    bool
	}{
		{name: "cdktf stack", content: cdktf, want: true},
		{name: "tf json resource", content: []byte(`{"resource":{"aws_s3_bucket":{"b":{"acl":"public-read"}}}}`), want: true},
		{name: "module only", content: []byte(`{"module":{"m":{"source":"./m"}}}`), want: true},
		{name: "package.json", content: []byte(`{"name":"app","dependencies":{}}`), want: false},
		{name: "data alone", content: []byte(`{"data":{"items":[1]}}`), want: false},
		{name: "plan", content: []byte(`{"format_version":"1.2","planned_values":{"root_module":{}}}`), want: false},
		{name: "cloudformation", content: []byte(`{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket"}}}`), want: false},
		{name: "not json", content: []byte(`resource "aws_s3_bucket" "b" {}`), want: false},
		{name: "empty object", content: []byte(`{}`), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LooksLikeJSONConfig(tt.content); got != tt.want {
				t.Errorf("LooksLikeJSONConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
