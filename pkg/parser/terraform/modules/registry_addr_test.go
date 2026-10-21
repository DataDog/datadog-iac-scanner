/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfmodules

import "testing"

func TestCanonicalModuleSource(t *testing.T) {
	const qualified = "registry.terraform.io/org/vpc/aws"
	for _, tc := range []struct{ source, want string }{
		{"org/vpc/aws", qualified},
		{qualified, qualified},
		{" org/vpc/aws ", qualified},
		{"org/vpc/aws//modules/child", qualified + "//modules/child"},
		{qualified + "//modules/child", qualified + "//modules/child"},
		{"org/vpc/aws//modules/child?version=1.0.0", qualified + "//modules/child"},
		{"registry.example.com:8443/org/vpc/aws", "registry.example.com:8443/org/vpc/aws"},
		{"registry.opentofu.org/org/vpc/aws", "registry.opentofu.org/org/vpc/aws"},
		{"./modules/child", ""},
		{"../modules/child", ""},
		{"git::https://github.com/org/repo.git//modules/child?ref=v1.0.0", ""},
		{"https://example.com/module.zip", ""},
		{"", ""},
	} {
		t.Run(tc.source, func(t *testing.T) {
			got, ok := CanonicalModuleSource(tc.source)
			if got != tc.want || ok != (tc.want != "") {
				t.Fatalf("CanonicalModuleSource(%q) = (%q, %t), want (%q, %t)", tc.source, got, ok, tc.want, tc.want != "")
			}
		})
	}
}

func TestParseRegistryModuleSource(t *testing.T) {
	tests := []struct {
		source string
		want   RegistryModuleSource
	}{
		{
			source: "terraform-aws-modules/vpc/aws",
			want: RegistryModuleSource{
				Host:      "registry.terraform.io",
				Namespace: "terraform-aws-modules",
				Name:      "vpc",
				Provider:  "aws",
			},
		},
		{
			source: "registry.terraform.io/org/vpc/aws//modules/child",
			want: RegistryModuleSource{
				Host:      "registry.terraform.io",
				Namespace: "org",
				Name:      "vpc",
				Provider:  "aws",
				Subdir:    "modules/child",
			},
		},
		{
			source: "registry.example.com:8443/ns/name/aws",
			want: RegistryModuleSource{
				Host:      "registry.example.com:8443",
				Namespace: "ns",
				Name:      "name",
				Provider:  "aws",
			},
		},
		{
			source: "registry.opentofu.org/org/module/aws",
			want: RegistryModuleSource{
				Host:      "registry.opentofu.org",
				Namespace: "org",
				Name:      "module",
				Provider:  "aws",
			},
		},
		{
			source: "registry.opentofu.org/org/module/aws//modules/child",
			want: RegistryModuleSource{
				Host:      "registry.opentofu.org",
				Namespace: "org",
				Name:      "module",
				Provider:  "aws",
				Subdir:    "modules/child",
			},
		},
	}
	for _, tt := range tests {
		got, err := ParseRegistryModuleSource(tt.source)
		if err != nil {
			t.Fatalf("ParseRegistryModuleSource(%q): %v", tt.source, err)
		}
		if got != tt.want {
			t.Errorf("ParseRegistryModuleSource(%q) = %+v, want %+v", tt.source, got, tt.want)
		}
	}
	if _, err := ParseRegistryModuleSource("git::https://github.com/org/repo"); err == nil {
		t.Fatal("git sources must not parse as registry addresses")
	}
}
