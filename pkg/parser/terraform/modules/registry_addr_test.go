/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfmodules

import "testing"

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
