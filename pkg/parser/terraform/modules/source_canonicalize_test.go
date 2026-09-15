/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfmodules

import "testing"

func TestCanonicalizeRemoteModuleSource(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{
			name: "registry short form vs explicit host",
			a:    "terraform-aws-modules/rds/aws",
			b:    "registry.terraform.io/terraform-aws-modules/rds/aws",
			want: true,
		},
		{
			name: "registry with version suffix ignored",
			a:    "terraform-aws-modules/rds/aws",
			b:    "terraform-aws-modules/rds/aws@v1.0.0",
			want: true,
		},
		{
			name: "git:: prefix and .git suffix and ref query",
			a:    "git::https://github.com/foo/bar.git//modules/rds?ref=v1.0.0",
			b:    "https://github.com/foo/bar//modules/rds",
			want: true,
		},
		{
			name: "git userinfo stripped",
			a:    "git::https://token@github.com/foo/bar.git",
			b:    "https://github.com/foo/bar",
			want: true,
		},
		{
			name: "different git repos are distinct",
			a:    "git::https://github.com/foo/bar.git",
			b:    "git::https://github.com/foo/baz.git",
			want: false,
		},
		{
			name: "different registry modules are distinct",
			a:    "terraform-aws-modules/rds/aws",
			b:    "terraform-aws-modules/vpc/aws",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotA := CanonicalizeRemoteModuleSource(tt.a)
			gotB := CanonicalizeRemoteModuleSource(tt.b)
			if (gotA == gotB) != tt.want {
				t.Errorf("CanonicalizeRemoteModuleSource(%q)=%q, CanonicalizeRemoteModuleSource(%q)=%q, match=%v want=%v",
					tt.a, gotA, tt.b, gotB, gotA == gotB, tt.want)
			}
		})
	}
}

func TestCanonicalizeRemoteModuleSourceEmpty(t *testing.T) {
	if got := CanonicalizeRemoteModuleSource(""); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}
