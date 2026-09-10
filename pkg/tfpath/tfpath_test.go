/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package tfpath

import (
	"maps"
	"slices"
	"testing"
)

func TestIsJSONConfig(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "main.tf.json", want: true},
		{path: "main.tofu.json", want: true},
		{path: "dir/main.tf.json", want: true},
		{path: "MAIN.TOFU.JSON", want: true},
		{path: "main.tf", want: false},
		{path: "main.tofu", want: false},
		{path: "main.json", want: false},
		{path: "main.tfvars", want: false},
		{path: "main.tf.json.backup", want: false},
		{path: "", want: false},
	}
	for _, tt := range tests {
		if got := IsJSONConfig(tt.path); got != tt.want {
			t.Errorf("IsJSONConfig(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsHCLConfig(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "main.tf", want: true},
		{path: "main.tofu", want: true},
		{path: "dir/main.tf", want: true},
		{path: "A.TOFU", want: true},
		{path: "main.tf.json", want: false},
		{path: "main.tofu.json", want: false},
		{path: "vars.tfvars", want: false},
		{path: "vars.auto.tfvars", want: false},
		{path: "main.json", want: false},
		{path: "x.tofuvars", want: false},
		{path: "", want: false},
	}
	for _, tt := range tests {
		if got := IsHCLConfig(tt.path); got != tt.want {
			t.Errorf("IsHCLConfig(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsConfig(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "main.tf", want: true},
		{path: "main.tofu", want: true},
		{path: "main.tf.json", want: true},
		{path: "main.tofu.json", want: true},
		{path: "stack/main.tf.json", want: true},
		{path: "vars.tfvars", want: false},
		{path: "prod.auto.tfvars", want: false},
		{path: "main.json", want: false},
		{path: "README.md", want: false},
		{path: "", want: false},
	}
	for _, tt := range tests {
		if got := IsConfig(tt.path); got != tt.want {
			t.Errorf("IsConfig(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestShadowedByTofu(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  []string // shadowed subset; nil means ShadowedByTofu returns nil
	}{
		{
			name:  "no tofu files returns nil",
			paths: []string{"a/main.tf", "a/other.tf", "a/main.tf.json"},
			want:  nil,
		},
		{
			name:  "foo.tofu shadows foo.tf",
			paths: []string{"dir/foo.tf", "dir/foo.tofu"},
			want:  []string{"dir/foo.tf"},
		},
		{
			name:  "foo.tofu does not shadow foo.tf.json",
			paths: []string{"dir/foo.tf.json", "dir/foo.tofu"},
			want:  nil,
		},
		{
			name:  "foo.tofu.json shadows foo.tf.json",
			paths: []string{"dir/foo.tf.json", "dir/foo.tofu.json"},
			want:  []string{"dir/foo.tf.json"},
		},
		{
			name:  "hcl and json families are independent",
			paths: []string{"dir/foo.tf", "dir/foo.tf.json", "dir/foo.tofu", "dir/foo.tofu.json"},
			want:  []string{"dir/foo.tf", "dir/foo.tf.json"},
		},
		{
			name:  "foo_override.tofu shadows foo_override.tf",
			paths: []string{"dir/foo_override.tf", "dir/foo_override.tofu"},
			want:  []string{"dir/foo_override.tf"},
		},
		{
			name:  "same basename in different directories does not shadow",
			paths: []string{"a/foo.tf", "b/foo.tofu"},
			want:  nil,
		},
		{
			name:  "directory case is significant",
			paths: []string{"modules/VPC/main.tf", "modules/vpc/main.tofu"},
			want:  nil,
		},
		{
			name:  "tofu file with no tf twin shadows nothing",
			paths: []string{"dir/foo.tofu", "dir/other.tf"},
			want:  nil,
		},
		{
			name:  "basename shadowing is case-sensitive",
			paths: []string{"dir/foo.tf", "dir/Foo.TOFU"},
			want:  nil,
		},
		{
			name:  "empty input returns nil",
			paths: nil,
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShadowedByTofu(tt.paths)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("ShadowedByTofu(%v) = %v, want nil", tt.paths, keys(got))
				}
				return
			}
			if got == nil {
				t.Fatalf("ShadowedByTofu(%v) = nil, want %v", tt.paths, tt.want)
			}
			if !slices.Equal(slices.Sorted(maps.Keys(got)), tt.want) {
				t.Errorf("ShadowedByTofu(%v) = %v, want %v", tt.paths, keys(got), tt.want)
			}
		})
	}
}

func TestFilterShadowed(t *testing.T) {
	in := []string{"dir/foo.tf", "dir/foo.tofu", "dir/other.tf"}
	got := FilterShadowed(in)
	if !slices.Equal(got, []string{"dir/foo.tofu", "dir/other.tf"}) {
		t.Errorf("FilterShadowed(%v) = %v", in, got)
	}
	noTofu := []string{"dir/foo.tf"}
	if kept := FilterShadowed(noTofu); !slices.Equal(kept, noTofu) {
		t.Errorf("FilterShadowed(%v) = %v, want same slice", noTofu, kept)
	}
}

func TestMatching(t *testing.T) {
	in := []string{"dir/foo.tf", "dir/foo.tofu", "dir/foo.tf.json", "dir/vars.tfvars"}
	got := Matching(in, IsHCLConfig)
	if !slices.Equal(got, []string{"dir/foo.tf", "dir/foo.tofu"}) {
		t.Errorf("Matching(IsHCLConfig) = %v", got)
	}
}

func TestSelect(t *testing.T) {
	in := []string{"dir/foo.tf", "dir/foo.tofu", "dir/foo.tf.json", "dir/vars.tfvars"}
	got := Select(in, IsHCLConfig)
	if !slices.Equal(got, []string{"dir/foo.tofu"}) {
		t.Errorf("Select(IsHCLConfig) = %v", got)
	}
	got = Select(in, IsConfig)
	if !slices.Equal(got, []string{"dir/foo.tofu", "dir/foo.tf.json"}) {
		t.Errorf("Select(IsConfig) = %v", got)
	}
}

func TestSelectWithTofuPrecedence(t *testing.T) {
	in := []string{"main.tf", "main.tofu", "variables.tf", "locals.tofu"}
	preferTofu := func(path string) bool { return path == "locals.tofu" }
	got := SelectWithTofuPrecedence(in, IsHCLConfig, preferTofu)
	if !slices.Equal(got, []string{"main.tf", "variables.tf", "locals.tofu"}) {
		t.Errorf("SelectWithTofuPrecedence() = %v", got)
	}
}

func TestSelectKeeping(t *testing.T) {
	in := []string{"dir/foo.tf", "dir/foo.tofu", "dir/other.tf"}
	got := SelectKeeping(in, IsHCLConfig, "dir/foo.tf")
	if !slices.Equal(got, []string{"dir/other.tf", "dir/foo.tf"}) {
		t.Errorf("SelectKeeping(foo.tf) = %v", got)
	}
	got = SelectKeeping(in, IsHCLConfig, "dir/foo.tofu")
	if !slices.Equal(got, []string{"dir/foo.tofu", "dir/other.tf"}) {
		t.Errorf("SelectKeeping(foo.tofu) = %v", got)
	}
	got = SelectKeeping(in, IsHCLConfig, "")
	if !slices.Equal(got, []string{"dir/foo.tofu", "dir/other.tf"}) {
		t.Errorf("SelectKeeping() = %v", got)
	}

	preferTF := func(string) bool { return false }
	got = SelectKeepingWithTofuPrecedence(in, IsHCLConfig, "dir/foo.tofu", preferTF)
	if !slices.Equal(got, []string{"dir/other.tf", "dir/foo.tofu"}) {
		t.Errorf("SelectKeepingWithTofuPrecedence(foo.tofu) = %v", got)
	}

	got = SelectKeeping([]string{"main.tf", "variable.tofu"}, IsHCLConfig, "main.tf")
	if !slices.Equal(got, []string{"main.tf", "variable.tofu"}) {
		t.Errorf("SelectKeeping(unrelated tofu file) = %v", got)
	}
}

func TestPartition(t *testing.T) {
	type rec struct{ p string }
	in := []rec{{"dir/foo.tf"}, {"dir/foo.tofu"}, {"dir/other.tf"}}
	kept, shadowed := Partition(in, func(r rec) string { return r.p })
	if len(kept) != 2 || kept[0].p != "dir/foo.tofu" || kept[1].p != "dir/other.tf" {
		t.Errorf("kept = %#v", kept)
	}
	if len(shadowed) != 1 || shadowed[0].p != "dir/foo.tf" {
		t.Errorf("shadowed = %#v", shadowed)
	}
	plain := []rec{{"dir/foo.tf"}}
	kept, shadowed = Partition(plain, func(r rec) string { return r.p })
	if len(kept) != 1 || kept[0].p != "dir/foo.tf" || shadowed != nil {
		t.Errorf("unchanged Partition = kept %#v shadowed %#v", kept, shadowed)
	}
}

func keys(m map[string]struct{}) []string {
	return slices.Sorted(maps.Keys(m))
}
