/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package modulegraph

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMapPackageDirectories(t *testing.T) {
	pkg := filepath.Join(string(filepath.Separator), "tmp", "modules", "abc")
	bucket := filepath.Join(pkg, "terraform-modules", "aws-bucket")
	helper := filepath.Join(pkg, "terraform-modules", "aws--helper")
	nested := filepath.Join(bucket, "policies")
	registry := filepath.Join(string(filepath.Separator), "tmp", "modules", "vpc")
	registryChild := filepath.Join(registry, "modules", "endpoints")
	const bucketSource = "git::https://github.com/DataDog/cloud-inventory//terraform-modules/aws-bucket?ref=v1"

	snapshot := walkerSnapshot{
		paths: []string{
			filepath.Join(bucket, "main.tf"),
			filepath.Join(helper, "@outputs.tf"),
			filepath.Join(nested, "main.tf"),
			filepath.Join(registry, "main.tf"),
			filepath.Join(registryChild, "main.tf"),
		},
		modules: []ResolvedModule{
			{LocalPath: bucket, PackageRoot: pkg},
			{LocalPath: registry, PackageRoot: registry},
		},
		sourceMappings: map[string]string{
			bucket:   bucketSource,
			registry: "registry.terraform.io/terraform-aws-modules/vpc/aws@5.0.0",
		},
	}

	mapPackageDirectories(&snapshot)

	require.Equal(t, map[string]string{
		bucket:   bucketSource,
		helper:   "git::https://github.com/DataDog/cloud-inventory//terraform-modules/aws--helper?ref=v1",
		registry: "registry.terraform.io/terraform-aws-modules/vpc/aws@5.0.0",
	}, snapshot.sourceMappings, "directories under a mapped one are already named after it")
}

func TestSplitPackageAddress(t *testing.T) {
	for _, tc := range []struct {
		source, subdir string
		want           packageAddress
		ok             bool
	}{
		{"git::https://github.com/org/repo//a/b?ref=v1", "a/b", packageAddress{"git::https://github.com/org/repo", "?ref=v1"}, true},
		{"git::https://github.com/org/repo?ref=v1", ".", packageAddress{"git::https://github.com/org/repo", "?ref=v1"}, true},
		{"git@github.com:org/repo//a", "a", packageAddress{"git@github.com:org/repo", ""}, true},
		{"registry.terraform.io/ns/name/aws//modules/x@1.0.0", "modules/x", packageAddress{"registry.terraform.io/ns/name/aws", "@1.0.0"}, true},
		{"git::https://github.com/org/repo//a", "b", packageAddress{}, false},
		{"git::https://github.com/org/repo//a", ".", packageAddress{}, false},
	} {
		got, ok := splitPackageAddress(tc.source, tc.subdir)
		require.Equal(t, tc.ok, ok, tc.source)
		require.Equal(t, tc.want, got, tc.source)
	}
}
