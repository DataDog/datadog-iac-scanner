/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetDatadogFingerprintHash_RemoteModuleVersionStripping(t *testing.T) {
	sci := SCIInfo{RepositoryCommitInfo: RepositoryCommitInfo{RepositoryUrl: "repo"}}

	v1 := GetDatadogFingerprintHash(sci, "registry.terraform.io/hashicorp/vpc/aws@1.0.0/main.tf", terraformPlatform, "aws_vpc", "this", "rule-1", "", "")
	v2 := GetDatadogFingerprintHash(sci, "registry.terraform.io/hashicorp/vpc/aws@2.0.0/main.tf", terraformPlatform, "aws_vpc", "this", "rule-1", "", "")
	require.Equal(t, v1, v2, "upgrading a remote module must not change the fingerprint")

	constraint := GetDatadogFingerprintHash(sci, "registry.terraform.io/hashicorp/vpc/aws@~> 3.0/main.tf", terraformPlatform, "aws_vpc", "this", "rule-1", "", "")
	concrete := GetDatadogFingerprintHash(sci, "registry.terraform.io/hashicorp/vpc/aws@3.2.1/main.tf", terraformPlatform, "aws_vpc", "this", "rule-1", "", "")
	require.Equal(t, constraint, concrete, "constraint string and resolved version must hash identically")

	noVersion := GetDatadogFingerprintHash(sci, "registry.terraform.io/hashicorp/vpc/aws/main.tf", terraformPlatform, "aws_vpc", "this", "rule-1", "", "")
	require.Equal(t, v1, noVersion, "explicit version and no-version path must hash identically")

	other := GetDatadogFingerprintHash(sci, "registry.terraform.io/hashicorp/eks/aws@1.0.0/main.tf", terraformPlatform, "aws_vpc", "this", "rule-1", "", "")
	require.NotEqual(t, v1, other, "different module sources must produce distinct fingerprints")

	local := GetDatadogFingerprintHash(sci, "modules/vpc/main.tf", terraformPlatform, "aws_vpc", "this", "rule-1", "", "")
	require.NotEqual(t, v1, local, "local and remote module paths must differ")
}

// Empty chain adds no segment; a chain changes the hash for Terraform and is ignored elsewhere.
func TestGetDatadogFingerprintHash_ModuleCallChain(t *testing.T) {
	sci := SCIInfo{RepositoryCommitInfo: RepositoryCommitInfo{RepositoryUrl: "repo"}}

	// An empty chain appends nothing, so Terraform matches the plain base hash (no fingerprint churn).
	base := GetDatadogFingerprintHash(sci, "modules/bucket/main.tf", "Kubernetes", "aws_s3_bucket", "this", "rule-1", "", "")
	tfEmpty := GetDatadogFingerprintHash(sci, "modules/bucket/main.tf", terraformPlatform, "aws_s3_bucket", "this", "rule-1", "", "")
	require.Equal(t, base, tfEmpty, "empty call chain must not change the fingerprint")

	fromA := GetDatadogFingerprintHash(sci, "modules/bucket/main.tf", terraformPlatform, "aws_s3_bucket", "this", "rule-1", "", "stack-a/main.tf|module.bucket")
	fromB := GetDatadogFingerprintHash(sci, "modules/bucket/main.tf", terraformPlatform, "aws_s3_bucket", "this", "rule-1", "", "stack-b/main.tf|module.bucket")

	require.NotEqual(t, tfEmpty, fromA, "a non-empty call chain must change the fingerprint")
	require.NotEqual(t, fromA, fromB, "distinct callers must produce distinct fingerprints")

	fromAAgain := GetDatadogFingerprintHash(sci, "modules/bucket/main.tf", terraformPlatform, "aws_s3_bucket", "this", "rule-1", "", "stack-a/main.tf|module.bucket")
	require.Equal(t, fromA, fromAAgain, "the same caller must produce a stable fingerprint")

	// Non-Terraform platforms must ignore the module call chain.
	k8sWithChain := GetDatadogFingerprintHash(sci, "modules/bucket/main.tf", "Kubernetes", "aws_s3_bucket", "this", "rule-1", "", "stack-a/main.tf|module.bucket")
	require.Equal(t, base, k8sWithChain, "non-Terraform platforms must ignore the module call chain")
}
