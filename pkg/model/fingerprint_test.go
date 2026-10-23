/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTerraformAddressFingerprint(t *testing.T) {
	sci := SCIInfo{RepositoryCommitInfo: RepositoryCommitInfo{RepositoryUrl: "repo"}}
	hash := func(file, root, addr, rule, platform string) string {
		return GetDatadogFingerprintHash(sci, file, platform, "type", "provider-name", rule, "evidence", "caller", TerraformIdentity{RootModuleDir: root, ResourceAddress: addr})
	}
	addr := `module.a["x"].module.b[0].aws_s3_bucket.example["key"]`
	want := sha256.Sum256([]byte("repo|stacks/prod|" + addr + "|rule"))
	got := hash("old.tf", "stacks/prod", addr, "rule", "Terraform")
	require.Equal(t, hex.EncodeToString(want[:]), got)
	require.Equal(t, got, hash("new.tf", "stacks/prod", addr, "rule", "terraform"))
	require.NotEqual(t, got, hash("old.tf", "stacks/dev", addr, "rule", "Terraform"))
	require.NotEqual(t, got, hash("old.tf", "stacks/prod", addr+"[1]", "rule", "Terraform"))
	require.NotEqual(t, got, hash("old.tf", "stacks/prod", addr, "other-rule", "Terraform"))
	legacy := GetDatadogFingerprintHash(sci, "old.tf", "Terraform", "type", "provider-name", "rule", "evidence", "caller")
	require.Equal(t, legacy, hash("old.tf", "stacks/prod", "", "rule", "Terraform"))
	require.Equal(t, legacy, hash("old.tf", "", addr, "rule", "Terraform"))
	for _, platform := range []string{"Dockerfile", "Kubernetes", "CloudFormation", "Ansible"} {
		old := GetDatadogFingerprintHash(sci, "old.tf", platform, "type", "provider-name", "rule", "evidence", "caller")
		require.Equal(t, old, hash("old.tf", "stacks/prod", addr, "rule", platform))
	}
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
