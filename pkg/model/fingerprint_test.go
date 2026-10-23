/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

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

// The fingerprint is the SHA-256 of the segments joined by "|", whatever the
// length of the segments.
func TestGetDatadogFingerprintHash_IsTheJoinedSegmentsDigest(t *testing.T) {
	sci := SCIInfo{RepositoryCommitInfo: RepositoryCommitInfo{RepositoryUrl: "https://example.invalid/repo.git"}}
	long := strings.Repeat("module.m[\"k\"].", 100)
	for _, c := range []struct {
		platform, line, chain string
		segments              []string
	}{
		{"Kubernetes", "7", "chain", nil},
		{dockerfilePlatform, "7", "chain", []string{"7"}},
		{terraformPlatform, "7", "", nil},
		{terraformPlatform, "7", "root/main.tf|module.m", []string{"root/main.tf|module.m"}},
		{terraformPlatform, "7", long, []string{long}},
	} {
		joined := strings.Join(append([]string{sci.RepositoryCommitInfo.RepositoryUrl,
			"modules/bucket/main.tf", "aws_s3_bucket", "this", "rule-1"}, c.segments...), "|")
		want := sha256.Sum256([]byte(joined))
		got := GetDatadogFingerprintHash(sci, "modules/bucket/main.tf", c.platform, "aws_s3_bucket", "this", "rule-1", c.line, c.chain)
		require.Equal(t, hex.EncodeToString(want[:]), got, "platform %s, chain of %d bytes", c.platform, len(c.chain))
	}
}
