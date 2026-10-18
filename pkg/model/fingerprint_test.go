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

var fingerprintSCI = SCIInfo{RepositoryCommitInfo: RepositoryCommitInfo{RepositoryUrl: "repo"}}

// legacyHash computes the pre-address formula, so tests can prove the
// non-Terraform outputs are byte-identical to what the scanner always emitted.
func legacyHash(filePath, platform, resourceType, resourceName, ruleID, vulnLine, moduleCallChain string) string {
	segments := []string{"repo", filePath, resourceType, resourceName, ruleID}
	if platform == "Dockerfile" {
		segments = append(segments, vulnLine)
	}
	if platform == "Terraform" && moduleCallChain != "" {
		segments = append(segments, moduleCallChain)
	}
	sum := sha256.Sum256([]byte(strings.Join(segments, "|")))
	return hex.EncodeToString(sum[:])
}

// Empty chain adds no segment; a chain changes the hash for Terraform and is ignored elsewhere.
func TestGetDatadogFingerprintHash_ModuleCallChain(t *testing.T) {
	// An empty chain appends nothing, so Terraform matches the plain base hash (no fingerprint churn).
	base := GetDatadogFingerprintHash(fingerprintSCI, "modules/bucket/main.tf", "Kubernetes", "aws_s3_bucket", "this", "rule-1", "", "", "", "")
	tfEmpty := GetDatadogFingerprintHash(fingerprintSCI, "modules/bucket/main.tf", terraformPlatform, "aws_s3_bucket", "this", "rule-1", "", "", "", "")
	require.Equal(t, base, tfEmpty, "empty call chain must not change the fingerprint")

	fromA := GetDatadogFingerprintHash(fingerprintSCI, "modules/bucket/main.tf", terraformPlatform, "aws_s3_bucket", "this", "rule-1", "", "stack-a/main.tf|module.bucket", "", "")
	fromB := GetDatadogFingerprintHash(fingerprintSCI, "modules/bucket/main.tf", terraformPlatform, "aws_s3_bucket", "this", "rule-1", "", "stack-b/main.tf|module.bucket", "", "")

	require.NotEqual(t, tfEmpty, fromA, "a non-empty call chain must change the fingerprint")
	require.NotEqual(t, fromA, fromB, "distinct callers must produce distinct fingerprints")

	fromAAgain := GetDatadogFingerprintHash(fingerprintSCI, "modules/bucket/main.tf", terraformPlatform, "aws_s3_bucket", "this", "rule-1", "", "stack-a/main.tf|module.bucket", "", "")
	require.Equal(t, fromA, fromAAgain, "the same caller must produce a stable fingerprint")

	// Non-Terraform platforms must ignore the module call chain.
	k8sWithChain := GetDatadogFingerprintHash(fingerprintSCI, "modules/bucket/main.tf", "Kubernetes", "aws_s3_bucket", "this", "rule-1", "", "stack-a/main.tf|module.bucket", "", "")
	require.Equal(t, base, k8sWithChain, "non-Terraform platforms must ignore the module call chain")
}

// A Terraform finding with an address is identified by the plan address, not
// by where the file happens to live or which call chain reached it.
func TestGetDatadogFingerprintHash_TerraformAddress(t *testing.T) {
	want := stringToHash(strings.Join([]string{"repo", "live/prod", `aws_s3_bucket.b["prod"]`, "rule-1"}, "|"))

	got := GetDatadogFingerprintHash(fingerprintSCI, "live/prod/main.tf", terraformPlatform, "aws_s3_bucket", "b", "rule-1", "12", "", `aws_s3_bucket.b["prod"]`, "live/prod")
	require.Equal(t, want, got, "the address formula must be repo|rootModuleDir|address|ruleID")

	// A file move must not change the identity.
	moved := GetDatadogFingerprintHash(fingerprintSCI, "elsewhere/main.tf", terraformPlatform, "aws_s3_bucket", "b", "rule-1", "3", "", `aws_s3_bucket.b["prod"]`, "live/prod")
	require.Equal(t, want, moved, "moving the file must not change the fingerprint")

	// A different call chain reaching the same instance must not either.
	chained := GetDatadogFingerprintHash(fingerprintSCI, "live/prod/main.tf", terraformPlatform, "aws_s3_bucket", "b", "rule-1", "12", "stack-a/main.tf|module.bucket", `aws_s3_bucket.b["prod"]`, "live/prod")
	require.Equal(t, want, chained, "the call chain must not change the fingerprint once the address is used")

	// A different root module or instance must.
	otherRoot := GetDatadogFingerprintHash(fingerprintSCI, "live/prod/main.tf", terraformPlatform, "aws_s3_bucket", "b", "rule-1", "12", "", `aws_s3_bucket.b["prod"]`, "live/staging")
	require.NotEqual(t, want, otherRoot, "another root module is another resource")
	otherInstance := GetDatadogFingerprintHash(fingerprintSCI, "live/prod/main.tf", terraformPlatform, "aws_s3_bucket", "b", "rule-1", "12", "", `aws_s3_bucket.b["staging"]`, "live/prod")
	require.NotEqual(t, want, otherInstance, "another instance is another resource")
}

// Non-Terraform fingerprints are byte-identical to the formula the scanner
// always emitted, with or without the new arguments.
func TestGetDatadogFingerprintHash_NonTerraformUnchanged(t *testing.T) {
	k8s := GetDatadogFingerprintHash(fingerprintSCI, "deploy.yaml", "Kubernetes", "Deployment", "web", "rule-1", "", "", `Deployment.web`, "root")
	require.Equal(t, legacyHash("deploy.yaml", "Kubernetes", "Deployment", "web", "rule-1", "", ""), k8s,
		"Kubernetes must ignore the address for identity")

	docker := GetDatadogFingerprintHash(fingerprintSCI, "Dockerfile", "Dockerfile", "docker", "", "rule-2", "7", "", "", "")
	require.Equal(t, legacyHash("Dockerfile", "Dockerfile", "docker", "", "rule-2", "7", ""), docker,
		"Dockerfile keeps the line in its identity")

	dockerAddr := GetDatadogFingerprintHash(fingerprintSCI, "Dockerfile", "Dockerfile", "docker", "", "rule-2", "7", "", "docker.x", "root")
	require.Equal(t, legacyHash("Dockerfile", "Dockerfile", "docker", "", "rule-2", "7", ""), dockerAddr,
		"a stray address must not change a non-Terraform fingerprint")

	// Terraform without an address keeps the legacy formula (unresolved expansion).
	tfNoAddr := GetDatadogFingerprintHash(fingerprintSCI, "main.tf", terraformPlatform, "aws_s3_bucket", "b", "rule-1", "", "chain", "", "")
	require.Equal(t, legacyHash("main.tf", "Terraform", "aws_s3_bucket", "b", "rule-1", "", "chain"), tfNoAddr)
}
