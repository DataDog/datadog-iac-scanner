/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"crypto/sha256"
	"encoding/hex"
)

const (
	dockerfilePlatform = "Dockerfile"
	terraformPlatform  = "Terraform"
)

// GetDatadogFingerprintHash is the single source of truth for a finding's
// stable identity. It is computed once when the summary is built and reused by
// every report format, so the fingerprint never diverges across outputs.
// nolint:gocritic
func GetDatadogFingerprintHash(
	sciInfo SCIInfo, filePath, platform, resourceType, resourceName, ruleID, vulnLine, moduleCallChain string,
) string {
	sum := FingerprintSum(sciInfo, filePath, platform, resourceType, resourceName, ruleID, vulnLine, moduleCallChain)
	return hex.EncodeToString(sum[:])
}

// fingerprintBuffer is how much of a fingerprint's input is assembled on the
// stack; longer inputs spill to the heap.
const fingerprintBuffer = 512

// FingerprintSum is the digest GetDatadogFingerprintHash encodes, for callers
// that only compare fingerprints.
// nolint:gocritic
func FingerprintSum(
	sciInfo SCIInfo, filePath, platform, resourceType, resourceName, ruleID, vulnLine, moduleCallChain string,
) [sha256.Size]byte {
	var stack [fingerprintBuffer]byte
	b := append(stack[:0], sciInfo.RepositoryCommitInfo.RepositoryUrl...)
	for _, segment := range [...]string{filePath, resourceType, resourceName, ruleID} {
		b = append(append(b, '|'), segment...)
	}

	switch platform {
	case dockerfilePlatform:
		b = append(append(b, '|'), vulnLine...)
	case terraformPlatform:
		// Same resource reached through different module call paths is a distinct finding.
		if moduleCallChain != "" {
			b = append(append(b, '|'), moduleCallChain...)
		}
	}

	return sha256.Sum256(b)
}
