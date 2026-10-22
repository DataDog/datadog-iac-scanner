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
	return stringToHash(fingerprintInput(sciInfo, filePath, platform, resourceType, resourceName, ruleID, vulnLine, moduleCallChain))
}

// FindingIdentity is the identity a scan reports one finding for: findings of
// equal identity share a fingerprint, and only the last of them is reported.
func FindingIdentity(v *Vulnerability, ruleID string) string {
	fileName, line := v.Identity()
	// SCIInfo is constant within a scan; an empty value yields the same grouping.
	return fingerprintInput(SCIInfo{}, fileName, v.Platform, v.ResourceType, v.ResourceName, ruleID, line, v.ModuleCallChain)
}

// nolint:gocritic
func fingerprintInput(
	sciInfo SCIInfo, filePath, platform, resourceType, resourceName, ruleID, vulnLine, moduleCallChain string,
) string {
	segments := []string{sciInfo.RepositoryCommitInfo.RepositoryUrl, filePath, resourceType, resourceName, ruleID}

	switch platform {
	case dockerfilePlatform:
		segments = append(segments, vulnLine)
	case terraformPlatform:
		// Same resource reached through different module call paths is a distinct finding.
		if moduleCallChain != "" {
			segments = append(segments, moduleCallChain)
		}
	}

	return strings.Join(segments, "|")
}

func stringToHash(str string) string {
	hash := sha256.Sum256([]byte(str))
	return hex.EncodeToString(hash[:])
}
