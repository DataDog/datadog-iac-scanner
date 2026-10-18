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
//
// For Terraform findings carrying a resource address, the identity is the
// address Terraform itself would use in a plan: the root module directory
// disambiguates repositories with several roots, and the address carries the
// module path and instance keys, so neither the file path nor the module call
// chain take part — a file move or a call-chain change does not change the
// identity of the same resource instance. Findings without an address (the
// expansion could not be resolved) keep the legacy formula.
// nolint:gocritic
func GetDatadogFingerprintHash(
	sciInfo SCIInfo, filePath, platform, resourceType, resourceName, ruleID, vulnLine, moduleCallChain,
	resourceAddress, rootModuleDir string,
) string {
	if strings.EqualFold(platform, terraformPlatform) && resourceAddress != "" {
		return stringToHash(strings.Join([]string{
			sciInfo.RepositoryCommitInfo.RepositoryUrl, rootModuleDir, resourceAddress, ruleID,
		}, "|"))
	}

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

	return stringToHash(strings.Join(segments, "|"))
}

func stringToHash(str string) string {
	hash := sha256.Sum256([]byte(str))
	return hex.EncodeToString(hash[:])
}
