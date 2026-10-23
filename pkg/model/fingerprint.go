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

// TerraformIdentity identifies one resource instance within a root module.
// Both fields must be resolved to use the Terraform address fingerprint.
type TerraformIdentity struct {
	RootModuleDir   string
	ResourceAddress string
}

// GetDatadogFingerprintHash is the single source of truth for a finding's
// stable identity. It is computed once when the summary is built and reused by
// every report format, so the fingerprint never diverges across outputs.
// nolint:gocritic
func GetDatadogFingerprintHash(
	sciInfo SCIInfo, filePath, platform, resourceType, resourceName, ruleID, vulnLine, moduleCallChain string,
	terraformIdentity ...TerraformIdentity,
) string {
	// Addressed Terraform findings are stable across file moves within a root.
	// Missing address/root keeps the legacy identity; reports expose that fallback.
	if strings.EqualFold(platform, terraformPlatform) && len(terraformIdentity) > 0 {
		identity := terraformIdentity[0]
		if identity.RootModuleDir != "" && identity.ResourceAddress != "" {
			segments := []string{sciInfo.RepositoryCommitInfo.RepositoryUrl, identity.RootModuleDir, identity.ResourceAddress, ruleID}
			return stringToHash(strings.Join(segments, "|"))
		}
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
