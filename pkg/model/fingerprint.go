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
	if platform == terraformPlatform {
		filePath = stripTerraformRegistryModuleVersion(filePath)
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

func stripTerraformRegistryModuleVersion(filePath string) string {
	slashed := strings.ReplaceAll(filePath, `\`, "/")
	parts := strings.Split(slashed, "/")
	if len(parts) < 5 || !strings.Contains(parts[0], ".") {
		return filePath
	}
	provider, _, hasVersion := strings.Cut(parts[3], "@")
	if !hasVersion || provider == "" {
		return filePath
	}
	parts[3] = provider
	return strings.Join(parts, "/")
}

func stringToHash(str string) string {
	hash := sha256.Sum256([]byte(str))
	return hex.EncodeToString(hash[:])
}
