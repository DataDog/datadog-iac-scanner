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

	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
)

const (
	dockerfilePlatform = "Dockerfile"
	terraformPlatform  = "Terraform"
)

// TerraformIdentity is a block instance's Terraform address and the
// repository-relative root module it belongs to (K9CODESEC-7158). A Terraform
// address is root-relative, so the two together — not either alone — identify
// an instance uniquely in a repository that can call the same module path from
// several root stacks.
type TerraformIdentity struct {
	RootModule string
	ResourceID string
}

// resolved reports whether id has both fields needed to identify an instance
// by its Terraform address rather than by resource name.
func (id TerraformIdentity) resolved() bool {
	return id.RootModule != "" && id.ResourceID != ""
}

// GetDatadogFingerprintHash is the single source of truth for a finding's
// stable identity. It is computed once when the summary is built and reused by
// every report format, so the fingerprint never diverges across outputs.
// nolint:gocritic
func GetDatadogFingerprintHash(
	sciInfo SCIInfo, filePath, platform, resourceType, resourceName, ruleID, vulnLine string,
	terraformIdentity ...TerraformIdentity,
) string {
	return stringToHash(fingerprintInput(
		sciInfo, filePath, platform, resourceType, resourceName, ruleID, vulnLine, terraformIdentity...,
	))
}

// FindingIdentity is what a scan reports one finding for: findings of equal
// identity share a fingerprint, and only the last of them is reported.
func FindingIdentity(v *Vulnerability) string {
	fileName, line, ruleID := fingerprintFields(v)
	return fingerprintInput(SCIInfo{}, fileName, v.Platform, v.ResourceType, v.ResourceName, ruleID, line,
		vulnerabilityTerraformIdentity(v))
}

func vulnerabilityTerraformIdentity(v *Vulnerability) TerraformIdentity {
	return TerraformIdentity{RootModule: v.RootModule, ResourceID: v.ResourceID}
}

// IdentityInput is the fingerprint input of a finding less its line, for a
// finding that is not built yet. It returns false when the platform puts the
// line in the identity, so the input cannot be known before line detection.
func IdentityInput(
	fileName, platform, resourceType, resourceName, ruleID string,
	terraformIdentity ...TerraformIdentity,
) (string, bool) {
	if platform == dockerfilePlatform {
		return "", false
	}
	return fingerprintInput(SCIInfo{}, fileName, platform, resourceType, resourceName, ruleID, "", terraformIdentity...), true
}

// IdentityInputFor is IdentityInput for a finding whose rule ID is not chosen
// yet. ruleID is the id FindingIdentity would choose (see utils.ChooseQueryID).
func IdentityInputFor(
	fileName, platform, resourceType, resourceName, queryID, legacyQueryID string,
	terraformIdentity ...TerraformIdentity,
) (string, bool) {
	return IdentityInput(
		fileName, platform, resourceType, resourceName, utils.ChooseQueryID(queryID, legacyQueryID), terraformIdentity...,
	)
}

// fingerprintFields picks the file, line and rule ID that identify a finding.
// FindingIdentity and CreateSummary's fingerprint must group findings on
// exactly the same fields, or storage could keep one finding where the report
// still shows two, or the reverse.
func fingerprintFields(v *Vulnerability) (file, line, ruleID string) {
	file, line = v.Identity()
	return file, line, utils.ChooseQueryID(v.QueryID, v.LegacyQueryID)
}

// nolint:gocritic
func fingerprintInput(
	sciInfo SCIInfo, filePath, platform, resourceType, resourceName, ruleID, vulnLine string,
	terraformIdentity ...TerraformIdentity,
) string {
	if platform == terraformPlatform && len(terraformIdentity) > 0 {
		if id := terraformIdentity[0]; id.resolved() {
			// The repository, root module and address already pick out exactly
			// one instance; resourceType and resourceName add nothing an
			// address-based identity needs (see K9CODESEC-7158).
			return strings.Join(
				[]string{sciInfo.RepositoryCommitInfo.RepositoryUrl, id.RootModule, id.ResourceID, ruleID}, "|",
			)
		}
	}

	segments := []string{sciInfo.RepositoryCommitInfo.RepositoryUrl, filePath, resourceType, resourceName, ruleID}

	if platform == dockerfilePlatform {
		segments = append(segments, vulnLine)
	}

	return strings.Join(segments, "|")
}

func stringToHash(str string) string {
	hash := sha256.Sum256([]byte(str))
	return hex.EncodeToString(hash[:])
}
