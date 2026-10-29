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
	kubernetesPlatform = "Kubernetes"
	// unnamedResource is the resourceName a rule reports for an object it
	// does not identify by name (kubelet and API server configuration files).
	unnamedResource = "n/a"
)

// KustomizeIdentity is a Kustomize-rendered object's render root (the
// repository-relative kustomization directory) and its resource ID within that
// render: "apiGroup/kind|namespace|name" read from the rendered object, or
// "apiGroup/kind" for an object its rule reports as unnamed. Like a Terraform
// address within its root module, the two together identify the object in the
// repository whatever file it is written in.
type KustomizeIdentity struct {
	RenderRoot string
	ResourceID string
}

func (id KustomizeIdentity) resolved() bool {
	return id.RenderRoot != "" && id.ResourceID != ""
}

func vulnerabilityKustomizeIdentity(v *Vulnerability) KustomizeIdentity {
	return KustomizeIdentity{RenderRoot: v.RenderRoot, ResourceID: v.KustomizeResourceID}
}

// GetDatadogFingerprintHash is the single source of truth for a finding's
// stable identity. It is computed once when the summary is built and reused by
// every report format, so the fingerprint never diverges across outputs.
// nolint:gocritic
func GetDatadogFingerprintHash(
	sciInfo SCIInfo, filePath, platform, resourceType, resourceName, ruleID, vulnLine, moduleCallChain string,
	kustomizeIdentity ...KustomizeIdentity,
) string {
	return stringToHash(fingerprintInput(
		sciInfo, filePath, platform, resourceType, resourceName, ruleID, vulnLine, moduleCallChain, kustomizeIdentity...,
	))
}

// FindingIdentity is what a scan reports one finding for: findings of equal
// identity share a fingerprint, and only the last of them is reported.
func FindingIdentity(v *Vulnerability) string {
	fileName, line, ruleID := fingerprintFields(v)
	kID := vulnerabilityKustomizeIdentity(v)
	if id, ok := chainedIdentity(fileName, v.Platform, v.ResourceType, v.ResourceName, ruleID, kID); ok {
		return id.WithChain(v.IdentityChain())
	}
	// SCIInfo is constant within a scan; an empty value yields the same grouping.
	return fingerprintInput(SCIInfo{}, fileName, v.Platform, v.ResourceType, v.ResourceName, ruleID, line, v.IdentityChain(), kID)
}

// ChainedIdentity is the FindingIdentity of a finding whose identity does not
// include its line, less its module call chain: the finding's identity under
// any call chain is built from it without rebuilding the rest.
type ChainedIdentity struct {
	prefix  string
	chained bool
}

// IdentityBeforeLine returns v's identity less its call chain. It returns
// false when v's platform puts the line in the identity.
func IdentityBeforeLine(v *Vulnerability) (ChainedIdentity, bool) {
	fileName, _, ruleID := fingerprintFields(v)
	return chainedIdentity(fileName, v.Platform, v.ResourceType, v.ResourceName, ruleID, vulnerabilityKustomizeIdentity(v))
}

// ChainedIdentityFor is IdentityBeforeLine for a finding that is not built
// yet. ruleID is the id FindingIdentity would choose (see utils.ChooseQueryID);
// kustomizeIdentity is the finding's, when its document was rendered.
func ChainedIdentityFor(
	fileName, platform, resourceType, resourceName, queryID, legacyQueryID string,
	kustomizeIdentity ...KustomizeIdentity,
) (ChainedIdentity, bool) {
	return chainedIdentity(
		fileName, platform, resourceType, resourceName, utils.ChooseQueryID(queryID, legacyQueryID), kustomizeIdentity...,
	)
}

// chainedIdentity builds a finding's identity less its line. A rendered
// Kubernetes finding already names its render root, so it takes no chain.
func chainedIdentity(
	fileName, platform, resourceType, resourceName, ruleID string, kustomizeIdentity ...KustomizeIdentity,
) (ChainedIdentity, bool) {
	if platform == dockerfilePlatform {
		return ChainedIdentity{}, false
	}
	rendered := isKubernetes(platform) && len(kustomizeIdentity) > 0 && kustomizeIdentity[0].resolved()
	return ChainedIdentity{
		prefix: fingerprintInput(
			SCIInfo{}, fileName, platform, resourceType, resourceName, ruleID, "", "", kustomizeIdentity...,
		),
		chained: !rendered && (platform == terraformPlatform || isKubernetes(platform)),
	}, true
}

func isKubernetes(platform string) bool {
	return strings.EqualFold(platform, kubernetesPlatform)
}

// WithChain is the identity of the finding reported under chain.
func (id ChainedIdentity) WithChain(chain string) string {
	if !id.chained || chain == "" {
		return id.prefix
	}
	return id.prefix + "|" + chain
}

// AppendWithChain appends WithChain(chain) to dst, so a caller looking the
// identity up can reuse one buffer instead of allocating a string per lookup.
func (id ChainedIdentity) AppendWithChain(dst []byte, chain string) []byte {
	dst = append(dst, id.prefix...)
	if id.chained && chain != "" {
		dst = append(dst, '|')
		dst = append(dst, chain...)
	}
	return dst
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
	sciInfo SCIInfo, filePath, platform, resourceType, resourceName, ruleID, vulnLine, moduleCallChain string,
	kustomizeIdentity ...KustomizeIdentity,
) string {
	if isKubernetes(platform) && len(kustomizeIdentity) > 0 {
		if id := kustomizeIdentity[0]; id.resolved() {
			// The render root and the rendered object identify the finding: the
			// file it is written in is not part of it, unless the rule reports
			// the object unnamed and the file is all that tells two apart.
			segments := []string{sciInfo.RepositoryCommitInfo.RepositoryUrl, id.RenderRoot}
			if resourceName == unnamedResource {
				segments = append(segments, filePath)
			}
			return strings.Join(append(segments, id.ResourceID, ruleID), "|")
		}
	}

	segments := []string{sciInfo.RepositoryCommitInfo.RepositoryUrl, filePath, resourceType, resourceName, ruleID}

	switch {
	case platform == dockerfilePlatform:
		segments = append(segments, vulnLine)
	case platform == terraformPlatform, isKubernetes(platform):
		// Same resource reached through different module call paths, or
		// rendered by different kustomizations, is a distinct finding.
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

// IdentityChain is the chain folded into v's identity: its module call chain
// for Terraform, its render root for a rendered Kubernetes document.
func (v *Vulnerability) IdentityChain() string {
	if v.ModuleCallChain != "" {
		return v.ModuleCallChain
	}
	return v.RenderRoot
}

// IdentityChain is FileMetadata's counterpart of Vulnerability.IdentityChain.
func (f *FileMetadata) IdentityChain() string {
	if f.ModuleCallChain != "" {
		return f.ModuleCallChain
	}
	return f.RenderRoot
}
