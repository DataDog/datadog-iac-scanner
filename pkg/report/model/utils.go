/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

const (
	kicsRuleIDTag   = "KICS_RuleID:%s"
	cweTag          = "CWE:%s"
	resourceTypeTag = "IAC_RESOURCE_TYPE:%s"
	resourceNameTag = "IAC_RESOURCE_NAME:%s"
)

// nolint:gocritic
func GetScanDurationTag(summary model.Summary) string {
	scanDuration := int(summary.Times.End.Sub(summary.Times.Start).Seconds())
	executionTimeTag := fmt.Sprintf(executionTimeTag, scanDuration)
	return executionTimeTag
}

func GetDiffAwareEnabledTag(diffAware model.DiffAware) string {
	return fmt.Sprintf(diffAwareEnabledTag, diffAware.Enabled)
}

func GetDiffAwareConfigDigestTag(diffAware model.DiffAware) string {
	return fmt.Sprintf(diffAwareConfigDigestTag, diffAware.ConfigDigest)
}

func GetDiffAwareBaseShaTag(diffAware model.DiffAware) string {
	return fmt.Sprintf(diffAwareBaseShaTag, diffAware.BaseSha)
}

func GetDiffAwareFilesTag(diffAware model.DiffAware) string {
	return fmt.Sprintf(diffAwareFileTag, diffAware.Files)
}

func GetCategoryTag(category string) string {
	return fmt.Sprintf(categoryTag, category)
}

func GetKICSRuleIDTag(ruleID string) string {
	return fmt.Sprintf(kicsRuleIDTag, ruleID)
}

func GetCWETag(cwe string) string {
	return fmt.Sprintf(cweTag, cwe)
}

func GetResourceTypeTag(resourceType string) string {
	return fmt.Sprintf(resourceTypeTag, resourceType)
}

func GetResourceNameTag(resourceName string) string {
	return fmt.Sprintf(resourceNameTag, resourceName)
}

func GetScannedFilesCountTag(scannedFiles int) string {
	return fmt.Sprintf(scannedFileCountTag, scannedFiles)
}

func GetPlatformTag(platform string) string {
	return fmt.Sprintf(platformTag, platform)
}

func GetProviderTag(provider string) string {
	return fmt.Sprintf(providerTag, provider)
}

func GetSeverityTag(severity model.Severity) string {
	return fmt.Sprintf(severityTag, severity)
}

// stringToHash returns a SHA256 hash of the input string.
func StringToHash(str string) string {
	hash := sha256.New()
	hash.Write([]byte(str))
	hashed := hash.Sum(nil)
	return hex.EncodeToString(hashed)
}

// toSlug turns a string to lowercase and replaces any space by "-"
// This is the exact same function as in the default rules for consistency
// Those functions must be kept up to date
// https://github.com/DataDog/datadog-iac-scanner-default-rules/blob/main/cmd/rules/rules.go#L363
func toSlug(name string) string {
	parts := []string{}
	part := strings.Builder{}
	for _, c := range name {
		if unicode.IsUpper(c) {
			part.WriteRune(unicode.ToLower(c))
		} else if unicode.IsDigit(c) || unicode.IsLower(c) {
			part.WriteRune(c)
		} else if part.Len() > 0 {
			parts = append(parts, part.String())
			part = strings.Builder{}
		}
	}
	if part.Len() > 0 {
		parts = append(parts, part.String())
	}
	return strings.Join(parts, "-")
}
