/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package platform

import "strings"

// Shared Rego libraries bundled with rules. These are not IaC scan targets.
const (
	// LibraryCommon is generic.common — cross-platform Rego utilities.
	LibraryCommon = "common"
	// LibraryDatadog is package datadog — scanner contract helpers (finding, scopes).
	LibraryDatadog = "datadog"
)

// RulePlatformCommon is the metadata.json platform for rules that evaluate all payloads.
const RulePlatformCommon = "common"

// IsCrossPlatformRule reports whether name is the cross-platform rule metadata platform.
func IsCrossPlatformRule(name string) bool {
	return strings.EqualFold(name, RulePlatformCommon)
}

// sharedLibraryIdentity resolves a shared library file key when name refers to one.
func sharedLibraryIdentity(name string) (string, bool) {
	switch strings.ToLower(name) {
	case LibraryCommon:
		return LibraryCommon, true
	case LibraryDatadog:
		return LibraryDatadog, true
	default:
		return "", false
	}
}
