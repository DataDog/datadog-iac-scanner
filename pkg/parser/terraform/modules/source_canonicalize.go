/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tfmodules

import (
	"net/url"
	"strings"
)

// CanonicalizeRemoteModuleSourceWithType normalizes a git/registry module source string for
// equality comparison, stripping textual differences that don't change identity: git:: prefix,
// query params (?ref=, ?depth=, ...), .git suffix, userinfo. Registry sources are parsed and
// rebuilt into canonical host/namespace/name/provider/subdir form. Version/ref is intentionally
// excluded from the result - same-source-different-version calls must be disambiguated separately.
func CanonicalizeRemoteModuleSourceWithType(source, sourceType string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}
	if sourceType == stringRegistry {
		stripped, _, _ := strings.Cut(source, "@")
		if addr, err := ParseRegistryModuleSource(stripped); err == nil {
			return addr.String()
		}
		return stripped
	}
	s := strings.TrimPrefix(source, "git::")
	s, _, _ = strings.Cut(s, "?")
	if parsed, err := url.Parse(s); err == nil && parsed.Scheme != "" {
		parsed.User = nil
		s = parsed.String()
	} else if at := strings.Index(s, "@"); at > 0 && strings.Contains(s[at+1:], ":") {
		s = s[at+1:]
	}
	s = strings.Replace(s, ".git//", "//", 1)
	return strings.TrimSuffix(s, ".git")
}

// CanonicalizeRemoteModuleSource is CanonicalizeRemoteModuleSourceWithType for a caller that
// doesn't already know the source type.
func CanonicalizeRemoteModuleSource(source string) string {
	typeProbe, _, _ := strings.Cut(strings.TrimSpace(source), "@")
	sourceType, _ := DetectModuleSourceType(typeProbe)
	return CanonicalizeRemoteModuleSourceWithType(source, sourceType)
}
