/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"net/url"
	"strings"
)

// GitModuleResolveKey returns a canonical cache key for pinned git module sources.
// Transport scheme is part of the key so disabled spellings cannot coalesce with HTTPS.
// Returns false when the source is not a git:: module with ref= (not BareGit-owned).
func GitModuleResolveKey(source, version string) (string, bool) {
	repoURL, subdir, ref, ok := parseGitGetterSource(source)
	if !ok || ref == "" {
		return "", false
	}
	if v := strings.TrimSpace(version); v != "" && v != ref {
		ref = ref + "\x00" + v
	}
	return gitModuleTransportKey(repoURL) + "\x00" + normalizeGitRepoURL(repoURL) + "\x00" + ref + "\x00" + subdir, true
}

func gitModuleTransportKey(repoURL string) string {
	parsed, err := url.Parse(repoURL)
	if err != nil || parsed.Scheme == "" {
		return "unknown"
	}
	return strings.ToLower(parsed.Scheme)
}

// bareGitOwnsSource reports whether BareGitResolver handles this module source.
func bareGitOwnsSource(source string) bool {
	repoURL, _, ref, ok := parseGitGetterSource(source)
	if !ok || ref == "" {
		return false
	}
	// Local file:// git repos stay on go-getter (small, used in unit tests).
	if strings.HasPrefix(repoURL, "file://") {
		return false
	}
	return true
}
