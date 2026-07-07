/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import "strings"

// GitModuleResolveKey returns a canonical cache key for pinned git module sources.
// Identical content folds transport spellings (https vs ssh, .git suffix) into one key.
// Returns false when the source is not a git:: module with ref= (not BareGit-owned).
func GitModuleResolveKey(source, version string) (string, bool) {
	repoURL, subdir, ref, ok := parseGitGetterSource(source)
	if !ok || ref == "" {
		return "", false
	}
	if v := strings.TrimSpace(version); v != "" && v != ref {
		ref = ref + "\x00" + v
	}
	return normalizeGitRepoURL(repoURL) + "\x00" + ref + "\x00" + subdir, true
}
