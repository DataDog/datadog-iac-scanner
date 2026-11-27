/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com) Copyright 2026 Datadog, Inc.
 */

package names

import (
	"path/filepath"
	"strings"
)

// IsGitLabFile identifies canonical GitLab CI entrypoints. Custom entrypoints
// and fragments are deliberately outside declaration-only discovery.
func IsGitLabFile(path string) bool {
	base := filepath.Base(path)
	dir := filepath.ToSlash(filepath.Dir(path))
	// Preserve GitHub workflows even when their filename resembles GitLab CI.
	if dir == ".github/workflows" || strings.HasSuffix(dir, "/.github/workflows") {
		return false
	}
	return base == ".gitlab-ci.yml" || base == ".gitlab-ci.yaml"
}
