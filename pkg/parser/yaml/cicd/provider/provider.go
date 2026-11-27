/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com) Copyright 2026 Datadog, Inc.
 */

// Package provider owns CI provider selection, independently of YAML parsing.
package provider

import (
	"path/filepath"
	"strings"
)

const (
	Unknown = ""
	GitHub  = "github"
	GitLab  = "gitlab"
	// LegacyEnriched retains the existing CI YAML/GitHub enrichment behavior,
	// including unrecognized CI paths. Provider identity is separate from contract.
	LegacyEnriched     = "cicd/legacy-enriched-v1"
	GitLabDeclarations = "cicd/gitlab-declarations-v1"
)

// Detect identifies only existing CI entrypoint conventions. It does not
// discover new files or inspect/compile their configuration.
func Detect(path string) string {
	base := filepath.Base(path)
	dir := filepath.ToSlash(filepath.Dir(path))
	if dir == ".github/workflows" || strings.HasSuffix(dir, "/.github/workflows") {
		return GitHub
	}
	if base == ".gitlab-ci.yml" || base == ".gitlab-ci.yaml" {
		return GitLab
	}
	if base == "action.yml" || base == "action.yaml" || strings.Contains("/"+dir+"/", "/.github/") {
		return GitHub
	}
	return Unknown
}
