/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com) Copyright 2026 Datadog, Inc.
 */

// Package provider owns CI provider selection, independently of YAML parsing.
package provider

import (
	"path"
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
func Detect(filename string) string {
	if detected := Entrypoint(filename); detected != Unknown {
		return detected
	}
	dir := path.Dir(strings.ReplaceAll(filename, `\`, "/"))
	if strings.Contains("/"+dir+"/", "/.github/") {
		return GitHub
	}
	return Unknown
}

// Entrypoint identifies canonical CI files independently of their contents.
// Other files may still be discovered by content, but must not inherit a
// provider merely because an unrelated YAML file lives in the same directory.
func Entrypoint(filename string) string {
	filename = strings.ReplaceAll(filename, `\`, "/")
	base, dir := path.Base(filename), path.Dir(filename)
	if (dir == ".github/workflows" || strings.HasSuffix(dir, "/.github/workflows")) &&
		(path.Ext(base) == ".yml" || path.Ext(base) == ".yaml") {
		return GitHub
	}
	if base == ".gitlab-ci.yml" || base == ".gitlab-ci.yaml" {
		return GitLab
	}
	if base == "action.yml" || base == "action.yaml" {
		return GitHub
	}
	return Unknown
}
