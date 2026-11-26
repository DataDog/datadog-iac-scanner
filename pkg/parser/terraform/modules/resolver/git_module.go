/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"net/url"
	"path/filepath"
	"strings"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

const defaultGitRef = "HEAD"

// GitModuleResolveKey returns a canonical cache key for pinnable git module sources.
// Transport scheme is part of the key so HTTPS and SSH spellings cannot coalesce.
// A missing ref is treated as HEAD so default-branch sources still share an identity.
func GitModuleResolveKey(source, version string) (string, bool) {
	repoURL, subdir, ref, ok := parseGitGetterSource(source)
	if !ok || !pinnableGitRepoURL(repoURL) {
		return "", false
	}
	if ref == "" {
		ref = defaultGitRef
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

func pinnableGitRepoURL(repoURL string) bool {
	if strings.HasPrefix(repoURL, "file://") {
		return false
	}
	parsed, err := url.Parse(repoURL)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case httpsScheme, sshScheme:
		return true
	default:
		return false
	}
}

func bareGitOwnsSource(source string) bool {
	repoURL, _, _, ok := parseGitGetterSource(source)
	return ok && pinnableGitRepoURL(repoURL)
}

func mutableGitRef(ref string) bool {
	return strings.EqualFold(ref, defaultGitRef)
}

// pinnableGitModuleFromGetterSource turns a go-getter download URL into a BareGit
// module. Registry X-Terraform-Get values and default-branch git sources land here
// instead of an unpinned git subprocess.
func pinnableGitModuleFromGetterSource(packageSource, selectedSubdir string) (*tfmodules.ParsedModule, bool) {
	repoURL, subdir, ref, ok := parseGitGetterSource(packageSource)
	if !ok || !pinnableGitRepoURL(repoURL) {
		return nil, false
	}
	if selectedSubdir != "" {
		subdir = selectedSubdir
	}
	if ref == "" {
		ref = defaultGitRef
	}
	source := "git::" + repoURL
	if subdir != "" && subdir != "." {
		source += "//" + strings.TrimPrefix(filepath.ToSlash(subdir), "/")
	}
	return &tfmodules.ParsedModule{Source: source + "?ref=" + url.QueryEscape(ref)}, true
}
