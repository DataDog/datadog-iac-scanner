package kustomize

import (
	"path/filepath"
	"regexp"
	"strings"
)

var remoteURLSchemes = []string{
	"http://",
	"https://",
	"ssh://",
	"oci://",
	"file://",
}

// scpStyleRE matches "user@host:path" (kustomize SCP-style git remote).
var scpStyleRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]*@[^/:]+:`)

// isRemoteKustomizeRef reports whether s would be treated as a remote
// reference by kustomize at render time (sigs.k8s.io/kustomize/api/internal/git,
// v0.21.1) or by go-getter, plus oci:// from #113.
func isRemoteKustomizeRef(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || isLocalKustomizePath(s) {
		return false
	}
	return hasRemoteURLScheme(s) ||
		hasPrefixCaseInsensitive(s, "git::") ||
		scpStyleRE.MatchString(s) ||
		isSchemelessGithubHost(s) ||
		hasGoGetterDoubleSlash(s) ||
		hasGitSuffixOverDelimiter(s)
}

func isLocalKustomizePath(s string) bool {
	return filepath.IsAbs(s) ||
		strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, "../") ||
		s == "." ||
		s == ".."
}

func hasRemoteURLScheme(s string) bool {
	for _, scheme := range remoteURLSchemes {
		if hasPrefixCaseInsensitive(s, scheme) {
			return true
		}
	}
	return false
}

// isSchemelessGithubHost mirrors kustomize's isStandardGithubHost.
func isSchemelessGithubHost(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "github.com/") || strings.HasPrefix(lower, "github.com:")
}

func hasGoGetterDoubleSlash(s string) bool {
	return strings.Contains(s, "//") && strings.Contains(s, ".")
}

func hasGitSuffixOverDelimiter(s string) bool {
	return strings.Contains(s, ".git") && (strings.Contains(s, "://") || strings.Contains(s, "@"))
}

func hasPrefixCaseInsensitive(s, prefix string) bool {
	return len(prefix) <= len(s) && strings.EqualFold(s[:len(prefix)], prefix)
}
