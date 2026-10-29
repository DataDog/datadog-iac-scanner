package giturl

import "strings"

// Normalize strips scheme prefixes, trailing .git, and trailing slashes
// so that URLs referring to the same repo compare equal regardless of transport.
//
//	"https://github.com/org/repo.git"  →  "github.com/org/repo"
//	"git@github.com:org/repo.git"      →  "github.com/org/repo"
//	"ssh://git@github.com/org/repo"    →  "github.com/org/repo"
func Normalize(raw string) string {
	// Strip getter protocol prefix (git::, etc.)
	if idx := strings.Index(raw, "::"); idx != -1 {
		raw = raw[idx+2:]
	}
	// Strip query string.
	if idx := strings.Index(raw, "?"); idx != -1 {
		raw = raw[:idx]
	}
	// Strip the transport scheme BEFORE removing the go-getter subdir separator.
	// Otherwise the "//" in "https://" is mistaken for the subdir marker and the
	// URL collapses to "https:", so https sources never match SCP-form remotes.
	for _, scheme := range []string{"https://", "http://", "ssh://", "git://"} {
		raw = strings.TrimPrefix(raw, scheme)
	}
	// SCP-style git@host:org/repo → host/org/repo
	if at := strings.IndexByte(raw, '@'); at != -1 {
		after := raw[at+1:]
		raw = strings.Replace(after, ":", "/", 1)
	}
	// Strip the go-getter subdir separator, now unambiguous after scheme removal.
	if idx := strings.Index(raw, "//"); idx != -1 {
		raw = raw[:idx]
	}
	raw = strings.TrimSuffix(raw, ".git")
	raw = strings.TrimSuffix(raw, "/")
	return raw
}
