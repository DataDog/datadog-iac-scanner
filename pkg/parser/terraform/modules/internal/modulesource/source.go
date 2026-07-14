package modulesource

import "strings"

// NormalizeGit normalizes unambiguous Git source forms.
func NormalizeGit(source string) (string, bool) {
	source = strings.TrimSpace(source)
	if source == "" {
		return "", false
	}
	if strings.HasPrefix(source, "git::") {
		return source, true
	}
	if strings.HasPrefix(source, "ssh://") {
		return "git::" + source, true
	}
	if !strings.Contains(source, "::") {
		if at := strings.IndexByte(source, '@'); at > 0 {
			rest := source[at+1:]
			slash := strings.IndexByte(rest, '/')
			if colon := strings.IndexByte(rest, ':'); colon > 0 &&
				(slash < 0 || colon < slash) &&
				colon < len(rest)-1 {
				return "git::ssh://" + source[:at] + "@" + rest[:colon] + "/" + rest[colon+1:], true
			}
		}
		if strings.HasPrefix(source, "github.com/") &&
			(strings.Contains(source, "//") || strings.Contains(source, "ref=")) {
			return "git::ssh://git@" + source, true
		}
	}
	return source, false
}
