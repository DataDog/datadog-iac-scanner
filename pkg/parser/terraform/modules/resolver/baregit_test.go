/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import "testing"

func TestNormalizeGitRepoURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"https with .git", "https://github.com/org/repo.git", "github.com/org/repo"},
		{"https without .git", "https://github.com/org/repo", "github.com/org/repo"},
		{"scp form", "git@github.com:org/repo.git", "github.com/org/repo"},
		{"ssh form", "ssh://git@github.com/org/repo.git", "github.com/org/repo"},
		{"git getter prefix", "git::https://github.com/org/repo.git", "github.com/org/repo"},
		{"with subdir", "https://github.com/org/repo.git//modules/child", "github.com/org/repo"},
		{"with subdir and query", "git::https://github.com/org/repo.git//mods/x?ref=v1.0", "github.com/org/repo"},
		{"trailing slash", "https://github.com/org/repo/", "github.com/org/repo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeGitRepoURL(tc.in); got != tc.want {
				t.Errorf("normalizeGitRepoURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestNormalizeGitRepoURLSchemeMatchesSCP guards the regression where an https
// source and an SCP-form remote for the same repo normalized to different keys
// (the "//" in "https://" was wrongly treated as the subdir separator),
// causing every self-referential git module to miss the local checkout.
func TestNormalizeGitRepoURLSchemeMatchesSCP(t *testing.T) {
	https := normalizeGitRepoURL("https://github.com/org/repo.git")
	scp := normalizeGitRepoURL("git@github.com:org/repo.git")
	if https != scp {
		t.Fatalf("https form %q must normalize equal to scp form %q", https, scp)
	}
}
