/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"strings"
	"testing"
)

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

func TestParseGitGetterSourceHTTPSGitHubToSSH(t *testing.T) {
	in := "git::https://github.com/DataDog/vault-platform.git//terraform/aws/external-iam?ref=v1.9.4-17"
	repoURL, subdir, ref, ok := parseGitGetterSource(in)
	if !ok {
		t.Fatal("expected ok")
	}
	if repoURL != "ssh://git@github.com/DataDog/vault-platform.git" {
		t.Errorf("repoURL = %q, want ssh URL", repoURL)
	}
	if subdir != "terraform/aws/external-iam" {
		t.Errorf("subdir = %q", subdir)
	}
	if ref != "v1.9.4-17" {
		t.Errorf("ref = %q", ref)
	}
}

func TestNormalizeSCPGitSource(t *testing.T) {
	in := "git@github.com:DataDog/vault-platform//terraform/aws/external-iam?ref=v1.8.2-17"
	got, ok := normalizeSCPGitSource(in)
	if !ok {
		t.Fatal("expected ok")
	}
	want := "git::ssh://git@github.com/DataDog/vault-platform//terraform/aws/external-iam?ref=v1.8.2-17"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalizeHTTPGitToSSH(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			"github",
			"git::https://github.com/DataDog/k8s-platform.git//terraform/modules/datacenter?ref=abc",
			"git::ssh://git@github.com/DataDog/k8s-platform.git//terraform/modules/datacenter?ref=abc",
		},
		{
			"gitlab",
			"git::https://gitlab.com/org/repo//modules/x?ref=v1",
			"git::ssh://git@gitlab.com/org/repo//modules/x?ref=v1",
		},
		{
			"ghe",
			"git::https://github.datadoghq.com/org/repo?ref=main",
			"git::ssh://git@github.datadoghq.com/org/repo?ref=main",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := normalizeHTTPGitToSSH(tc.in)
			if !ok {
				t.Fatal("expected ok")
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
	_, ok := normalizeHTTPGitToSSH("git::ssh://git@github.com/org/repo?ref=main")
	if ok {
		t.Error("already-ssh source should not normalize again")
	}
}

func TestNormalizeImplicitGitHubSource(t *testing.T) {
	in := "github.com/oracle-quickstart/terraform-oci-cis-landing-zone-iam//identity-domains?ref=release-0.3.0"
	got, ok := normalizeImplicitGitHubSource(in)
	if !ok {
		t.Fatal("expected ok")
	}
	want := "git::ssh://git@github.com/oracle-quickstart/terraform-oci-cis-landing-zone-iam//identity-domains?ref=release-0.3.0"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	_, ok = normalizeImplicitGitHubSource("aws-ia/eks-blueprints-addon/aws")
	if ok {
		t.Error("registry short form should not match")
	}
}

func TestNormalizeGitModuleSource(t *testing.T) {
	scp := "git@github.com:DataDog/vault-platform//terraform/aws/external-iam?ref=v1.8.2-17"
	got, ok := normalizeGitModuleSource(scp)
	if !ok {
		t.Fatal("expected scp normalization")
	}
	if !strings.HasPrefix(got, "git::ssh://git@github.com/DataDog/vault-platform") {
		t.Errorf("scp: got %q", got)
	}

	https := "git::https://github.com/DataDog/vault-platform.git//terraform/aws/external-iam?ref=v1.9.4-17"
	got, ok = normalizeGitModuleSource(https)
	if !ok {
		t.Fatal("expected https normalization")
	}
	_, subdir, ref, ok := parseGitGetterSource(https)
	if !ok || ref != "v1.9.4-17" || subdir != "terraform/aws/external-iam" {
		t.Fatalf("parse after https: ok=%v subdir=%q ref=%q", ok, subdir, ref)
	}
}

func TestBareRepoKeyDedupesGitSuffix(t *testing.T) {
	withGit := canonicalSSHCloneURL("ssh://git@github.com/DataDog/vault-platform.git")
	withoutGit := canonicalSSHCloneURL("ssh://git@github.com/DataDog/vault-platform")
	if withGit != withoutGit {
		t.Fatalf("canonical clone URLs differ: %q vs %q", withGit, withoutGit)
	}
	if normalizeGitRepoURL("ssh://git@github.com/DataDog/vault-platform.git") !=
		normalizeGitRepoURL("git@github.com:DataDog/vault-platform") {
		t.Fatal("normalized repo keys should match across spellings")
	}
}
