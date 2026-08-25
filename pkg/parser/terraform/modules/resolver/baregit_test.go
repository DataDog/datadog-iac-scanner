/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

func TestResolveUsesCachedSHAArchiveWithoutDNS(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	r := NewBareGitResolver(t.TempDir(), "github.com")
	remote := r.getOrInitRemote("https://github.com/org/repo.git")
	dest := archiveCacheDir(remote.extractBase, sha)
	if err := os.MkdirAll(dest, dirPerm); err != nil {
		t.Fatal(err)
	}
	marker := archiveMarkerPath(remote.extractBase, sha, ".")
	if err := os.MkdirAll(filepath.Dir(marker), dirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, nil, cacheFilePerms); err != nil {
		t.Fatal(err)
	}

	r.policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		t.Fatal("cached SHA extract must not resolve DNS")
		return nil, errors.New("offline")
	}

	res, err := r.Resolve(context.Background(), &tfmodules.ParsedModule{
		Source: "git::https://github.com/org/repo.git?ref=" + sha,
	})
	if err != nil {
		t.Fatalf("expected a cache hit without DNS, got %v", err)
	}
	if res.PackageRoot != dest {
		t.Fatalf("PackageRoot = %q, want %q", res.PackageRoot, dest)
	}
}

func TestBareGitResolverRejectsDisallowedHost(t *testing.T) {
	r := NewBareGitResolver(t.TempDir(), "allowed.example")
	_, err := r.Resolve(context.Background(), &tfmodules.ParsedModule{
		Source: "git::https://disallowed.example/org/repo.git?ref=main",
	})
	if err == nil || !strings.Contains(err.Error(), `module host "disallowed.example" is not in --module-host-allowlist`) {
		t.Fatalf("expected host allowlist error, got %v", err)
	}
}

func TestBareGitResolverRejectsUnpinnableTransport(t *testing.T) {
	r := NewBareGitResolver(t.TempDir())
	for _, source := range []string{
		"git::http://modules.example/org/repo.git?ref=main",
		"git::git://modules.example/org/repo.git?ref=main",
	} {
		t.Run(source, func(t *testing.T) {
			_, err := r.Resolve(t.Context(), &tfmodules.ParsedModule{Source: source})
			if err == nil || !strings.Contains(err.Error(), "destination cannot be pinned") {
				t.Fatalf("expected unpinnable transport rejection, got %v", err)
			}
		})
	}
}

func TestBareGitResolverRejectsSSHWithoutPinnedHostKey(t *testing.T) {
	t.Setenv(knownHostsEnvVar, writeKnownHosts(t, ""))
	r := NewBareGitResolver(t.TempDir())
	for _, source := range []string{
		"git::ssh://git@modules.example/org/repo.git?ref=main",
		"git@modules.example:org/repo.git?ref=main",
	} {
		t.Run(source, func(t *testing.T) {
			_, err := r.Resolve(t.Context(), &tfmodules.ParsedModule{Source: source})
			if err == nil || !strings.Contains(err.Error(), "is not pinned in known_hosts") {
				t.Fatalf("expected unpinned host key rejection, got %v", err)
			}
		})
	}
}

func TestBareGitResolverRejectsSSHPasswordInSource(t *testing.T) {
	t.Setenv(knownHostsEnvVar, writeKnownHosts(t, ""))
	r := NewBareGitResolver(t.TempDir())
	_, err := r.Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: "git::ssh://git:secret@modules.example/org/repo.git?ref=main",
	})
	if err == nil || !strings.Contains(err.Error(), "does not accept a password") {
		t.Fatalf("expected embedded password rejection, got %v", err)
	}
}

func TestBareGitResolverRejectsHTTPSCredentialsInSource(t *testing.T) {
	r := NewBareGitResolver(t.TempDir())
	_, err := r.Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: "git::https://user:secret@modules.example/org/repo.git?ref=main",
	})
	if err == nil || !strings.Contains(err.Error(), "does not accept credentials embedded") {
		t.Fatalf("expected embedded credential rejection, got %v", err)
	}
}

func TestBareGitResolverRejectsPrivateHTTPSDestination(t *testing.T) {
	r := NewBareGitResolver(t.TempDir())
	r.policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}
	_, err := r.Resolve(t.Context(), &tfmodules.ParsedModule{
		Source: "git::https://modules.example/org/repo.git?ref=main",
	})
	if err == nil || !strings.Contains(err.Error(), "not a public unicast destination") {
		t.Fatalf("expected private destination rejection, got %v", err)
	}
}

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

// TestGetOrInitRemoteSeparatesStorePerTransport pins the transport into the cache
// identity. A shared store measured much slower on a large repository: extraction
// serializes on a per-(clone, sha) lock, so two spellings of one repository queue
// behind each other rather than materializing concurrently.
func TestGetOrInitRemoteSeparatesStorePerTransport(t *testing.T) {
	r := NewBareGitResolver(t.TempDir(), "github.com")
	https := r.getOrInitRemote("https://github.com/org/repo.git")
	ssh := r.getOrInitRemote("ssh://git@github.com/org/repo")

	if https.barePath == ssh.barePath {
		t.Errorf("transports must not share a bare clone, both used %q", https.barePath)
	}
	if https.transport != httpsScheme || ssh.transport != sshScheme {
		t.Errorf("transports = %q, %q; want https, ssh", https.transport, ssh.transport)
	}
	if https.cloneURL == ssh.cloneURL {
		t.Errorf("each transport needs its own remote URL, both were %q", https.cloneURL)
	}
}

// TestGetOrInitRemoteReusesStorePerTransport checks the same spelling still resolves
// to one store, so repeated sources in a repository do not re-clone.
func TestGetOrInitRemoteReusesStorePerTransport(t *testing.T) {
	r := NewBareGitResolver(t.TempDir(), "github.com")
	first := r.getOrInitRemote("https://github.com/org/repo.git//a?ref=v1")
	second := r.getOrInitRemote("https://github.com/org/repo.git//b?ref=v1")
	if first.bareRepo != second.bareRepo {
		t.Fatal("two sources in one repository must share a bare clone")
	}
}

// TestCloneErrorIsScopedToTransport keeps an https failure (no credentials, say) from
// poisoning the ssh attempt that would have worked for the same repo.
func TestCloneErrorIsScopedToTransport(t *testing.T) {
	r := NewBareGitResolver(t.TempDir(), "github.com")
	const sentinel = "https clone failed for want of credentials"

	https := r.getOrInitRemote("https://github.com/org/repo.git")
	https.cloneErrs = map[string]error{https.transport: errors.New(sentinel)}
	if err := https.ensureClone(context.Background()); err == nil || !strings.Contains(err.Error(), sentinel) {
		t.Fatalf("https should see its own memoized failure, got %v", err)
	}

	ssh := r.getOrInitRemote("ssh://git@github.com/org/repo")
	// Reject the destination so the attempt fails locally rather than reaching out.
	ssh.policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}
	err := ssh.ensureClone(context.Background())
	if err == nil {
		t.Fatal("expected the ssh attempt to fail on its own terms")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Errorf("ssh inherited the https failure: %v", err)
	}
}

func TestGitCloneRetryable(t *testing.T) {
	transient := errors.New("exit status 128")
	cases := []struct {
		name string
		out  string
		err  error
		want bool
	}{
		{name: "success", err: nil, want: true},
		{name: "transient network", out: "unable to access 'https://github.com/org/repo.git/'", err: transient, want: true},
		{
			name: "missing username",
			out:  "fatal: could not read Username for 'https://github.com': terminal prompts disabled",
			err:  transient,
			want: false,
		},
		{name: "authentication failed", out: "fatal: Authentication failed for 'https://github.com/org/repo.git/'", err: transient, want: false},
		{name: "invalid password", out: "remote: Invalid username or password", err: transient, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := gitCloneRetryable([]byte(tc.out), tc.err); got != tc.want {
				t.Fatalf("gitCloneRetryable(%q, %v) = %v, want %v", tc.out, tc.err, got, tc.want)
			}
		})
	}
}

func TestParseGitGetterSourcePreservesHTTPS(t *testing.T) {
	in := "git::https://github.com/DataDog/vault-platform.git//terraform/aws/external-iam?ref=v1.9.4-17"
	repoURL, subdir, ref, ok := parseGitGetterSource(in)
	if !ok {
		t.Fatal("expected ok")
	}
	if repoURL != "https://github.com/DataDog/vault-platform.git" {
		t.Errorf("repoURL = %q, want HTTPS URL", repoURL)
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

func TestNormalizeImplicitGitHubSource(t *testing.T) {
	in := "github.com/oracle-quickstart/terraform-oci-cis-landing-zone-iam//identity-domains?ref=release-0.3.0"
	got, ok := normalizeImplicitGitHubSource(in)
	if !ok {
		t.Fatal("expected ok")
	}
	want := "git::https://github.com/oracle-quickstart/terraform-oci-cis-landing-zone-iam//identity-domains?ref=release-0.3.0"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	_, ok = normalizeImplicitGitHubSource("aws-ia/eks-blueprints-addon/aws")
	if ok {
		t.Error("registry short form should not match")
	}
}

func TestNormalizeGitModuleSourceForGetterPreservesHTTPS(t *testing.T) {
	https := "git::https://github.com/DataDog/vault-platform.git//terraform/aws/external-iam?ref=v1.9.4-17"
	if got, ok := normalizeGitModuleSourceForGetter(https); ok {
		t.Fatalf("getter normalization must not rewrite git::https, got %q", got)
	}
	full, ok := normalizeGitModuleSource(https)
	if ok || full != https {
		t.Fatalf("baregit resolver must preserve HTTPS, got %q ok=%v", full, ok)
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
	if ok || got != https {
		t.Fatalf("expected HTTPS to remain unchanged, got %q ok=%v", got, ok)
	}
	_, subdir, ref, ok := parseGitGetterSource(https)
	if !ok || ref != "v1.9.4-17" || subdir != "terraform/aws/external-iam" {
		t.Fatalf("parse after https: ok=%v subdir=%q ref=%q", ok, subdir, ref)
	}
}

func TestCanonicalHTTPSCloneURL(t *testing.T) {
	got := canonicalHTTPSCloneURL("https://github.com:8443/DataDog/vault-platform.git?ref=v1#fragment")
	if got != "https://github.com:8443/DataDog/vault-platform.git" {
		t.Fatalf("canonical clone URL = %q", got)
	}
	if got := canonicalHTTPSCloneURL("https://user:token@github.com/DataDog/vault-platform.git"); got != "" {
		t.Fatalf("clone URL with embedded credentials must be rejected, got %q", got)
	}
	if got := canonicalHTTPSCloneURL("ssh://git@github.com/DataDog/vault-platform.git"); got != "" {
		t.Fatalf("SSH clone URL must be rejected, got %q", got)
	}
}

func TestBareRepoRejectsUnsafeCachedConfig(t *testing.T) {
	root := t.TempDir()
	barePath := root + "/repo.git"
	runGit(t, root, "init", "--bare", barePath)
	repo := &bareRepo{barePath: barePath}
	if !repo.cachedConfigIsSafe(t.Context()) {
		t.Fatal("standard bare repository config must be accepted")
	}
	runGit(t, root, "--git-dir", barePath, "config", "http.https://modules.example.proxy", "")
	if repo.cachedConfigIsSafe(t.Context()) {
		t.Fatal("URL-specific proxy config must invalidate the cache")
	}
}
