/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// initBareRepo creates an empty bare repository for exercising git invocations that
// only need a valid git directory.
func initBareRepo(t *testing.T) string {
	t.Helper()
	bare := filepath.Join(t.TempDir(), "repo.git")
	if out, err := exec.Command("git", "init", "--bare", "-q", bare).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	return bare
}

func publicAddressPolicy(address string) *httpDestinationPolicy {
	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP(address)}, nil
	}
	return policy
}

// TestArchiveCommandPinsSSHPromisorRemote reads back the remote git would lazily fetch
// missing blobs from. A blob:none clone makes git archive fetch on demand, so that
// remote has to name the address the policy validated.
func TestArchiveCommandPinsSSHPromisorRemote(t *testing.T) {
	const host = "modules.example"
	t.Setenv(knownHostsEnvVar, writeKnownHosts(t, knownHostsLineFor(t, host)))

	repo := &bareRemote{
		transport: sshScheme,
		cloneURL:  "ssh://git@" + host + "/org/repo.git",
		bareRepo: &bareRepo{
			barePath: initBareRepo(t),
			policy:   publicAddressPolicy("140.82.121.4"),
		},
	}

	out, err := runArchiveCommand(
		t, repo, []string{"config", "--get", "remote.origin.url"},
	)
	if err != nil {
		t.Fatalf("archive command: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "ssh://git@140.82.121.4/org/repo.git" {
		t.Fatalf("promisor remote = %q, want the validated address", got)
	}
}

// TestArchiveCommandRoutesHTTPSThroughProxy checks that a lazy blob fetch during
// archive is proxied rather than sent straight out.
func TestArchiveCommandRoutesHTTPSThroughProxy(t *testing.T) {
	repo := &bareRemote{
		transport: httpsScheme,
		cloneURL:  "https://modules.example/org/repo.git",
		bareRepo: &bareRepo{
			barePath: initBareRepo(t),
			policy:   publicAddressPolicy("140.82.121.4"),
		},
	}

	out, err := runArchiveCommand(
		t, repo, []string{"config", "--get-regexp", `^http\..*proxy$`},
	)
	if err != nil {
		t.Fatalf("archive command: %v", err)
	}
	config := string(out)
	if !strings.Contains(config, "http.proxy http://127.0.0.1:") {
		t.Errorf("expected archive to run behind the local policy proxy, got %q", config)
	}
	if !strings.Contains(config, repo.cloneURL) {
		t.Errorf("expected a remote-scoped proxy setting for %q, got %q", repo.cloneURL, config)
	}
}

// TestArchiveCommandRejectsUnvalidatedDestination makes sure the archive step cannot
// run at all when the destination fails the policy.
func TestArchiveCommandRejectsUnvalidatedDestination(t *testing.T) {
	const host = "modules.example"
	t.Setenv(knownHostsEnvVar, writeKnownHosts(t, knownHostsLineFor(t, host)))

	repo := &bareRemote{
		transport: sshScheme,
		cloneURL:  "ssh://git@" + host + "/org/repo.git",
		bareRepo: &bareRepo{
			barePath: initBareRepo(t),
			policy:   publicAddressPolicy("169.254.169.254"),
		},
	}

	_, err := runArchiveCommand(t, repo, []string{"config", "--list"})
	if err == nil || !strings.Contains(err.Error(), "not a public unicast destination") {
		t.Fatalf("expected the archive step to refuse an unvalidated destination, got %v", err)
	}
}

// TestLocalCloneArchiveCommandKeepsStdoutClean guards the tar stream against stderr
// being folded into it.
func TestLocalCloneArchiveCommandKeepsStdoutClean(t *testing.T) {
	bare := initBareRepo(t)
	preps, err := localCloneArchiveCommand(bare)(
		context.Background(), []string{"config", "--get", "core.bare"},
	)
	if err != nil {
		t.Fatalf("local archive command: %v", err)
	}
	if len(preps) != 1 {
		t.Fatalf("got %d archive preps, want 1", len(preps))
	}
	defer preps[0].close()
	out, err := preps[0].cmd.Output()
	if err != nil {
		t.Fatalf("local archive command: %v", err)
	}
	if strings.TrimSpace(string(out)) != "true" {
		t.Fatalf("unexpected output %q", out)
	}
}

func TestArchiveCommandPreparesEverySSHAddress(t *testing.T) {
	const host = "modules.example"
	t.Setenv(knownHostsEnvVar, writeKnownHosts(t, knownHostsLineFor(t, host)))

	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("140.82.121.4"), net.ParseIP("140.82.121.3")}, nil
	}
	repo := &bareRemote{
		transport: sshScheme,
		cloneURL:  "ssh://git@" + host + "/org/repo.git",
		bareRepo: &bareRepo{
			barePath: initBareRepo(t),
			policy:   policy,
		},
	}

	preps, err := repo.archiveCommand(context.Background(), []string{"rev-parse", "--git-dir"})
	if err != nil {
		t.Fatalf("archive command: %v", err)
	}
	if len(preps) != 2 {
		t.Fatalf("got %d archive preps, want one per validated address", len(preps))
	}
	joined := strings.Join(preps[0].cmd.Args, " ") + "\n" + strings.Join(preps[1].cmd.Args, " ")
	if !strings.Contains(joined, "remote.origin.url=ssh://git@140.82.121.4/org/repo.git") ||
		!strings.Contains(joined, "remote.origin.url=ssh://git@140.82.121.3/org/repo.git") {
		t.Fatalf("archive preps did not pin both addresses:\n%s", joined)
	}
}

func runArchiveCommand(t *testing.T, repo *bareRemote, args []string) ([]byte, error) {
	t.Helper()
	preps, err := repo.archiveCommand(context.Background(), args)
	if err != nil {
		return nil, err
	}
	if len(preps) == 0 {
		t.Fatal("no archive command")
	}
	defer preps[0].close()
	return preps[0].cmd.Output()
}
