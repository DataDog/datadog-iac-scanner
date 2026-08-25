/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitCombinedOutput(cmd *exec.Cmd) ([]byte, error) {
	return cmd.CombinedOutput()
}

// writeKnownHosts writes content to a temporary known_hosts file and returns its path.
func writeKnownHosts(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing known_hosts: %v", err)
	}
	return path
}

// knownHostsLineFor generates a real host key entry for host, so ssh-keygen -F
// parses it the same way it would parse an operator's file.
func knownHostsLineFor(t *testing.T, host string) string {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not available")
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	cmd := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", keyPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen could not generate a key: %v\n%s", err, out)
	}
	pub, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatalf("reading generated public key: %v", err)
	}
	fields := strings.Fields(string(pub))
	if len(fields) < 2 {
		t.Fatalf("unexpected public key format %q", pub)
	}
	return host + " " + fields[0] + " " + fields[1] + "\n"
}

func TestSSHHostKeyIsPinned(t *testing.T) {
	const host = "modules.example"
	pinned := writeKnownHosts(t, knownHostsLineFor(t, host))
	empty := writeKnownHosts(t, "")

	if !sshHostKeyIsPinned(context.Background(), host, []string{pinned}) {
		t.Fatal("expected host key to be reported as pinned")
	}
	if sshHostKeyIsPinned(context.Background(), host, []string{empty}) {
		t.Fatal("expected empty known_hosts to report no pinned key")
	}
	if sshHostKeyIsPinned(context.Background(), "other.example", []string{pinned}) {
		t.Fatal("expected a different host to report no pinned key")
	}
}

func TestSSHHostKeyName(t *testing.T) {
	cases := []struct {
		host, port, want string
	}{
		{host: "modules.example", port: "", want: "modules.example"},
		{host: "modules.example", port: "22", want: "modules.example"},
		{host: "modules.example", port: "2222", want: "[modules.example]:2222"},
		{host: "::1", port: "2222", want: "[::1]:2222"},
	}
	for _, tc := range cases {
		if got := sshHostKeyName(tc.host, tc.port); got != tc.want {
			t.Errorf("sshHostKeyName(%q, %q) = %q, want %q", tc.host, tc.port, got, tc.want)
		}
	}
}

func TestCheckSSHHostKeyPinnedCustomPort(t *testing.T) {
	const host = "modules.example"
	lookup := sshHostKeyName(host, "2222")
	t.Setenv(knownHostsEnvVar, writeKnownHosts(t, knownHostsLineFor(t, lookup)))
	if err := checkSSHHostKeyPinned(context.Background(), lookup); err != nil {
		t.Fatalf("expected [host]:port entry to pin the custom-port remote: %v", err)
	}
	if err := checkSSHHostKeyPinned(context.Background(), host); err == nil {
		t.Fatal("a default-port lookup must not match a [host]:port known_hosts entry")
	}
}

func TestGitSSHCommandUsesPortHostKeyAlias(t *testing.T) {
	knownHosts := writeKnownHosts(t, "")
	command, err := gitSSHCommand("[modules.example]:2222", []string{knownHosts})
	if err != nil {
		t.Fatalf("building ssh command: %v", err)
	}
	if !strings.Contains(command, "'HostKeyAlias=[modules.example]:2222'") {
		t.Fatalf("ssh command %q is missing the custom-port HostKeyAlias", command)
	}
}

func TestCheckSSHHostKeyPinnedUsesEnvOverride(t *testing.T) {
	const host = "modules.example"
	t.Setenv(knownHostsEnvVar, writeKnownHosts(t, knownHostsLineFor(t, host)))
	if err := checkSSHHostKeyPinned(context.Background(), host); err != nil {
		t.Fatalf("expected pinned host to be accepted: %v", err)
	}

	t.Setenv(knownHostsEnvVar, writeKnownHosts(t, ""))
	if err := checkSSHHostKeyPinned(context.Background(), host); err == nil {
		t.Fatal("expected unpinned host to be rejected")
	}
}

func TestGitSSHCommandHardening(t *testing.T) {
	knownHosts := writeKnownHosts(t, "")
	command, err := gitSSHCommand("modules.example", []string{knownHosts})
	if err != nil {
		t.Fatalf("building ssh command: %v", err)
	}
	for _, want := range []string{
		"'-F' '" + os.DevNull + "'",
		"'StrictHostKeyChecking=yes'",
		"'HostKeyAlias=modules.example'",
		"'ProxyCommand=none'",
		"'ProxyJump=none'",
		"'BatchMode=yes'",
		knownHosts,
	} {
		if !strings.Contains(command, want) {
			t.Errorf("ssh command %q is missing %q", command, want)
		}
	}
}

func TestGitSSHCommandRejectsUnquotablePath(t *testing.T) {
	if _, err := gitSSHCommand("modules.example", []string{"/tmp/known'hosts"}); err == nil {
		t.Fatal("expected a path containing a quote to be rejected")
	}
}

func TestPinnedSSHRemote(t *testing.T) {
	cases := []struct {
		name string
		in   string
		addr string
		want string
	}{
		{
			name: "ipv4 keeps user and path",
			in:   "ssh://git@github.com/org/repo.git",
			addr: "140.82.121.4",
			want: "ssh://git@140.82.121.4/org/repo.git",
		},
		{
			name: "ipv6 is bracketed",
			in:   "ssh://git@github.com/org/repo.git",
			addr: "2606:50c0:8000::153",
			want: "ssh://git@[2606:50c0:8000::153]/org/repo.git",
		},
		{
			name: "explicit port is preserved",
			in:   "ssh://git@github.com:2222/org/repo.git",
			addr: "140.82.121.4",
			want: "ssh://git@140.82.121.4:2222/org/repo.git",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := url.Parse(tc.in)
			if err != nil {
				t.Fatalf("parsing %q: %v", tc.in, err)
			}
			got := pinnedSSHRemote(parsed, netip.MustParseAddr(tc.addr))
			if got != tc.want {
				t.Fatalf("pinnedSSHRemote() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSSHGitCommandEnvKeepsAgentAndBlocksRedirection(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	t.Setenv("SSH_ASKPASS", "/tmp/askpass")
	t.Setenv("GIT_SSH_COMMAND", "ssh -o ProxyCommand=attacker")
	t.Setenv("GIT_CONFIG_GLOBAL", "/tmp/attacker-config")
	t.Setenv("HTTPS_PROXY", "http://attacker.example")

	env := sshGitCommandEnv("ssh -o StrictHostKeyChecking=yes")
	values := make(map[string]string, len(env))
	for _, variable := range env {
		name, value, _ := strings.Cut(variable, "=")
		values[name] = value
	}

	if values["SSH_AUTH_SOCK"] != "/tmp/agent.sock" {
		t.Error("expected SSH_AUTH_SOCK to be preserved for agent authentication")
	}
	if _, ok := values["SSH_ASKPASS"]; ok {
		t.Error("expected SSH_ASKPASS to be dropped")
	}
	if _, ok := values["HTTPS_PROXY"]; ok {
		t.Error("expected inherited proxy settings to be dropped")
	}
	if values["GIT_SSH_COMMAND"] != "ssh -o StrictHostKeyChecking=yes" {
		t.Errorf("expected the inherited GIT_SSH_COMMAND to be replaced, got %q", values["GIT_SSH_COMMAND"])
	}
	if values["GIT_CONFIG_GLOBAL"] != os.DevNull {
		t.Errorf("expected global git config to be neutralized, got %q", values["GIT_CONFIG_GLOBAL"])
	}
	if values["GIT_CONFIG_NOSYSTEM"] != "1" {
		t.Error("expected system git config to be disabled")
	}
	if values["GIT_ALLOW_PROTOCOL"] != sshScheme {
		t.Errorf("expected only ssh to be allowed, got %q", values["GIT_ALLOW_PROTOCOL"])
	}
	if values["GIT_TERMINAL_PROMPT"] != "0" {
		t.Error("expected terminal prompts to be disabled")
	}
}

func TestRunGitSSHCommandRejectsPrivateAddress(t *testing.T) {
	const host = "modules.example"
	t.Setenv(knownHostsEnvVar, writeKnownHosts(t, knownHostsLineFor(t, host)))

	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}

	ran := false
	_, err := runGitSSHCommand(
		context.Background(),
		policy,
		"ssh://git@"+host+"/org/repo.git",
		func(string, []string) *exec.Cmd {
			ran = true
			return exec.Command("true")
		},
		gitCombinedOutput,
	)
	if err == nil || !strings.Contains(err.Error(), "not a public unicast destination") {
		t.Fatalf("expected private destination rejection, got %v", err)
	}
	if ran {
		t.Fatal("expected no git command to run for a rejected destination")
	}
}

func TestRunGitSSHCommandPinsValidatedAddress(t *testing.T) {
	const host = "modules.example"
	t.Setenv(knownHostsEnvVar, writeKnownHosts(t, knownHostsLineFor(t, host)))

	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("140.82.121.4")}, nil
	}

	var remotes []string
	if _, err := runGitSSHCommand(
		context.Background(),
		policy,
		"ssh://git@"+host+"/org/repo.git",
		func(remote string, extraConfig []string) *exec.Cmd {
			remotes = append(remotes, remote)
			if len(extraConfig) != 0 {
				t.Errorf("expected no proxy config for ssh, got %v", extraConfig)
			}
			return exec.Command("true")
		},
		gitCombinedOutput,
	); err != nil {
		t.Fatalf("running pinned ssh command: %v", err)
	}

	if len(remotes) != 1 {
		t.Fatalf("expected one attempt, got %v", remotes)
	}
	if remotes[0] != "ssh://git@140.82.121.4/org/repo.git" {
		t.Fatalf("expected the validated address to be pinned, got %q", remotes[0])
	}
	if strings.Contains(remotes[0], host) {
		t.Error("expected the hostname to be replaced so ssh cannot re-resolve it")
	}
}

func TestRunGitSSHCommandRequiresPinnedHostKey(t *testing.T) {
	t.Setenv(knownHostsEnvVar, writeKnownHosts(t, ""))
	policy := newHTTPDestinationPolicy(nil)

	ran := false
	_, err := runGitSSHCommand(
		context.Background(),
		policy,
		"ssh://git@modules.example/org/repo.git",
		func(string, []string) *exec.Cmd {
			ran = true
			return exec.Command("true")
		},
		gitCombinedOutput,
	)
	if err == nil || !strings.Contains(err.Error(), "is not pinned in known_hosts") {
		t.Fatalf("expected unpinned host key rejection, got %v", err)
	}
	if ran {
		t.Fatal("expected no git command to run without a pinned host key")
	}
}
