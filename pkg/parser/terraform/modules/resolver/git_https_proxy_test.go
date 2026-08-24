/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGitHTTPSProxyRejectsPrivateDestination(t *testing.T) {
	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}
	proxy, err := startGitHTTPSProxy(policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })

	conn, response := connectThroughProxy(t, proxy.URL(), "modules.example:443")
	_ = conn.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
}

func TestGitHTTPSProxyPinsValidatedAddress(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	go func() {
		conn, acceptErr := backend.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(conn, conn)
	}()

	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	var dialed string
	policy.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = address
		return (&net.Dialer{}).DialContext(ctx, network, backend.Addr().String())
	}
	proxy, err := startGitHTTPSProxy(policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })

	conn, response := connectThroughProxy(t, proxy.URL(), "modules.example:443")
	defer func() { _ = conn.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if dialed != "93.184.216.34:443" {
		t.Fatalf("dialed %q, want validated address", dialed)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "ping" {
		t.Fatalf("reply = %q", reply)
	}
}

func TestGitHTTPSProxyCloseTerminatesHijackedTunnel(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := backend.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	policy.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, backend.Addr().String())
	}
	proxy, err := startGitHTTPSProxy(policy)
	if err != nil {
		t.Fatal(err)
	}
	conn, response := connectThroughProxy(t, proxy.URL(), "modules.example:443")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	upstream := <-accepted
	defer func() { _ = upstream.Close() }()

	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("tunnel remained open after proxy shutdown")
	}
	_ = conn.Close()
}

func TestGitCommandEnvRemovesTransportOverrides(t *testing.T) {
	t.Setenv("GIT_SSH_COMMAND", "ssh -o StrictHostKeyChecking=no")
	t.Setenv("GIT_CONFIG_GLOBAL", "/tmp/attacker-config")
	t.Setenv("HTTPS_PROXY", "http://attacker.invalid")
	t.Setenv("NO_PROXY", "*")

	env := gitCommandEnv("http://127.0.0.1:1234")
	joined := strings.Join(env, "\n")
	for _, forbidden := range []string{
		"StrictHostKeyChecking=no",
		"/tmp/attacker-config",
		"http://attacker.invalid",
		"NO_PROXY=*",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("environment retained %q", forbidden)
		}
	}
	for _, required := range []string{
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_ALLOW_PROTOCOL=https",
		"HTTPS_PROXY=http://127.0.0.1:1234",
		"NO_PROXY=",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("environment missing %q", required)
		}
	}
}

// TestGitEnvIgnoresGlobalInsteadOfRewrite checks the transport git actually resolves.
// A url.<base>.insteadOf rule redirects a URL before git picks a transport, so it would
// send the request somewhere the destination policy never validated.
func TestGitEnvIgnoresGlobalInsteadOfRewrite(t *testing.T) {
	const requested = "https://github.com/org/repo.git"
	const hijacked = "ssh://git@attacker.invalid/"

	configPath := filepath.Join(t.TempDir(), "gitconfig")
	config := "[url \"" + hijacked + "\"]\n\tinsteadOf = https://github.com/\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("writing git config: %v", err)
	}

	resolveURL := func(env []string) string {
		t.Helper()
		cmd := exec.Command("git", "ls-remote", "--get-url", requested)
		cmd.Dir = t.TempDir()
		cmd.Env = env
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git ls-remote --get-url: %v", err)
		}
		return strings.TrimSpace(string(out))
	}

	// Control: with the rule visible, git really does rewrite the destination.
	hijackedEnv := append(os.Environ(), "GIT_CONFIG_GLOBAL="+configPath, "GIT_CONFIG_NOSYSTEM=1")
	if got := resolveURL(hijackedEnv); !strings.HasPrefix(got, hijacked) {
		t.Skipf("git did not apply the insteadOf rule (%q); nothing to protect against here", got)
	}

	t.Setenv("GIT_CONFIG_GLOBAL", configPath)
	for _, env := range [][]string{
		gitCommandEnv("http://127.0.0.1:1234"),
		sshGitCommandEnv("ssh -o StrictHostKeyChecking=yes"),
	} {
		if got := resolveURL(env); got != requested {
			t.Errorf("git resolved %q to %q; the insteadOf rule was not neutralized", requested, got)
		}
	}
}

func connectThroughProxy(t *testing.T, proxyURL, target string) (net.Conn, *http.Response) {
	t.Helper()
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if err := request.Write(conn); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	return conn, response
}
