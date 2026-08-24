/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// knownHostsEnvVar points at a dedicated host key file. When set it replaces the
// invoking user's known_hosts, so a deployment can pin keys independently of the
// account running the scan.
const knownHostsEnvVar = "IAC_GIT_SSH_KNOWN_HOSTS"

const sshConnectTimeoutSeconds = 30

// systemKnownHostsFile is consulted after the user's own files.
const systemKnownHostsFile = "/etc/ssh/ssh_known_hosts"

// sshKnownHostsFiles returns the existing files used to verify host keys.
func sshKnownHostsFiles() []string {
	var candidates []string
	if pinned := strings.TrimSpace(os.Getenv(knownHostsEnvVar)); pinned != "" {
		candidates = []string{pinned}
	} else {
		if home, err := os.UserHomeDir(); err == nil {
			candidates = append(candidates,
				filepath.Join(home, ".ssh", "known_hosts"),
				filepath.Join(home, ".ssh", "known_hosts2"),
			)
		}
		candidates = append(candidates, systemKnownHostsFile)
	}

	files := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		info, err := os.Stat(candidate) //nolint:gosec // operator-supplied host key file
		if err != nil || info.IsDir() {
			continue
		}
		// A path that cannot be quoted safely cannot be handed to ssh at all.
		if _, err := shellSingleQuote(candidate); err != nil {
			continue
		}
		files = append(files, candidate)
	}
	return files
}

// sshHostKeyIsPinned reports whether host already has a host key entry. Hosts
// without one are refused rather than trusted on first use, so a hijacked
// destination cannot silently present a new key.
func sshHostKeyIsPinned(ctx context.Context, host string, knownHosts []string) bool {
	for _, file := range knownHosts {
		out, err := exec.CommandContext(ctx, "ssh-keygen", "-F", host, "-f", file).Output() //nolint:gosec
		if err == nil && len(bytes.TrimSpace(out)) > 0 {
			return true
		}
	}
	return false
}

// pinnedHostKeyCache memoizes host key lookups. The archive path re-checks the same
// host once per materialized subdirectory, and each miss costs a subprocess.
var pinnedHostKeyCache sync.Map // host+known_hosts files → bool

// checkSSHHostKeyPinned validates that host keys are available for host.
func checkSSHHostKeyPinned(ctx context.Context, host string) error {
	knownHosts := sshKnownHostsFiles()
	if len(knownHosts) == 0 {
		return fmt.Errorf("no known_hosts file is available to verify the host key for %q", host)
	}

	cacheKey := host + "\x00" + strings.Join(knownHosts, "\x00")
	pinned, cached := pinnedHostKeyCache.Load(cacheKey)
	if !cached {
		pinned = sshHostKeyIsPinned(ctx, host, knownHosts)
		pinnedHostKeyCache.Store(cacheKey, pinned)
	}
	if isPinned, ok := pinned.(bool); !ok || !isPinned {
		return fmt.Errorf(
			"host key for %q is not pinned in known_hosts; ssh git modules are only fetched from hosts with a known host key",
			host,
		)
	}
	return nil
}

// shellSingleQuote quotes arg for the shell that git uses to run GIT_SSH_COMMAND.
// Arguments that cannot be represented are rejected instead of escaped.
func shellSingleQuote(arg string) (string, error) {
	if strings.ContainsAny(arg, "'\n\r") {
		return "", fmt.Errorf("cannot pass %q to the ssh command line", arg)
	}
	return "'" + arg + "'", nil
}

// gitSSHCommand builds the GIT_SSH_COMMAND used for every ssh git subprocess.
//
// The connection is made to an address the destination policy already validated, so
// user ssh configuration is ignored (-F /dev/null): a Hostname, ProxyCommand or
// ProxyJump directive there would otherwise redirect the connection past that check.
// HostKeyAlias keeps host key verification bound to the real hostname even though the
// remote URL names an address literal.
func gitSSHCommand(host string, knownHosts []string) (string, error) {
	quotedFiles := make([]string, 0, len(knownHosts))
	for _, file := range knownHosts {
		// ssh splits UserKnownHostsFile on whitespace, so each path is quoted for ssh
		// itself in addition to the shell quoting applied below.
		quotedFiles = append(quotedFiles, `"`+file+`"`)
	}

	args := []string{
		"ssh",
		"-F", os.DevNull,
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "HostKeyAlias=" + host,
		"-o", "ProxyCommand=none",
		"-o", "ProxyJump=none",
		"-o", "ClearAllForwardings=yes",
		"-o", "ControlPath=none",
		"-o", "ConnectTimeout=" + strconv.Itoa(sshConnectTimeoutSeconds),
		"-o", "UserKnownHostsFile=" + strings.Join(quotedFiles, " "),
	}

	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		safe, err := shellSingleQuote(arg)
		if err != nil {
			return "", err
		}
		quoted = append(quoted, safe)
	}
	return strings.Join(quoted, " "), nil
}

// pinnedSSHRemote rewrites remote to target addr so the ssh subprocess cannot
// re-resolve the hostname and reach a destination the policy never approved.
func pinnedSSHRemote(remote *url.URL, addr netip.Addr) string {
	pinned := *remote
	literal := addr.String()
	if addr.Is6() {
		literal = "[" + literal + "]"
	}
	if port := remote.Port(); port != "" {
		literal += ":" + port
	}
	pinned.Host = literal
	pinned.RawQuery = ""
	pinned.Fragment = ""
	return pinned.String()
}

// sshGitCommandEnv builds the environment for an ssh git subprocess. SSH_AUTH_SOCK is
// preserved because agent authentication is how private repositories are reached;
// everything else that could redirect the connection is dropped.
func sshGitCommandEnv(sshCommand string) []string {
	env := gitBaseEnv("SSH_AUTH_SOCK")
	env = append(env, gitHardenedConfigEnv(sshScheme)...)
	return append(env, "GIT_SSH_COMMAND="+sshCommand)
}

func sshGitSetup(
	ctx context.Context, policy *httpDestinationPolicy, remoteURL string,
) (*url.URL, []string, []netip.Addr, error) {
	remote, err := url.Parse(remoteURL)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing ssh git remote %q: %w", remoteURL, err)
	}
	host := remote.Hostname()
	if host == "" {
		return nil, nil, nil, fmt.Errorf("ssh git remote %q has no host", remoteURL)
	}
	if err := checkSSHHostKeyPinned(ctx, host); err != nil {
		return nil, nil, nil, err
	}
	sshCommand, err := gitSSHCommand(host, sshKnownHostsFiles())
	if err != nil {
		return nil, nil, nil, err
	}
	addresses, err := policy.resolveHost(ctx, host)
	if err != nil {
		return nil, nil, nil, err
	}
	return remote, sshGitCommandEnv(sshCommand), addresses, nil
}

func runGitSSHCommand(
	ctx context.Context,
	policy *httpDestinationPolicy,
	remoteURL string,
	command gitNetworkCommand,
	output gitOutputFunc,
) ([]byte, error) {
	remote, env, addresses, err := sshGitSetup(ctx, policy, remoteURL)
	if err != nil {
		return nil, err
	}
	var lastOut []byte
	lastErr := errors.New("ssh git remote had no validated address")
	for _, address := range addresses {
		cmd := command(pinnedSSHRemote(remote, address), nil)
		cmd.Env = env
		out, runErr := output(cmd)
		if runErr == nil {
			return out, nil
		}
		lastOut, lastErr = out, runErr
	}
	return lastOut, lastErr
}

func prepareGitSSHCommand(
	ctx context.Context,
	policy *httpDestinationPolicy,
	remoteURL string,
	command gitNetworkCommand,
) (*exec.Cmd, func(), error) {
	remote, env, addresses, err := sshGitSetup(ctx, policy, remoteURL)
	if err != nil {
		return nil, nil, err
	}
	if len(addresses) == 0 {
		return nil, nil, errors.New("ssh git remote had no validated address")
	}
	cmd := command(pinnedSSHRemote(remote, addresses[0]), nil)
	cmd.Env = env
	return cmd, func() {}, nil
}
