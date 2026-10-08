/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
)

const sshScheme = "ssh"

// gitNetworkCommand builds a git command that contacts remote. extraConfig carries
// ready-to-use "-c key=value" argument pairs that the transport needs, and remote is
// the destination the transport has already validated and pinned.
type gitNetworkCommand func(remote string, extraConfig []string) *exec.Cmd

// gitOutputFunc captures the output of a git command built by a gitNetworkCommand.
type gitOutputFunc func(cmd *exec.Cmd) ([]byte, error)

// gitInheritedEnvBlockedPrefixes lists environment prefixes that let the caller
// redirect a git subprocess to an unvalidated destination.
var gitInheritedEnvBlockedPrefixes = []string{
	"GIT_",
	"SSH_",
	"HTTP_PROXY=",
	"HTTPS_PROXY=",
	"ALL_PROXY=",
	"NO_PROXY=",
	"http_proxy=",
	"https_proxy=",
	"all_proxy=",
	"no_proxy=",
}

// gitBaseEnv returns the parent environment with redirection-capable variables
// removed. Variables named in keep survive even when they match a blocked prefix.
func gitBaseEnv(keep ...string) []string {
	environ := os.Environ()
	env := make([]string, 0, len(environ))
	for _, variable := range environ {
		name, _, _ := strings.Cut(variable, "=")
		if slices.Contains(keep, name) {
			env = append(env, variable)
			continue
		}
		blocked := false
		for _, prefix := range gitInheritedEnvBlockedPrefixes {
			if strings.HasPrefix(variable, prefix) {
				blocked = true
				break
			}
		}
		if !blocked {
			env = append(env, variable)
		}
	}
	return env
}

// neutralGitConfigPath is an empty gitconfig Git can open on every platform.
// os.DevNull works on Unix but Git for Windows rejects NUL with exit status 128.
var neutralGitConfigPath = sync.OnceValue(func() string {
	if runtime.GOOS != "windows" {
		return os.DevNull
	}
	file, err := os.CreateTemp("", "iac-neutral-gitconfig-")
	if err != nil {
		return "NUL"
	}
	_ = file.Close()
	return file.Name()
})

// gitHardenedConfigEnv neutralizes system and global git configuration. Without it a
// url.<base>.insteadOf rule would rewrite the destination after the policy validated
// it, and a credential prompt would block the scan waiting on a terminal.
// Automatic gc and maintenance are disabled because a detached repack would
// delete pack files that concurrent extractions and object budget walks rely on.
func gitHardenedConfigEnv(allowedProtocol string) []string {
	return []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + neutralGitConfigPath(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL=" + allowedProtocol,
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=gc.auto",
		"GIT_CONFIG_VALUE_0=0",
		"GIT_CONFIG_KEY_1=maintenance.auto",
		"GIT_CONFIG_VALUE_1=false",
	}
}
