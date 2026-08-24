/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"os"
	"os/exec"
	"slices"
	"strings"
)

const sshScheme = "ssh"

// gitNetworkCommand builds a git command that contacts remote. extraConfig carries
// ready-to-use "-c key=value" argument pairs that the transport needs, and remote is
// the destination the transport has already validated and pinned.
type gitNetworkCommand func(remote string, extraConfig []string) *exec.Cmd

// gitOutputFunc captures the output of a git command built by a gitNetworkCommand.
type gitOutputFunc func(cmd *exec.Cmd) ([]byte, error)

// gitCombinedOutput folds stderr into the result, which suits commands whose output is
// only ever read for diagnostics.
func gitCombinedOutput(cmd *exec.Cmd) ([]byte, error) {
	return cmd.CombinedOutput()
}

// gitStdoutOnly keeps stderr out of the result so binary output, such as a tar stream,
// is not corrupted by progress or warning messages.
func gitStdoutOnly(cmd *exec.Cmd) ([]byte, error) {
	return cmd.Output()
}

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

// gitHardenedConfigEnv neutralizes system and global git configuration. Without it a
// url.<base>.insteadOf rule would rewrite the destination after the policy validated
// it, and a credential prompt would block the scan waiting on a terminal.
func gitHardenedConfigEnv(allowedProtocol string) []string {
	return []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL=" + allowedProtocol,
	}
}
