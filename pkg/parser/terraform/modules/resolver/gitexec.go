/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	gitSHALength = 40

	// cacheFilePerms is used for small auxiliary files written alongside cached git repos.
	cacheFilePerms = 0o600
)

// gitProcSem caps concurrent git subprocesses across resolvers.
var gitProcSem = make(chan struct{}, gitProcConcurrency())

func gitProcConcurrency() int {
	n := runtime.GOMAXPROCS(0)
	const minGitProcConcurrency = 4
	if n < minGitProcConcurrency {
		return minGitProcConcurrency
	}
	return n
}

func acquireGitProc(ctx context.Context) (release func(), err error) {
	select {
	case gitProcSem <- struct{}{}:
		return func() { <-gitProcSem }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

// looksLikeSHA reports whether ref is a full 40-character hex SHA-1.
func looksLikeSHA(ref string) bool {
	if len(ref) != gitSHALength {
		return false
	}
	for _, c := range ref {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func gitSafePath(path string) string {
	return filepath.Clean(path)
}

func gitSafeArg(arg string) (string, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", fmt.Errorf("empty git argument")
	}
	if strings.HasPrefix(arg, "-") {
		return "", fmt.Errorf("invalid git argument %q", arg)
	}
	return arg, nil
}

func gitInDir(ctx context.Context, gitDir string, args ...string) *exec.Cmd {
	cmdArgs := make([]string, 0, 2+len(args))
	cmdArgs = append(cmdArgs, "--git-dir", gitSafePath(gitDir))
	cmdArgs = append(cmdArgs, args...)
	return exec.CommandContext(ctx, "git", cmdArgs...) //nolint:gosec
}

func gitInWorktree(ctx context.Context, root string, args ...string) *exec.Cmd {
	cmdArgs := make([]string, 0, 2+len(args))
	cmdArgs = append(cmdArgs, "-C", gitSafePath(root))
	cmdArgs = append(cmdArgs, args...)
	return exec.CommandContext(ctx, "git", cmdArgs...) //nolint:gosec
}

// cloneBareArgCount counts the fixed arguments appended after extraConfig:
// clone, --bare, --filter, the remote and the destination.
const cloneBareArgCount = 5

func gitCloneBare(ctx context.Context, remoteURL, dest string, extraConfig []string) *exec.Cmd {
	args := make([]string, 0, len(extraConfig)+cloneBareArgCount)
	args = append(args, extraConfig...)
	args = append(args, "clone", "--bare", "--filter=blob:none", remoteURL, gitSafePath(dest))
	return exec.CommandContext(ctx, "git", args...) //nolint:gosec
}
