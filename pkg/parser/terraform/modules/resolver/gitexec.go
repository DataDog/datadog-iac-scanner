/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

const (
	gitSHALength = 40

	// cacheFilePerms is used for small auxiliary files written alongside cached git repos.
	cacheFilePerms = 0o600

	defaultGitProcConcurrency = 8 // network-bound; override via IAC_MODULE_GIT_CONCURRENCY
)

// gitProcSem caps concurrent git subprocesses that may reach a remote: clones,
// fetches, and archives, which pull blobs lazily from blob-filtered clones.
// They mostly wait on the network, so the cap is not tied to the CPU count;
// local metadata reads bypass it.
var gitProcSem = make(chan struct{}, gitProcConcurrency())

func gitProcConcurrency() int {
	if v := os.Getenv("IAC_MODULE_GIT_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return max(defaultGitProcConcurrency, runtime.GOMAXPROCS(0))
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

// gitLocalInDir runs a read that must stay local: in a partial clone a missing
// object would otherwise be fetched from the remote outside acquireGitProc and
// the destination policy that runNetworkGit applies.
func gitLocalInDir(ctx context.Context, gitDir string, args ...string) *exec.Cmd {
	cmd := gitInDir(ctx, gitDir, args...)
	cmd.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1")
	return cmd
}

// minNoLazyFetchVersion is the first git release that honors GIT_NO_LAZY_FETCH.
var minNoLazyFetchVersion = [2]int{2, 44}

// localReadsStayLocal reports whether gitLocalInDir can keep a partial clone
// from fetching. Older git ignores GIT_NO_LAZY_FETCH, so callers skip their
// local fast paths and go through the policed network fetch instead.
var localReadsStayLocal = sync.OnceValue(func() bool {
	out, err := exec.Command("git", "version").Output()
	return err == nil && gitVersionAtLeast(string(out), minNoLazyFetchVersion)
})

// gitVersionAtLeast parses `git version` output such as "git version 2.44.0"
// or "git version 2.39.3 (Apple Git-146)".
func gitVersionAtLeast(output string, minimum [2]int) bool {
	fields := strings.Fields(output)
	if len(fields) < 3 {
		return false
	}
	parts := strings.SplitN(fields[2], ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	if majorErr != nil || minorErr != nil {
		return false
	}
	return major > minimum[0] || major == minimum[0] && minor >= minimum[1]
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
