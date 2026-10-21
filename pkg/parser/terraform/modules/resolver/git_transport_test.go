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
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

func TestGitEnvsKeepInstallationPathsAndBlockOverrides(t *testing.T) {
	t.Setenv("PATH", os.Getenv("PATH"))
	installation := map[string]string{
		"GIT_EXEC_PATH":    filepath.Join(t.TempDir(), "bundled git=exec"),
		"GIT_TEMPLATE_DIR": filepath.Join(t.TempDir(), "bundled git=templates"),
	}
	for name, value := range installation {
		t.Setenv(name, value)
	}
	const untrusted = "untrusted-parent-value"
	blocked := []string{
		"GIT_SSH", "GIT_SSH_COMMAND", "GIT_SSH_VARIANT", "GIT_PROXY_COMMAND",
		"GIT_CONFIG", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM",
		"GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
		"GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
		"GIT_ALLOW_PROTOCOL", "GIT_SSL_NO_VERIFY", "GIT_ASKPASS",
		"GIT_EXEC_PATH_EXTRA", "GIT_TEMPLATE_DIR_EXTRA", "GIT_UNKNOWN_OVERRIDE",
		"SSH_ASKPASS", "SSH_AGENT_PID",
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
		"http_proxy", "https_proxy", "all_proxy", "no_proxy",
	}
	for _, name := range blocked {
		t.Setenv(name, untrusted)
	}
	for name, build := range map[string]func() []string{
		"base":  func() []string { return gitBaseEnv() },
		"https": func() []string { return gitCommandEnv("http://127.0.0.1:1234") },
		"ssh":   func() []string { return sshGitCommandEnv("ssh -o StrictHostKeyChecking=yes") },
	} {
		t.Run(name, func(t *testing.T) {
			env := build()
			for key, value := range installation {
				if !slices.Contains(env, key+"="+value) {
					t.Errorf("environment did not preserve %s=%s", key, value)
				}
			}
			if !slices.Contains(env, "PATH="+os.Getenv("PATH")) {
				t.Error("environment did not preserve PATH")
			}
			for _, key := range blocked {
				if slices.Contains(env, key+"="+untrusted) {
					t.Errorf("environment retained inherited %s", key)
				}
			}
		})
	}
}

func TestGitHTTPSCloneUsesInstallationPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper requires a POSIX shell")
	}
	execDir := t.TempDir()
	templateDir := t.TempDir()
	// An empty remote-helper response lets real git clone an empty repository
	// without network access. Only the supplied exec path contains this helper.
	helper := `#!/bin/sh
while read -r command; do
    case "$command" in
        capabilities|list) printf '\n' ;;
        *) exit 1 ;;
    esac
done
`
	if err := os.WriteFile(filepath.Join(execDir, "git-remote-https"), []byte(helper), 0o700); err != nil {
		t.Fatal(err)
	}
	const marker = "bundled-install-template"
	if err := os.WriteFile(filepath.Join(templateDir, marker), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_EXEC_PATH", execDir)
	t.Setenv("GIT_TEMPLATE_DIR", templateDir)

	policy := newHTTPDestinationPolicy(nil)
	policy.lookupNetIP = func(context.Context, string, string) ([]net.IP, error) {
		return nil, errors.New("test clone must use the bundled helper without network access")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	destination := filepath.Join(t.TempDir(), "repo.git")
	out, err := runGitHTTPSCommand(policy, "https://modules.invalid/repo.git",
		func(remote string, config []string) *exec.Cmd {
			args := append(slices.Clone(config), "clone", "--bare", remote, destination)
			return exec.CommandContext(ctx, "git", args...)
		}, gitCombinedOutput)
	if err != nil {
		t.Fatalf("clone using bundled helper: %v\n%s", err, out)
	}
	if data, err := os.ReadFile(filepath.Join(destination, marker)); err != nil || string(data) != marker {
		t.Fatalf("clone did not use bundled templates: content = %q, err = %v", data, err)
	}
}

func BenchmarkGitCommandEnvs(b *testing.B) {
	b.Setenv("GIT_EXEC_PATH", "/tmp/bundled-git/libexec/git-core")
	b.Setenv("GIT_TEMPLATE_DIR", "/tmp/bundled-git/share/git-core/templates")
	for name, build := range map[string]func() []string{
		"https": func() []string { return gitCommandEnv("http://127.0.0.1:1234") },
		"ssh":   func() []string { return sshGitCommandEnv("ssh -o StrictHostKeyChecking=yes") },
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = build()
			}
		})
	}
}
