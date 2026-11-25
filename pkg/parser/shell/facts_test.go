/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package shell

import (
	"runtime/debug"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLiteral(t *testing.T) {
	for _, tc := range []struct {
		raw, text string
		known     bool
	}{
		{`n"p"m`, "npm", true},
		{`'literal $HOME'`, "literal $HOME", true},
		{`a\ b`, "a b", true},
		{`"a\qb"`, `a\qb`, true},
		{`"$HOME"`, "", false},
		{`$(id)`, "", false},
		{`*.txt`, "", false},
		{`"*.txt"`, "*.txt", true},
		{`$'a\nb'`, "", false},
	} {
		actual := Literal(tc.raw)
		require.Equal(t, tc.known, actual.Known, tc.raw)
		if tc.known {
			require.Equal(t, tc.text, actual.Text, tc.raw)
		}
	}
}

func TestAnalyzeCalls(t *testing.T) {
	script := `echo "pip install data"; timeout 10 sudo -u root /usr/bin/pip install 'x==1'; sh -c 'apt-get install x'; echo $(id)`
	result := Analyze(script, "sh")
	require.True(t, result.Complete, result.Diagnostics)
	names := make([]string, 0, len(result.Calls))
	for _, call := range result.Calls {
		names = append(names, call.Name)
	}
	require.Equal(t, []string{"echo", "pip", "sh", "apt-get", "id", "echo"}, names)
	require.Equal(t, []string{"timeout", "sudo"}, result.Calls[1].Wrappers)
	require.Equal(t, "x==1", result.Calls[1].Arguments[1].Text)
	require.Equal(t, "/usr/bin/pip install 'x==1'", script[result.Calls[1].Span.Start:result.Calls[1].Span.End][len("timeout 10 sudo -u root "):])
	require.Equal(t, "'x==1'", script[result.Calls[1].ArgumentSpans[1].Start:result.Calls[1].ArgumentSpans[1].End])
	require.Equal(t, ScopeShellScript, result.Scopes[result.Calls[3].Scope].Kind)
	require.Equal(t, "'apt-get install x'", script[result.Calls[3].Span.Start:result.Calls[3].Span.End],
		"a nested script call spans the argument that holds the script")
	require.Equal(t, ScopeCommandSubstitution, result.Scopes[result.Calls[4].Scope].Kind)

	// Package.Span is safe even for nested scripts whose ArgumentSpans is nil.
	require.Len(t, result.PackageCommands, 2)
	nestedPkgSpan := result.PackageCommands[1].Packages[0].Span
	require.Equal(t, "'apt-get install x'", script[nestedPkgSpan.Start:nestedPkgSpan.End])

	result = AnalyzeArgv([]string{"echo", "$(pip install x)", "|"})
	require.Len(t, result.Calls, 1)
	require.True(t, result.Calls[0].Arguments[0].Known)
	require.True(t, result.Complete)

	// Analyze and AnalyzeShell agree on shell flags such as -o pipefail.
	for _, res := range []*Facts{
		Analyze("curl https://example.test | tar -xz | sh", "bash -o pipefail"),
		AnalyzeShell("curl https://example.test | tar -xz | sh", []string{"/bin/bash", "-o", "pipefail", "-c"}),
	} {
		require.True(t, res.Complete, res.Diagnostics)
		require.Len(t, res.Pipelines, 1)
		require.True(t, res.Pipelines[0].Pipefail)
		require.True(t, res.Pipelines[0].Known)
		require.Len(t, res.Calls, 3)
	}
}

func TestAnalyzeControlFlow(t *testing.T) {
	result := Analyze("apt-get update && apt-get install x; echo fallback || echo failed; if true; then echo body; fi", "/usr/local/bin/bash")
	require.True(t, result.Complete, result.Diagnostics)
	require.False(t, result.Calls[0].Conditional)
	require.Equal(t, []Guard{{Kind: GuardSuccess, Call: 0}}, result.Calls[1].Guards)
	require.Equal(t, []Guard{{Kind: GuardFailure, Call: 2}}, result.Calls[3].Guards)
	require.True(t, result.Calls[5].Conditional)

	result = Analyze(`f() { cd relative; }; (cd third); apt-get() { :; }; apt-get install x`, "bash")
	require.True(t, result.Calls[0].Deferred)
	require.Equal(t, ScopeSubshell, result.Scopes[result.Calls[1].Scope].Kind)
	require.True(t, result.Calls[len(result.Calls)-1].Function)

	result = Analyze("for ((i=0; i<0; i++)); do set -o pipefail; done; curl x | cat", "bash")
	require.Len(t, result.Pipelines, 1)
	require.False(t, result.Pipelines[0].Known)

	result = Analyze("set -- -o pipefail; curl x | cat", "bash")
	require.Len(t, result.Pipelines, 1)
	require.False(t, result.Pipelines[0].Pipefail)
	require.True(t, result.Pipelines[0].Known)

	result = Analyze("set -o pipefail | { curl x | sh; }", "bash")
	require.Len(t, result.Pipelines, 2)
	require.False(t, result.Pipelines[1].Pipefail)
	require.True(t, result.Pipelines[1].Known)

	// POSIX `[` builtin guard stays complete and does not mark environment mutation.
	result = Analyze("[ -f /etc/os-release ] && apt-get install -y curl", "sh")
	require.True(t, result.Complete, result.Diagnostics)
	require.False(t, result.EnvironmentMayChange)
	require.Equal(t, "[", result.Calls[0].Name)
	require.True(t, result.Calls[0].Executable.Known)
	require.Len(t, result.PackageCommands, 1)

	for _, script := range []string{
		"bash -c -- 'pip install flask'",
		"bash -eo pipefail -c 'pip install flask'",
		"sh -euo pipefail -c 'pip install flask'",
		"su -s /bin/sh -- root -c 'pip install flask'",
		"su root --command 'pip install flask'",
		"su root -s /bin/sh -c 'pip install flask'",
		"su root -- -c 'pip install flask'",
		"su -lc 'pip install flask' root",
	} {
		result = Analyze(script, "bash")
		require.True(t, result.Complete, script, result.Diagnostics)
		require.Len(t, result.PackageCommands, 1, script)
		require.Equal(t, "pip", result.PackageCommands[0].Manager, script)
		require.Equal(t, "install", result.PackageCommands[0].Action, script)
	}

	result = AnalyzeArgv([]string{"/bin/bash", "-eo", "pipefail", "-c", "apt-get install -y curl"})
	require.True(t, result.Complete, result.Diagnostics)
	require.Len(t, result.PackageCommands, 1)
	require.Equal(t, "apt-get", result.PackageCommands[0].Manager)

	result = Analyze("su -s /bin/sh root /dev/null -- -c 'pip install flask'", "bash")
	require.True(t, result.Complete, result.Diagnostics)
	require.Empty(t, result.PackageCommands)

	result = Analyze("if set -o pipefail; false; then :; else curl x | sh; fi", "bash")
	require.Len(t, result.Pipelines, 1)
	require.True(t, result.Pipelines[0].Pipefail)
	require.True(t, result.Pipelines[0].Known)
}

func TestAnalyzeCompleteness(t *testing.T) {
	for _, script := range []string{
		`"$BIN" install`, `sh -c "$SCRIPT"`, `bash "$OPTS" -c 'pip install x'`,
		`sudo -l apt-get install x`, `env -S 'apt-get install x'`,
		`xargs -n 1 pip install x`, `alias apt-get=echo; apt-get install x`, "echo 'unterminated",
	} {
		require.False(t, Analyze(script, "sh").Complete, script)
	}
	require.False(t, Analyze("Write-Output hi", "powershell").Complete)
	require.False(t, Analyze("echo hi", "").Complete)

	builder := newFactBuilder()
	builder.script("pip install x", "sh", 0, false, false, maxShellDepth)
	require.Contains(t, builder.result.Diagnostics, "shell analysis limit reached")
}

func TestAnalyzeDeepNestingAndLargePipelines(t *testing.T) {
	t.Run("deep nesting does not overflow stack", func(t *testing.T) {
		deep := strings.Repeat("(", 170000) + "1" + strings.Repeat(")", 170000)
		old := debug.SetMaxStack(8 << 20)
		defer debug.SetMaxStack(old)

		for _, script := range []string{
			"echo $((" + deep + "))",
			"# don't\necho $((" + deep + "))\n# won't\n",
			"echo \"it's\"\necho $((" + deep + "))\necho \"that's\"\n",
			"cat <<EOF\ndon't\nEOF\necho $((" + deep + "))\n",
			"echo $'don\\'t'\necho $((" + deep + "))\n",
			"echo \"$((" + deep + "))\"",
			"echo " + strings.Repeat("$(echo ')' ", 20000) + strings.Repeat(")", 20000),
		} {
			facts := Analyze(script, "bash")
			require.False(t, facts.Complete)
			require.Contains(t, facts.Diagnostics, "shell analysis limit reached")
		}

		for _, raw := range []string{
			deep,
			`"'` + `"` + `$(($(` + deep + `)))`,
		} {
			require.False(t, Literal(raw).Known)
		}
	})

	t.Run("large pipeline is linear", func(t *testing.T) {
		facts := Analyze(strings.Repeat("a|", 2000)+"a", "sh")
		require.True(t, facts.Complete, facts.Diagnostics)
		require.Len(t, facts.Pipelines, 1)
		require.Len(t, facts.Calls, 2001)
	})
}

func TestAnalyzeSuccessPrecedes(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   [][]int
	}{
		{
			name:   "and chain is transitive",
			script: "apt-get update && apt-get install curl && rm -rf /var/lib/apt/lists/*",
			want:   [][]int{nil, {0}, {0, 1}},
		},
		{
			name:   "ordinary sequencing does not require success",
			script: "apt-get update; apt-get install curl",
			want:   [][]int{nil, nil},
		},
		{
			name:   "failure branch is not a success predecessor",
			script: "apt-get update || apt-get install curl",
			want:   [][]int{nil, nil},
		},
		{
			name:   "success branch after a failure branch only depends on the success guard",
			script: "apt-get update || apt-get install curl && rm -rf /var/lib/apt/lists/*",
			want:   [][]int{nil, nil, nil},
		},
		{
			name:   "pipeline stages are isolated",
			script: "apt-get update | cat && apt-get install curl",
			want:   [][]int{nil, nil, nil},
		},
		{
			name:   "and chain inside conditional retains its success relation",
			script: "if true; then apt-get update && apt-get install curl; fi",
			want:   [][]int{nil, nil, {1}},
		},
		{
			name:   "negated command does not establish a success predecessor",
			script: "! apt-get update && apt-get install curl",
			want:   [][]int{nil, nil},
		},
		{
			name:   "block ending in unknown status does not attribute success to earlier call",
			script: "{ apt-get update; false || true; } && apt-get install curl",
			want:   [][]int{nil, nil, nil, nil},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(tc.script, "sh")
			require.True(t, facts.Complete, facts.Diagnostics)
			require.Len(t, facts.Calls, len(tc.want))
			for later, wantPredecessors := range tc.want {
				var got []int
				for earlier := range facts.Calls {
					if facts.SuccessPrecedes(earlier, later) {
						got = append(got, earlier)
					}
				}
				require.Equal(t, wantPredecessors, got, "call %d", later)
			}
		})
	}
}

func TestAnalyzePrecedes(t *testing.T) {
	for _, tc := range []struct {
		name, script, shell string
		want                [][]int
	}{
		{
			name:   "ordinary sequential cleanup is ordered",
			script: "apk add curl; rm -rf /var/cache/apk/*",
			want:   [][]int{nil, {0}},
		},
		{
			name:   "mutually exclusive conditional branches are not ordered",
			script: "if true; then apk add curl; else echo skip; fi",
			want:   [][]int{nil, nil, nil},
		},
		{
			name:   "success edge inside a conditional is ordered",
			script: "if true; then apk add curl && rm -rf /var/cache/apk/*; fi",
			want:   [][]int{nil, nil, {1}},
		},
		{
			name:   "pipeline calls are not ordered",
			script: "apk add curl | cat; rm -rf /var/cache/apk/*",
			want:   [][]int{nil, nil, nil},
		},
		{
			name:   "background commands are not ordered before subsequent calls",
			script: "apk add curl & rm -rf /var/cache/apk/*",
			want:   [][]int{nil, nil},
		},
		{
			name:   "coprocesses are not ordered before subsequent calls",
			script: "coproc { apt-get update; }; apt-get install curl",
			shell:  "bash",
			want:   [][]int{nil, nil},
		},
		{
			name:   "conditional calls are not guaranteed predecessors of later commands",
			script: "false && apt-get update; apt-get install curl",
			want:   [][]int{nil, {0}, {0}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shellName := tc.shell
			if shellName == "" {
				shellName = "sh"
			}
			facts := Analyze(tc.script, shellName)
			require.True(t, facts.Complete, facts.Diagnostics)
			require.Len(t, facts.Calls, len(tc.want))
			for later, wantPredecessors := range tc.want {
				var got []int
				for earlier := range facts.Calls {
					if facts.Precedes(earlier, later) {
						got = append(got, earlier)
					}
				}
				require.Equal(t, wantPredecessors, got, "call %d", later)
			}
		})
	}
}

func TestAnalyzeLargeSequentialScriptStaysComplete(t *testing.T) {
	facts := Analyze(strings.Repeat("echo x; ", 500), "sh")
	require.True(t, facts.Complete, facts.Diagnostics)
	require.Len(t, facts.Calls, 500)
	require.True(t, facts.Precedes(0, 499))
	require.False(t, facts.Precedes(499, 0))
}

func TestAnalyzeCDOperand(t *testing.T) {
	for _, tt := range []struct {
		script string
		value  string
		known  bool
		absent bool
	}{
		{script: "cd -LP /tmp", value: "/tmp", known: true},
		{script: "cd -P -- '/tmp path'", value: "/tmp path", known: true},
		{script: "cd -- -L", value: "-L", known: true},
		{script: "cd -- -"},
		{script: "cd relative", value: "relative", known: true},
		{script: "cd $FLAGS /tmp"},
		{script: "cd *"},
		{script: "cd -"},
		{script: "cd -Z /tmp"},
		{script: "cd before after"},
		{script: "cd ''"},
		{script: "cd", absent: true},
		{script: "echo cd", absent: true},
	} {
		t.Run(tt.script, func(t *testing.T) {
			facts := Analyze(tt.script, "sh")
			require.Len(t, facts.Calls, 1)
			operand := facts.Calls[0].CDPath
			if tt.absent {
				require.Nil(t, operand)
				return
			}
			require.NotNil(t, operand)
			require.Equal(t, tt.known, operand.Known)
			if tt.known {
				require.Equal(t, tt.value, operand.Text)
			}
		})
	}
}

func TestAnalyzeEnvironmentMayChange(t *testing.T) {
	for _, script := range []string{
		"HOME=/tmp pip install flask",
		"export HOME=/tmp; pip install flask",
		"unset HOME; pip install flask",
		"configure() { HOME=/tmp; }; pip install flask",
		"cd /tmp; pip install --cache-dir cache flask",
		"$SETUP; pip install flask",
		". ./environment; pip install flask",
		"eval \"$SETUP\"; pip install flask",
	} {
		t.Run(script, func(t *testing.T) {
			require.True(t, Analyze(script, "sh").EnvironmentMayChange)
		})
	}
	for _, script := range []string{
		"pip install flask==1.0",
		"curl 'https://example.test/?x=y'",
		"echo 'HOME=/tmp'",
	} {
		t.Run(script, func(t *testing.T) {
			require.False(t, Analyze(script, "sh").EnvironmentMayChange)
		})
	}
}

func TestAnalyzePackageCommands(t *testing.T) {
	type pkg struct {
		name   string
		pinned bool
	}
	for _, tc := range []struct {
		script, manager, action string
		assumeYes, known        bool
		packages                []pkg
	}{
		{"apt-get -qq install -o Dpkg::Options::=--force-confold curl=7.0 git", "apt-get", "install", true, true,
			[]pkg{{"curl=7.0", true}, {"git", false}}},
		{"apt-get install -y --no-install-recommends curl", "apt-get", "install", true, true, []pkg{{"curl", false}}},
		{"apt-get install libgtk-3-0 libpcre2-8-0 libc6:amd64=2.36-9+deb12u10 7zip --assume-yes=false", "apt-get", "install", false, true,
			[]pkg{{"libgtk-3-0", false}, {"libpcre2-8-0", false}, {"libc6:amd64=2.36-9+deb12u10", true}, {"7zip", false}}},
		{"apt-get install -y --assume-yes=false curl", "apt-get", "install", false, true, []pkg{{"curl", false}}},
		{"apk add --virtual .build gcc~=12 curl~8", "apk", "install", false, true,
			[]pkg{{"gcc~=12", true}, {"curl~8", true}}},
		{"dnf --setopt=x=1 --enablerepo epel in -y nginx-1.2.3 systemd-252-46.el9.x86_64 systemd-0:252-46.el9.x86_64 rpm-4.20.0~rc1 tzdata-2024a-1.el9.noarch", "dnf", "install", true, true,
			[]pkg{{"nginx-1.2.3", true}, {"systemd-252-46.el9.x86_64", true}, {"systemd-0:252-46.el9.x86_64", true}, {"rpm-4.20.0~rc1", true}, {"tzdata-2024a-1.el9.noarch", true}}},
		{"yum install -y java-1.8.0-openjdk", "yum", "install", true, true, []pkg{{"java-1.8.0-openjdk", false}}},
		{"dnf --setopt=assumeyes=1 install curl", "dnf", "install", true, true, []pkg{{"curl", false}}},
		{"dnf --setopt=defaultyes=1 install curl", "dnf", "install", false, true, []pkg{{"curl", false}}},
		{"dnf -y --setopt=defaultyes=0 install curl", "dnf", "install", true, true, []pkg{{"curl", false}}},
		{"zypper --non-interactive in vim", "zypper", "install", true, true, []pkg{{"vim", false}}},
		{"zypper -n in vim", "zypper", "install", true, true, []pkg{{"vim", false}}},
		{"zypper install -n vim", "zypper", "install", false, true, []pkg{{"vim", false}}},
		{"zypper -p http://r in vim", "zypper", "install", false, true, []pkg{{"vim", false}}},
		{"pip --timeout 60 --retries 3 install requests", "pip", "install", false, true, []pkg{{"requests", false}}},
		{"python3 -m pip install -r reqs.txt -e git+https://example.com/x.git 'requests[socks]==2.31.0'", "pip", "install", false, true,
			[]pkg{{"git+https://example.com/x.git", false}, {"requests[socks]==2.31.0", true}}},
		{"npm i --registry https://registry.example.com --omit dev --audit-level high @scope/a@1 git-rev-sync user/repo ./local https://example.com/pkg.tgz", "npm", "install", false, true,
			[]pkg{{"@scope/a@1", true}, {"git-rev-sync", false}}},
		{"yarn global add pm2", "yarn", "install", false, true, []pkg{{"pm2", false}}},
		{"gem install rails -v 7.0 puma --version=6.0.0 rack -v3.0.0 rake", "gem", "install", false, true,
			[]pkg{{"rails", true}, {"puma", true}, {"rack", true}, {"rake", false}}},
		{"gem install -v 7.0 rails", "gem", "install", false, true, []pkg{{"rails", true}}},
		{`yarn add "$PKG"`, "yarn", "install", false, false, []pkg{}},
		{`gem install rake --version $VERSION`, "gem", "install", false, false, []pkg{{"rake", true}}},
		{`pip install --index-url $INDEX requests`, "pip", "install", false, false, []pkg{{"requests", false}}},
		{`apk add -- $PACKAGES`, "apk", "install", false, false, []pkg{}},
	} {
		facts := Analyze(tc.script, "sh")
		require.True(t, facts.Complete, tc.script)
		require.Len(t, facts.PackageCommands, 1, tc.script)
		command := facts.PackageCommands[0]
		require.Equal(t, tc.manager, command.Manager, tc.script)
		require.Equal(t, tc.action, command.Action, tc.script)
		require.Equal(t, tc.assumeYes, command.AssumeYes, tc.script)
		require.Equal(t, tc.known, command.Known, tc.script)
		packages := []pkg{}
		for _, p := range command.Packages {
			packages = append(packages, pkg{p.Name, p.Pinned})
			require.Contains(t, tc.script[p.Span.Start:p.Span.End], p.Name, tc.script)
		}
		require.Equal(t, tc.packages, packages, tc.script)
	}
	require.Empty(t, Analyze("f() { pip install x; }; echo pip install x", "sh").PackageCommands)
	require.Empty(t, Analyze("python3 -c 'print(1)' -m pip install flask", "sh").PackageCommands)
	require.Empty(t, Analyze("python3 -c'print(1)' -m pip install flask", "sh").PackageCommands)
}

func TestAnalyzePackageCleanupChainsAreOrdered(t *testing.T) {
	for _, tc := range []struct {
		name, script, manager, cleanup string
	}{
		{"apt chain and list removal", "apt-get install -y curl && apt-get clean && rm -rf /var/lib/apt/lists/*", "apt-get", "rm"},
		{"dnf chain after setup", "dnf config-manager --set-enabled repo && sed -i 's/a/b/' /etc/config && dnf install -y curl && dnf clean all", "dnf", "dnf"},
		{"zypper install then clean", "zypper install -y httpd=2.4 && zypper clean", "zypper", "zypper"},
		{"yum install then clean", "yum install -y curl && yum clean all", "yum", "yum"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(tc.script, "sh")
			require.True(t, facts.Complete, facts.Diagnostics)
			installCall, cleanupCall := -1, -1
			for _, command := range facts.PackageCommands {
				if command.Manager == tc.manager && command.Action == "install" {
					installCall = command.Call
				}
			}
			for i, call := range facts.Calls {
				if call.Name != tc.cleanup || len(call.Arguments) == 0 {
					continue
				}
				if tc.cleanup == "rm" || call.Arguments[0].Text == "clean" {
					cleanupCall = i
				}
			}
			require.NotEqual(t, -1, installCall, "install call is present: %#v", facts.PackageCommands)
			require.NotEqual(t, -1, cleanupCall, "cleanup call is present: %#v", facts.Calls)
			require.True(t, facts.Precedes(installCall, cleanupCall),
				"cleanup call must retain the install call as a proven predecessor")
		})
	}
}
