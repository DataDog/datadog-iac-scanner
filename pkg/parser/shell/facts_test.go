/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package shell

import (
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
	require.Equal(t, "shell_script", result.Scopes[result.Calls[3].Scope].Kind)
	require.Equal(t, "'apt-get install x'", script[result.Calls[3].Span.Start:result.Calls[3].Span.End],
		"a nested script call spans the argument that holds the script")
	require.Equal(t, "command_substitution", result.Scopes[result.Calls[4].Scope].Kind)

	result = AnalyzeArgv([]string{"echo", "$(pip install x)", "|"})
	require.Len(t, result.Calls, 1)
	require.True(t, result.Calls[0].Arguments[0].Known)
	require.True(t, result.Complete)

	result = AnalyzeShell("curl https://example.test | tar -xz | sh", []string{"/bin/bash", "-o", "pipefail", "-c"})
	require.True(t, result.Complete, result.Diagnostics)
	require.Len(t, result.Pipelines, 1)
	require.True(t, result.Pipelines[0].Pipefail)
	require.True(t, result.Pipelines[0].Known)
	require.Len(t, result.Calls, 3)
}

func TestAnalyzeControlFlow(t *testing.T) {
	result := Analyze("apt-get update && apt-get install x; echo fallback || echo failed; if true; then echo body; fi", "/usr/local/bin/bash")
	require.True(t, result.Complete, result.Diagnostics)
	require.False(t, result.Calls[0].Conditional)
	require.Equal(t, []Guard{{Kind: "success", Call: 0}}, result.Calls[1].Guards)
	require.Equal(t, []Guard{{Kind: "failure", Call: 2}}, result.Calls[3].Guards)
	require.True(t, result.Calls[5].Conditional)

	result = Analyze(`f() { cd relative; }; (cd third); apt-get() { :; }; apt-get install x`, "bash")
	require.True(t, result.Calls[0].Deferred)
	require.Equal(t, "subshell", result.Scopes[result.Calls[1].Scope].Kind)
	require.True(t, result.Calls[len(result.Calls)-1].Function)

	result = Analyze("for ((i=0; i<0; i++)); do set -o pipefail; done; curl x | cat", "bash")
	require.Len(t, result.Pipelines, 1)
	require.False(t, result.Pipelines[0].Known)

	result = Analyze("set -- -o pipefail; curl x | cat", "bash")
	require.Len(t, result.Pipelines, 1)
	require.False(t, result.Pipelines[0].Pipefail)
	require.True(t, result.Pipelines[0].Known)
}

func TestAnalyzeCompleteness(t *testing.T) {
	for _, script := range []string{
		`"$BIN" install`, `sh -c "$SCRIPT"`, `sudo -l apt-get install x`, `env -S 'apt-get install x'`,
		`xargs -n 1 pip install x`, `alias apt-get=echo; apt-get install x`, "echo 'unterminated",
	} {
		require.False(t, Analyze(script, "sh").Complete, script)
	}
	require.False(t, Analyze("Write-Output hi", "powershell").Complete)

	builder := newFactBuilder()
	builder.script("pip install x", "sh", 0, false, false, maxShellDepth)
	require.Contains(t, builder.result.Diagnostics, "shell analysis limit reached")
}

func TestAnalyzeSuccessPredecessors(t *testing.T) {
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(tc.script, "sh")
			require.True(t, facts.Complete, facts.Diagnostics)
			require.Len(t, facts.Calls, len(tc.want))
			for i, predecessors := range tc.want {
				require.Equal(t, predecessors, facts.Calls[i].SuccessPredecessors, "call %d", i)
			}
		})
	}
}

func TestAnalyzeOrderedPredecessors(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		want         [][]int
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
			name:   "conditional calls are not guaranteed predecessors of later commands",
			script: "false && apt-get update; apt-get install curl",
			want:   [][]int{nil, {0}, {0}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(tc.script, "sh")
			require.True(t, facts.Complete, facts.Diagnostics)
			require.Len(t, facts.Calls, len(tc.want))
			for i, predecessors := range tc.want {
				require.Equal(t, predecessors, facts.Calls[i].OrderedPredecessors, "call %d", i)
			}
		})
	}
}

func TestAnalyzeOrderingBudget(t *testing.T) {
	facts := Analyze(strings.Repeat("echo x; ", 1000), "sh")
	require.False(t, facts.Complete)
	require.Contains(t, facts.Diagnostics, "command ordering analysis limit reached")
	require.Len(t, facts.Calls, 1000, "known calls survive when relation expansion reaches its budget")
	require.Equal(t, "echo", facts.Calls[0].Name)
	require.Equal(t, "echo", facts.Calls[len(facts.Calls)-1].Name)
	for i := range facts.Calls {
		require.Empty(t, facts.Calls[i].SuccessPredecessors, "partial success edges must be cleared")
		require.Empty(t, facts.Calls[i].OrderedPredecessors, "partial order edges must be cleared")
	}
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
		{"apt-get install 7zip --assume-yes=false", "apt-get", "install", false, true, []pkg{{"7zip", false}}},
		{"apt-get install -y --assume-yes=false curl", "apt-get", "install", false, true, []pkg{{"curl", false}}},
		{"apk add --virtual .build gcc~=12", "apk", "install", false, true, []pkg{{"gcc~=12", true}}},
		{"dnf --setopt=x=1 --enablerepo epel in -y nginx-1.2.3", "dnf", "install", true, true, []pkg{{"nginx-1.2.3", true}}},
		{"zypper --non-interactive in vim", "zypper", "install", true, true, []pkg{{"vim", false}}},
		{"python3 -m pip install -r reqs.txt -e git+https://example.com/x.git 'requests[socks]==2.31.0'", "pip", "install", false, true,
			[]pkg{{"git+https://example.com/x.git", false}, {"requests[socks]==2.31.0", true}}},
		{"npm i --registry https://registry.example.com --omit dev @scope/a@1 git-rev-sync ./local https://example.com/pkg.tgz", "npm", "install", false, true,
			[]pkg{{"@scope/a@1", true}, {"git-rev-sync", false}}},
		{"gem install rails -v 7.0 puma --version=6.0.0 rack -v3.0.0 rake", "gem", "install", false, true,
			[]pkg{{"rails", true}, {"puma", true}, {"rack", true}, {"rake", false}}},
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
			span := facts.Calls[command.Call].ArgumentSpans[p.Argument]
			require.Contains(t, tc.script[span.Start:span.End], p.Name, tc.script)
		}
		require.Equal(t, tc.packages, packages, tc.script)
	}
	require.Empty(t, Analyze("f() { pip install x; }; echo pip install x", "sh").PackageCommands)
	require.Empty(t, Analyze("python3 -c 'print(1)' -m pip install flask", "sh").PackageCommands)
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
			require.Contains(t, facts.Calls[cleanupCall].OrderedPredecessors, installCall,
				"cleanup call must retain the install call as a proven predecessor")
		})
	}
}
