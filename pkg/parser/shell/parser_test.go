/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package shell

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShellParser_parseRunBlock_SimpleCommand(t *testing.T) {
	script := "echo hello world"
	result := Parse(script, "bash")

	require.True(t, result.ParseOK, "parsing should succeed")
	require.Equal(t, "bash", result.Shell)
	require.Len(t, result.Commands, 1, "should have 1 command")

	cmd := result.Commands[0]
	assert.Equal(t, "command", cmd.Type)
	assert.Equal(t, "echo", cmd.Command)
	require.Len(t, cmd.Args, 2)
	assert.Equal(t, "literal", cmd.Args[0].Type)
	assert.Equal(t, "hello", cmd.Args[0].Value)
	assert.Equal(t, "literal", cmd.Args[1].Type)
	assert.Equal(t, "world", cmd.Args[1].Value)
}

func TestShellParser_parseRunBlock_VariableExpansion(t *testing.T) {
	script := "echo $USER_INPUT"
	result := Parse(script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "echo", cmd.Command)
	require.Len(t, cmd.Args, 1)
	assert.Equal(t, "simple_expansion", cmd.Args[0].Type)
	assert.Equal(t, "$USER_INPUT", cmd.Args[0].Value)
	assert.Equal(t, "USER_INPUT", cmd.Args[0].Var)
}

func TestShellParser_parseRunBlock_RedirectedStatement(t *testing.T) {
	script := "echo $FOO >> $GITHUB_ENV"
	result := Parse(script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "redirected_statement", cmd.Type)
	assert.Equal(t, "echo", cmd.Command)
	require.Len(t, cmd.Args, 1)
	assert.Equal(t, "simple_expansion", cmd.Args[0].Type)
	assert.Equal(t, "FOO", cmd.Args[0].Var)

	require.NotNil(t, cmd.Redirect)
	assert.Equal(t, ">>", cmd.Redirect.Operator)
	assert.Equal(t, "simple_expansion", cmd.Redirect.Target.Type)
	assert.Equal(t, "GITHUB_ENV", cmd.Redirect.Target.Var)
}

func TestShellParser_parseRunBlock_Pipeline(t *testing.T) {
	script := "something | tee $GITHUB_ENV"
	result := Parse(script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "pipeline", cmd.Type)
	require.Len(t, cmd.Pipeline, 2)

	// First command in pipeline
	assert.Equal(t, "something", cmd.Pipeline[0].Command)

	// Second command (tee)
	assert.Equal(t, "tee", cmd.Pipeline[1].Command)
	require.Len(t, cmd.Pipeline[1].Args, 1)
	assert.Equal(t, "simple_expansion", cmd.Pipeline[1].Args[0].Type)
	assert.Equal(t, "GITHUB_ENV", cmd.Pipeline[1].Args[0].Var)
}

func TestShellParser_parseRunBlock_LiteralString(t *testing.T) {
	script := `echo "static value" >> $GITHUB_ENV`
	result := Parse(script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "redirected_statement", cmd.Type)
	assert.Equal(t, "echo", cmd.Command)
	require.Len(t, cmd.Args, 1)
	assert.Equal(t, "literal", cmd.Args[0].Type) // Should be marked as literal (no expansions)
	assert.Equal(t, `"static value"`, cmd.Args[0].Value)
}

func TestShellParser_parseRunBlock_StringWithExpansion(t *testing.T) {
	script := `echo "FOO=$BAR" >> $GITHUB_ENV`
	result := Parse(script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "echo", cmd.Command)
	require.Len(t, cmd.Args, 1)
	assert.Equal(t, "string_with_expansion", cmd.Args[0].Type) // Has variable expansion
}

func TestShellParser_parseRunBlock_CargoPublish(t *testing.T) {
	script := "cargo publish --token $TOKEN"
	result := Parse(script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "cargo", cmd.Command)
	require.Len(t, cmd.Args, 3)
	assert.Equal(t, "publish", cmd.Args[0].Value)
	assert.Equal(t, "--token", cmd.Args[1].Value)
	assert.Equal(t, "simple_expansion", cmd.Args[2].Type)
}

func TestShellParser_parseRunBlock_NpmPublish(t *testing.T) {
	script := "npm publish"
	result := Parse(script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "npm", cmd.Command)
	require.Len(t, cmd.Args, 1)
	assert.Equal(t, "publish", cmd.Args[0].Value)
}

func TestShellParser_parseRunBlock_TwineUpload(t *testing.T) {
	script := "twine upload dist/*"
	result := Parse(script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "twine", cmd.Command)
	require.Len(t, cmd.Args, 2)
	assert.Equal(t, "upload", cmd.Args[0].Value)
	assert.Equal(t, "dist/*", cmd.Args[1].Value)
}

func TestShellParser_parseRunBlock_MultipleCommands(t *testing.T) {
	script := `
echo "Building..."
cargo build --release
cargo publish
`
	result := Parse(script, "bash")

	require.True(t, result.ParseOK)
	assert.GreaterOrEqual(t, len(result.Commands), 3, "should have at least 3 commands")
}

func TestShellParser_parseRunBlock_UnsupportedShell(t *testing.T) {
	script := "Write-Output 'test'"
	result := Parse(script, "powershell")

	require.False(t, result.ParseOK)
	assert.Contains(t, result.Error.Error(), "PowerShell")
}

func TestShellParser_parseRunBlock_InvalidScript(t *testing.T) {
	// Empty script should still parse OK (no commands found)
	script := ""
	result := Parse(script, "bash")

	require.True(t, result.ParseOK)
	assert.Len(t, result.Commands, 0)
}

func TestNormalizeShell(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/bin/bash", "bash"},
		{"/usr/bin/bash", "bash"},
		{"bash", "bash"},
		{"bash -e", "bash"},
		{"/bin/sh -x", "sh"},
		{"zsh", "zsh"},
		{"pwsh", "pwsh"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeShell(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLiteral(t *testing.T) {
	for _, tc := range []struct {
		raw, text string
		known     bool
	}{
		{`n"p"m`, "npm", true}, {`'literal $HOME'`, "literal $HOME", true}, {`a\ b`, "a b", true},
		{`"a\qb"`, `a\qb`, true}, {`"$HOME"`, "", false}, {`$(id)`, "", false}, {`*.txt`, "", false},
		{`"*.txt"`, "*.txt", true}, {`$'a\nb'`, "", false},
	} {
		actual := Literal(tc.raw)
		require.Equal(t, tc.known, actual.Known, tc.raw)
		if tc.known {
			require.Equal(t, tc.text, actual.Text, tc.raw)
		}
	}
}

func TestFactsCalls(t *testing.T) {
	script := `echo "pip install data"; timeout 10 sudo -u root /usr/bin/pip install 'x==1'; sh -c 'apt-get install x'; echo $(id)`
	result := Analyze(script, "sh")
	require.True(t, result.Complete, result.Diagnostics)
	names := []string{}
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
}

func TestFactsControlFlow(t *testing.T) {
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
}

func TestFactsCompleteness(t *testing.T) {
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

func TestPackageCommands(t *testing.T) {
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
		{"apk add --virtual .build gcc~=12", "apk", "install", false, true, []pkg{{"gcc~=12", true}}},
		{"dnf --setopt=x=1 --enablerepo epel in -y nginx-1.2.3", "dnf", "install", true, true, []pkg{{"nginx-1.2.3", true}}},
		{"zypper --non-interactive in vim", "zypper", "install", true, true, []pkg{{"vim", false}}},
		{"python3 -m pip install -r reqs.txt -e git+https://example.com/x.git flask==2.0", "pip", "install", false, true,
			[]pkg{{"git+https://example.com/x.git", false}, {"flask==2.0", true}}},
		{"npm i --registry https://registry.example.com @scope/a@1 b ./local", "npm", "install", false, true,
			[]pkg{{"@scope/a@1", true}, {"b", false}}},
		{"gem install rails -v 7.0", "gem", "install", false, true, []pkg{{"rails", true}}},
		{`yarn add "$PKG"`, "yarn", "install", false, false, []pkg{}},
	} {
		facts := Analyze(tc.script, "sh")
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
}
