/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package cicd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShellParser_parseRunBlock_SimpleCommand(t *testing.T) {
	script := "echo hello world"
	result := parseRunBlock(script, "bash")

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
	result := parseRunBlock(script, "bash")

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
	result := parseRunBlock(script, "bash")

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
	result := parseRunBlock(script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 3)

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
	result := parseRunBlock(script, "bash")

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
	result := parseRunBlock(script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "echo", cmd.Command)
	require.Len(t, cmd.Args, 1)
	assert.Equal(t, "string_with_expansion", cmd.Args[0].Type) // Has variable expansion
}

func TestShellParser_parseRunBlock_CargoPublish(t *testing.T) {
	script := "cargo publish --token $TOKEN"
	result := parseRunBlock(script, "bash")

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
	result := parseRunBlock(script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "npm", cmd.Command)
	require.Len(t, cmd.Args, 1)
	assert.Equal(t, "publish", cmd.Args[0].Value)
}

func TestShellParser_parseRunBlock_TwineUpload(t *testing.T) {
	script := "twine upload dist/*"
	result := parseRunBlock(script, "bash")

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
	result := parseRunBlock(script, "bash")

	require.True(t, result.ParseOK)
	assert.GreaterOrEqual(t, len(result.Commands), 3, "should have at least 3 commands")
}

func TestShellParser_parseRunBlock_UnsupportedShell(t *testing.T) {
	script := "Write-Output 'test'"
	result := parseRunBlock(script, "powershell")

	require.False(t, result.ParseOK)
	assert.Contains(t, result.Error.Error(), "PowerShell")
}

func TestShellParser_parseRunBlock_InvalidScript(t *testing.T) {
	// Empty script should still parse OK (no commands found)
	script := ""
	result := parseRunBlock(script, "bash")

	require.True(t, result.ParseOK)
	assert.Len(t, result.Commands, 0)
}

func TestShellParser_parseRunBlock_EmptyShell(t *testing.T) {
	result := parseRunBlock("echo hello", "")
	require.False(t, result.ParseOK)
	require.Error(t, result.Error)
}

func TestNormalizeShell(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/bin/bash", "bash"},
		{"/usr/bin/bash", "bash"},
		{"/usr/local/bin/bash", "bash"},
		{"bash", "bash"},
		{"bash -e", "bash"},
		{"/bin/sh -x", "sh"},
		{"zsh", "zsh"},
		{"pwsh", "pwsh"},
		{"", ""},
		{"   ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeShell(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestShellParser_SyntaxStatus(t *testing.T) {
	for _, script := range []string{`echo "unterminated`, "if true; then echo ok", "echo $("} {
		parsed := parseRunBlock(script, "bash")
		require.True(t, parsed.ParseOK, "legacy rules must retain recovered facts")
		require.Error(t, parsed.Error, script)
	}
}

func TestShellParser_GitHubTemplates(t *testing.T) {
	for _, argument := range []string{
		`${{ github.event.issue.title }}`, `"${{ inputs.title }}"`, `'${{ format('}}{0}', inputs.title) }}'`,
		"${{ contains('main',\n github.ref) }}",
	} {
		t.Run(argument, func(t *testing.T) {
			parsed := parseGitHubRunBlock("echo "+argument+" >> \"$GITHUB_ENV\"", "bash")
			require.True(t, parsed.ParseOK, "%v", parsed.Error)
			require.Len(t, parsed.Commands, 1)
			cmd := parsed.Commands[0]
			require.Len(t, cmd.Args, 1)
			require.Equal(t, argument, cmd.Args[0].Value)
			require.Equal(t, string_with_expansion, cmd.Args[0].Type)
			require.Empty(t, cmd.Args[0].Var)
			require.Equal(t, "GITHUB_ENV", cmd.Redirect.Target.Var)
		})
	}
}

func TestShellParser_RedirectedPipeline(t *testing.T) {
	parsed := parseRunBlock(`printf %s "$PAYLOAD" | cat >> "$GITHUB_ENV"`, "bash")
	require.True(t, parsed.ParseOK)
	require.Len(t, parsed.Commands, 4)
	cmd := parsed.Commands[0]
	require.Equal(t, "GITHUB_ENV", cmd.Redirect.Target.Var)
	require.Len(t, cmd.Pipeline, 2)
	require.Equal(t, "printf", cmd.Pipeline[0].Command)
	require.Equal(t, "cat", cmd.Pipeline[1].Command)
}

// Commands must remain visible to existing rules regardless of shell grouping.
func TestShellParser_ExecutableCommandVisibility(t *testing.T) {
	for _, script := range []string{
		"npm publish", "npm publish | tee publish.log", "{ npm publish; } >publish.log",
		"(npm publish) >publish.log", "if true; then npm publish; fi >publish.log",
		"echo $(npm publish) >publish.log", "npm publish >publish.log | cat",
	} {
		t.Run(script, func(t *testing.T) {
			parsed := parseRunBlock(script, "bash")
			require.True(t, parsed.ParseOK, "%v", parsed.Error)
			count := 0
			for _, cmd := range parsed.Commands {
				if cmd.Command == "npm" {
					count++
					require.Equal(t, "publish", cmd.Args[0].Value)
				}
			}
			require.Equal(t, 1, count, "each executable command appears once")
		})
	}
	for _, script := range []string{`echo 'npm publish'`, "# npm publish", `echo "npm publish"`} {
		parsed := parseRunBlock(script, "bash")
		require.True(t, parsed.ParseOK)
		for _, cmd := range parsed.Commands {
			require.NotEqual(t, "npm", cmd.Command)
		}
	}
}

func TestShellParser_RecoveryPreservesExecutablePrefix(t *testing.T) {
	parsed := parseRunBlock("echo \"$PAYLOAD\" >> \"$GITHUB_ENV\"\nprintf \"unterminated", "bash")
	require.True(t, parsed.ParseOK)
	require.Error(t, parsed.Error)
	require.NotEmpty(t, parsed.Commands)
	require.Equal(t, "echo", parsed.Commands[0].Command)
	require.Equal(t, "GITHUB_ENV", parsed.Commands[0].Redirect.Target.Var)
}
