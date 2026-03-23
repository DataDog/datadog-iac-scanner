/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package cicd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShellParser_ParseRunBlock_SimpleCommand(t *testing.T) {
	parser := NewShellScriptParser()
	ctx := context.Background()

	script := "echo hello world"
	result := parser.ParseRunBlock(ctx, script, "bash")

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

func TestShellParser_ParseRunBlock_VariableExpansion(t *testing.T) {
	parser := NewShellScriptParser()
	ctx := context.Background()

	script := "echo $USER_INPUT"
	result := parser.ParseRunBlock(ctx, script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "echo", cmd.Command)
	require.Len(t, cmd.Args, 1)
	assert.Equal(t, "simple_expansion", cmd.Args[0].Type)
	assert.Equal(t, "$USER_INPUT", cmd.Args[0].Value)
	assert.Equal(t, "USER_INPUT", cmd.Args[0].Var)
}

func TestShellParser_ParseRunBlock_RedirectedStatement(t *testing.T) {
	parser := NewShellScriptParser()
	ctx := context.Background()

	script := "echo $FOO >> $GITHUB_ENV"
	result := parser.ParseRunBlock(ctx, script, "bash")

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

func TestShellParser_ParseRunBlock_Pipeline(t *testing.T) {
	parser := NewShellScriptParser()
	ctx := context.Background()

	script := "something | tee $GITHUB_ENV"
	result := parser.ParseRunBlock(ctx, script, "bash")

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

func TestShellParser_ParseRunBlock_LiteralString(t *testing.T) {
	parser := NewShellScriptParser()
	ctx := context.Background()

	script := `echo "static value" >> $GITHUB_ENV`
	result := parser.ParseRunBlock(ctx, script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "redirected_statement", cmd.Type)
	assert.Equal(t, "echo", cmd.Command)
	require.Len(t, cmd.Args, 1)
	assert.Equal(t, "literal", cmd.Args[0].Type) // Should be marked as literal (no expansions)
	assert.Equal(t, `"static value"`, cmd.Args[0].Value)
}

func TestShellParser_ParseRunBlock_StringWithExpansion(t *testing.T) {
	parser := NewShellScriptParser()
	ctx := context.Background()

	script := `echo "FOO=$BAR" >> $GITHUB_ENV`
	result := parser.ParseRunBlock(ctx, script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "echo", cmd.Command)
	require.Len(t, cmd.Args, 1)
	assert.Equal(t, "string_with_expansion", cmd.Args[0].Type) // Has variable expansion
}

func TestShellParser_ParseRunBlock_CargoPublish(t *testing.T) {
	parser := NewShellScriptParser()
	ctx := context.Background()

	script := "cargo publish --token $TOKEN"
	result := parser.ParseRunBlock(ctx, script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "cargo", cmd.Command)
	require.Len(t, cmd.Args, 3)
	assert.Equal(t, "publish", cmd.Args[0].Value)
	assert.Equal(t, "--token", cmd.Args[1].Value)
	assert.Equal(t, "simple_expansion", cmd.Args[2].Type)
}

func TestShellParser_ParseRunBlock_NpmPublish(t *testing.T) {
	parser := NewShellScriptParser()
	ctx := context.Background()

	script := "npm publish"
	result := parser.ParseRunBlock(ctx, script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "npm", cmd.Command)
	require.Len(t, cmd.Args, 1)
	assert.Equal(t, "publish", cmd.Args[0].Value)
}

func TestShellParser_ParseRunBlock_TwineUpload(t *testing.T) {
	parser := NewShellScriptParser()
	ctx := context.Background()

	script := "twine upload dist/*"
	result := parser.ParseRunBlock(ctx, script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "twine", cmd.Command)
	require.Len(t, cmd.Args, 2)
	assert.Equal(t, "upload", cmd.Args[0].Value)
	assert.Equal(t, "dist/*", cmd.Args[1].Value)
}

func TestShellParser_ParseRunBlock_MultipleCommands(t *testing.T) {
	parser := NewShellScriptParser()
	ctx := context.Background()

	script := `
echo "Building..."
cargo build --release
cargo publish
`
	result := parser.ParseRunBlock(ctx, script, "bash")

	require.True(t, result.ParseOK)
	assert.GreaterOrEqual(t, len(result.Commands), 3, "should have at least 3 commands")
}

func TestShellParser_ParseRunBlock_UnsupportedShell(t *testing.T) {
	parser := NewShellScriptParser()
	ctx := context.Background()

	script := "Write-Output 'test'"
	result := parser.ParseRunBlock(ctx, script, "powershell")

	require.False(t, result.ParseOK)
	assert.Contains(t, result.Error, "PowerShell")
}

func TestShellParser_ParseRunBlock_InvalidScript(t *testing.T) {
	parser := NewShellScriptParser()
	ctx := context.Background()

	// Empty script should still parse OK (no commands found)
	script := ""
	result := parser.ParseRunBlock(ctx, script, "bash")

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
