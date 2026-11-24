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

func TestParse_SimpleCommand(t *testing.T) {
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

func TestParse_VariableExpansion(t *testing.T) {
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

func TestParse_RedirectedStatement(t *testing.T) {
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

func TestParse_Pipeline(t *testing.T) {
	script := "something | tee $GITHUB_ENV"
	result := Parse(script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "pipeline", cmd.Type)
	require.Len(t, cmd.Pipeline, 2)

	assert.Equal(t, "something", cmd.Pipeline[0].Command)
	assert.Equal(t, "tee", cmd.Pipeline[1].Command)
	require.Len(t, cmd.Pipeline[1].Args, 1)
	assert.Equal(t, "simple_expansion", cmd.Pipeline[1].Args[0].Type)
	assert.Equal(t, "GITHUB_ENV", cmd.Pipeline[1].Args[0].Var)
}

func TestParse_LiteralString(t *testing.T) {
	script := `echo "static value" >> $GITHUB_ENV`
	result := Parse(script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "redirected_statement", cmd.Type)
	assert.Equal(t, "echo", cmd.Command)
	require.Len(t, cmd.Args, 1)
	assert.Equal(t, "literal", cmd.Args[0].Type)
	assert.Equal(t, `"static value"`, cmd.Args[0].Value)
}

func TestParse_StringWithExpansion(t *testing.T) {
	script := `echo "FOO=$BAR" >> $GITHUB_ENV`
	result := Parse(script, "bash")

	require.True(t, result.ParseOK)
	require.Len(t, result.Commands, 1)

	cmd := result.Commands[0]
	assert.Equal(t, "echo", cmd.Command)
	require.Len(t, cmd.Args, 1)
	assert.Equal(t, "string_with_expansion", cmd.Args[0].Type)
}

func TestParse_PackagePublishCommands(t *testing.T) {
	t.Run("cargo publish", func(t *testing.T) {
		result := Parse("cargo publish --token $TOKEN", "bash")
		require.True(t, result.ParseOK)
		require.Len(t, result.Commands, 1)

		cmd := result.Commands[0]
		assert.Equal(t, "cargo", cmd.Command)
		require.Len(t, cmd.Args, 3)
		assert.Equal(t, "publish", cmd.Args[0].Value)
		assert.Equal(t, "--token", cmd.Args[1].Value)
		assert.Equal(t, "simple_expansion", cmd.Args[2].Type)
	})

	t.Run("npm publish", func(t *testing.T) {
		result := Parse("npm publish", "bash")
		require.True(t, result.ParseOK)
		require.Len(t, result.Commands, 1)

		cmd := result.Commands[0]
		assert.Equal(t, "npm", cmd.Command)
		require.Len(t, cmd.Args, 1)
		assert.Equal(t, "publish", cmd.Args[0].Value)
	})

	t.Run("twine upload", func(t *testing.T) {
		result := Parse("twine upload dist/*", "bash")
		require.True(t, result.ParseOK)
		require.Len(t, result.Commands, 1)

		cmd := result.Commands[0]
		assert.Equal(t, "twine", cmd.Command)
		require.Len(t, cmd.Args, 2)
		assert.Equal(t, "upload", cmd.Args[0].Value)
		assert.Equal(t, "dist/*", cmd.Args[1].Value)
	})
}

func TestParse_MultipleCommands(t *testing.T) {
	script := `
echo "Building..."
cargo build --release
cargo publish
`
	result := Parse(script, "bash")

	require.True(t, result.ParseOK)
	assert.GreaterOrEqual(t, len(result.Commands), 3, "should have at least 3 commands")
}

func TestParse_UnsupportedShell(t *testing.T) {
	result := Parse("Write-Output 'test'", "powershell")
	require.False(t, result.ParseOK)
	assert.Contains(t, result.Error.Error(), "PowerShell")
}

func TestParse_EmptyScript(t *testing.T) {
	result := Parse("", "bash")
	require.True(t, result.ParseOK)
	assert.Empty(t, result.Commands)
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
			assert.Equal(t, tt.expected, normalizeShell(tt.input))
		})
	}
}
