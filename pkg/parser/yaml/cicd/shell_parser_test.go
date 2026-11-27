/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package cicd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

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
	cmd := shellFact(t, result.Commands, pipeline, "")
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
	for _, script := range []string{`echo "unterminated`, "if true; then echo ok", "echo $(", "echo A | cat <<<", "echo A | cat <", "echo A > >(", "echo A >&", "echo A | cat <<EOF"} {
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
	cat := shellFact(t, parsed.Commands, redirected_statement, "cat")
	require.Empty(t, cat.Args)
	require.Equal(t, "GITHUB_ENV", cat.Redirect.Target.Var)
	printf := shellFact(t, parsed.Commands, command, "printf")
	require.Nil(t, printf.Redirect)
	group := shellFact(t, parsed.Commands, pipeline, "")
	require.Len(t, group.Pipeline, 2)
	require.Equal(t, "printf", group.Pipeline[0].Command)
	require.Equal(t, "cat", group.Pipeline[1].Command)
}

// Commands must remain visible to existing rules regardless of shell grouping.
func TestShellParser_ExecutableCommandVisibility(t *testing.T) {
	for _, script := range []string{
		"npm publish", "npm publish | tee publish.log", "{ npm publish; } >publish.log",
		"(npm publish) >publish.log", "if true; then npm publish; fi >publish.log",
		"echo $(npm publish) >publish.log", "npm publish >publish.log | cat",
		"echo >(npm publish)", "echo > >(npm publish)", "cat < <(npm publish)",
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

func shellFact(t *testing.T, facts []ParsedCommand, kind, name string) ParsedCommand {
	t.Helper()
	var matches []ParsedCommand
	for _, fact := range facts {
		if fact.Type == kind && fact.Command == name {
			matches = append(matches, fact)
		}
	}
	require.Len(t, matches, 1, "%s %s", kind, name)
	return matches[0]
}

func redirectedChain(size int) string {
	var script strings.Builder
	script.WriteString("a")
	for i := 0; i < size; i++ {
		fmt.Fprintf(&script, " | c%d > f%d", i, i)
	}
	return script.String()
}

func TestShellParser_RedirectedPipelineLinearFacts(t *testing.T) {
	for _, size := range []int{16, 128, 800, 1600} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			parsed := parseRunBlock(redirectedChain(size), "bash")
			require.True(t, parsed.ParseOK)
			require.NoError(t, parsed.Error)
			var names []string
			entries := len(parsed.Commands)
			for _, fact := range parsed.Commands {
				if fact.Type == pipeline {
					entries += len(fact.Pipeline)
					for _, member := range fact.Pipeline {
						require.Empty(t, member.Pipeline)
					}
				} else {
					names = append(names, fact.Command)
				}
			}
			require.Len(t, names, size+1, "every executable command is emitted once")
			require.Equal(t, "a", names[0])
			for i := 0; i < size; i++ {
				require.Equal(t, fmt.Sprint("c", i), names[i+1])
			}
			require.LessOrEqual(t, entries, 2*(size+1)+1, "group members must not copy nested subtrees")
		})
	}
}

func BenchmarkShellParser_RedirectedPipeline(b *testing.B) {
	for _, size := range []int{200, 400, 800, 1600} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			script := redirectedChain(size)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !parseRunBlock(script, "bash").ParseOK {
					b.Fatal("parse failed")
				}
			}
		})
	}
}

func TestShellParser_UnterminatedTemplateStatus(t *testing.T) {
	for _, script := range []string{"echo ${{ toJSON(secrets)", "echo ${{ toJSON(secrets) && 'unfinished }}"} {
		parsed := parseGitHubRunBlock(script, "bash")
		require.False(t, parsed.ParseOK)
		require.Error(t, parsed.Error)
	}
}

func TestShellParser_RedirectionScope(t *testing.T) {
	for _, tc := range []struct{ script, target string }{
		{`{ echo "$PAYLOAD"; } >> "$GITHUB_ENV"`, "GITHUB_ENV"},
		{`{ echo "$PAYLOAD" > "$SAFE_FILE"; } >> "$GITHUB_ENV"`, "SAFE_FILE"},
		{`echo "$(printf %s "$PAYLOAD")" >> "$GITHUB_ENV"`, "GITHUB_ENV"},
		{`echo "$PAYLOAD" >> "$GITHUB_ENV" > "$SAFE_FILE"`, "SAFE_FILE"},
	} {
		t.Run(tc.script, func(t *testing.T) {
			parsed := parseRunBlock(tc.script, "bash")
			require.NoError(t, parsed.Error)
			cmd := shellFact(t, parsed.Commands, redirected_statement, "echo")
			require.Equal(t, tc.target, cmd.Redirect.Target.Var)
			for _, fact := range parsed.Commands {
				if fact.Command == "printf" {
					require.Nil(t, fact.Redirect)
				}
			}
		})
	}
}

func TestShellParser_DifferentRedirectStreams(t *testing.T) {
	for _, tc := range []struct {
		script    string
		inherited bool
	}{
		{`{ echo "$PAYLOAD" 2> "$SAFE_FILE"; } >> "$GITHUB_ENV"`, true},
		{`{ echo "$PAYLOAD" < "$SAFE_FILE"; } >> "$GITHUB_ENV"`, true},
		{`{ echo "$PAYLOAD" > "$SAFE_FILE"; } >> "$GITHUB_ENV"`, false},
		{`{ echo "$PAYLOAD" 2> "$SAFE_FILE" > "$OTHER_FILE"; } >> "$GITHUB_ENV"`, false},
	} {
		t.Run(tc.script, func(t *testing.T) {
			parsed := parseRunBlock(tc.script, "bash")
			require.NoError(t, parsed.Error)
			found := false
			for _, cmd := range parsed.Commands {
				if cmd.Redirect != nil && cmd.Redirect.Target.Var == "GITHUB_ENV" {
					require.NotNil(t, cmd.Args, "rule-facing argument lists must serialize as arrays")
					found = true
				}
			}
			require.Equal(t, tc.inherited, found)
		})
	}
}

// Check both sides of the existing rule contract: literal output must stay
// literal, and dynamic or unknown output must remain visible at the sink.
func TestShellParser_EnvironmentWriteSemantics(t *testing.T) {
	for _, tc := range []struct {
		script string
		unsafe bool
	}{
		{`./build.sh && echo "BUILT=1" >> "$GITHUB_ENV"`, false},
		{`./check.sh || echo "FAILED=true" >> "$GITHUB_ENV"`, false},
		{`[ -n "$X" ] && echo "A=$X" >> "$GITHUB_ENV"`, true},
		{`./check.sh || echo "$X" >> "$GITHUB_ENV"`, true},
		{`./a && ./b || echo "A=1" >> "$GITHUB_ENV"`, false},
		{`./a && ./b || echo "$X" >> "$GITHUB_ENV"`, true},
		{`{ ./a && echo "A=1" > /dev/null; } >> "$GITHUB_ENV"`, true},
		{`{ echo "A=1" && echo "B=2"; } >> "$GITHUB_ENV"`, false},
		{`{ ./build.sh && echo "BUILT=1"; } >> "$GITHUB_ENV"`, true},
		{`{ echo "A=1" 2>/dev/null; } >> "$GITHUB_ENV"`, false},
		{`{ echo "$X" 2>/dev/null; } >> "$GITHUB_ENV"`, true},
		{`{ echo "$X" > /dev/null; } >> "$GITHUB_ENV"`, false},
		{`echo "A=1" | sort >> "$GITHUB_ENV"`, true},
		{`echo "$X" | sort >> "$GITHUB_ENV"`, true},
		{`echo "A=1" | cat | sort >> "$GITHUB_ENV"`, true},
		{`echo "$X" | cat | sort >> "$GITHUB_ENV"`, true},
		{`echo "$X" 2>/dev/null | sort >> "$GITHUB_ENV"`, true},
		{`echo "A=1" 2>/dev/null | sort >> "$GITHUB_ENV"`, true},
		{`./source.sh | sort >> "$GITHUB_ENV"`, true},
		{`cat file | sort >> "$GITHUB_ENV"`, true},
		{`echo "$X" > /dev/null | sort >> "$GITHUB_ENV"`, true},
		{`echo "A=1" | sort < "$INPUT" >> "$GITHUB_ENV"`, true},
		{`echo "A=1" >> "$GITHUB_ENV"`, false},
		{`echo "$X" >> "$GITHUB_ENV"`, true},
		{`echo A < "$INPUT" |& sort >> "$GITHUB_ENV"`, true},
		{`echo "A=1" 1>> "$GITHUB_ENV" 2>/dev/null`, false},
		{`echo "$X" 1>> "$GITHUB_ENV" 2>/dev/null`, true},
		{`echo "A=1" > /dev/null 2>> "$GITHUB_ENV"`, false},
		{`echo "$X" > /dev/null 2>> "$GITHUB_ENV"`, true},
		{`echo "A=1" | sort >> "$GITHUB_ENV" # tail comment`, true},
		{`echo "$X" | sort >> "$GITHUB_ENV" # tail comment`, true},
		{`echo "$(printf %s "$X")" | sort >> "$GITHUB_ENV"`, true},
	} {
		t.Run(tc.script, func(t *testing.T) {
			parsed := parseGitHubRunBlock(tc.script, "bash")
			require.True(t, parsed.ParseOK)
			require.NoError(t, parsed.Error)
			unsafe := shellHasUnsafeEnvWrite(parsed)
			require.Equal(t, tc.unsafe, unsafe)
		})
	}
}

func BenchmarkShellParser_NestedSubstitution(b *testing.B) {
	for _, shape := range []struct{ name, open, close string }{
		{"pipeline", "a | b $(", ")"}, {"plain", "echo $(", ")"}, {"quoted", `echo "$(`, `)"`}, {"process", "echo >(", ")"},
	} {
		for _, depth := range []int{1000, 2000, 4000} {
			b.Run(fmt.Sprintf("%s/%d", shape.name, depth), func(b *testing.B) {
				script := strings.Repeat(shape.open, depth) + "c" + strings.Repeat(shape.close, depth)
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if !parseRunBlock(script, "bash").ParseOK {
						b.Fatal("parse failed")
					}
				}
			})
		}
	}
}

func TestShellParser_NestedSubstitutionSourceSharing(t *testing.T) {
	for _, shape := range []string{"echo $(", "a | b $(", `echo "$(`, "echo >("} {
		for _, depth := range []int{8, 64, 4000} {
			t.Run(fmt.Sprintf("%s/%d", shape, depth), func(t *testing.T) {
				close := ")"
				if strings.Contains(shape, `"`) {
					close = `)"`
				}
				script := strings.Repeat(shape, depth) + "npm publish" + strings.Repeat(close, depth)
				parsed := parseRunBlock(script, "bash")
				require.True(t, parsed.ParseOK)
				require.NoError(t, parsed.Error)
				publish := shellFact(t, parsed.Commands, command, "npm")
				require.Equal(t, "publish", publish.Args[0].Value)
				for _, cmd := range parsed.Commands {
					for _, arg := range cmd.Args {
						if arg.Value != "" {
							require.True(t, stringSharesSource(script, arg.Value), "argument text must share the original source")
						}
					}
				}
			})
		}
	}
}

func stringSharesSource(source, value string) bool {
	start := uintptr(unsafe.Pointer(unsafe.StringData(source)))
	address := uintptr(unsafe.Pointer(unsafe.StringData(value)))
	return address >= start && address+uintptr(len(value)) <= start+uintptr(len(source))
}

// This predicate exercises the existing rule-facing write/content contract.
func shellHasUnsafeEnvWrite(parsed *ParsedRun) bool {
	for _, cmd := range parsed.Commands {
		if cmd.Redirect == nil || (cmd.Redirect.Target.Var != "GITHUB_ENV" && cmd.Redirect.Target.Var != "GITHUB_PATH") {
			continue
		}
		if cmd.Redirect.Operator != ">" && cmd.Redirect.Operator != ">>" {
			continue
		}
		if len(cmd.Args) == 0 {
			return true
		}
		for _, arg := range cmd.Args {
			if arg.Type != literal {
				return true
			}
		}
	}
	return false
}

// Bash is the independent oracle for authored fixture programs only. Production
// scanning never executes source. Unknown syntax must not justify a safe fact;
// the proven-safe controls must also stay free of false positives.
func TestShellParser_BashPipelineContent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Bash behavior suite runs on Unix")
	}
	bashPath, err := exec.LookPath("bash")
	require.NoError(t, err)
	for _, tc := range []struct {
		name, script     string
		payload, unknown bool
	}{
		{"literal", `echo "A=1" | sort >> "$GITHUB_ENV"`, false, true},
		{"dynamic", `echo "$PAYLOAD" | sort >> "$GITHUB_ENV"`, true, false},
		{"single quote", `echo '$PAYLOAD' | sort >> "$GITHUB_ENV"`, false, true},
		{"here string dynamic", `echo "A=1" | cat <<< "$PAYLOAD" | sort >> "$GITHUB_ENV"`, true, false},
		{"here string literal", `echo "$PAYLOAD" | cat <<< "A=1" | sort >> "$GITHUB_ENV"`, false, true},
		{"single quote here string", `echo "$PAYLOAD" | cat <<< '$PAYLOAD' | sort >> "$GITHUB_ENV"`, false, true},
		{"substitution here string", `echo A | cat <<< "$(printf %s "$PAYLOAD")" | sort >> "$GITHUB_ENV"`, true, false},
		{"prefix input", `echo "A=1" | < "$INPUT" cat | sort >> "$GITHUB_ENV"`, true, true},
		{"suffix input", `echo "A=1" | cat < "$INPUT" | sort >> "$GITHUB_ENV"`, true, true},
		{"prefix safe input", `echo "$PAYLOAD" | < "$SAFE_INPUT" cat | sort >> "$GITHUB_ENV"`, false, true},
		{"here doc", "echo A | cat <<EOF | sort >> \"$GITHUB_ENV\"\n$PAYLOAD\nEOF\n", true, true},
		{"quoted here doc", "echo A | cat <<'EOF' | sort >> \"$GITHUB_ENV\"\n$PAYLOAD\nEOF\n", false, true},
		{"identity descriptor dynamic", `echo "$PAYLOAD" >&1 | sort >> "$GITHUB_ENV"`, true, false},
		{"identity descriptor literal", `echo "A=1" >&1 | sort >> "$GITHUB_ENV"`, false, true},
		{"identity after null", `echo "$PAYLOAD" >/dev/null >&1 | sort >> "$GITHUB_ENV"`, false, true},
		{"fd path dynamic", `echo "$PAYLOAD" >/dev/fd/1 | sort >> "$GITHUB_ENV"`, true, false},
		{"fd path literal", `echo A >/dev/fd/1 | sort >> "$GITHUB_ENV"`, false, true},
		{"null after identity", `echo "$PAYLOAD" >&1 >/dev/null | sort >> "$GITHUB_ENV"`, false, true},
		{"stdout path dynamic", `echo "$PAYLOAD" >/dev/stdout | sort >> "$GITHUB_ENV"`, true, false},
		{"stdout path literal", `echo "A=1" >/dev/stdout | sort >> "$GITHUB_ENV"`, false, true},
		{"stdout after null", `echo "$PAYLOAD" >/dev/null >/dev/stdout | sort >> "$GITHUB_ENV"`, false, true},
		{"dynamic destination", `echo "$PAYLOAD" > "$FORWARD" | sort >> "$GITHUB_ENV"`, true, true},
		{"dynamic destination literal", `echo A > "$FORWARD" | sort >> "$GITHUB_ENV"`, false, true},
		{"null literal", `echo "$PAYLOAD" >/dev/null | sort >> "$GITHUB_ENV"`, false, true},
		{"quoted null", `echo "$PAYLOAD" >"/dev/null" | sort >> "$GITHUB_ENV"`, false, true},
		{"process forwarding", `echo "$PAYLOAD" > >(cat) | sort >> "$GITHUB_ENV"`, true, true},
		{"overridden process sink", `echo "$PAYLOAD" > >(cat) >/dev/null | sort >> "$GITHUB_ENV"`, false, true},
		{"independent process after null", `echo A > >(printf %s "$PAYLOAD") >/dev/null | sort >> "$GITHUB_ENV"`, true, true},
		{"process forwarding literal", `echo A > >(cat) | sort >> "$GITHUB_ENV"`, false, true},
		{"additional producer", `echo A >(echo "$PAYLOAD") | sort >> "$GITHUB_ENV"`, true, true},
		{"literal additional producer", `echo A >(echo B) | sort >> "$GITHUB_ENV"`, false, true},
		{"additional producer after null", `echo A >(echo "$PAYLOAD") >/dev/null | sort >> "$GITHUB_ENV"`, true, true},
		{"concatenated producer", `echo A"" >(echo "$PAYLOAD") | sort >> "$GITHUB_ENV"`, true, true},
		{"input process", `echo A | cat < <(echo "$PAYLOAD") | sort >> "$GITHUB_ENV"`, true, true},
		{"prefix here string", `echo A | <<< "$PAYLOAD" cat | sort >> "$GITHUB_ENV"`, true, false},
		{"here string identity stdin", `echo A | cat <<< "$PAYLOAD" 0<&0 | sort >> "$GITHUB_ENV"`, true, false},
		{"here string discarded stdin", `echo A | cat <<< "$PAYLOAD" </dev/null | sort >> "$GITHUB_ENV"`, false, true},
		{"here string replacing file", `echo "$PAYLOAD" | < "$INPUT" cat <<< A | sort >> "$GITHUB_ENV"`, false, true},
		{"merged stderr literal", `echo A 2>&1 | sort >> "$GITHUB_ENV"`, false, true},
		{"merged stderr dynamic", `echo "$PAYLOAD" 2>&1 | sort >> "$GITHUB_ENV"`, true, false},
		{"input error as producer", `echo A 2>&1 < "$MISSING_INPUT" | sort >> "$GITHUB_ENV"`, true, true},
		{"discarded stdout with live stderr", `printf %s "$PAYLOAD" 2>&1 >/dev/null | sort >> "$GITHUB_ENV"`, false, true},
		{"compound stdin with new producer", `{ cat | printf %s "$PAYLOAD" | sort; } <<< A >> "$GITHUB_ENV"`, true, true},
		{"compound stdin literal", `{ cat | sort; } <<< A >> "$GITHUB_ENV"`, false, true},
		{"split stdout before pipe", `>/dev/null printf %s "$PAYLOAD" >> "$GITHUB_ENV" | cat`, true, false},
		{"reverse stdout before pipe", `>> "$GITHUB_ENV" printf %s "$PAYLOAD" >/dev/null | cat`, false, false},
		{"split stdout after and", `true && >/dev/null echo "$PAYLOAD" >> "$GITHUB_ENV"`, true, false},
		{"reverse stdout after and", `true && >> "$GITHUB_ENV" echo "$PAYLOAD" >/dev/null`, false, false},
		{"split stdout after or", `false || >/dev/null echo "$PAYLOAD" >> "$GITHUB_ENV"`, true, false},
		{"reverse stdout after or", `false || >> "$GITHUB_ENV" echo "$PAYLOAD" >/dev/null`, false, false},
		{"enclosing scope siblings", `{ echo "$PAYLOAD"; >/dev/null echo A >> "$GITHUB_ENV"; } >> "$GITHUB_ENV"`, true, false},
		{"enclosing input pipe", `{ cat | sort; } < "$INPUT" >> "$GITHUB_ENV"`, true, true},
		{"spare descriptor env", `exec 3>> "$GITHUB_ENV"; echo "$PAYLOAD" >&3`, true, false},
		{"spare descriptor path", `exec 5>> "$GITHUB_PATH"; echo "$PAYLOAD" >&5`, true, false},
		{"literal and", `true && echo A >> "$GITHUB_ENV"`, false, false},
		{"dynamic and", `true && echo "$PAYLOAD" >> "$GITHUB_ENV"`, true, false},
		{"literal or", `false || echo A >> "$GITHUB_ENV"`, false, false},
		{"dynamic or", `false || echo "$PAYLOAD" >> "$GITHUB_ENV"`, true, false},
		{"stderr override literal", `{ echo A 2>/dev/null; } >> "$GITHUB_ENV"`, false, false},
		{"stderr override dynamic", `{ echo "$PAYLOAD" 2>/dev/null; } >> "$GITHUB_ENV"`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertBashShellContent(t, bashPath, tc.script, tc.payload, tc.unknown)
		})
	}
}

func assertBashShellContent(t *testing.T, bashPath, script string, payload, unknown bool) {
	t.Helper()
	dir := t.TempDir()
	result := filepath.Join(dir, "env")
	input := filepath.Join(dir, "input")
	safe := filepath.Join(dir, "safe")
	const marker = "UNTRUSTED_VALUE_5817"
	require.NoError(t, os.WriteFile(result, nil, 0o600))
	require.NoError(t, os.WriteFile(input, []byte(marker+"\n"), 0o600))
	require.NoError(t, os.WriteFile(safe, []byte("A=1\n"), 0o600))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bashPath, "--noprofile", "--norc", "-c", script)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "HOME=" + dir, "GITHUB_ENV=" + result, "GITHUB_PATH=" + result, "PAYLOAD=" + marker, "INPUT=" + input, "SAFE_INPUT=" + safe, "FORWARD=/dev/stdout", "MISSING_INPUT=" + filepath.Join(dir, marker)}
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", output)
	contents, err := os.ReadFile(result)
	require.NoError(t, err)
	require.Equal(t, payload, strings.Contains(string(contents), marker), "Bash oracle: %s", contents)
	parsed := parseRunBlock(script, "bash")
	require.True(t, parsed.ParseOK)
	if !unknown {
		require.NoError(t, parsed.Error)
	}
	require.Equal(t, payload || unknown, shellHasUnsafeEnvWrite(parsed), "scanner must preserve dynamic/unknown content and literal controls")
}

// The same ordered redirect sequence must behave identically when the grammar
// stores it on a command, a wrapper, or both. Enclosing scope is a separate base.
func TestShellParser_BashRedirectPermutations(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Bash behavior suite runs on Unix")
	}
	bashPath, err := exec.LookPath("bash")
	require.NoError(t, err)
	outputs := []string{`>/dev/null`, `>> "$GITHUB_ENV"`, `>&1`, `>/dev/stdout`}
	for i, first := range outputs {
		for j, second := range outputs {
			for placement := range 3 {
				for _, dynamic := range []bool{false, true} {
					for _, scope := range []string{"direct", "null group", "env group"} {
						t.Run(fmt.Sprintf("output/%d/%d/%d/%t/%s", i, j, placement, dynamic, scope), func(t *testing.T) {
							arg := "A=1"
							if dynamic {
								arg = `"$PAYLOAD"`
							}
							script := placedShellCommand("echo", arg, first, second, placement)
							sink := scope == "env group"
							for _, redirect := range []int{i, j} {
								switch redirect {
								case 0:
									sink = false
								case 1:
									sink = true
								}
							}
							switch scope {
							case "null group":
								script = "{ " + script + "; } >/dev/null"
							case "env group":
								script = "{ " + script + `; } >> "$GITHUB_ENV"`
							}
							assertBashShellContent(t, bashPath, script, dynamic && sink, false)
						})
					}
				}
			}
		}
	}
	inputs := []string{`<<< A=1`, `<<< "$PAYLOAD"`, `< "$INPUT"`, `< "$SAFE_INPUT"`, `0<&0`}
	for i, first := range inputs {
		for j, second := range inputs {
			for placement := range 3 {
				t.Run(fmt.Sprintf("input/%d/%d/%d", i, j, placement), func(t *testing.T) {
					payload, unknown := false, false
					for _, redirect := range []int{i, j} {
						switch redirect {
						case 0:
							payload, unknown = false, false
						case 1:
							payload, unknown = true, false
						case 2:
							payload, unknown = true, true
						case 3:
							payload, unknown = false, true
						}
					}
					// Pipeline content is deliberately unknown; Bash still checks
					// which input wins, independently of scanner syntax placement.
					unknown = true
					script := `echo A | ` + placedShellCommand("cat", "", first, second, placement) + ` | sort >> "$GITHUB_ENV"`
					assertBashShellContent(t, bashPath, script, payload, unknown)
				})
			}
		}
	}
}

func placedShellCommand(command, arg, first, second string, placement int) string {
	switch placement {
	case 0:
		return fmt.Sprintf("%s %s %s %s", first, second, command, arg)
	case 1:
		return fmt.Sprintf("%s %s %s %s", first, command, arg, second)
	default:
		return fmt.Sprintf("%s %s %s %s", command, arg, first, second)
	}
}

func TestShellParser_RedirectInventory(t *testing.T) {
	for _, tc := range []struct{ script, name, operator, target string }{
		{`bash < script.sh`, "bash", "<", "script.sh"},
		{`sh < "$F"`, "sh", "<", `"$F"`},
		{`exec 3>> "$GITHUB_ENV"`, "exec", ">>", `"$GITHUB_ENV"`},
		{`exec 5>> "$GITHUB_PATH"`, "exec", ">>", `"$GITHUB_PATH"`},
		{`<<< A cat < "$INPUT"`, "cat", "<", `"$INPUT"`},
		{`< "$INPUT" cat <<< A`, "cat", "<<<", "A"},
	} {
		t.Run(tc.script, func(t *testing.T) {
			parsed := parseRunBlock(tc.script, "bash")
			require.True(t, parsed.ParseOK)
			require.NoError(t, parsed.Error)
			cmd := shellFact(t, parsed.Commands, redirected_statement, tc.name)
			require.Equal(t, tc.operator, cmd.Redirect.Operator)
			require.Equal(t, tc.target, cmd.Redirect.Target.Value)
		})
	}
	parsed := parseRunBlock(`exec 3>> "$GITHUB_ENV" 5>> "$GITHUB_PATH"`, "bash")
	var targets []string
	for _, cmd := range parsed.Commands {
		if cmd.Redirect != nil {
			targets = append(targets, cmd.Redirect.Target.Var)
		}
	}
	require.ElementsMatch(t, []string{"GITHUB_ENV", "GITHUB_PATH"}, targets)
}
