package docker

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExpandValues_ValidWords(t *testing.T) {
	scope := map[string]string{
		"H":     "hello",
		"EMPTY": "",
		"X":     "literal $H",
	}
	tests := []struct {
		name   string
		source string
		raw    bool
		escape rune
		want   string
	}{
		{"plain and braced", `$H ${H}`, true, '\\', `hello hello`},
		{"quoting and escapes in commands", `echo \$H '$H' "\$H" "$H"`, true, '\\', `echo \$H '$H' "\$H" "hello"`},
		{"quoting and escapes in declarations", `"$H words"`, false, '\\', `hello words`},
		{"single-quoted declaration", `'$H'`, false, '\\', `$H`},
		{"escaped declaration", `\$H`, false, '\\', `$H`},
		{"backtick escape directive", "echo `$H $H", true, '`', "echo `$H hello"},
		{"known modifiers", `${H:-fallback} ${EMPTY:-fallback} ${H:+alt} ${EMPTY:+alt}`, true, '\\', `hello fallback alt `},
		{"known prefix suffix replace", `${H#he} ${H%lo} ${H/l/L}`, true, '\\', `llo hel heLlo`},
		{"unknown plain and operators preserved", `$UNKNOWN ${UNKNOWN} ${UNKNOWN:-default} ${UNKNOWN:+alt} ${UNKNOWN:?err} ${UNKNOWN#pre}`, true, '\\', `$UNKNOWN ${UNKNOWN} ${UNKNOWN:-default} ${UNKNOWN:+alt} ${UNKNOWN:?err} ${UNKNOWN#pre}`},
		{"nested known expanded inside unset default", `${UNKNOWN:-$H}`, true, '\\', `${UNKNOWN:-hello}`},
		{"shell specials preserved", `$? $$ $@ $* $# $- $! $0 $1`, true, '\\', `$? $$ $@ $* $# $- $! $0 $1`},
		{"single-pass no rescan", `$X`, true, '\\', `literal $H`},
		{"apostrophe inside double quotes", `"it's $H"`, true, '\\', `"it's hello"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandValues(newWordExpander(tt.escape, tt.raw), []string{tt.source}, scope)
			require.Equal(t, []string{tt.want}, got)
		})
	}
}

func TestExpandValues_FallbackOnMalformedOrBashSyntax(t *testing.T) {
	scope := map[string]string{
		"H": "hello",
		"X": "literal $H",
	}
	tests := []struct {
		name   string
		source string
		escape rune
		want   string
	}{
		{"unsupported bash length operator", `echo ${#H} $H ${H}`, '\\', `echo ${#H} hello hello`},
		{"unsupported bash case operator", `echo $H ${H@Q} $H`, '\\', `echo hello ${H@Q} hello`},
		{"unclosed double quote preserves apostrophe", `"it's ${A:-x} isn't $H`, '\\', `"it's ${A:-x} isn't hello`},
		{"unclosed single quote suppresses later refs", `echo $H it's $H`, '\\', `echo hello it's $H`},
		{"escapes and single quotes respected in fallback", `${#H} \$H '$H' "$H" ${H}`, '\\', `${#H} \$H '$H' "hello" hello`},
		{"backtick escape in fallback", "${#H} `$H $H", '`', "${#H} `$H hello"},
		{"double dollar consumed atomically", `${#H} $$H $$${H}`, '\\', `${#H} $$H $$hello`},
		{"known plain ref inside operator operand", `${#H} ${A:-$H} ${A:-'$H'} ${A:-"$H"}`, '\\', `${#H} ${A:-hello} ${A:-'$H'} ${A:-"hello"}`},
		{"non-plain operators on known var untouched", `${#H} ${H:-other} ${H/h/H}`, '\\', `${#H} ${H:-other} ${H/h/H}`},
		{"single-pass in fallback", `${#H} $X ${X}`, '\\', `${#H} literal $H literal $H`},
	}

	for _, tt := range tests {
		for _, raw := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/raw=%t", tt.name, raw), func(t *testing.T) {
				got := expandValues(newWordExpander(tt.escape, raw), []string{tt.source}, scope)
				require.Equal(t, []string{tt.want}, got)
			})
		}
	}
}

func TestExpandValues_PreservesBadBytesWithoutDiagnostics(t *testing.T) {
	const child = "SCANNER_EXPANSION_DIAGNOSTICS_CHILD"
	if os.Getenv(child) == "1" {
		scope := map[string]string{"H": "hello", "BAD": "a\x00b"}
		for _, raw := range []bool{true, false} {
			for _, value := range []string{
				"echo \x00 $H",
				"echo caf\xe9 $H",
				"$BAD $H",
				"echo it's \x00 $H",
			} {
				expandValues(newWordExpander('\\', raw), []string{value}, scope)
			}
		}
		return
	}

	scope := map[string]string{"H": "hello"}
	for _, bad := range []string{"\x00", "caf\xe9", "\xff\xc0\xaf"} {
		got := expandValues(newWordExpander('\\', true), []string{"echo " + bad + " $H '$H'"}, scope)
		require.Equal(t, []string{"echo " + bad + " hello '$H'"}, got)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestExpandValues_PreservesBadBytesWithoutDiagnostics$")
	cmd.Env = append(os.Environ(), child+"=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	require.NoError(t, err, "%s", output)
	require.Empty(t, stderr.String(), "expansion must not write lexer diagnostics to stderr")
}

func TestExpandValues_MalformedInputIsLinear(t *testing.T) {
	const size = 100 * 1024
	pattern := `"it's ${A:-x} isn't $H `
	source := "$H ${#BROKEN} " + strings.Repeat(pattern, size/len(pattern))
	expander := newWordExpander('\\', true)
	scope := map[string]string{"H": "hello"}

	start := time.Now()
	got := expandValues(expander, []string{source}, scope)[0]
	elapsed := time.Since(start)

	require.Less(t, elapsed, 100*time.Millisecond)
	require.True(t, strings.HasPrefix(got, "hello ${#BROKEN} "))
}

// BuildKit rebuilds an unset reference with an operator from its parsed parts,
// which changes it. Such words keep every byte as written, and the known
// references around them are still expanded.
func TestExpandValues_UnsetOperatorsKeepEveryByte(t *testing.T) {
	scope := variableScope{"H": "hello"}
	for _, raw := range []bool{true, false} {
		for _, ref := range []string{
			`${UNKNOWN//a/b}`, `${UNKNOWN/a/b}`, `${UNKNOWN:-"a b"}`, `${UNKNOWN:-a\ b}`, `${UNKNOWN:-'q'}`,
			`${UNKNOWN#"pre"}`, `${UNKNOWN%/}`, `${UNKNOWN:?need}`, `${UNKNOWN:+--flag}`, `${1:-x}`, `${@:-x}`,
		} {
			t.Run(fmt.Sprintf("%t/%s", raw, ref), func(t *testing.T) {
				got := expandValues(newWordExpander('\\', raw), []string{ref + " $H"}, scope)
				require.Equal(t, []string{ref + " hello"}, got)
			})
		}
	}
}

func TestExpandValues_LeadingByteOrderMarkIsKept(t *testing.T) {
	got := expandValues(newWordExpander('\\', true), []string{"\ufeff$H"}, variableScope{"H": "hello"})
	require.Equal(t, []string{"\ufeffhello"}, got)
}
