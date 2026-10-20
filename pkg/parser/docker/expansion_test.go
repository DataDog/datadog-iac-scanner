package docker

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExpandValuesUnsetDefaultsAndRecovery(t *testing.T) {
	for _, tt := range []struct {
		source, want string
		raw          bool
	}{
		{`pre'fix $H'post ${#H} $H`, `pre'fix $H'post ${#H} hello`, true},
		{`pre'fix $H'post ${#H} $H`, `prefix $Hpost ${#H} hello`, false},
		{`pre'fix $H' ${#H} $H`, `pre'fix $H' ${#H} hello`, true},
		{`pre'fix $H' ${#H} $H`, `prefix $H ${#H} hello`, false},
		{`it's pre'fix $H' ${#H} $H`, `it's pre'fix $H' ${#H} hello`, true},
		{`${A:-x} $É ${É} $1word`, `x $É ${É} $1word`, true},
		{`it's ${A:-$É} $H`, `it's $É hello`, true},
		{"\ue000 ${A:-x} $X", "\ue000 x literal $H", true},
		{`test ${A:-1} -eq 1 || exit $?`, `test 1 -eq 1 || exit $?`, true},
		{`${A:-1} $$ $@ $* $# $? $- $! $0 $1 ${?} ${@}`, `1 $$ $@ $* $# $? $- $! $0 $1 ${?} ${@}`, true},
		{`${A:-1} $$ $@ $* $# $? $- $! $0 $1 ${?} ${@}`, `1 $$ $@ $* $# $? $- $! $0 $1 ${?} ${@}`, false},
		{`echo ${A:-$B}`, `echo $B`, true},
		{`echo it's ${A:-$B}`, `echo it's $B`, true},
		{`echo it's ${A:-${B:-$C}} $? $H`, `echo it's $C $? hello`, true},
		{`echo it's "${A:-$B}" '$H' \$H`, `echo it's "$B" '$H' \$H`, true},
		{`echo it's ${A:-$B}`, `echo it's $B`, false},
		{`echo ${A:-$B} ${UNKNOWN} ${A:-x}`, `echo $B ${UNKNOWN} x`, true},
		{`${MISSING:-"a}b"}`, `a}b`, false},
		{`"${MISSING:-"word"}" $UNKNOWN`, `""word"" $UNKNOWN`, true},
		{`${MISSING:-d} \$UNKNOWN '${UNKNOWN}' "$UNKNOWN"`, `d \$UNKNOWN '${UNKNOWN}' "$UNKNOWN"`, true},
		{`${MISSING:-d} \$UNKNOWN '${UNKNOWN}' "$UNKNOWN"`, `d $UNKNOWN ${UNKNOWN} $UNKNOWN`, false},
		{`${MISSING:-d} $X $UNKNOWN ${UNKNOWN}`, `d literal $H $UNKNOWN ${UNKNOWN}`, true},
		{`${#H} $H \$H '$H' "$H"`, `${#H} hello \$H '$H' "hello"`, true},
	} {
		t.Run(tt.source, func(t *testing.T) {
			scope := map[string]string{"H": "hello", "X": "literal $H", "MARKER": "\ue000", "OTHER": "\ue000\ue000"}
			require.Equal(t, []string{tt.want}, expandValues(newWordExpander('\\', tt.raw), []string{tt.source}, scope))
		})
	}
}

// A subprocess makes lexer diagnostics observable without swapping the process-wide
// stderr used by unrelated tests or racing concurrent scans.
func TestExpandValuesNoDiagnostics(t *testing.T) {
	const child = "SCANNER_EXPANSION_DIAGNOSTICS_CHILD"
	if os.Getenv(child) == "1" {
		scope := map[string]string{"MARKER": "\ue000", "OTHER": "\ue000\ue000", "BAD": "a\x00b", "LATIN": "caf\xe9"}
		for _, raw := range []bool{true, false} {
			for _, value := range []string{`echo ${UNKNOWN} ${A:-x}`, `$BAD $LATIN ${A:-x}`, `echo it's ${A:-$B}`, "echo \x00 $H ${A:-x}", "echo caf\xe9 $H ${A:-x}", "\ue000 ${A:-x} ${UNKNOWN}"} {
				expandValues(newWordExpander('\\', raw), []string{value}, scope)
			}
		}
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestExpandValuesNoDiagnostics$")
	command.Env = append(os.Environ(), child+"=1")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	require.NoError(t, err, "%s", output)
	require.Empty(t, stderr.String(), "expansion must not emit lexer diagnostics")
}

func TestExpansionDefaultsPreserveRuntimeReferences(t *testing.T) {
	for _, reference := range []string{"$?", "$$", "$@", "$*", "$#", "$-", "$!", "$0", "$1", "$10", "${?}", "${@}", "$UNKNOWN", "${UNKNOWN}", "$É", "${É}"} {
		for _, raw := range []bool{true, false} {
			for _, prefix := range []string{"", "${A:-x} ", "it's ${A:-x} "} {
				wantPrefix := strings.ReplaceAll(prefix, "${A:-x}", "x")
				got := expandValues(newWordExpander('\\', raw), []string{prefix + reference})
				require.Equal(t, []string{wantPrefix + reference}, got, "raw=%t source=%s", raw, prefix+reference)
			}
		}
	}
}

func TestExpandValuesPreservesBadBytes(t *testing.T) {
	for _, raw := range []bool{true, false} {
		for _, source := range []string{"echo \x00 $H", "echo caf\xe9 $H", "it's \x00 ${A:-x} $H", "it's caf\xe9 ${A:-x} $H"} {
			require.Equal(t, []string{source}, expandValues(newWordExpander('\\', raw), []string{source}, map[string]string{"H": "hello"}))
		}
	}
}

func TestExpansionInsertedBadBytesStayLiteral(t *testing.T) {
	for _, value := range []string{"caf\xe9", "a\x00b"} {
		for _, raw := range []bool{true, false} {
			for _, source := range []string{"$H", "${H:-x}", "${#A} $H"} {
				want := strings.ReplaceAll(strings.ReplaceAll(source, "${H:-x}", value), "$H", value)
				require.Equal(t, []string{want}, expandValues(newWordExpander('\\', raw), []string{source}, map[string]string{"H": value}))
			}
		}
	}
}
