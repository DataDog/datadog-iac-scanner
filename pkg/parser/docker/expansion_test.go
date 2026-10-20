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
		scope := map[string]string{"MARKER": "\ue000", "OTHER": "\ue000\ue000"}
		for _, raw := range []bool{true, false} {
			for _, value := range []string{`echo ${UNKNOWN} ${A:-x}`, `echo it's ${A:-$B}`, "\ue000 ${A:-x} ${UNKNOWN}"} {
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
