package docker

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/stretchr/testify/require"
)

func TestExpandValuesUnsetDefaultsAndRecovery(t *testing.T) {
	for _, tt := range []struct {
		source, want string
		raw          bool
	}{
		{`pre'fix $H' it's ${#H} $H`, `pre'fix $H' it's ${#H} hello`, true},
		{`pre'fix $H' it's ${#H} $H`, `prefix $H it's ${#H} hello`, false},
		{`pre'fix $H' it's $H`, `pre'fix $H' it's hello`, true},
		{`pre'fix $H' it's $H`, `prefix $H it's hello`, false},
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
			for _, value := range []string{`echo ${UNKNOWN} ${A:-x}`, `$BAD $LATIN ${A:-x}`, `echo it's ${A:-$B}`, "echo \x00 $H ${A:-x}", "echo caf\xe9 $H ${A:-x}", "${#H} \\\x00 $H", "${#H} \\\xe9 $H", "\ue000 ${A:-x} ${UNKNOWN}"} {
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
		for _, bad := range []string{"\x00", "caf\xe9", "\xff\xc0\xaf"} {
			for _, tt := range []struct{ source, want string }{
				{"echo " + bad + " $H", "echo " + bad + " hello"},
				{"it's " + bad + " ${A:-x} $H", "it's " + bad + " x hello"},
				{"${#H} " + bad + " $H", "${#H} " + bad + " hello"},
			} {
				require.Equal(t, []string{tt.want}, expandValues(newWordExpander('\\', raw), []string{tt.source}, map[string]string{"H": "hello"}))
			}
		}
	}
}

func TestExpansionBadBytesAdjacentToSyntax(t *testing.T) {
	for _, bad := range []string{"\x00", "\xe9", "\xff\xc0"} {
		for _, raw := range []bool{true, false} {
			for _, escape := range []rune{'\\', '`'} {
				esc := string(escape)
				for _, recovery := range []string{"", "${#H} "} {
					wantEscape := ""
					if raw {
						wantEscape = esc
					}
					for _, tt := range []struct{ source, want string }{
						{esc + bad + " $H", wantEscape + bad + " hello"},
						{bad + "$H" + bad, bad + "hello" + bad},
						{"${A:-" + bad + "} $H", bad + " hello"},
					} {
						require.Equal(t, []string{recovery + tt.want}, expandValues(newWordExpander(escape, raw), []string{recovery + tt.source}, map[string]string{"H": "hello", "marker": "\ue001"}))
					}
				}
			}
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

// Valid shell fragments must have identical quoting and escaping behavior even
// when an unrelated unsupported reference forces the recovery path.
func TestExpansionRecoveryAgreesWithBuildKit(t *testing.T) {
	fragments := []string{
		`"${EMPTY:-"word"}"`, `"prefix ${EMPTY:-"$H"} suffix"`, `pre"${EMPTY:-"x}y"}"post`,
		`pre'fix $H'post`, `pre'fix text'post`, `'a " $H' "$H"`, `"a '$H" '$H'`,
		`one 'two $H' three "$H"`, `echo \$H '$H' "\$H" "$H"`,
		`'a \' $H`, `"one \" $H"`, `foo'bar'qux '$H'`,
		`echo ${H:-other} ${EMPTY:-value} ${H:+yes}`, `$${H}`, `$${#H}`, `$$${H}`, `$${H:-x}`, `$? $$ $@ $# $* $!`,
	}
	for _, raw := range []bool{true, false} {
		for _, escape := range []rune{'\\', '`'} {
			for _, fragment := range fragments {
				env := variableEnvironment{map[string]string{"H": "hello", "EMPTY": "", "?": "?", "$": "$", "@": "@", "#": "#", "*": "*", "!": "!"}}
				lex := shell.NewLex(escape)
				lex.RawQuotes, lex.RawEscapes = raw, raw
				want, _, err := lex.ProcessWord(fragment, env)
				if err != nil {
					continue
				} // Some backslash fragments are invalid with escape=`.
				for _, suffix := range []bool{false, true} {
					source, expected := "${#BROKEN} "+fragment, "${#BROKEN} "+want
					if suffix {
						source, expected = fragment+" ${#BROKEN}", want+" ${#BROKEN}"
					}
					t.Run(fmt.Sprintf("%t/%c/%t/%s", raw, escape, suffix, fragment), func(t *testing.T) {
						require.Equal(t, []string{expected}, expandValues(newWordExpander(escape, raw), []string{source}, env...))
					})
				}
			}
		}
	}
}

func FuzzExpansionRecoveryQuotes(f *testing.F) {
	for _, s := range []string{`pre'fix $H'post`, `'a " $H' "$H"`, `"a '$H" '$H'`, `echo \$H '$H' "$H"`, `one 'two' three`, `$${H}`, `$${#H}`, `$$${H}`, `$${H:-x}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, fragment string) {
		if !utf8.ValidString(fragment) || strings.ContainsRune(fragment, 0) {
			return
		}
		for _, raw := range []bool{true, false} {
			env := collectingEnvironment{}
			lex := shell.NewLex('\\')
			lex.RawQuotes, lex.RawEscapes = raw, raw
			want, _, err := lex.ProcessWord(fragment, env)
			if err != nil {
				return
			}
			// A newline separates a trailing escape from the unsupported token.
			source := "${#BROKEN} " + fragment
			require.Equal(t, []string{"${#BROKEN} " + want}, expandValues(newWordExpander('\\', raw), []string{source}, map[string]string(env)))
		}
	})
}

func BenchmarkExpansionRecoveryQuotes(b *testing.B) {
	for _, count := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			value := strings.Repeat(`pre'fix $H' it's `, count) + `orphan' $H`
			lex := newWordExpander('\\', true)
			env := map[string]string{"H": "hello"}
			if _, err := lex.expandWord(value, variableEnvironment{env}); err == nil {
				b.Fatal("benchmark must exercise unmatched-quote recovery")
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(value)))
			for b.Loop() {
				expandValues(lex, []string{value}, env)
			}
		})
	}
}

// Every name requested by the oracle is populated, keeping this differential
// test independent of the scanner's intentional unknown-variable policy.
type collectingEnvironment map[string]string

func (e collectingEnvironment) Get(name string) (string, bool) {
	e[name] = "hello"
	return "hello", true
}
func (e collectingEnvironment) Keys() []string { return nil }
