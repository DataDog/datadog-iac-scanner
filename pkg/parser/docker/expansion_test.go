package docker

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/stretchr/testify/require"
)

// Malformed complete words have a deliberately conservative policy: no quote
// repair, quote removal, escape processing or operator/default evaluation.
func TestExpansionMalformedPlainReferences(t *testing.T) {
	for _, tt := range []struct{ source, want string }{
		{`"it's ${A:-x} isn't $H`, `"it's ${A:-x} isn't hello`},
		{`"$H isn't ${A:-x} it's`, `"hello isn't ${A:-x} it's`},
		{`before "it's ${A:-"x y"} isn't $H`, `before "it's ${A:-"x y"} isn't hello`},
		{`"it's ${A:-'q'} isn't '$H' $H`, `"it's ${A:-'q'} isn't 'hello' hello`},
		{`" ${A:-'q'} $H`, `" ${A:-'q'} hello`},
		{`${A:-'q'} " $H`, `${A:-'q'} " hello`},
		{`${A:-'q'} ' $H`, `${A:-'q'} ' $H`},
		{`pre'fix $H' it's $H`, `pre'fix $H' it's $H`},
		{`it's pre'fix $H' ${#H} $H`, `it's pre'fix hello' ${#H} $H`},
		{`${#H} pre'fix $H'post $H`, `${#H} pre'fix $H'post hello`},
		{`${#H} ${A:-"${UNSET%/}"} $H`, `${#H} ${A:-"${UNSET%/}"} hello`},
		{`${#H} ${A:-"${UNSET/a/b}"} $H`, `${#H} ${A:-"${UNSET/a/b}"} hello`},
		{`it's ${A:-"${UNSET#prefix}"} $H`, `it's ${A:-"${UNSET#prefix}"} $H`},
		{`it's ${A:-$É} $H`, `it's ${A:-$É} $H`},
		{`echo it's ${A:-$B}`, `echo it's ${A:-$B}`},
		{`echo it's ${A:-${B:-$C}} $? $H`, `echo it's ${A:-${B:-$C}} $? $H`},
		{`echo it's "${A:-$B}" '$H' \$H`, `echo it's "${A:-$B}" 'hello' \$H`},
		{`${#H} $H ${H} '$H ${H}' "$H ${H}"`, `${#H} hello hello '$H ${H}' "hello hello"`},
		{`${#H} ${A:-$H} ${A:-'$H'} ${A:-"$H"}`, `${#H} ${A:-hello} ${A:-'$H'} ${A:-"hello"}`},
		{`${#H} $X ${X} ${H:-other} ${H/h/H}`, `${#H} literal $H literal $H ${H:-other} ${H/h/H}`},
		{`${#H} $? $$ $@ $# $* $! $1 $É ${É}`, `${#H} $? $$ $@ $# $* $! $1 café café`},
	} {
		for _, raw := range []bool{false, true} {
			for _, escape := range []rune{'\\', '`'} {
				// This row specifically tests a backslash escape.
				if escape == '`' && strings.Contains(tt.source, `\$H`) {
					continue
				}
				t.Run(fmt.Sprintf("%t/%c/%s", raw, escape, tt.source), func(t *testing.T) {
					expander := newWordExpander(escape, raw)
					env := variableEnvironment{map[string]string{"H": "hello", "X": "literal $H", "É": "café", "?": "special", "$": "special", "1": "special"}}
					_, syntax, err := expander.expandWord(tt.source, env)
					require.Error(t, err, "table must exercise complete-word rejection")
					require.Equal(t, tt.want, expandValues(expander, []string{tt.source}, env...)[0])
					require.Equal(t, tt.want, expander.recoverWord(tt.source, env, syntax))
				})
			}
		}
	}
}

func TestExpansionMalformedPreservesEscapes(t *testing.T) {
	for _, escape := range []rune{'\\', '`'} {
		for _, raw := range []bool{false, true} {
			for _, tail := range []string{`$H`, `${H}`, `"$H"`} {
				source := "${#H} " + string(escape) + tail + " $H"
				// In the double-quoted variant the escape protects the opening quote;
				// the H itself still expands before the final unmatched double quote.
				want := "${#H} " + string(escape) + tail + " hello"
				if tail == `"$H"` {
					want = "${#H} " + string(escape) + `"hello" hello`
				}
				require.Equal(t, []string{want}, expandValues(newWordExpander(escape, raw), []string{source}, map[string]string{"H": "hello"}))
			}
		}
	}
}

func TestExpansionMalformed100KB(t *testing.T) {
	const size = 100 * 1024
	for _, pattern := range []string{`pre'fix $H' "${A:-x}" `, `"it's ${A:-x} isn't $H `, `${A:-${B:-$H}} '$H' `} {
		t.Run(pattern, func(t *testing.T) {
			const prefix = "$H ${#BROKEN} "
			source := prefix + strings.Repeat(pattern, (size-len(prefix))/len(pattern))
			source += strings.Repeat("x", size-len(source))
			expander := newWordExpander('\\', true)
			env := variableEnvironment{map[string]string{"H": "hello"}}
			_, _, err := expander.expandWord(source, env)
			require.Error(t, err)
			start := time.Now()
			got := expandValues(expander, []string{source}, env...)[0]
			elapsed := time.Since(start)
			require.Less(t, elapsed, 100*time.Millisecond, "100 KB malformed expansion must stay linear")
			require.True(t, strings.HasPrefix(got, "hello ${#BROKEN} "))
			require.True(t, onlyPlainHEdits(source, got))
			t.Logf("100 KB malformed expansion: %s", elapsed)
		})
	}
}

func TestExpandValuesUnsetDefaults(t *testing.T) {
	for _, tt := range []struct {
		source, want string
		raw          bool
	}{
		{`${A:-"${UNSET%/}"}`, `"${UNSET%/}"`, true},
		{`${A:-"${UNSET%/}"}`, `${UNSET%/}`, false},
		{`${A:-"${UNSET/a/b}"}`, `"${UNSET/a/b}"`, true},
		{`${A:-"${UNSET#prefix}"}`, `${UNSET#prefix}`, false},
		{`${A:-x} $É ${É} $1word`, `x $É ${É} $1word`, true},
		{"\ue000 ${A:-x} $X", "\ue000 x literal $H", true},
		{`test ${A:-1} -eq 1 || exit $?`, `test 1 -eq 1 || exit $?`, true},
		{`${A:-1} $$ $@ $* $# $? $- $! $0 $1 ${?} ${@}`, `1 $$ $@ $* $# $? $- $! $0 $1 ${?} ${@}`, true},
		{`${A:-1} $$ $@ $* $# $? $- $! $0 $1 ${?} ${@}`, `1 $$ $@ $* $# $? $- $! $0 $1 ${?} ${@}`, false},
		{`echo ${A:-$B}`, `echo $B`, true},
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
			for _, prefix := range []string{"", "${A:-x} "} {
				wantPrefix := strings.ReplaceAll(prefix, "${A:-x}", "x")
				got := expandValues(newWordExpander('\\', raw), []string{prefix + reference})
				require.Equal(t, []string{wantPrefix + reference}, got, "raw=%t source=%s", raw, prefix+reference)
			}
		}
	}
}

// Valid words preserve whole unknown operators while evaluating defaults.
// Rejected words preserve operator syntax but can substitute plain operands.
func TestExpansionPreservesUnknownOperators(t *testing.T) {
	for _, reference := range []string{
		`${REG#https://}`, `${BASE%/}`, `${X/a/b}`, `${X##*/}`, `${X%%/*}`, `${X//a/b}`,
		`${X#${H}}`, `${X/a/${H}}`,
		`${X?need}`, `${X:?need}`, `${X?}`, `${X:?}`,
		`${X+--insecure}`, `${X:+--insecure}`, `${X+${H}}`, `${X:+${A:-x}}`,
	} {
		for _, raw := range []bool{true, false} {
			for _, escape := range []rune{'\\', '`'} {
				for _, tt := range []struct{ prefix, want string }{
					{"", ""}, {`${A:-x} `, "x "}, {`${#BROKEN} `, `${#BROKEN} `},
				} {
					t.Run(fmt.Sprintf("%s/%t/%c/%s", reference, raw, escape, tt.prefix), func(t *testing.T) {
						env := map[string]string{"H": "hello"}
						source := tt.prefix + reference + " $H " + reference
						wantReference := reference
						if tt.prefix != "" && strings.HasPrefix(tt.prefix, "${#BROKEN}") {
							wantReference = strings.ReplaceAll(reference, "${H}", "hello")
						}
						want := tt.want + wantReference + " hello " + wantReference
						require.Equal(t, []string{want}, expandValues(newWordExpander(escape, raw), []string{source}, env))
					})
				}
			}
		}
	}
}

// Unknown operators must keep unrelated valid defaults on the BuildKit path.
func TestExpansionUnknownOperatorsKeepQuotedDefaults(t *testing.T) {
	for _, reference := range []string{`${X:?need}`, `${X?need}`, `${X:+--insecure}`, `${X+--insecure}`} {
		for _, raw := range []bool{true, false} {
			for _, escape := range []rune{'\\', '`'} {
				for _, fragment := range []string{`"${A:-"x y"}" $H`, `$H "${A:-'q'}"`, `${A:-"${B:-'q'}"} $H`} {
					lex := shell.NewLex(escape)
					lex.RawQuotes, lex.RawEscapes = raw, raw
					env := variableEnvironment{map[string]string{"H": "hello"}}
					want, _, err := lex.ProcessWord(fragment, env)
					require.NoError(t, err)
					for _, source := range []string{reference + " " + fragment, fragment + " " + reference, fragment + " " + reference + " " + fragment} {
						expected := strings.ReplaceAll(source, fragment, want)
						require.Equal(t, []string{expected}, expandValues(newWordExpander(escape, raw), []string{source}, env...), "raw=%t escape=%c source=%s", raw, escape, source)
					}
				}
			}
		}
	}
}

func TestExpandValuesPreservesBadBytes(t *testing.T) {
	for _, raw := range []bool{true, false} {
		for _, bad := range []string{"\x00", "caf\xe9", "\xff\xc0\xaf"} {
			for _, tt := range []struct{ source, want string }{
				{"echo " + bad + " $H", "echo " + bad + " hello"},
				{"it's " + bad + " ${A:-x} $H", "it's " + bad + " ${A:-x} $H"},
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
					if raw || recovery != "" {
						wantEscape = esc
					}
					for _, tt := range []struct{ source, want string }{
						{esc + bad + " $H", wantEscape + bad + " hello"},
						{bad + "$H" + bad, bad + "hello" + bad},
						{"${A:-" + bad + "} $H", bad + " hello"},
					} {
						want := tt.want
						if recovery != "" && strings.HasPrefix(tt.source, "${A:-") {
							want = strings.ReplaceAll(tt.source, "$H", "hello")
						}
						require.Equal(t, []string{recovery + want}, expandValues(newWordExpander(escape, raw), []string{recovery + tt.source}, map[string]string{"H": "hello", "marker": "\ue001"}))
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

// Valid values retain BuildKit quoting, escaping and operator behavior.
func TestExpansionAgreesWithBuildKit(t *testing.T) {
	fragments := []string{
		`"${EMPTY:-"word"}"`, `"prefix ${EMPTY:-"$H"} suffix"`, `pre"${EMPTY:-"x}y"}"post`,
		`pre'fix $H'post`, `pre'fix text'post`, `'a " $H' "$H"`, `"a '$H" '$H'`,
		`one 'two $H' three "$H"`, `echo \$H '$H' "\$H" "$H"`,
		`'a \' $H`, `"one \" $H"`, `foo'bar'qux '$H'`,
		`echo ${H:-other} ${EMPTY:-value} ${H:+yes}`, `$${H}`, `$${#H}`, `$$${H}`, `$${H:-x}`, `$? $$ $@ $# $* $!`,
		`${$#}`, `${$%}`, `${$/a/b}`, `${$##h} $H`, `${$%%o} ${H/h/H}`, `${$//l/L}`,
		`${H#h} ${H##h*}`, `${H%o} ${H%%l*}`, `${H/l/L} ${H//l/L}`, `${H#${EMPTY}} ${H/${EMPTY:-h}/H}`,
		`'${'}`, `before'${H#x'}after`, `"'${H#h}'"`,
		`${H/}/}`, `${H/a}/b}`, `${H/}/'x'}`,
		`'${X#''}'`, `pre'${X%''}'post`, `'${X/a/''b}'`,
		`"${H#{}"}`, `"${H%{}"}`, `"${H/{/x}"}`,
		`"${0#"$${"'${0'}"`, `"${H#"$${"'${H'}"`, `before "${H#"$${"'${H'}" after $H`,
		`"${0#0'0"${ '0}"`, `"${H#0'0"${ '0}"`, `before "${H#0'0"${ '0}" after $H`,
	}
	for _, raw := range []bool{true, false} {
		for _, escape := range []rune{'\\', '`'} {
			for _, fragment := range fragments {
				env := variableEnvironment{map[string]string{"H": "hello", "EMPTY": "", "0": "hello", "?": "?", "$": "$", "@": "@", "#": "#", "*": "*", "!": "!"}}
				lex := shell.NewLex(escape)
				lex.RawQuotes, lex.RawEscapes = raw, raw
				want, _, err := lex.ProcessWord(fragment, env)
				if err != nil {
					continue
				} // Some backslash fragments are invalid with escape=`.
				t.Run(fmt.Sprintf("%t/%c/%s", raw, escape, fragment), func(t *testing.T) {
					require.Equal(t, []string{want}, expandValues(newWordExpander(escape, raw), []string{fragment}, env...))
				})
			}
		}
	}
}

// A colon modifier consumes its operand up to }, including :/; only a direct /
// modifier uses a slash-delimited pattern. BuildKit decides modifier validity.
func TestExpansionColonModifierBoundaries(t *testing.T) {
	for _, expression := range []string{`${A:/x}`, `${A://x}`, `${A:/"x/y"}`} {
		for _, raw := range []bool{false, true} {
			for _, escape := range []rune{'\\', '`'} {
				lex := shell.NewLex(escape)
				lex.RawQuotes, lex.RawEscapes = raw, raw
				_, _, err := lex.ProcessWord(expression, variableEnvironment{map[string]string{"A": "a/b"}})
				require.ErrorContains(t, err, "unsupported modifier (:/)")
				for _, placement := range []struct{ prefix, suffix string }{
					{suffix: ` "$H"`}, {prefix: `"$H" `}, {prefix: `before `, suffix: ` "$H" after`},
					{suffix: ` $H /tail} "$H"`}, {prefix: `"$H" `, suffix: ` $H /tail}`},
					{prefix: `before `, suffix: ` $H /tail} "$H" after`},
				} {
					source := placement.prefix + expression + placement.suffix
					expander := newWordExpander(escape, raw)
					syntax := expander.scanShell(source, false)
					var found bool
					for _, ref := range syntax.references {
						if ref.start == len(placement.prefix) {
							require.Equal(t, len(placement.prefix)+len(expression), ref.end, "%s", source)
							found = true
						}
					}
					require.True(t, found)
					want := strings.ReplaceAll(source, "$H", "hello")
					require.Equal(t, []string{want}, expandValues(expander, []string{source}, map[string]string{"A": "a/b", "H": "hello"}))
					require.Equal(t, want, expander.recoverWord(source, variableEnvironment{map[string]string{"A": "a/b", "H": "hello"}}, syntax))
				}
			}
		}
	}
}

// BuildKit's parameter operands have their own quote context, even under an
// outer double quote. Apostrophes are literal only in a double-quote frame.
func TestExpansionContextNestingMatchesBuildKit(t *testing.T) {
	for _, source := range []string{
		`"${V//./'$1'}"`,
		`before "${V//./'$1'}" after $H`,
		`${A:-"${V//./'$1'}"}`,
		`"${A:-"it's ${X:+a} '"}"`,
		`before "${A:-"it's ${X:+a} '"}" after $H`,
		`${B:-"${A:-"it's ${X:+a} '"}"}`,
	} {
		for _, raw := range []bool{false, true} {
			for _, escape := range []rune{'\\', '`'} {
				for _, unknown := range []bool{false, true} {
					env := map[string]string{"V": "a.b.c", "H": "hello", "1": "must-not-expand", "X": "set"}
					oracleSource := source
					const marker = "scanner-unknown-alternate"
					if unknown {
						delete(env, "X")
						delete(env, "1")
						oracleSource = strings.ReplaceAll(source, "${X:+a}", marker)
					}
					lex := shell.NewLex(escape)
					lex.RawQuotes, lex.RawEscapes = raw, raw
					want, _, err := lex.ProcessWord(oracleSource, variableEnvironment{env})
					require.NoError(t, err, "source=%s", source)
					want = strings.ReplaceAll(want, marker, "${X:+a}")
					t.Run(fmt.Sprintf("%s/raw=%t/escape=%c/unknown=%t", source, raw, escape, unknown), func(t *testing.T) {
						require.Equal(t, []string{want, want}, expandValues(newWordExpander(escape, raw), []string{source, source}, env))
						// The same nesting cases take the conservative path if
						// an unsupported expression rejects the complete word.
						for _, placement := range []struct{ prefix, suffix string }{{prefix: "${#BROKEN} "}, {suffix: " ${#BROKEN}"}} {
							input := placement.prefix + source + placement.suffix
							expected := strings.ReplaceAll(input, "$H", "hello")
							expander := newWordExpander(escape, raw)
							_, syntax, err := expander.expandWord(input, variableEnvironment{env})
							require.Error(t, err)
							require.Equal(t, []string{expected}, expandValues(expander, []string{input}, env))
							require.Equal(t, expected, expander.recoverWord(input, variableEnvironment{env}, syntax))
						}
					})
				}
			}
		}
	}
}

func FuzzExpansionRecoveryQuotes(f *testing.F) {
	for _, s := range []string{`pre'fix $H'post`, `'a " $H' "$H"`, `"a '$H" '$H'`, `echo \$H '$H' "$H"`, `one 'two' three`, `$${H}`, `$${#H}`, `$$${H}`, `$${H:-x}`, `${$#}`, `${$%}`, `${$/a/b}`, `"${V//./'$1'}"`, `"${A:-"it's ${X:+a} '"}"`, "$1", "$$", "$?", "\ufeff$H", `"it's ${A:-x} isn't $H`, `${A:/x} "$H"`, `"it's isn't ${A:-'q'} '$H' $H`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, fragment string) {
		// Go's scanner drops only a leading BOM. Prefixing recovery syntax would
		// move it into the middle and give the oracle a different input.
		if !utf8.ValidString(fragment) || strings.ContainsRune(fragment, 0) || strings.HasPrefix(fragment, "\ufeff") {
			return
		}
		for _, raw := range []bool{true, false} {
			checkMalformedRecovery(t, fragment, raw)
			env := collectingEnvironment{}
			lex := shell.NewLex('\\')
			lex.RawQuotes, lex.RawEscapes = raw, raw
			want, _, err := lex.ProcessWord(fragment, env)
			if err != nil {
				// The leading reference cannot be enclosed by any quote or
				// parameter in the malformed suffix. Recovery must retain it.
				got := expandValues(newWordExpander('\\', raw), []string{"$H " + fragment}, map[string]string{"H": "hello"})
				require.True(t, strings.HasPrefix(got[0], "hello "), "%q -> %q", fragment, got[0])
				continue
			}
			// The shared context scanner must expose exactly the names BuildKit
			// read, including references nested under quotes and parameters.
			names := map[string]bool{}
			for _, ref := range newWordExpander('\\', raw).scanShell(fragment, false).references {
				if (ref.name(fragment) != "" || ref.braced(fragment)) && ref.end > 0 {
					names[ref.name(fragment)] = true
				}
			}
			wantNames := map[string]bool{}
			for name := range env {
				wantNames[name] = true
			}
			require.Equal(t, wantNames, names)
			require.Equal(t, []string{want}, expandValues(newWordExpander('\\', raw), []string{fragment}, map[string]string(env)))
		}
	})
}

// This property uses no quote scanner: every output edit must be exactly a
// source $H or ${H} replaced by hello. No quote removal, operator evaluation or
// newly synthesized expression is permitted. The valid-input fuzz domain stays
// unchanged; dedicated tables also exercise NUL and invalid UTF-8.
func onlyPlainHEdits(source, output string) bool {
	for len(source) > 0 {
		if strings.HasPrefix(output, "hello") {
			if strings.HasPrefix(source, "${H}") {
				source, output = source[4:], output[5:]
				continue
			}
			next, _ := utf8.DecodeRuneInString(strings.TrimPrefix(source, "$H"))
			if strings.HasPrefix(source, "$H") && next != '_' && !unicode.IsLetter(next) && !unicode.IsDigit(next) {
				source, output = source[2:], output[5:]
				continue
			}
		}
		if len(output) == 0 || source[0] != output[0] {
			return false
		}
		source, output = source[1:], output[1:]
	}
	return output == ""
}

func TestMalformedRecoveryEditProperty(t *testing.T) {
	for _, tt := range []struct{ source, output string }{
		{`"it's ${A:-x} isn't $H`, `"its ${A:-x} isnt hello`},
		{`${#H} ${A:-x} $H`, `${#H} x hello`},
		{`${#H} $Hello`, `${#H} helloello`},
		{`${#H} plain text`, `${#H} ${NEW} plain text`},
	} {
		require.False(t, onlyPlainHEdits(tt.source, tt.output), "%q -> %q", tt.source, tt.output)
	}
}

func checkMalformedRecovery(t *testing.T, fragment string, raw bool) {
	t.Helper()
	env := variableEnvironment{map[string]string{"H": "hello"}}
	for _, escape := range []rune{'\\', '`'} {
		expander := newWordExpander(escape, raw)
		// Check the actual fuzz input too, without adding context that might
		// close a quote or parameter at its end.
		if _, syntax, err := expander.expandWord(fragment, env); err != nil {
			got := expandValues(expander, []string{fragment}, env...)[0]
			require.True(t, onlyPlainHEdits(fragment, got), "%q -> %q", fragment, got)
			require.Equal(t, got, expander.recoverWord(fragment, env, syntax))
		}
		// Single-quoted arbitrary data cannot hide the following known name,
		// even when an unsupported modifier earlier forces recovery.
		literal := strings.ReplaceAll(fragment, "'", "")
		source := "${#BROKEN} '" + literal + "' $H"
		got := expandValues(expander, []string{source}, env...)[0]
		require.Equal(t, "${#BROKEN} '"+literal+"' hello", got)
		require.True(t, onlyPlainHEdits(source, got), "%q -> %q", source, got)

		// Prefix H in unquoted, double-quoted and parameter-operand contexts. Each
		// is independent of arbitrary later quoting. The unsupported suffix ensures
		// well-formed fragments also exercise recovery.
		for _, prefix := range []string{"$H ", `"$H" `, `${A:-$H} `} {
			source := prefix + fragment + " ${#BROKEN}"
			_, syntax, err := expander.expandWord(source, env)
			if err == nil {
				continue
			} // A fragment may quote or escape the suffix.
			got := expandValues(expander, []string{source}, env...)[0]
			require.True(t, onlyPlainHEdits(source, got), "%q -> %q", source, got)
			require.True(t, strings.HasPrefix(got, strings.ReplaceAll(prefix, "$H", "hello")), "%q -> %q", source, got)
			require.Equal(t, got, expander.recoverWord(source, env, syntax))
		}
	}
}

func BenchmarkExpansionRecoveryQuotes(b *testing.B) {
	for _, count := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			value := strings.Repeat(`pre'fix $H' it's `, count) + `orphan' $H`
			lex := newWordExpander('\\', true)
			env := map[string]string{"H": "hello"}
			if _, _, err := lex.expandWord(value, variableEnvironment{env}); err == nil {
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

func BenchmarkExpansionMalformedContractions(b *testing.B) {
	for _, count := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			prefix := `"` + strings.Repeat("it's ", count)
			value := prefix + `${A:-'q'} '$H' $H`
			want := prefix + `${A:-'q'} 'hello' hello`
			expander := newWordExpander('\\', true)
			env := map[string]string{"H": "hello"}
			b.SetBytes(int64(len(value)))
			b.ReportAllocs()
			for b.Loop() {
				if got := expandValues(expander, []string{value}, env)[0]; got != want {
					b.Fatal("recovery must preserve all bytes except known plain references")
				}
			}
		})
	}
}

func BenchmarkExpansionUnknownOperators(b *testing.B) {
	for _, count := range []int{100, 1000, 10000} {
		for _, reference := range []string{`${MISSING%/}`, `${MISSING:?need}`, `${MISSING:+--insecure}`} {
			for _, prefix := range []string{"", "${#BROKEN} "} {
				b.Run(fmt.Sprintf("%d/%s/%s", count, reference, prefix), func(b *testing.B) {
					value := prefix + strings.Repeat(reference+`/$H `, count)
					expander := newWordExpander('\\', true)
					env := map[string]string{"H": "hello"}
					b.ReportAllocs()
					b.SetBytes(int64(len(value)))
					for b.Loop() {
						expandValues(expander, []string{value}, env)
					}
				})
			}
		}
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

func BenchmarkShellContextScan(b *testing.B) {
	const nested = `"${V//./'$1'}" "${A:-"it's ${X:+a} '"}"`
	for _, size := range []int{100_000, 1_000_000, 10_000_000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			value := strings.Repeat("plain text ", size/11) + nested
			expander := newWordExpander('\\', true)
			b.SetBytes(int64(len(value)))
			b.ReportAllocs()
			for b.Loop() {
				if got := len(expander.scanShell(value, false).references); got != 3 {
					b.Fatalf("want V, A, X references, got %d", got)
				}
			}
		})
	}
}
