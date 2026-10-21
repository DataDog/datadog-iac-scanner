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
		{`" ${A:-'q'} $H`, `" 'q' hello`, true},
		{`${A:-'q'} " $H`, `'q' " hello`, true},
		{`${A:-'q'} ' $H`, `'q' ' hello`, true},
		{`${A:-"${UNSET%/}"}`, `"${UNSET%/}"`, true},
		{`${A:-"${UNSET%/}"}`, `${UNSET%/}`, false},
		{`${A:-"${UNSET/a/b}"}`, `"${UNSET/a/b}"`, true},
		{`${A:-"${UNSET#prefix}"}`, `${UNSET#prefix}`, false},
		{`${#H} ${A:-"${UNSET%/}"}`, `${#H} "${UNSET%/}"`, true},
		{`${#H} ${A:-"${UNSET/a/b}"}`, `${#H} ${UNSET/a/b}`, false},
		{`it's ${A:-"${UNSET#prefix}"}`, `it's "${UNSET#prefix}"`, true},
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

// Operators that need an unknown value must retain the whole expression.
// Defaults still evaluate, and unrelated references expand in every recovery path.
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
					{"", ""}, {`${A:-x} `, "x "}, {`${#BROKEN} `, `${#BROKEN} `}, {`it's ${A:-x} `, "it's x "},
				} {
					t.Run(fmt.Sprintf("%s/%t/%c/%s", reference, raw, escape, tt.prefix), func(t *testing.T) {
						env := map[string]string{"H": "hello"}
						source := tt.prefix + reference + " $H " + reference
						want := tt.want + reference + " hello " + reference
						require.Equal(t, []string{want}, expandValues(newWordExpander(escape, raw), []string{source}, env))
					})
				}
			}
		}
	}
}

// Unknown operands must not force unrelated valid fragments into quote recovery.
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
					for _, prefix := range []string{"", "${#BROKEN} "} {
						for _, source := range []string{reference + " " + fragment, fragment + " " + reference, fragment + " " + reference + " " + fragment} {
							expected := strings.ReplaceAll(source, fragment, want)
							require.Equal(t, []string{prefix + expected}, expandValues(newWordExpander(escape, raw), []string{prefix + source}, env...), "raw=%t escape=%c source=%s", raw, escape, prefix+source)
						}
					}
				}
			}
		}
	}
}

// An orphan apostrophe must not change later independent, balanced fragments.
func TestExpansionMalformedQuotesKeepIndependentDefaults(t *testing.T) {
	for _, fragment := range []string{`pre'fix $H' ${A:-'q'} $H`, `${A:-"x y"} 'end' $H`, `pre'fix $H' ${A:-${B:-'q'}} 'end' $H`} {
		for _, raw := range []bool{true, false} {
			for _, escape := range []rune{'\\', '`'} {
				lex := shell.NewLex(escape)
				lex.RawQuotes, lex.RawEscapes = raw, raw
				env := variableEnvironment{map[string]string{"H": "hello"}}
				want, _, err := lex.ProcessWord(fragment, env)
				require.NoError(t, err)
				for _, prefix := range []string{"", "${#BROKEN} "} {
					source := prefix + "it's " + fragment
					require.Equal(t, []string{prefix + "it's " + want}, expandValues(newWordExpander(escape, raw), []string{source}, env...), "raw=%t escape=%c source=%s", raw, escape, source)
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

// Repairing one unmatched quote must not let a newly exposed final apostrophe
// hide an independent known reference. Closed single quotes stay literal.
func TestExpansionMalformedQuotedTail(t *testing.T) {
	for _, tt := range []struct{ source, want string }{
		{`" ${A:-"x y"} it's $H`, `" "x y" it's hello`},
		{`" "${A:-'q'}" ' $H`, `" "'q'" ' hello`},
		{`" "${A:-"x y"}" pre'fix $H' it's $H`, `" ""x y"" pre'fix $H' it's hello`},
	} {
		for _, escape := range []rune{'\\', '`'} {
			for _, prefix := range []string{"", "${#BROKEN} "} {
				require.Equal(t, []string{prefix + tt.want}, expandValues(newWordExpander(escape, true), []string{prefix + tt.source}, map[string]string{"H": "hello"}))
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
					for _, placement := range []struct{ prefix, suffix string }{{}, {prefix: "${#BROKEN} "}, {suffix: " ${#BROKEN}"}} {
						input := placement.prefix + source + placement.suffix
						expected := placement.prefix + want + placement.suffix
						t.Run(fmt.Sprintf("%s/raw=%t/escape=%c/unknown=%t/%s%s", source, raw, escape, unknown, placement.prefix, placement.suffix), func(t *testing.T) {
							require.Equal(t, []string{expected, expected}, expandValues(newWordExpander(escape, raw), []string{input, input}, env))
						})
					}
				}
			}
		}
	}
}

func FuzzExpansionRecoveryQuotes(f *testing.F) {
	for _, s := range []string{`pre'fix $H'post`, `'a " $H' "$H"`, `"a '$H" '$H'`, `echo \$H '$H' "$H"`, `one 'two' three`, `$${H}`, `$${#H}`, `$$${H}`, `$${H:-x}`, `${$#}`, `${$%}`, `${$/a/b}`, `"${V//./'$1'}"`, `"${A:-"it's ${X:+a} '"}"`, "$1", "$$", "$?", "\ufeff$H"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, fragment string) {
		// Go's scanner drops only a leading BOM. Prefixing recovery syntax would
		// move it into the middle and give the oracle a different input.
		if !utf8.ValidString(fragment) || strings.ContainsRune(fragment, 0) || strings.HasPrefix(fragment, "\ufeff") {
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
			// Force recovery without changing the fragment's quote/escape boundaries.
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
