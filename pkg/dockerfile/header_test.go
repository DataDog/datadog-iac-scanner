package dockerfile

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/stretchr/testify/require"
)

func TestHasFromValidatesBody(t *testing.T) {
	for _, source := range []string{
		"FROM alpine\nRUN <<EOF\necho hi\n",
		"ARG IMAGE=alpine\nFROM $IMAGE\nCOPY <<EOF /x\nhi\n",
	} {
		require.False(t, HasFrom(strings.NewReader(source)), "malformed candidates must be skipped")
	}
	require.True(t, HasFrom(strings.NewReader("FROM alpine\nRUN <<EOF\necho hi\nEOF\n")))
}

// Long headers exercise BuildKit's continuation handling without repeatedly
// parsing every growing prefix. Both successful and failed inputs are measured.
func BenchmarkHasFrom(b *testing.B) {
	for _, lines := range []int{100, 1000, 10000} {
		for _, malformed := range []bool{false, true} {
			source := "ARG IMAGE=\\\n" + strings.Repeat(" alpine\\\n", lines) + " alpine\nFROM $IMAGE\n"
			if malformed {
				source += "RUN <<EOF\necho hi\n"
			}
			b.Run(fmt.Sprintf("lines=%d/malformed=%t", lines, malformed), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(source)))
				for b.Loop() {
					require.Equal(b, !malformed, HasFrom(strings.NewReader(source)))
				}
			})
		}
	}
}

func TestHasFromDirectivesAndContinuations(t *testing.T) {
	for _, source := range []string{
		"\ufeff# syntax=docker/dockerfile:1\r\nARG X=1\r\nFROM alpine\r\n",
		"# escape=`\nARG IMAGE=`\n# comment\n alpine\nFROM `\n $IMAGE\n",
		"ARG IMAGE=\\  \n\n# comment\n alpine\nFROM \\\n $IMAGE\n",
		"ARG\tIMAGE=alpine\nFROM\talpine\n",
		"FR\\\nOM alpine\n", "AR\\\nG X=1\nFROM alpine\n",
		"# escape=`\nFR`\nOM alpine\n",
	} {
		require.True(t, HasFrom(strings.NewReader(source)), source)
	}
	for _, source := range []string{
		"ARG IMAGE=\\\nFROM alpine\n", "ARG X\nRUN echo hi\nFROM alpine\n", "FROM\n",
		"# escape=x\nFROM alpine\n", strings.Repeat("\x00", 100000),
	} {
		require.False(t, HasFrom(strings.NewReader(source)), source[:min(100, len(source))])
	}
}

// The reader has a small invalid header and an arbitrarily large tail. Rejection
// must not consume the tail, including when comments/directives precede it.
func TestHasFromRejectsBeforeReadingBody(t *testing.T) {
	for _, header := range []string{"package main\n", "\ufeff# syntax=docker/dockerfile:1\r\n\n package main\r\n", "RUN echo no\n", "ARG X=1\nARG Y=2\nRUN echo no\n"} {
		source := strings.NewReader(header + strings.Repeat("junk\n", 2_000_000))
		require.False(t, HasFrom(source))
		position, err := source.Seek(0, io.SeekCurrent)
		require.NoError(t, err)
		require.Less(t, position, int64(8192))
	}
}

func BenchmarkHasFromRejectedBody(b *testing.B) {
	for _, size := range []int{1000, 10_000_000} {
		source := "package main\n" + strings.Repeat("x\n", size/2)
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if HasFrom(strings.NewReader(source)) {
					b.Fatal("accepted")
				}
			}
		})
	}
}

// Early rejection must agree with the full parser, including odd whitespace,
// directives and keywords split across physical lines.
func FuzzHasFromAgreesWithBuildKit(f *testing.F) {
	for _, source := range []string{"FROM alpine\n", "ARG X=1\nFROM alpine\n", "RUN no\nFROM alpine\n", "FR\\\nOM alpine\n", "\ufeff# escape=`\r\nARG X=`\r\n value\r\nFROM alpine\r\n", "FROM alpine\nRUN <<EOF\nhi\n"} {
		f.Add(source)
	}
	f.Fuzz(func(t *testing.T, source string) {
		parsed, err := parser.Parse(strings.NewReader(source))
		want := false
		if err == nil {
			for _, node := range parsed.AST.Children {
				if strings.EqualFold(node.Value, "arg") {
					continue
				}
				want = strings.EqualFold(node.Value, "from") && node.Next != nil
				break
			}
		}
		require.Equal(t, want, HasFrom(strings.NewReader(source)), "source=%q", source)
	})
}
