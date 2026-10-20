package dockerfile

import (
	"fmt"
	"strings"
	"testing"

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
