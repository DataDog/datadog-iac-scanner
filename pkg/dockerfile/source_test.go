package dockerfile

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSourceLinesSharedWithParser(t *testing.T) {
	source := []byte("# escape=`\nfrom alpine\nrun echo `\n hi\nCOPY <<EOF /x\nFROM busybox\nEOF\n")
	var recorded []string
	calls := 0
	parsed, err := Parse(WithSourceLines(t.Context(), strings.Split(string(source), "\n"), func(lines []string) { recorded = lines; calls++ }), source)
	require.NoError(t, err)
	require.Len(t, parsed.AST.Children, 3)
	require.Equal(t, 1, calls)
	require.Equal(t, InstructionLines(strings.Split(string(source), "\n")), recorded)
	require.Equal(t, "run echo  hi", recorded[2])
	require.Empty(t, recorded[3])
	require.Empty(t, recorded[5], "heredoc payloads do not become instructions")
}

func TestFromArguments(t *testing.T) {
	for _, tt := range []struct{ source, want string }{
		{"", ""}, {"F", ""}, {"fro", ""}, {"FROM", ""}, {"RUN echo hi", ""},
		{"FROM\falpine", "alpine"}, {"FROM\valpine", "alpine"}, {"FROMAGE alpine", ""}, {"FROM--platform=x alpine", ""}, {"FROM --platform=linux/amd64 alpine AS build", "--platform=linux/amd64 alpine AS build"}, {"FROM alpine", "alpine"}, {"  fRoM\talpine AS build  ", "alpine AS build"},
	} {
		t.Run(tt.source, func(t *testing.T) {
			require.Equal(t, tt.want, FromArguments(tt.source))
		})
	}
}

// Classification and every later consumer must reuse the same content-bound
// AST, including parse errors; another file must never inherit a stale result.
func TestPreparedSourceLifecycle(t *testing.T) {
	for _, source := range []string{
		"FROM alpine\nRUN echo hi\n",
		"ARG X=alpine\r\nFROM $X\r\n",
		"# escape=`\nFROM alpine\nRUN echo `\n hi\n",
		"FROM alpine\nRUN <<EOF\nunterminated\n",
		"package main\n" + strings.Repeat("x\n", 5_000_000),
	} {
		t.Run(source[:min(24, len(source))], func(t *testing.T) {
			content := []byte(source)
			ctx := PrepareSource(t.Context(), content, true)
			snapshot := preparedSource(ctx, content)
			require.NotNil(t, snapshot)
			require.Nil(t, snapshot.parsed, "preparation stays lazy for shared-document cache hits")
			want := HasFrom(strings.NewReader(source))
			require.Equal(t, want, HasFromContext(ctx, content))
			first, firstErr := Parse(ctx, content)
			for range 3 {
				parsed, err := Parse(SourceContext(ctx)(t.Context()), content)
				require.Same(t, first, parsed)
				require.Equal(t, firstErr, err)
			}
			other := []byte("FROM busybox\n")
			parsed, err := Parse(ctx, other)
			require.NoError(t, err)
			require.NotSame(t, first, parsed)
			require.Equal(t, "busybox", parsed.AST.Children[0].Next.Value)
			content[0] = 'X'
			require.Nil(t, preparedSource(ctx, content), "mutated content invalidates snapshot identity")
		})
	}
}

func TestFromSeparatorsAgreeWithBuildKit(t *testing.T) {
	for _, separator := range []string{" ", "\t", "\v", "\f", "\r", " \t\v\f "} {
		for _, args := range []string{"alpine", "alpine AS build", "--platform=linux/amd64 alpine AS build"} {
			source := "FrOm" + separator + args + "\n"
			parsed, err := Parse(t.Context(), []byte(source))
			require.NoError(t, err)
			require.Len(t, parsed.AST.Children, 1)
			node := parsed.AST.Children[0]
			require.Equal(t, args, FromArguments(node.Original))
			require.Equal(t, "alpine", node.Next.Value)
		}
	}
}

func BenchmarkPreparedSourcePipeline(b *testing.B) {
	for _, lines := range []int{100, 1000, 10000} {
		for _, prepared := range []bool{false, true} {
			b.Run(fmt.Sprintf("lines=%d/prepared=%t", lines, prepared), func(b *testing.B) {
				content := []byte("ARG X=alpine\nFROM $X\n" + strings.Repeat("RUN echo hello\n", lines))
				b.ReportAllocs()
				b.SetBytes(int64(len(content)))
				for b.Loop() {
					ctx := b.Context()
					if prepared {
						ctx = PrepareSource(ctx, content, true)
					}
					if !HasFromContext(ctx, content) || !HasFromContext(ctx, content) {
						b.Fatal("rejected")
					}
					if _, err := Parse(ctx, content); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
