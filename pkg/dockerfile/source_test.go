package dockerfile

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
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
			changed := append([]byte(nil), content...)
			changed[0] = 'X'
			require.Nil(t, preparedSource(ctx, changed), "different bytes invalidate snapshot identity")
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

// Dispatch owns one immutable input and AST; detaching keeps only parser-owned
// location data, independent of whether any finding later needs it.
func TestSourceOwnershipEndsAtDispatch(t *testing.T) {
	for _, source := range []string{
		"FROM alpine\nRUN a\n",
		"# escape=`\nFROM alpine\nRUN a `\n b\n",
		"FROM alpine\nCOPY <<EOF /x\nFROM busybox\nEOF\n",
	} {
		content := []byte(source)
		ctx := PrepareSource(t.Context(), content, true)
		snapshot := preparedSource(ctx, content)
		require.Equal(t, &content[0], &snapshot.content[0], "immutable bytes are borrowed")
		_, err := Parse(ctx, content)
		require.NoError(t, err)
		compact := []int{1, 2}
		RememberSource(ctx, compact)
		for range 3 {
			require.Equal(t, compact, SavedSource(ctx))
			require.NotNil(t, snapshot.parsed, "reading metadata must not detach the AST")
			require.NotNil(t, snapshot.content)
		}
		require.Equal(t, compact, DetachSource(ctx))
		require.Nil(t, snapshot.parsed)
		require.Nil(t, snapshot.content)
		require.Equal(t, compact, DetachSource(ctx), "repeat transfers keep no AST")
	}
}

// Cached and fresh layouts preserve untrimmed physical text where possible;
// BuildKit determines instruction boundaries and joins actual continuations.
func TestSourceLineViews(t *testing.T) {
	for _, tt := range []struct {
		source, view string
		shared       bool
	}{
		{"FROM alpine\nRUN echo hi\r ", "FROM alpine\nRUN echo hi ", true},
		{"FROM alpine\nRUN echo hi\r \\ \n there ", "FROM alpine\nRUN echo hi  there \n", false},
		{"FROM alpine\nRUN echo hi\r \\ \n\n", "FROM alpine\nRUN echo hi \\ \n\n", true},
		{"FROM alpine\nRUN echo hi ", "FROM alpine\nRUN echo hi ", true},
		{"FROM alpine\t \nRUN echo hi\t", "FROM alpine\t \nRUN echo hi\t", true},
		{"FROM alpine\nRUN echo hi \\", "FROM alpine\nRUN echo hi \\", true},
		{"FROM alpine\nRUN echo hi \\  \n\n", "FROM alpine\nRUN echo hi \\  \n\n", true},
		{"FROM alpine\n  RUN echo hi \t", "FROM alpine\n  RUN echo hi \t", true},
		{"FROM alpine\nRUN echo first \nFROM busybox\nRUN echo last \t", "FROM alpine\nRUN echo first \nFROM busybox\nRUN echo last \t", true},
		{"# escape=`\nFROM alpine\nRUN echo hi `", "\nFROM alpine\nRUN echo hi `", false},
		{"\ufeffFROM alpine\nRUN echo hi ", "FROM alpine\nRUN echo hi ", false},
		{"FROM alpine\nRUN echo a&&\\  \n b\t ", "FROM alpine\nRUN echo a&& b\t \n", false},
		{"# escape=`\nFROM alpine\nRUN echo `\n hi\t ", "\nFROM alpine\nRUN echo  hi\t \n", false},
		{"FROM alpine\nCOPY <<EOF /x\nRUN hi \nEOF\nRUN hi ", "FROM alpine\nCOPY <<EOF /x\n\n\nRUN hi ", false},
		{"# comment\nFROM alpine\nRUN echo caf\xe9 \n", "\nFROM alpine\nRUN echo caf\xe9 \n", false},
	} {
		t.Run(tt.source, func(t *testing.T) {
			parsed, err := parser.Parse(strings.NewReader(tt.source))
			require.NoError(t, err)
			physical := *utils.SplitLines(tt.source)
			want := strings.Split(tt.view, "\n")
			for _, got := range [][]string{CaptureSourceLines(parsed, []byte(tt.source)).Apply(physical), InstructionLines(physical)} {
				require.Equal(t, want, got)
				if tt.shared {
					require.Same(t, &physical[0], &got[0])
				}
			}
		})
	}
}

func TestSourceLinesIgnoreInvalidMarkers(t *testing.T) {
	for _, starts := range [][]int{{-2, 1, 99}, {0, 1, 2, 100}, {1, 2, 999999}} {
		physical := []string{"FROM alpine", "RUN hi "}
		layout := SourceLines{overrides: map[int]string{99: "bad"}}
		for _, line := range starts {
			layout.record(line, "", "")
		}
		got := layout.Apply(physical)
		require.Equal(t, "FROM alpine", got[0])
		require.Len(t, got, len(physical))
	}
}

func FuzzSourceLineViews(f *testing.F) {
	for _, seed := range []string{"FROM alpine\nRUN hi ", "FROM alpine\nRUN x \\", "# escape=`\nFROM alpine\nRUN x`\n y"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		parsed, err := parser.Parse(strings.NewReader(source))
		if err != nil {
			t.Skip()
		}
		physical := *utils.SplitLines(source)
		want := make([]string, len(physical))
		for _, node := range parsed.AST.Children {
			if node.StartLine > 0 && node.StartLine <= len(want) {
				text := utils.StripCarriageReturns(node.Original)
				physicalLine := physical[node.StartLine-1]
				// Location display preserves a physical line containing the whole
				// instruction; only joined text and a stripped BOM differ.
				if strings.Contains(physicalLine, text) && !strings.HasPrefix(physicalLine, "\ufeff") {
					text = physicalLine
				}
				want[node.StartLine-1] = text
			}
		}
		require.Equal(t, want, CaptureSourceLines(parsed, []byte(source)).Apply(physical))
		require.Equal(t, want, instructionLines(parsed, physical))
	})
}

func TestPreparedSourceConcurrentMemoization(t *testing.T) {
	for _, source := range []string{"FROM alpine\nRUN a\n", "ARG X=alpine\nFROM $X\n", "FROM alpine\nRUN <<EOF\nmissing\n"} {
		t.Run(source, func(t *testing.T) {
			content := []byte(source)
			ctx := PrepareSource(t.Context(), content, true)
			first, firstErr := Parse(ctx, content)
			var wg sync.WaitGroup
			for range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					got, err := Parse(SourceContext(ctx)(t.Context()), content)
					require.Equal(t, firstErr, err)
					if firstErr == nil {
						require.Same(t, first, got)
					}
				}()
			}
			wg.Wait()
		})
	}
}

// Layout retention follows gaps in instructions, not file size: a large plain
// Dockerfile keeps one range and shares its complete physical source slice.
func TestSourceLayoutRetention(t *testing.T) {
	for _, count := range []int{10, 1000, 10000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			content := "FROM alpine\n" + strings.Repeat("RUN echo hi\n", count)
			parsed, err := parser.Parse(strings.NewReader(content))
			require.NoError(t, err)
			layout := CaptureSourceLines(parsed, []byte(content))
			require.Len(t, layout.runs, 1)
			require.Empty(t, layout.overrides)
			physical := *utils.SplitLines(content)
			view := layout.Apply(physical)
			require.Same(t, &physical[0], &view[0])
		})
	}
}
