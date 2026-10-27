package model

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFileMetadata_JSONMarshalSkipsLazyState(t *testing.T) {
	fm := &FileMetadata{ID: "id", Document: Document{"k": "v"}}
	fm.SetLineInfoLoader(func(context.Context, *FileMetadata) (map[string]interface{}, error) {
		return nil, nil
	})

	b, err := json.Marshal(fm)
	require.NoError(t, err)
	require.Contains(t, string(b), `"ID":"id"`)
	require.NotContains(t, string(b), "LineInfoLoader")
}

func TestCombine_lineInfoFallbackOnEnsureFailure(t *testing.T) {
	ctx := context.Background()
	fm := &FileMetadata{
		ID:       "id",
		FilePath: "main.tf",
		Document: Document{"resource": map[string]interface{}{}},
	}
	fm.SetLineInfoLoader(func(context.Context, *FileMetadata) (map[string]interface{}, error) {
		return nil, errors.New("reparse failed")
	})

	out := FileMetadatas{fm}.Combine(ctx, true)
	require.Len(t, out.Documents, 1)
	require.Equal(t, "id", out.Documents[0]["id"])
	require.Equal(t, "main.tf", out.Documents[0]["file"])
	require.NotNil(t, out.Documents[0]["resource"])
}

func TestCombine_lineInfoAfterDocumentRelease(t *testing.T) {
	ctx := context.Background()
	fm := &FileMetadata{
		ID:       "id",
		FilePath: "pod.yaml",
		Document: nil,
	}
	fm.SetLineInfoLoader(func(context.Context, *FileMetadata) (map[string]interface{}, error) {
		return Document{"kind": "Pod"}, nil
	})

	out := FileMetadatas{fm}.Combine(ctx, true)
	require.Len(t, out.Documents, 1)
	require.Equal(t, "id", out.Documents[0]["id"])
	require.Equal(t, "pod.yaml", out.Documents[0]["file"])
	require.Equal(t, "Pod", out.Documents[0]["kind"])
}

func TestUseLineInfoDocument_discardReloads(t *testing.T) {
	ctx := context.Background()
	var loads atomic.Int32
	fm := &FileMetadata{FilePath: "workflow.yaml"}
	fm.SetLineInfoLoader(func(context.Context, *FileMetadata) (map[string]interface{}, error) {
		loads.Add(1)
		return Document{"_dd_lines": map[string]interface{}{"k": 1}}, nil
	})

	require.NoError(t, fm.UseLineInfoDocument(ctx, func(doc map[string]interface{}) error {
		require.NotNil(t, doc)
		return nil
	}))
	fm.DiscardLineInfoDocument()
	require.Nil(t, fm.LineInfoDocument)
	require.NoError(t, fm.UseLineInfoDocument(ctx, func(doc map[string]interface{}) error {
		require.NotNil(t, doc)
		return nil
	}))
	require.Equal(t, int32(2), loads.Load())
}

// TestDiscardLineInfoDocumentWithoutLoader verifies the no-op guard: without
// a lazy loader the tree can never be rebuilt, so discarding is refused
// rather than writing the field outside the state mutex (which would race
// concurrent readers).
func TestDiscardLineInfoDocumentWithoutLoader(t *testing.T) {
	fm := &FileMetadata{
		FilePath:         "doc.json",
		LineInfoDocument: Document{"_dd_lines": map[string]interface{}{"k": 1}},
	}
	fm.DiscardLineInfoDocument()
	require.NotNil(t, fm.LineInfoDocument, "tree without a loader must not be discarded")
}

func TestEnsureLineInfoDocument_concurrent(t *testing.T) {
	ctx := context.Background()
	var loads atomic.Int32
	fm := &FileMetadata{FilePath: "main.tf"}
	fm.SetLineInfoLoader(func(context.Context, *FileMetadata) (map[string]interface{}, error) {
		loads.Add(1)
		return Document{"_dd_lines": map[string]interface{}{}}, nil
	})

	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			require.NoError(t, fm.EnsureLineInfoDocument(ctx))
		}()
	}
	wg.Wait()
	require.Equal(t, int32(1), loads.Load())
	require.NotNil(t, fm.LineInfoDocument)
}

func TestFileMetadata_ShallowCopyPreservesLazyLoader(t *testing.T) {
	src := &FileMetadata{FilePath: "mod.tf"}
	loader := func(context.Context, *FileMetadata) (map[string]interface{}, error) {
		return Document{"x": 1}, nil
	}
	src.SetLineInfoLoader(loader)

	clone := src.ShallowCopy()
	require.NoError(t, clone.EnsureLineInfoDocument(context.Background()))
	require.Nil(t, src.LineInfoDocument)
	require.NoError(t, src.EnsureLineInfoDocument(context.Background()))
	require.NotNil(t, src.LineInfoDocument)
}

// Copies of one file (module instances) build its line-info tree once and
// share it until it is discarded; the file itself keeps its own tree.
func TestShallowCopy_SharesLineInfoAcrossCopies(t *testing.T) {
	ctx := context.Background()
	var loads atomic.Int32
	fm := &FileMetadata{ID: "id", FilePath: "main.tf", Kind: KindTerraform, OriginalData: "x"}
	fm.SetLineInfoLoader(func(context.Context, *FileMetadata) (map[string]interface{}, error) {
		loads.Add(1)
		return map[string]interface{}{"resource": map[string]interface{}{}}, nil
	})
	a, b := fm.ShallowCopy(), fm.ShallowCopy()
	require.Equal(t, a.LineInfoShareKey(), b.LineInfoShareKey())
	require.NotEqual(t, fm.LineInfoShareKey(), a.LineInfoShareKey())

	use := func(f *FileMetadata) {
		require.NoError(t, f.UseLineInfoDocument(ctx, func(doc map[string]interface{}) error {
			require.Contains(t, doc, "resource")
			return nil
		}))
		require.Nil(t, f.LineInfoDocument, "a copy only holds the shared tree while using it")
	}
	use(a)
	use(b)
	require.Equal(t, int32(1), loads.Load())

	a.DiscardLineInfoDocument()
	use(b)
	require.Equal(t, int32(2), loads.Load())

	require.NoError(t, fm.EnsureLineInfoDocument(ctx))
	require.Equal(t, int32(3), loads.Load())
	require.NotNil(t, fm.LineInfoDocument)
}

func TestShallowCopy_SharedLineInfoErrorIsKept(t *testing.T) {
	var loads atomic.Int32
	fm := &FileMetadata{ID: "id", FilePath: "main.tf", Kind: KindTerraform}
	fm.SetLineInfoLoader(func(context.Context, *FileMetadata) (map[string]interface{}, error) {
		loads.Add(1)
		return nil, errors.New("reparse failed")
	})
	a, b := fm.ShallowCopy(), fm.ShallowCopy()
	noop := func(map[string]interface{}) error { return nil }
	require.Error(t, a.UseLineInfoDocument(context.Background(), noop))
	require.Error(t, b.UseLineInfoDocument(context.Background(), noop))
	require.Equal(t, int32(1), loads.Load())
}

// A file larger than maxCachedLineMatches lines keeps caching substrings past
// that number, and the results stay those of a scan.
func TestLinesContainingCachesPerLineInLargeFiles(t *testing.T) {
	var b strings.Builder
	n := 3 * maxCachedLineMatches
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "resource \"t\" \"r%d\" {}\n", i)
	}
	f := &FileMetadata{OriginalData: b.String()}
	f.SetLazyLines()
	for i := 0; i < n; i++ {
		got, ok := f.LinesContaining(fmt.Sprintf("\"r%d\"", i))
		require.True(t, ok)
		require.Equal(t, []int{i}, got)
	}
	require.Greater(t, len(f.linesLazy.matches), maxCachedLineMatches)
	got, _ := f.LinesContaining("\"r7\"")
	require.Equal(t, []int{7}, got)
}

func scanLinesContaining(lines []string, sub string) []int {
	var out []int
	for i, line := range lines {
		if strings.Contains(line, sub) {
			out = append(out, i)
		}
	}
	return out
}

// Once a file is indexed, every lookup returns what a scan of its lines does,
// for substrings within a line, spanning lines, or absent.
func TestLinesContainingIndexMatchesScan(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	const alphabet = "ab\" =\r\n{}"
	randomString := func(n int) string {
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = alphabet[rng.Intn(len(alphabet))]
		}
		return string(buf)
	}
	indexed := 0
	for run := 0; run < 200; run++ {
		f := &FileMetadata{OriginalData: randomString(rng.Intn(2000))}
		f.SetLazyLines()
		lines := f.Lines()
		for i := 0; i < 192; i++ {
			var sub string
			switch i % 4 {
			case 0:
				sub = randomString(1 + rng.Intn(4))
			case 1:
				if len(f.OriginalData) > 0 {
					start := rng.Intn(len(f.OriginalData))
					sub = f.OriginalData[start:min(len(f.OriginalData), start+1+rng.Intn(6))]
				}
			case 2:
				if len(lines) > 0 {
					line := lines[rng.Intn(len(lines))]
					if len(line) > 0 {
						start := rng.Intn(len(line))
						sub = line[start:min(len(line), start+1+rng.Intn(5))]
					}
				}
			}
			want := scanLinesContaining(lines, sub)
			got, ok := f.LinesContaining(sub)
			require.True(t, ok)
			require.Equal(t, want, got, "run %d sub %q", run, sub)
			if x := f.linesLazy.index; x != nil {
				if direct, ok := x.linesContaining(sub); ok {
					indexed++
					require.Equal(t, want, direct, "run %d sub %q (index)", run, sub)
				}
			}
		}
	}
	require.Greater(t, indexed, 1000)
}

// A line holding a newline could let an indexed match span two lines, so such
// a file is never indexed and lookups keep scanning.
func TestLinesContainingDoesNotIndexLinesWithNewlines(t *testing.T) {
	lines := []string{"a\nb", "ab"}
	f := &FileMetadata{LinesOriginalData: &lines}
	f.SetLazyLines()
	for i := 0; i < 2*substringIndexAfterScans; i++ {
		got, ok := f.LinesContaining(fmt.Sprintf("x%d", i))
		require.True(t, ok)
		require.Nil(t, got)
	}
	got, _ := f.LinesContaining("a\nb")
	require.Equal(t, []int{0}, got)
	require.Nil(t, f.linesLazy.index)
	require.True(t, f.linesLazy.noIndex)
}

func TestLinesContainingIndexConcurrent(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&b, "resource \"t\" \"r%d\" {}\n", i)
	}
	f := &FileMetadata{OriginalData: b.String()}
	f.SetLazyLines()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := g; i < 400; i += 3 {
				got, ok := f.LinesContaining(fmt.Sprintf("\"r%d\"", i))
				if !ok || len(got) != 1 || got[0] != i {
					t.Errorf("r%d: %v %v", i, got, ok)
				}
			}
		}(g)
	}
	wg.Wait()
}
