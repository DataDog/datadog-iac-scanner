package model

import (
	"context"
	"encoding/json"
	"errors"
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

// Release serializes with an in-flight lazy location request and leaves the
// shared loader empty for every copy, without replacing synchronization state.
func TestLineInfoReleaseSerializesWithLoading(t *testing.T) {
	for _, mode := range []string{"original", "copy", "discarded"} {
		t.Run(mode, func(t *testing.T) {
			file := &FileMetadata{OriginalData: "FROM alpine"}
			file.SetLazyLines()
			entered, finish := make(chan struct{}), make(chan struct{})
			file.SetLineInfoLoader(func(_ context.Context, f *FileMetadata) (map[string]interface{}, error) {
				close(entered)
				<-finish
				return Document{"source": f.OriginalData}, nil
			})
			copy := file.ShallowCopy()
			var wg sync.WaitGroup
			wg.Add(1)
			go func() { defer wg.Done(); require.NoError(t, file.EnsureLineInfoDocument(t.Context())) }()
			<-entered
			wg.Add(1)
			go func() {
				defer wg.Done()
				if mode == "copy" {
					copy.ReleasePostEvalData()
				} else {
					file.ReleasePostEvalData()
				}
			}()
			close(finish)
			wg.Wait()
			if mode == "discarded" {
				file.DiscardLineInfoDocument()
			}
			require.Nil(t, file.lineInfo.source.loader)
			require.Nil(t, copy.lineInfo.source.loader)
		})
	}
}
