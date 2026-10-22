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

func TestShallowCopySharingLineInfo_parsesOnceForAllCopies(t *testing.T) {
	ctx := context.Background()
	var loads atomic.Int32
	fm := &FileMetadata{ID: "id", FilePath: "main.tf", OriginalData: "a\nb\n"}
	fm.SetLazyLines()
	fm.SetLineInfoLoader(func(context.Context, *FileMetadata) (map[string]interface{}, error) {
		loads.Add(1)
		return map[string]interface{}{"resource": "as parsed"}, nil
	})

	first, second := fm.ShallowCopySharingLineInfo(), fm.ShallowCopySharingLineInfo()
	require.True(t, first.SharesLineInfoWith(second))
	require.False(t, first.SharesLineInfoWith(fm))
	require.Equal(t, []string{"a", "b", ""}, second.Lines())

	for _, copyFm := range []*FileMetadata{first, second, first} {
		require.NoError(t, copyFm.UseLineInfoDocument(ctx, func(doc map[string]interface{}) error {
			require.Equal(t, "as parsed", doc["resource"])
			return nil
		}))
		copyFm.DiscardLineInfoDocument()
	}
	require.Equal(t, int32(1), loads.Load(), "copies of one file share one parse")

	// Once the shared parse is dropped, the next copy to need it parses again.
	first.DiscardSharedLineInfo()
	require.NoError(t, second.EnsureLineInfoDocument(ctx))
	require.Equal(t, int32(2), loads.Load())
	// The file keeps its own line info, unaffected by its copies.
	require.NoError(t, fm.EnsureLineInfoDocument(ctx))
	require.Equal(t, int32(3), loads.Load())
}
