package model

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func lineInfoReturning(docs []Document, err error, loads *atomic.Int32) *LineInfoSource {
	return NewLineInfoSource(func(context.Context, *FileMetadata) ([]Document, map[DerivedKey]any, error) {
		if loads != nil {
			loads.Add(1)
		}
		return docs, nil, err
	})
}

func TestFileMetadata_JSONMarshalSkipsLazyState(t *testing.T) {
	fm := &FileMetadata{ID: "id", Document: Document{"k": "v"}}
	fm.SetLineInfoSource(lineInfoReturning([]Document{{}}, nil, nil), 0)

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
	fm.SetLineInfoSource(lineInfoReturning(nil, errors.New("reparse failed"), nil), 0)

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
	fm.SetLineInfoSource(lineInfoReturning([]Document{{"kind": "Pod"}}, nil, nil), 0)

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
	fm.SetLineInfoSource(lineInfoReturning([]Document{{"_dd_lines": map[string]interface{}{"k": 1}}}, nil, &loads), 0)

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
	fm.SetLineInfoSource(lineInfoReturning([]Document{{"_dd_lines": map[string]interface{}{}}}, nil, &loads), 0)

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

func TestFileMetadata_ShallowCopySharesTheParse(t *testing.T) {
	var loads atomic.Int32
	parent := &FileMetadata{FilePath: "mod.tf", OriginalData: "resource {}\n"}
	parent.SetLineInfoSource(lineInfoReturning([]Document{{"x": 1}}, nil, &loads), 0)
	clone := parent.ShallowCopy()

	lease := parent.LeaseLineInfo()
	defer lease.Close()
	require.NoError(t, clone.EnsureLineInfoDocument(context.Background()))
	require.NoError(t, parent.EnsureLineInfoDocument(context.Background()))
	require.Equal(t, int32(1), loads.Load())
	require.Equal(t, parent.LineInfoDocument, clone.LineInfoDocument)
	require.Equal(t, &parent.Lines()[0], &clone.Lines()[0])
}

func TestCombine_lineInfoDoesNotWriteIntoTheSharedParse(t *testing.T) {
	shared := Document{"kind": "Pod"}
	src := lineInfoReturning([]Document{shared}, nil, nil)
	a := &FileMetadata{ID: "a", FilePath: "p.yaml"}
	b := &FileMetadata{ID: "b", FilePath: "p.yaml"}
	a.SetLineInfoSource(src, 0)
	b.SetLineInfoSource(src, 0)

	out := FileMetadatas{a, b}.Combine(context.Background(), true)
	require.Equal(t, "a", out.Documents[0]["id"])
	require.Equal(t, "b", out.Documents[1]["id"])
	require.NotContains(t, shared, "id")
}

func TestCombine_lineInfoReleasesItsLastLease(t *testing.T) {
	first := lineInfoReturning([]Document{{"kind": "Pod"}}, nil, nil)
	last := lineInfoReturning([]Document{{"kind": "Service"}}, nil, nil)
	a := &FileMetadata{ID: "a", FilePath: "a.yaml"}
	b := &FileMetadata{ID: "b", FilePath: "b.yaml"}
	a.SetLineInfoSource(first, 0)
	b.SetLineInfoSource(last, 0)

	FileMetadatas{a, b}.Combine(context.Background(), true)
	for _, src := range []*LineInfoSource{first, last} {
		require.Zero(t, src.held)
		require.Nil(t, src.docs)
	}
}

func TestReleasePostEvalData_releasesTheSharedLineSplit(t *testing.T) {
	src := lineInfoReturning([]Document{{}, {}}, nil, nil)
	a := &FileMetadata{FilePath: "p.yaml", OriginalData: "a: 1\n---\nb: 2\n"}
	b := &FileMetadata{FilePath: "p.yaml", OriginalData: a.OriginalData}
	a.SetLineInfoSource(src, 0)
	b.SetLineInfoSource(src, 1)
	require.Equal(t, &a.Lines()[0], &b.Lines()[0])
	split := src.sharedLines()
	require.NotNil(t, split.lines)

	a.ReleasePostEvalData()
	b.ReleasePostEvalData()
	require.NotSame(t, split, src.sharedLines())
	require.Nil(t, src.sharedLines().lines)
	require.Nil(t, a.linesLazy)
	require.Nil(t, b.linesLazy)
}

func TestLineInfoSource_doesNotRememberACanceledParse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	fm := &FileMetadata{FilePath: "a.yaml"}
	fm.SetLineInfoSource(NewLineInfoSource(func(context.Context, *FileMetadata) ([]Document, map[DerivedKey]any, error) {
		if calls.Add(1) == 1 {
			return nil, nil, context.DeadlineExceeded
		}
		return []Document{{"k": 1}}, nil, nil
	}), 0)
	require.ErrorIs(t, fm.EnsureLineInfoDocument(ctx), context.Canceled)
	require.Zero(t, calls.Load(), "a caller canceled before loading must not start a parse")
	require.ErrorIs(t, fm.EnsureLineInfoDocument(context.Background()), context.DeadlineExceeded)
	require.NoError(t, fm.EnsureLineInfoDocument(context.Background()))
	require.Equal(t, int32(2), calls.Load())
}

func TestLineInfoSource_oneCallersCancelDoesNotFailTheOthers(t *testing.T) {
	started := make(chan struct{})
	proceed := make(chan struct{})
	var calls atomic.Int32
	src := NewLineInfoSource(func(ctx context.Context, _ *FileMetadata) ([]Document, map[DerivedKey]any, error) {
		calls.Add(1)
		close(started)
		<-proceed
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		return []Document{{"k": 1}}, nil, nil
	})
	canceled := &FileMetadata{FilePath: "a.yaml"}
	live := &FileMetadata{FilePath: "a.yaml"}
	canceled.SetLineInfoSource(src, 0)
	live.SetLineInfoSource(src, 0)

	cancelCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	canceledErr := make(chan error, 1)
	go func() { canceledErr <- canceled.EnsureLineInfoDocument(cancelCtx) }()
	<-started
	liveErr := make(chan error, 1)
	go func() { liveErr <- live.EnsureLineInfoDocument(context.Background()) }()
	// Give the live caller time to join the in-flight parse.
	time.Sleep(50 * time.Millisecond)
	cancel()
	close(proceed)

	require.ErrorIs(t, <-canceledErr, context.Canceled)
	require.NoError(t, <-liveErr)
	require.Equal(t, int32(1), calls.Load(), "both callers share one parse")
	require.Equal(t, 1, live.LineInfoDocument["k"])
}

func TestLineInfoSource_reparseKeepsAValueDerivedBeforeIt(t *testing.T) {
	var reparses atomic.Int32
	fm := &FileMetadata{FilePath: "main.tf"}
	fm.SetLineInfoSource(NewLineInfoSource(func(context.Context, *FileMetadata) ([]Document, map[DerivedKey]any, error) {
		reparses.Add(1)
		return []Document{{"k": 1}}, map[DerivedKey]any{HCLBodyKey: "from reparse"}, nil
	}), 0)
	lease := fm.LeaseLineInfo()
	defer lease.Close()

	first, err := fm.Derived(HCLBodyKey, func() (any, error) { return "from line detection", nil })
	require.NoError(t, err)
	require.Equal(t, "from line detection", first)
	require.NoError(t, fm.EnsureLineInfoDocument(context.Background()))
	require.Equal(t, int32(1), reparses.Load())

	again, err := fm.Derived(HCLBodyKey, func() (any, error) {
		t.Fatal("the derived value must still be kept")
		return nil, nil
	})
	require.NoError(t, err)
	require.Equal(t, "from line detection", again, "the reparse must not overwrite a published value")
}
