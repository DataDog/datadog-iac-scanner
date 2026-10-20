/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestExtensions_MatchedFilesRegex tests the functions [MatchedFilesRegex()] and all the methods called by them
func TestExtensions_MatchedFilesRegex(t *testing.T) {
	var e Extensions
	require.Equal(t, "NO_MATCHED_FILES", e.MatchedFilesRegex())

	e = Extensions{}
	require.Equal(t, "NO_MATCHED_FILES", e.MatchedFilesRegex())

	e = Extensions{
		".txt": struct{}{},
	}
	require.Equal(t, "(.*)(\\.txt)$", e.MatchedFilesRegex())

	e = Extensions{
		".txt": struct{}{},
		".tf":  struct{}{},
	}
	require.Equal(t, "(.*)(\\.tf|\\.txt)$", e.MatchedFilesRegex())
}

// TestInclude tests the functions [Include()] and all the methods called by them
func TestInclude(t *testing.T) {
	e := Extensions{
		".txt": struct{}{},
		".tf":  struct{}{},
	}
	require.Equal(t, true, e.Include(".txt"))
}

// TestFileMetadatas tests the functions [Combine(),ToMap()] and all the methods called by them
func TestFileMetadatas(t *testing.T) {
	m := FileMetadatas{
		&FileMetadata{
			ID:           "id",
			ScanID:       "scan_id",
			OriginalData: "orig_data",
			FilePath:     "file_name",
			Document: Document{
				"id": "",
			},
		},
	}

	mEmptyDocuments := FileMetadatas{
		&FileMetadata{
			ID:           "id",
			ScanID:       "scan_id",
			OriginalData: "orig_data",
			FilePath:     "file_name",
			Document:     nil,
		},
	}

	mIgnoreCommand := FileMetadatas{
		&FileMetadata{
			ID:           "id",
			ScanID:       "scan_id",
			OriginalData: "orig_data",
			FilePath:     "file_name",
			Document: Document{
				"id": "",
			},
			Commands: CommentsCommands{
				"ignore": "",
			},
		},
	}

	t.Run("to_map", func(t *testing.T) {
		result := m.ToMap()
		require.Len(t, result, 1)
		require.Equal(t, m[0], result["id"])
	})

	t.Run("combine", func(t *testing.T) {
		ctx := context.Background()
		result := m.Combine(ctx, false)
		require.Equal(t, Documents{Documents: []Document{{"file": "file_name", "id": "id"}}}, result)
	})

	t.Run("combine_empty_documents", func(t *testing.T) {
		ctx := context.Background()
		result := mEmptyDocuments.Combine(ctx, false)
		require.Equal(t, Documents{Documents: []Document{}}, result)
	})

	t.Run("ignore_documents", func(t *testing.T) {
		ctx := context.Background()
		result := mIgnoreCommand.Combine(ctx, false)
		require.Equal(t, Documents{Documents: []Document{}}, result)
	})
}

func TestHelmInvocationsContaining(t *testing.T) {
	invocations := HelmInvocations{
		{RenderedLine: 3, RenderedEnd: 6, Position: ResourceLine{Line: 1}},
		{RenderedLine: 8, RenderedEnd: 9, Position: ResourceLine{Line: 2}},
		{RenderedLine: 12, Position: ResourceLine{Line: 4}},
	}
	for renderedLine, want := range map[int]int{2: 0, 3: 1, 5: 1, 6: 0, 8: 2, 9: 0, 12: 0, 30: 0} {
		invocation, ok := invocations.Containing(renderedLine)
		require.Equal(t, want != 0, ok, "rendered line %d", renderedLine)
		require.Equal(t, want, invocation.Position.Line, "rendered line %d", renderedLine)
	}
	require.True(t, invocations.KnownBefore(11))
	require.False(t, invocations.KnownBefore(12))
}

func TestNewHelmAttribution(t *testing.T) {
	one := HelmInvocations{{RenderedLine: 1, Position: ResourceLine{Line: 4}}}

	require.Nil(t, NewHelmAttribution(nil, ""))
	require.Empty(t, NewHelmAttribution(nil, "rendered").Invocations)
	require.Equal(t, "rendered", NewHelmAttribution(one, "rendered").RenderedContent)

	var none *HelmAttribution
	require.Equal(t, ResourceLine{}, none.First())
	require.Equal(t, 4, NewHelmAttribution(one, "rendered").First().Line)
}

func TestLinesMatchingWithoutLazyCache(t *testing.T) {
	for _, tt := range []struct {
		lines []string
		want  []int
	}{
		{[]string{}, nil},
		{[]string{"ARG X=1", "FROM alpine", "RUN a"}, []int{1}},
		{[]string{"FROM alpine", "RUN a", "FROM busybox"}, []int{0, 2}},
	} {
		for _, cached := range []bool{false, true} {
			f := &FileMetadata{LinesOriginalData: &tt.lines}
			if cached {
				f.SetLazyLines()
			}
			indexes := f.LinesMatching("test.stages", func(line string) bool { return len(line) >= 4 && line[:4] == "FROM" })
			require.Equal(t, tt.want, indexes)
		}
	}
}

func TestReleasePostEvalDropsSourceLoader(t *testing.T) {
	for _, state := range []string{"none", "lazy", "loaded"} {
		f := &FileMetadata{OriginalData: "FROM alpine"}
		f.SetLazyLines()
		if state != "none" {
			f.SetLineInfoLoader(func(context.Context, *FileMetadata) (map[string]interface{}, error) {
				return map[string]interface{}{}, nil
			})
		}
		if state == "loaded" {
			require.NoError(t, f.UseLineInfoDocument(t.Context(), func(map[string]interface{}) error { return nil }))
		}
		clones := []*FileMetadata{f.ShallowCopy(), f.ShallowCopy(), f.ShallowCopy()}
		previous := f.lineInfo
		f.ReleasePostEvalData()
		require.Same(t, previous, f.lineInfo, "state pointers stay stable for concurrent readers")
		if f.lineInfo != nil {
			require.Nil(t, f.lineInfo.source.loader)
		}
		for _, clone := range clones {
			if clone.lineInfo != nil {
				require.Nil(t, clone.lineInfo.source.loader, "clones release captured source too")
			}
		}
		require.Nil(t, f.linesLazy)
		require.Empty(t, f.OriginalData)
	}
}
