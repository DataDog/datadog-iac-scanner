/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
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

func TestGitLabRuleInputPreservesConfiguration(t *testing.T) {
	for _, lineInfo := range []bool{false, true} {
		pipeline := Document{}
		for _, name := range []string{"id", "file", GitLabInputKey, GitLabScriptsKey, "_dd_lines", "_parsed_before_script", "_parsed_after_script", "build"} {
			pipeline[name] = map[string]interface{}{"script": []interface{}{"echo " + name}}
		}
		file := &FileMetadata{ID: "scanner-id", FilePath: ".gitlab-ci.yml", DocumentDialect: GitLabDialect,
			Document: pipeline, LineInfoDocument: pipeline, GlobalScripts: map[string]interface{}{"before_script": "parsed analysis"}}
		combined := (FileMetadatas{file}).Combine(t.Context(), lineInfo)
		require.Len(t, combined.Documents, 1)
		envelope := combined.Documents[0]
		require.Equal(t, "scanner-id", envelope["id"])
		require.Equal(t, file.FilePath, envelope["file"])
		require.Equal(t, pipeline, envelope[GitLabInputKey])
		require.Equal(t, file.GlobalScripts, envelope[GitLabScriptsKey])
		for _, name := range []string{"id", "file", GitLabInputKey, GitLabScriptsKey, "_dd_lines", "_parsed_before_script", "_parsed_after_script", "build"} {
			require.IsType(t, map[string]interface{}{}, pipeline[name], name)
		}
	}
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

func TestDetectionView_PrepareOnceConcurrently(t *testing.T) {
	file := &FileMetadata{OriginalData: "from alpine\nrun echo hello\n"}
	file.SetLazyLines()
	var calls, otherCalls atomic.Int32
	prepare := func(lines []string) []string {
		calls.Add(1)
		prepared := slices.Clone(lines)
		prepared[0] = "prepared"
		return prepared
	}
	results := make(chan string, 16)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			results <- file.DetectionView("prepared", prepare).Lines()[0]
			file.DetectionView("other", func(lines []string) []string {
				otherCalls.Add(1)
				return slices.Clone(lines)
			})
		})
	}
	workers.Wait()
	close(results)
	for got := range results {
		require.Equal(t, "prepared", got)
	}
	require.EqualValues(t, 1, calls.Load())
	require.EqualValues(t, 1, otherCalls.Load())
	require.Equal(t, "from alpine", file.Lines()[0], "cached preparation must not change source text")
}

func TestDetectionView_IndependentTransformationsAndIndexes(t *testing.T) {
	file := &FileMetadata{OriginalData: "from alpine\nrun echo hello\n"}
	file.SetLazyLines()
	first := file.DetectionView("upper", func(lines []string) []string {
		result := slices.Clone(lines)
		result[0] = "FROM alpine"
		return result
	})
	source := file.DetectionLines("raw", func(lines []string) []string { return slices.Clone(lines) })
	require.Equal(t, "from alpine", source[0])
	second := file.DetectionView("mask", func(lines []string) []string {
		return []string{"", lines[1]}
	})
	require.Equal(t, "FROM alpine", first.Lines()[0])
	require.Equal(t, "", second.Lines()[0])
	indexes, ok := first.LinesContaining("FROM")
	require.True(t, ok)
	require.Equal(t, []int{0}, indexes)
	indexes, ok = second.LinesContaining("FROM")
	require.True(t, ok)
	require.Empty(t, indexes)
	indexes, ok = file.LinesContaining("FROM")
	require.True(t, ok)
	require.Empty(t, indexes)
	require.Equal(t, "from alpine", file.Lines()[0])
}

func TestDetectionView_ReleaseSubstringIndex(t *testing.T) {
	file := &FileMetadata{OriginalData: "from alpine\nrun echo hello\n"}
	file.SetLazyLines()
	view := file.DetectionView("upper", func(lines []string) []string {
		result := slices.Clone(lines)
		result[0] = "FROM alpine"
		return result
	})
	for i := range substringIndexAfterScans {
		_, ok := view.LinesContaining(string(rune('a'+i%26)) + string(rune('A'+i/26)))
		require.True(t, ok)
	}
	require.NotNil(t, view.linesLazy.index)
	file.ReleaseSubstringIndex()
	require.Nil(t, view.linesLazy.index)
	require.Zero(t, view.linesLazy.scans)
}
