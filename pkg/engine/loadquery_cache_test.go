/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"bytes"
	"context"
	"testing"

	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// cacheTracker is a no-op Tracker for building a QueryLoader in tests.
type cacheTracker struct{}

func (cacheTracker) TrackQueryLoad(int)      {}
func (cacheTracker) TrackQueryExecuting(int) {}
func (cacheTracker) TrackQueryExecution(int) {}
func (cacheTracker) FailedDetectLine()       {}
func (cacheTracker) FailedLineInfoDocument() {}
func (cacheTracker) GetOutputLines() int     { return 3 }

func newCacheTestLoader(t *testing.T, platform string, queries []model.QueryMetadata) *QueryLoader {
	t.Helper()
	commonLib := source.RegoLibraries{LibraryCode: "package common\n", LibraryInputData: "{}"}
	platformLibs := map[string]source.RegoLibraries{
		platform: {LibraryCode: "package generic." + platform + "\n", LibraryInputData: "{}"},
	}
	loader, err := prepareQueries(queries, commonLib, platformLibs, cacheTracker{})
	require.NoError(t, err)
	return &loader
}

func baseStoresFor(platform, data string) (map[string]storage.Store, map[string]uint64) {
	stores := map[string]storage.Store{platform: inmem.NewFromReader(bytes.NewBufferString(data))}
	hashes := hashBaseInputData(map[string]string{platform: data})
	return stores, hashes
}

func staticQuery(platform, name, body string) model.QueryMetadata {
	return model.QueryMetadata{
		Query:     name,
		Platform:  platform,
		Content:   "package datadog\n" + body,
		InputData: "{}",
	}
}

func clearPreparedCache() {
	preparedQueryCache.Range(func(k, _ any) bool { preparedQueryCache.Delete(k); return true })
}

func TestBuildMergedInputData_PropagatesLibraryErrors(t *testing.T) {
	platform := "terraform"
	query := staticQuery(platform, "test-rule", "")
	validLibrary := source.RegoLibraries{LibraryInputData: "{}"}

	tests := []struct {
		name       string
		common     source.RegoLibraries
		platform   source.RegoLibraries
		wantErrMsg string
	}{
		{
			name:       "platform library",
			common:     validLibrary,
			platform:   source.RegoLibraries{LibraryInputData: "null"},
			wantErrMsg: "could not merge terraform library input data",
		},
		{
			name:       "common library",
			common:     source.RegoLibraries{LibraryInputData: "null"},
			platform:   validLibrary,
			wantErrMsg: "could not merge common library input data",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader := QueryLoader{
				commonLibrary: tt.common,
				platformLibraries: map[string]source.RegoLibraries{
					platform: tt.platform,
				},
			}
			merged, err := loader.buildMergedInputData(&query, nil)
			require.ErrorContains(t, err, tt.wantErrMsg)
			require.Empty(t, merged)
		})
	}
}

// TestLoadQuery_CacheGate is the core of the --use-rules-cache wiring: with the
// cache disabled, two loads of the same query must compile fresh each time; with
// it enabled, the second load must return the cached pointer.
func TestLoadQuery_CacheGate(t *testing.T) {
	platform := "Terraform"
	q := staticQuery(platform, "q1", "")
	loader := newCacheTestLoader(t, platform, []model.QueryMetadata{q})
	stores, hashes := baseStoresFor(platform, "{}")
	ctx := context.Background()

	t.Run("disabled compiles fresh", func(t *testing.T) {
		clearPreparedCache()
		first, err := loader.LoadQuery(ctx, &q, nil, stores, hashes, false)
		require.NoError(t, err)
		second, err := loader.LoadQuery(ctx, &q, nil, stores, hashes, false)
		require.NoError(t, err)
		require.NotSame(t, first, second, "cache disabled: each load must compile a fresh query")
	})

	t.Run("enabled returns cached pointer", func(t *testing.T) {
		clearPreparedCache()
		first, err := loader.LoadQuery(ctx, &q, nil, stores, hashes, true)
		require.NoError(t, err)
		second, err := loader.LoadQuery(ctx, &q, nil, stores, hashes, true)
		require.NoError(t, err)
		require.Same(t, first, second, "cache enabled: identical query must return the cached pointer")
	})
}

func TestLoadQuery_DifferentContentDifferentEntry(t *testing.T) {
	clearPreparedCache()
	platform := "Terraform"
	qa := staticQuery(platform, "q1", "")
	qb := staticQuery(platform, "q1", "allow := true\n")
	loader := newCacheTestLoader(t, platform, []model.QueryMetadata{qa, qb})
	stores, hashes := baseStoresFor(platform, "{}")
	ctx := context.Background()

	a, err := loader.LoadQuery(ctx, &qa, nil, stores, hashes, true)
	require.NoError(t, err)
	b, err := loader.LoadQuery(ctx, &qb, nil, stores, hashes, true)
	require.NoError(t, err)
	require.NotSame(t, a, b, "different query content must compile to a distinct cache entry")
}

func TestLoadQuery_DifferentBaseDataDifferentEntry(t *testing.T) {
	clearPreparedCache()
	platform := "Terraform"
	q := staticQuery(platform, "q1", "")
	loader := newCacheTestLoader(t, platform, []model.QueryMetadata{q})
	ctx := context.Background()

	stores1, hashes1 := baseStoresFor(platform, "{}")
	stores2, hashes2 := baseStoresFor(platform, `{"common_lib":{"modules":{"aws":{}}}}`)

	a, err := loader.LoadQuery(ctx, &q, nil, stores1, hashes1, true)
	require.NoError(t, err)
	b, err := loader.LoadQuery(ctx, &q, nil, stores2, hashes2, true)
	require.NoError(t, err)
	require.NotSame(t, a, b, "different base store data must not share a cache entry")
}

func TestLoadQuery_CustomInputNotCached(t *testing.T) {
	clearPreparedCache()
	platform := "Terraform"
	q := staticQuery(platform, "q1", "")
	q.InputData = `{"foo":"bar"}`
	loader := newCacheTestLoader(t, platform, []model.QueryMetadata{q})
	stores, hashes := baseStoresFor(platform, "{}")
	ctx := context.Background()

	first, err := loader.LoadQuery(ctx, &q, nil, stores, hashes, true)
	require.NoError(t, err)
	second, err := loader.LoadQuery(ctx, &q, nil, stores, hashes, true)
	require.NoError(t, err)
	require.NotSame(t, first, second, "custom-input queries must bypass the cache even when it is enabled")
}
