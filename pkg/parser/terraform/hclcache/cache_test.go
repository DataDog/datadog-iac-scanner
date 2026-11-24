/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package hclcache

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCacheReuseContentKeyAndClose(t *testing.T) {
	c := New(1024)
	ctx := WithCache(context.Background(), c)

	srcA := []byte(`resource "aws_s3_bucket" "a" {}`)
	f1, diags1 := ParseConfig(ctx, srcA, "/repo/root/main.tf")
	require.False(t, diags1.HasErrors())
	require.NotNil(t, f1)

	// Same path (including uncleaned form) + same content returns the identical AST pointer.
	f2, diags2 := ParseConfig(ctx, srcA, "/repo/root/./main.tf")
	require.False(t, diags2.HasErrors())
	require.Same(t, f1, f2)
	require.Equal(t, 1, c.Len())
	stats := c.Stats()
	require.Equal(t, int64(1), stats.Misses)
	require.Equal(t, int64(1), stats.Hits)

	// Modified content at the same path parses fresh without stale ASTs.
	srcB := []byte(`resource "aws_s3_bucket" "b" {}`)
	f3, diags3 := ParseConfig(ctx, srcB, "/repo/root/main.tf")
	require.False(t, diags3.HasErrors())
	require.NotSame(t, f1, f3)
	require.Equal(t, 2, c.Len())

	// Close clears entries and permanently prevents subsequent parses from refilling the cache.
	c.Close()
	require.Equal(t, 0, c.Len())
	require.Equal(t, 0, c.Stats().SourceBytes)
	f4, diags4 := ParseConfig(ctx, srcA, "/repo/modules/s3/main.tf")
	require.False(t, diags4.HasErrors())
	require.NotNil(t, f4)
	require.Equal(t, 0, c.Len())
}

func TestCacheEvictionAndOversizedBypass(t *testing.T) {
	const maxBytes = 2048
	c := New(maxBytes)

	// Single entry exceeding maxBytes/4 (512 bytes) bypasses storage without evicting existing entries.
	small := []byte(`variable "a" { default = "1" }`) // 30 bytes
	hotFile, diags := c.ParseConfig(small, "/repo/hot.tf")
	require.False(t, diags.HasErrors())
	// Bump hit count on hotFile so eviction prefers cold single-hit entries.
	for range 5 {
		again, _ := c.ParseConfig(small, "/repo/hot.tf")
		require.Same(t, hotFile, again)
	}

	oversized := bytes.Repeat([]byte("# padding line\n"), 40) // 600 bytes > 512
	fBig, diags := c.ParseConfig(oversized, "/repo/big.tf")
	require.False(t, diags.HasErrors())
	require.NotNil(t, fBig)
	require.Equal(t, 1, c.Len())

	// Fill past maxBytes with cold entries; occupancy must remain bounded by maxBytes.
	for i := range 20 {
		src := []byte(fmt.Sprintf("resource \"aws_s3_bucket\" \"b_%02d\" { bucket = \"bucket-%02d\" }\n", i, i))
		f, d := c.ParseConfig(src, fmt.Sprintf("/repo/cold_%02d.tf", i))
		require.False(t, d.HasErrors())
		require.NotNil(t, f)
		require.LessOrEqual(t, c.Stats().SourceBytes, maxBytes)
	}

	// Hot entry survived eviction while cold entries were recycled.
	stillHot, _ := c.ParseConfig(small, "/repo/hot.tf")
	require.Same(t, hotFile, stillHot)
}

func TestCacheBoundsEmptyFilesByEntryCount(t *testing.T) {
	const maxBytes = 4096
	c := New(maxBytes)

	for i := range 40 {
		f, diags := c.ParseConfig(nil, fmt.Sprintf("/repo/empty_%02d.tf", i))
		require.False(t, diags.HasErrors())
		require.NotNil(t, f)
	}

	stats := c.Stats()
	require.LessOrEqual(t, stats.Entries, maxBytes/minEntryBudgetBytes)
	require.Equal(t, 0, stats.SourceBytes)
	// Repeated access to an empty file still benefits from the cache while its
	// entry remains resident.
	path := "/repo/empty_39.tf"
	f1, _ := c.ParseConfig(nil, path)
	f2, _ := c.ParseConfig(nil, path)
	require.Same(t, f1, f2)
}

func TestCacheConcurrentSingleflightAndClose(t *testing.T) {
	c := New(DefaultMaxSourceBytes)
	ctx := WithCache(context.Background(), c)
	src := []byte(`
variable "env" { default = "prod" }
locals { prefix = "${var.env}-app" }
resource "aws_s3_bucket" "b" { bucket = local.prefix }
`)

	const workers = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	files := make([]any, workers)
	for i := range workers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			f, diags := ParseConfig(ctx, src, "/repo/shared/main.tf")
			require.False(t, diags.HasErrors())
			require.NotNil(t, f)
			files[idx] = f
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 1; i < workers; i++ {
		require.Same(t, files[0], files[i])
	}
	stats := c.Stats()
	require.Equal(t, int64(1), stats.Misses)
	require.Equal(t, int64(workers-1), stats.Hits)

	// Concurrent ParseConfig calls racing with Close must not panic or refill after Close.
	var raceWG sync.WaitGroup
	for i := range workers {
		raceWG.Add(1)
		go func(idx int) {
			defer raceWG.Done()
			for j := range 20 {
				p := fmt.Sprintf("/repo/race/f_%d_%d.tf", idx, j)
				f, diags := ParseConfig(ctx, src, p)
				require.False(t, diags.HasErrors())
				require.NotNil(t, f)
			}
		}(i)
	}
	c.Close()
	raceWG.Wait()
	require.Equal(t, 0, c.Len())
}

func TestCacheNilSafety(t *testing.T) {
	var c *Cache
	require.Equal(t, 0, c.Len())
	require.Equal(t, Stats{}, c.Stats())
	c.Close()

	f, diags := c.ParseConfig([]byte(`resource "a" "b" {}`), "/repo/main.tf")
	require.False(t, diags.HasErrors())
	require.NotNil(t, f)

	ctx := WithCache(context.Background(), nil)
	require.Nil(t, FromContext(ctx))
	require.Nil(t, FromContext(context.TODO()))
}
