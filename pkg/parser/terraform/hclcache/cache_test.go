/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package hclcache

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
)

func TestCache_HitsAndCanonicalizesRelativeAndAbsolutePaths(t *testing.T) {
	cache := New()
	ctx := WithCache(context.Background(), cache)
	src := []byte("resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"demo\"\n}\n")

	wd, err := filepath.Abs(".")
	require.NoError(t, err)
	relPath := filepath.Join("sub", "main.tf")
	absPath := filepath.Join(wd, "sub", "main.tf")

	body1, diags1 := ParseConfig(ctx, vfs.DiskFS{}, relPath, src)
	require.False(t, diags1.HasErrors())
	require.NotNil(t, body1)
	require.Equal(t, absPath, body1.SrcRange.Filename)

	body2, diags2 := ParseConfig(ctx, vfs.DiskFS{}, absPath, src)
	require.False(t, diags2.HasErrors())
	require.Same(t, body1, body2)

	body3, diags3 := ParseConfigString(ctx, vfs.DiskFS{}, absPath, string(src))
	require.False(t, diags3.HasErrors())
	require.Same(t, body1, body3)

	stats := cache.Stats()
	require.Equal(t, int64(1), stats.Misses)
	require.Equal(t, int64(2), stats.Hits)
	require.Equal(t, 1, stats.Entries)
	require.Equal(t, int64(len(src)), stats.LiveSourceBytes)
}

func TestCache_ContentChangeInvalidatesEntry(t *testing.T) {
	cache := New()
	src1 := []byte("locals { a = 1 }\n")
	src2 := []byte("locals { a = 2 }\n")

	body1, diags := cache.ParseConfig(vfs.DiskFS{}, "/repo/main.tf", src1)
	require.False(t, diags.HasErrors())
	require.NotNil(t, body1)

	body2, diags := cache.ParseConfig(vfs.DiskFS{}, "/repo/main.tf", src2)
	require.False(t, diags.HasErrors())
	require.NotNil(t, body2)
	require.NotSame(t, body1, body2)

	stats := cache.Stats()
	require.Equal(t, int64(2), stats.Misses)
	require.Equal(t, 1, stats.Entries)
	require.Equal(t, int64(len(src2)), stats.LiveSourceBytes)
}

func TestCache_CachesParseErrorsWithoutChargingSourceBytes(t *testing.T) {
	cache := New()
	bad := []byte("resource \"aws_s3_bucket\" {\n")

	body1, diags1 := cache.ParseConfig(vfs.DiskFS{}, "/repo/bad.tf", bad)
	require.Nil(t, body1)
	require.True(t, diags1.HasErrors())

	body2, diags2 := cache.ParseConfig(vfs.DiskFS{}, "/repo/bad.tf", bad)
	require.Nil(t, body2)
	require.True(t, diags2.HasErrors())

	stats := cache.Stats()
	require.Equal(t, int64(1), stats.Misses)
	require.Equal(t, int64(1), stats.Hits)
	require.Equal(t, int64(0), stats.LiveSourceBytes)
}

func TestCache_ForgetDirAndRelease(t *testing.T) {
	cache := New()
	srcA := []byte("locals { a = 1 }\n")
	srcB := []byte("locals { b = 2 }\n")

	bodyA, _ := cache.ParseConfig(vfs.DiskFS{}, "/repo/rootA/main.tf", srcA)
	bodyB, _ := cache.ParseConfig(vfs.DiskFS{}, "/repo/rootB/main.tf", srcB)
	require.NotNil(t, bodyA)
	require.NotNil(t, bodyB)
	require.Equal(t, 2, cache.Stats().Entries)

	cache.ForgetDir(vfs.DiskFS{}, "/repo/rootA")
	require.Equal(t, 1, cache.Stats().Entries)
	require.Equal(t, int64(len(srcB)), cache.Stats().LiveSourceBytes)

	// rootB is still cached; rootA re-parses on demand.
	bodyB2, _ := cache.ParseConfig(vfs.DiskFS{}, "/repo/rootB/main.tf", srcB)
	require.Same(t, bodyB, bodyB2)

	bodyA2, _ := cache.ParseConfig(vfs.DiskFS{}, "/repo/rootA/main.tf", srcA)
	require.NotSame(t, bodyA, bodyA2)

	cache.Release()
	stats := cache.Stats()
	require.Equal(t, 0, stats.Entries)
	require.Equal(t, int64(0), stats.LiveSourceBytes)
}

func TestCache_BudgetCapReclaimsAfterForgetDir(t *testing.T) {
	src1 := []byte("locals { a = \"1234567890\" }\n")
	src2 := []byte("locals { b = \"1234567890\" }\n")
	cache := NewWithMaxSourceBytes(int64(len(src1)))

	b1, _ := cache.ParseConfig(vfs.DiskFS{}, "/repo/d1/main.tf", src1)
	require.NotNil(t, b1)

	// Second directory exceeds the cap: still parses cleanly, just not stored.
	b2, diags := cache.ParseConfig(vfs.DiskFS{}, "/repo/d2/main.tf", src2)
	require.False(t, diags.HasErrors())
	require.NotNil(t, b2)
	require.Equal(t, int64(1), cache.Stats().BudgetSkips)
	require.Equal(t, 1, cache.Stats().Entries)

	// Evicting d1 frees budget so d2 can now be cached.
	cache.ForgetDir(vfs.DiskFS{}, "/repo/d1")
	b2a, _ := cache.ParseConfig(vfs.DiskFS{}, "/repo/d2/main.tf", src2)
	b2b, _ := cache.ParseConfig(vfs.DiskFS{}, "/repo/d2/main.tf", src2)
	require.Same(t, b2a, b2b)
	require.Equal(t, 1, cache.Stats().Entries)
}

func TestCache_ConcurrentAccessAndMemFS(t *testing.T) {
	fsys := vfs.NewMemFS(map[string][]byte{
		"infra/main.tf": []byte("locals { env = \"prod\" }\n"),
	})
	cache := New()
	src := []byte("locals { env = \"prod\" }\n")

	const goroutines = 16
	bodies := make([]any, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			body, diags := cache.ParseConfig(fsys, "infra/main.tf", src)
			require.False(t, diags.HasErrors())
			require.NotNil(t, body)
			require.Equal(t, "infra/main.tf", body.SrcRange.Filename)
			bodies[idx] = body
		}(i)
	}
	wg.Wait()

	for i := 1; i < goroutines; i++ {
		require.Same(t, bodies[0], bodies[i])
	}
	require.Equal(t, int64(1), cache.Stats().Misses)
}
