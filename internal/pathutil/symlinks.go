package pathutil

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type resolvedPathCacheKey struct{}

// WithResolvedPathCache attaches a scan-scoped EvalSymlinks cache to ctx.
// Nested calls reuse the existing cache so graph walking and evaluation share hits.
func WithResolvedPathCache(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if resolvedPathCacheFrom(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, resolvedPathCacheKey{}, &sync.Map{})
}

func resolvedPathCacheFrom(ctx context.Context) *sync.Map {
	if ctx == nil {
		return nil
	}
	cache, _ := ctx.Value(resolvedPathCacheKey{}).(*sync.Map)
	return cache
}

func EvalSymlinksCached(ctx context.Context, path string) (string, error) {
	clean := filepath.Clean(path)
	if cache := resolvedPathCacheFrom(ctx); cache != nil {
		if v, ok := cache.Load(clean); ok {
			return v.(string), nil
		}
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", err
	}
	if cache := resolvedPathCacheFrom(ctx); cache != nil {
		cache.Store(clean, resolved)
	}
	return resolved, nil
}

func PathEscapesDir(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
