/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
)

type DefaultChainConfig struct {
	DiscoveryPaths []string
	Manifest       *Manifest
	Additional     []Resolver
	FetchRemote    bool
	FetchTimeout   time.Duration
	HostAllowlist  []string
	CacheRoot      string
	MaxCacheBytes  int64
}

// NewDefaultChain builds the standard local, prefetched, injected, git, and registry resolver chain.
func NewDefaultChain(ctx context.Context, config *DefaultChainConfig) (*ChainResolver, error) {
	if config == nil {
		config = &DefaultChainConfig{}
	}
	contextLogger := logger.FromContext(ctx)
	roots := TerraformRootDirs(config.DiscoveryPaths)
	resolvers := []Resolver{
		LocalResolver{},
		&DotTerraformResolver{RootDirs: roots},
	}
	if config.Manifest != nil {
		resolvers = append(resolvers, NewPrefetchedResolver(config.Manifest))
	}
	for _, additional := range config.Additional {
		if additional != nil {
			resolvers = append(resolvers, additional)
		}
	}
	if !config.FetchRemote {
		return NewChainResolver(resolvers...), nil
	}

	getterConfig := NewGoGetterConfig()
	if config.FetchTimeout > 0 {
		getterConfig.FetchTimeout = config.FetchTimeout
	}
	getterConfig.HostAllowlist = append([]string(nil), config.HostAllowlist...)

	cacheRoot := strings.TrimSpace(config.CacheRoot)
	if cacheRoot == "" {
		var err error
		cacheRoot, err = DefaultModuleCacheRoot()
		if err != nil {
			contextLogger.Warn().Err(err).
				Msg("Remote module cache root unavailable; cache limits will not be enforced")
		}
	}
	maxCacheBytes := config.MaxCacheBytes
	if maxCacheBytes == 0 {
		maxCacheBytes = DefaultMaxCacheBytes
	}
	var budget *ModuleCacheBudget
	if cacheRoot != "" {
		var err error
		budget, err = NewModuleCacheBudget(cacheRoot, maxCacheBytes)
		if err != nil {
			contextLogger.Warn().Err(err).
				Msg("Remote module cache budget unavailable; cache limits will not be enforced")
		}
	}

	git := NewBareGitResolver(ModuleCacheSubdir(cacheRoot, CacheSubdirGitBare), config.HostAllowlist...)
	git.Budget = budget
	getterConfig.Git = git
	localGit := NewLocalGitRefResolver(roots, ModuleCacheSubdir(cacheRoot, CacheSubdirGitLocal))
	localGit.Budget = budget
	resolvers = append(resolvers, localGit, git)

	cache, err := NewModuleCacheWithDir(ModuleCacheSubdir(cacheRoot, CacheSubdirModules), budget)
	if err != nil {
		contextLogger.Warn().Err(err).
			Msg("Module disk cache unavailable; fetched modules will not be cached")
	} else {
		getterConfig.Cache = cache
	}
	resolvers = append(resolvers, NewGoGetterResolver(getterConfig))
	return NewChainResolver(resolvers...), nil
}

// TerraformRootDirs returns the Terraform workspace root for each distinct discovery path.
func TerraformRootDirs(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	roots := make([]string, 0, len(paths))
	for _, path := range paths {
		root := terraformRootDir(path)
		if root == "" || seen[root] {
			continue
		}
		seen[root] = true
		roots = append(roots, root)
	}
	return roots
}

func terraformRootDir(path string) string {
	info, err := os.Stat(path)
	if err == nil && !info.IsDir() {
		path = filepath.Dir(path)
	}
	clean := filepath.Clean(path)
	for {
		if _, err := os.Stat(filepath.Join(clean, ".terraform", "modules", "modules.json")); err == nil {
			return clean
		}
		parent := filepath.Dir(clean)
		if parent == clean {
			return filepath.Clean(path)
		}
		clean = parent
	}
}
