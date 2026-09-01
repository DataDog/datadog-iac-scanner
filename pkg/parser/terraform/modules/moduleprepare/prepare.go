/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
// Package moduleprepare materializes Terraform modules for a later offline scan.
package moduleprepare

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/modulegraph"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

const (
	DefaultMaxDepth          = 8
	DefaultResolutionTimeout = 5 * time.Minute
	DefaultFetchTimeout      = 30 * time.Second
	manifestFilename         = "modules.json"
	manifestRoot             = "modules"
)

type Config struct {
	RepositoryRoot string
	// ArtifactDir is published atomically and must not already exist.
	ArtifactDir    string
	DiscoveryPaths []string
	// Resolver replaces the standard resolver chain when set.
	Resolver resolver.Resolver
	// AdditionalResolvers run before the standard network resolvers.
	AdditionalResolvers []resolver.Resolver
	HostAllowlist       []string
	CacheDir            string
	MaxCacheBytes       int64
	// MaxDepth caps remote-module traversal depth. nil uses DefaultMaxDepth; explicit zero disables traversal.
	MaxDepth          *int
	FetchTimeout      time.Duration
	ResolutionTimeout time.Duration
	ResourceLimits    resolver.ResourceLimits
	TotalParseBytes   int64
	FS                vfs.FS
}

type Result struct {
	ManifestPath string
	Modules      []resolver.ManifestModule
	Failures     []modulegraph.ResolutionFailure
	BudgetEvents []modulegraph.BudgetEvent
	TimedOut     bool
}

// Prepare resolves a staged repository's module graph into an offline scan artifact.
func Prepare(ctx context.Context, config *Config) (Result, error) {
	var output Result
	if err := validateConfig(config); err != nil {
		return output, err
	}
	repositoryRoot, artifactDir, err := validatePaths(config.RepositoryRoot, config.ArtifactDir)
	if err != nil {
		return output, err
	}
	discoveryPaths, err := configuredDiscoveryPaths(
		ctx,
		repositoryRoot,
		config.DiscoveryPaths,
		config.CacheDir,
	)
	if err != nil {
		return output, err
	}

	moduleResolver := config.Resolver
	if moduleResolver == nil {
		moduleResolver, err = resolver.NewDefaultChain(ctx, &resolver.DefaultChainConfig{
			DiscoveryPaths: discoveryPaths,
			Additional:     config.AdditionalResolvers,
			FetchRemote:    true,
			FetchTimeout:   defaultDuration(config.FetchTimeout, DefaultFetchTimeout),
			HostAllowlist:  config.HostAllowlist,
			CacheRoot:      config.CacheDir,
			MaxCacheBytes:  config.MaxCacheBytes,
		})
		if err != nil {
			return output, fmt.Errorf("building module resolver: %w", err)
		}
	}

	resolveCtx, cancel := resolutionContext(ctx, config.ResolutionTimeout)
	defer cancel()
	graphResult := modulegraph.Resolve(resolveCtx, &modulegraph.Request{
		RootPaths:       []string{repositoryRoot},
		DiscoveryPaths:  discoveryPaths,
		Resolver:        moduleResolver,
		MaxDepth:        configuredMaxDepth(config.MaxDepth),
		ResourceLimits:  defaultResourceLimits(config.ResourceLimits),
		BaselinePaths:   discoveryPaths,
		TotalParseBytes: config.TotalParseBytes,
		FS:              config.FS,
	})
	defer graphResult.Cleanup()

	output.Failures = graphResult.Failures
	output.BudgetEvents = redactedBudgetEvents(graphResult.BudgetEvents)
	output.TimedOut = graphResult.TimedOut
	if err := ctx.Err(); err != nil {
		return output, err
	}

	tempArtifact, err := os.MkdirTemp(filepath.Dir(artifactDir), "."+filepath.Base(artifactDir)+"-")
	if err != nil {
		return output, fmt.Errorf("creating temporary module artifact: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tempArtifact)
	}()

	materializer, err := newMaterializer(ctx, tempArtifact, graphResult.Modules, graphResult.Failures)
	if err != nil {
		return output, err
	}
	output.Modules, err = buildManifestModules(ctx, repositoryRoot, &graphResult, materializer)
	if err != nil {
		return output, err
	}
	tempManifest := filepath.Join(tempArtifact, manifestFilename)
	if err := resolver.WriteManifest(ctx, tempManifest, manifestRoot, output.Modules); err != nil {
		return output, err
	}
	if _, err := os.Stat(artifactDir); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return output, fmt.Errorf("artifact directory %q already exists", artifactDir)
		}
		return output, fmt.Errorf("checking artifact directory: %w", err)
	}
	if err := publishArtifact(tempArtifact, artifactDir); err != nil {
		return output, fmt.Errorf("publishing module artifact: %w", err)
	}
	output.ManifestPath = filepath.Join(artifactDir, manifestFilename)
	return output, nil
}

func configuredDiscoveryPaths(
	ctx context.Context, root string, configured []string, cacheDir string,
) ([]string, error) {
	paths := append([]string(nil), configured...)
	if len(paths) == 0 {
		var err error
		paths, err = discoverTerraformFiles(ctx, root, effectiveCacheDir(cacheDir))
		if err != nil {
			return nil, err
		}
	}
	return normalizeDiscoveryPaths(root, paths)
}

func effectiveCacheDir(configured string) string {
	if strings.TrimSpace(configured) != "" {
		return configured
	}
	root, _ := resolver.DefaultModuleCacheRoot()
	return root
}

func redactedBudgetEvents(events []modulegraph.BudgetEvent) []modulegraph.BudgetEvent {
	output := append([]modulegraph.BudgetEvent(nil), events...)
	for i := range output {
		output[i].Source = model.RedactURLCredentials(output[i].Source)
	}
	return output
}

func validateConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("configuration is required")
	}
	if config.MaxDepth != nil && *config.MaxDepth < 0 {
		return fmt.Errorf("maximum depth must not be negative")
	}
	if config.FetchTimeout < 0 {
		return fmt.Errorf("fetch timeout must not be negative")
	}
	if config.ResolutionTimeout < 0 {
		return fmt.Errorf("resolution timeout must not be negative")
	}
	return nil
}

func validatePaths(repositoryRoot, artifactDir string) (root, artifact string, err error) {
	if strings.TrimSpace(repositoryRoot) == "" {
		return "", "", fmt.Errorf("repository root is required")
	}
	if strings.TrimSpace(artifactDir) == "" {
		return "", "", fmt.Errorf("artifact directory is required")
	}
	root, err = filepath.Abs(repositoryRoot)
	if err != nil {
		return "", "", fmt.Errorf("resolving repository root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", fmt.Errorf("resolving repository root: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return "", "", fmt.Errorf("checking repository root: %w", err)
	}
	if !info.IsDir() {
		return "", "", fmt.Errorf("repository root must be a directory")
	}
	artifact, err = filepath.Abs(artifactDir)
	if err != nil {
		return "", "", fmt.Errorf("resolving artifact directory: %w", err)
	}
	if root == filepath.Clean(artifact) {
		return "", "", fmt.Errorf("artifact directory must differ from repository root")
	}
	if _, err := os.Stat(artifact); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return "", "", fmt.Errorf("artifact directory %q already exists", artifact)
		}
		return "", "", fmt.Errorf("checking artifact directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(artifact), artifactDirectoryPermissions); err != nil {
		return "", "", fmt.Errorf("creating artifact parent directory: %w", err)
	}
	return root, filepath.Clean(artifact), nil
}

func discoverTerraformFiles(ctx context.Context, root, excludedDir string) ([]string, error) {
	if strings.TrimSpace(excludedDir) != "" {
		excludedDir, _ = filepath.Abs(excludedDir)
		if resolved, err := filepath.EvalSymlinks(excludedDir); err == nil {
			excludedDir = resolved
		}
	}
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			if excludedDir != "" && filepath.Clean(path) == filepath.Clean(excludedDir) {
				return fs.SkipDir
			}
			if entry.Type()&fs.ModeSymlink != 0 {
				return fs.SkipDir
			}
			name := strings.ToLower(entry.Name())
			if path != root && (name == ".git" || strings.HasPrefix(name, ".terra")) {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type().IsRegular() && tfmodules.IsTerraformConfigPath(path) {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discovering Terraform files: %w", err)
	}
	sort.Strings(paths)
	return paths, nil
}

func normalizeDiscoveryPaths(root string, paths []string) ([]string, error) {
	normalized := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		absolute := path
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(root, absolute)
		}
		absolute, err := filepath.Abs(absolute)
		if err != nil {
			return nil, fmt.Errorf("resolving discovery path %q: %w", path, err)
		}
		resolved, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			return nil, fmt.Errorf("resolving discovery path %q: %w", path, err)
		}
		relative, err := filepath.Rel(root, resolved)
		if err != nil || pathEscapes(relative) {
			return nil, fmt.Errorf("discovery path %q is outside repository root", path)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return nil, fmt.Errorf("checking discovery path %q: %w", path, err)
		}
		if !info.Mode().IsRegular() || !tfmodules.IsTerraformConfigPath(resolved) {
			return nil, fmt.Errorf("discovery path %q is not a Terraform configuration file", path)
		}
		if _, ok := seen[resolved]; ok {
			continue
		}
		seen[resolved] = struct{}{}
		normalized = append(normalized, resolved)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func resolutionContext(ctx context.Context, configured time.Duration) (context.Context, context.CancelFunc) {
	timeout := defaultDuration(configured, DefaultResolutionTimeout)
	return context.WithTimeout(ctx, timeout)
}

func defaultDuration(value, fallback time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}
	return value
}

func configuredMaxDepth(depth *int) int {
	if depth == nil {
		return DefaultMaxDepth
	}
	return *depth
}

func defaultResourceLimits(limits resolver.ResourceLimits) resolver.ResourceLimits {
	if limits.MaxTotalBytes == 0 {
		limits.MaxTotalBytes = resolver.DefaultMaxTotalBytes
	}
	if limits.MaxPackageBytes == 0 {
		limits.MaxPackageBytes = resolver.DefaultMaxPackageBytes
	}
	if limits.MaxFileBytes == 0 {
		limits.MaxFileBytes = resolver.DefaultMaxFileBytes
	}
	if limits.MaxPackageFiles == 0 {
		limits.MaxPackageFiles = resolver.DefaultMaxPackageFiles
	}
	return limits
}

func pathEscapes(relative string) bool {
	return relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}
