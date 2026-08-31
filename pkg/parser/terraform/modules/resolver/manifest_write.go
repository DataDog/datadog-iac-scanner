/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const (
	manifestDirectoryMode = 0o750
	manifestFileMode      = 0o600
)

// WriteManifest writes and validates a versioned module manifest atomically.
func WriteManifest(ctx context.Context, path, root string, entries []ManifestModule) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manifestPath, manifestDir, relativeRoot, err := resolveManifestWritePaths(path, root)
	if err != nil {
		return err
	}
	data, err := encodeManifest(relativeRoot, entries)
	if err != nil {
		return err
	}
	return writeValidatedManifest(ctx, manifestPath, manifestDir, data)
}

func resolveManifestWritePaths(
	path, root string,
) (manifestPath, manifestDir, relativeRoot string, err error) {
	manifestPath, err = filepath.Abs(path)
	if err != nil {
		return "", "", "", fmt.Errorf("resolving manifest path: %w", err)
	}
	manifestDir = filepath.Dir(manifestPath)
	if err := os.MkdirAll(manifestDir, manifestDirectoryMode); err != nil {
		return "", "", "", fmt.Errorf("creating manifest directory: %w", err)
	}
	resolvedManifestDir, err := filepath.EvalSymlinks(manifestDir)
	if err != nil {
		return "", "", "", fmt.Errorf("resolving manifest directory: %w", err)
	}
	moduleRoot, err := filepath.Abs(root)
	if err != nil {
		return "", "", "", fmt.Errorf("resolving module root: %w", err)
	}
	moduleRoot, err = filepath.EvalSymlinks(moduleRoot)
	if err != nil {
		return "", "", "", fmt.Errorf("resolving module root: %w", err)
	}
	relativeRoot, err = filepath.Rel(resolvedManifestDir, moduleRoot)
	if err != nil || !filepath.IsLocal(relativeRoot) {
		return "", "", "", fmt.Errorf(
			"module root %q must be relative to manifest directory %q",
			moduleRoot,
			resolvedManifestDir,
		)
	}
	return manifestPath, manifestDir, relativeRoot, nil
}

func encodeManifest(relativeRoot string, entries []ManifestModule) ([]byte, error) {
	sortedEntries := append([]ManifestModule(nil), entries...)
	for i := range sortedEntries {
		sortedEntries[i].Declarations = append([]ManifestDeclaration(nil), sortedEntries[i].Declarations...)
		sort.Slice(sortedEntries[i].Declarations, func(left, right int) bool {
			a, b := sortedEntries[i].Declarations[left], sortedEntries[i].Declarations[right]
			if a.CallerModule != b.CallerModule {
				return a.CallerModule < b.CallerModule
			}
			if a.Filename != b.Filename {
				return a.Filename < b.Filename
			}
			if a.LineStart != b.LineStart {
				return a.LineStart < b.LineStart
			}
			return a.ModuleName < b.ModuleName
		})
	}
	sort.Slice(sortedEntries, func(left, right int) bool {
		a, b := sortedEntries[left], sortedEntries[right]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.RequestedVersion != b.RequestedVersion {
			return a.RequestedVersion < b.RequestedVersion
		}
		return a.RequestID < b.RequestID
	})

	data, err := json.MarshalIndent(struct {
		SchemaVersion int              `json:"schema_version"`
		Root          string           `json:"root"`
		Modules       []ManifestModule `json:"modules"`
	}{
		SchemaVersion: ManifestSchemaVersion,
		Root:          filepath.ToSlash(relativeRoot),
		Modules:       sortedEntries,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding manifest: %w", err)
	}
	return append(data, '\n'), nil
}

func writeValidatedManifest(ctx context.Context, manifestPath, manifestDir string, data []byte) error {
	temp, err := os.CreateTemp(manifestDir, ".modules-*.json")
	if err != nil {
		return fmt.Errorf("creating temporary manifest: %w", err)
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if err := temp.Chmod(manifestFileMode); err != nil {
		_ = temp.Close()
		return fmt.Errorf("setting manifest permissions: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("writing temporary manifest: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("closing temporary manifest: %w", err)
	}
	if _, err := LoadManifest(ctx, tempPath); err != nil {
		return fmt.Errorf("validating generated manifest: %w", err)
	}
	if err := os.Rename(tempPath, manifestPath); err != nil {
		return fmt.Errorf("replacing manifest: %w", err)
	}
	return nil
}
