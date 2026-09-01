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
	manifestDirectoryPermissions = 0o750
	manifestFilePermissions      = 0o640
)

type manifestV1 struct {
	SchemaVersion int              `json:"schema_version"`
	Root          string           `json:"root"`
	Modules       []ManifestModule `json:"modules"`
}

// WriteManifest writes and validates a versioned prefetched-module manifest atomically.
func WriteManifest(ctx context.Context, path, root string, modules []ManifestModule) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path = filepath.Clean(path)
	if root == "" || !filepath.IsLocal(root) {
		return fmt.Errorf("manifest root must be a non-empty relative path")
	}

	ordered := append(make([]ManifestModule, 0, len(modules)), modules...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Source != ordered[j].Source {
			return ordered[i].Source < ordered[j].Source
		}
		if ordered[i].RequestedVersion != ordered[j].RequestedVersion {
			return ordered[i].RequestedVersion < ordered[j].RequestedVersion
		}
		return ordered[i].ID < ordered[j].ID
	})
	data, err := json.MarshalIndent(manifestV1{
		SchemaVersion: ManifestSchemaVersion,
		Root:          filepath.ToSlash(root),
		Modules:       ordered,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling manifest: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, manifestDirectoryPermissions); err != nil {
		return fmt.Errorf("creating manifest directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".modules-*.json")
	if err != nil {
		return fmt.Errorf("creating temporary manifest: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		_ = os.Remove(tempPath)
	}()
	if err := temp.Chmod(manifestFilePermissions); err != nil {
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
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("publishing manifest: %w", err)
	}
	return nil
}
