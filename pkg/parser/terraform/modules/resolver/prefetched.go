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

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

// ManifestEntry is one row in a --modules-manifest JSON file.
type ManifestEntry struct {
	LocalPath   string `json:"local_path"`
	PackageRoot string `json:"package_root,omitempty"`
	Version     string `json:"version,omitempty"`
	Origin      string `json:"origin,omitempty"`
}

// Manifest is validated JSON: optional root Dir plus source or source@version → ManifestEntry.
type Manifest struct {
	Dir     string                   `json:"dir"`
	Modules map[string]ManifestEntry `json:"modules"`
}

// LoadManifest parses and validates manifest JSON from path.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading manifest %q: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest %q: %w", path, err)
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("invalid manifest %q: %w", path, err)
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	for src, entry := range m.Modules {
		if !filepath.IsAbs(entry.LocalPath) {
			return fmt.Errorf("entry %q: local_path must be absolute, got %q", src, entry.LocalPath)
		}
		if entry.PackageRoot == "" {
			entry.PackageRoot = entry.LocalPath
		}
		if !filepath.IsAbs(entry.PackageRoot) {
			return fmt.Errorf("entry %q: package_root must be absolute, got %q", src, entry.PackageRoot)
		}
		if m.Dir != "" {
			for field, path := range map[string]string{
				"local_path":   entry.LocalPath,
				"package_root": entry.PackageRoot,
			} {
				rel, err := filepath.Rel(m.Dir, path)
				if err != nil || pathEscapesDir(rel) {
					return fmt.Errorf("entry %q: %s %q is not confined to dir %q", src, field, path, m.Dir)
				}
			}
		}
		confined, err := ConfineResolution(Resolution{
			LocalPath:   entry.LocalPath,
			PackageRoot: entry.PackageRoot,
		})
		if err != nil {
			return fmt.Errorf("entry %q: %w", src, err)
		}
		if m.Dir != "" {
			for field, path := range map[string]string{
				"local_path":   confined.LocalPath,
				"package_root": confined.PackageRoot,
			} {
				if _, err := ResolvePathWithinRoot(m.Dir, path); err != nil {
					return fmt.Errorf("entry %q: resolved %s %q escapes dir %q: %w", src, field, path, m.Dir, err)
				}
			}
		}
	}
	return nil
}

// PrefetchedResolver resolves modules from a --modules-manifest.
type PrefetchedResolver struct {
	manifest *Manifest
}

func NewPrefetchedResolver(m *Manifest) *PrefetchedResolver {
	return &PrefetchedResolver{manifest: m}
}

func (r *PrefetchedResolver) Resolve(_ context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	if mod.IsLocal {
		return Resolution{}, &tfmodules.UnresolvedError{Reason: "local modules are handled by LocalResolver"}
	}
	entry, ok := r.manifest.Modules[manifestModuleKey(mod.Source, mod.Version)]
	if !ok {
		entry, ok = r.manifest.Modules[mod.Source]
	}
	if !ok {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("module %q not found in manifest", mod.Source),
		}
	}
	if entry.Version != "" && mod.Version != "" && entry.Version != mod.Version {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("module %q version %q not found in manifest", mod.Source, mod.Version),
		}
	}
	return ConfineResolution(Resolution{
		LocalPath:   entry.LocalPath,
		PackageRoot: entry.PackageRoot,
	})
}

func manifestModuleKey(source, version string) string {
	if version == "" {
		return source
	}
	return source + "@" + version
}
