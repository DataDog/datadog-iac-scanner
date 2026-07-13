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
	"strings"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	goversion "github.com/hashicorp/go-version"
)

// ManifestEntry is one row in a --modules-manifest JSON file.
type ManifestEntry struct {
	LocalPath string `json:"local_path"`
	Version   string `json:"version,omitempty"`
	Origin    string `json:"origin,omitempty"`
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
		if m.Dir != "" {
			rel, err := filepath.Rel(m.Dir, entry.LocalPath)
			if err != nil || pathEscapesDir(rel) {
				return fmt.Errorf("entry %q: local_path %q is not confined to dir %q", src, entry.LocalPath, m.Dir)
			}
		}
		resolved, err := filepath.EvalSymlinks(entry.LocalPath)
		if err != nil {
			return fmt.Errorf("entry %q: cannot resolve symlinks for %q: %w", src, entry.LocalPath, err)
		}
		if m.Dir != "" {
			rel, err := filepath.Rel(m.Dir, resolved)
			if err != nil || pathEscapesDir(rel) {
				return fmt.Errorf("entry %q: resolved path %q escapes dir %q", src, resolved, m.Dir)
			}
		}
	}
	return nil
}

func pathEscapesDir(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator))
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
	if entry.Version != "" && mod.Version != "" && !versionMatchesConstraint(entry.Version, mod.Version) {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("module %q version %q not found in manifest", mod.Source, mod.Version),
		}
	}
	return Resolution{LocalPath: entry.LocalPath}, nil
}

func versionMatchesConstraint(version, constraint string) bool {
	constraints, err := goversion.NewConstraint(constraint)
	if err != nil {
		return version == constraint
	}
	resolved, err := goversion.NewVersion(version)
	return err == nil && constraints.Check(resolved)
}

func manifestModuleKey(source, version string) string {
	if version == "" {
		return source
	}
	return source + "@" + version
}
