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
	"strings"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	goversion "github.com/hashicorp/go-version"
)

// ManifestEntry is one row in a --modules-manifest JSON file.
type ManifestEntry struct {
	LocalPath        string `json:"local_path,omitempty"`
	Source           string `json:"source,omitempty"`
	Name             string `json:"name,omitempty"`
	CallerPath       string `json:"caller_path,omitempty"`
	CallID           string `json:"call_id,omitempty"`
	Version          string `json:"version,omitempty"`
	Origin           string `json:"origin,omitempty"`
	RequestedVersion string `json:"requested_version,omitempty"`
	ResolvedVersion  string `json:"resolved_version,omitempty"`
	CanonicalSource  string `json:"canonical_source,omitempty"`
	ContentDigest    string `json:"content_digest,omitempty"`
	Provenance       string `json:"provenance,omitempty"`
	Outcome          string `json:"outcome,omitempty"`
}

// Manifest is validated JSON: optional root Dir plus source or source@version → ManifestEntry.
type Manifest struct {
	Version       int                      `json:"version,omitempty"`
	SchemaVersion int                      `json:"schema_version,omitempty"`
	Dir           string                   `json:"dir"`
	Modules       map[string]ManifestEntry `json:"modules"`
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
	if err := validateManifestVersions(m.Version, m.SchemaVersion); err != nil {
		return err
	}
	resolvedDir, err := validateManifestDir(m.Dir)
	if err != nil {
		return err
	}
	for src := range m.Modules {
		entry := m.Modules[src]
		if err := validateManifestEntry(src, &entry, m.Dir, resolvedDir); err != nil {
			return err
		}
	}
	return nil
}

func validateManifestVersions(version, schemaVersion int) error {
	if version < 0 || version > 2 {
		return fmt.Errorf("unsupported manifest version %d", version)
	}
	if schemaVersion < 0 || schemaVersion > 2 {
		return fmt.Errorf("unsupported schema_version %d", schemaVersion)
	}
	if version != 0 && schemaVersion != 0 && version != schemaVersion {
		return fmt.Errorf("manifest version %d does not match schema_version %d", version, schemaVersion)
	}
	return nil
}

func validateManifestDir(dir string) (string, error) {
	if dir == "" {
		return "", nil
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("manifest dir must be absolute, got %q", dir)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("cannot resolve manifest dir %q: %w", dir, err)
	}
	return resolved, nil
}

func validateManifestEntry(src string, entry *ManifestEntry, dir, resolvedDir string) error {
	if entry.Version != "" && entry.ResolvedVersion != "" && entry.Version != entry.ResolvedVersion {
		return fmt.Errorf(
			"entry %q: version %q does not match resolved_version %q",
			src, entry.Version, entry.ResolvedVersion,
		)
	}
	if !manifestEntryResolved(entry.Outcome) {
		return nil
	}
	if entry.LocalPath == "" {
		return fmt.Errorf("entry %q: resolved module requires local_path", src)
	}
	if !filepath.IsAbs(entry.LocalPath) {
		return fmt.Errorf("entry %q: local_path must be absolute, got %q", src, entry.LocalPath)
	}
	if dir != "" && !pathConfinedTo(dir, entry.LocalPath) {
		return fmt.Errorf("entry %q: local_path %q is not confined to dir %q", src, entry.LocalPath, dir)
	}
	resolved, err := filepath.EvalSymlinks(entry.LocalPath)
	if err != nil {
		return fmt.Errorf("entry %q: cannot resolve symlinks for %q: %w", src, entry.LocalPath, err)
	}
	if resolvedDir != "" && !pathConfinedTo(resolvedDir, resolved) {
		return fmt.Errorf("entry %q: resolved path %q escapes dir %q", src, resolved, dir)
	}
	return nil
}

func pathConfinedTo(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && !pathEscapesDir(rel)
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
	entry, ok := r.findEntry(mod)
	if !ok {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("module %q not found in manifest", mod.Source),
		}
	}
	if !manifestEntryResolved(entry.Outcome) {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("module %q manifest outcome is %q", mod.Source, entry.Outcome),
		}
	}
	if entry.RequestedVersion != "" &&
		strings.TrimSpace(entry.RequestedVersion) != strings.TrimSpace(mod.Version) {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf(
				"module %q requested version %q does not match manifest request %q",
				mod.Source, mod.Version, entry.RequestedVersion,
			),
		}
	}
	resolvedVersion := entry.Version
	if resolvedVersion == "" {
		resolvedVersion = entry.ResolvedVersion
	}
	if resolvedVersion != "" && mod.Version != "" && !versionMatchesConstraint(resolvedVersion, mod.Version) {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf(
				"module %q resolved version %q does not satisfy requested constraint %q",
				mod.Source, resolvedVersion, mod.Version,
			),
		}
	}
	return Resolution{
		LocalPath:        entry.LocalPath,
		RequestedVersion: mod.Version,
		ResolvedVersion:  resolvedVersion,
		CanonicalSource:  entry.CanonicalSource,
		ContentDigest:    entry.ContentDigest,
		Provenance:       firstNonEmpty(entry.Provenance, entry.Origin),
		Outcome:          firstNonEmpty(entry.Outcome, "resolved"),
	}, nil
}

func (r *PrefetchedResolver) findEntry(mod *tfmodules.ParsedModule) (ManifestEntry, bool) {
	keys := make([]string, 0, len(r.manifest.Modules))
	for key := range r.manifest.Modules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if entry, found, scoped := r.findScopedEntry(mod, keys); found || scoped {
		return entry, found
	}
	return r.findLegacyEntry(mod, keys)
}

func (r *PrefetchedResolver) findScopedEntry(
	mod *tfmodules.ParsedModule,
	keys []string,
) (ManifestEntry, bool, bool) {
	hasScopedEntries := false
	for _, key := range keys {
		entry := r.manifest.Modules[key]
		if entry.CallID == "" || entry.CallerPath == "" {
			continue
		}
		if entry.Source != "" && entry.Source != mod.Source {
			continue
		}
		if entry.RequestedVersion != "" &&
			strings.TrimSpace(entry.RequestedVersion) != strings.TrimSpace(mod.Version) {
			continue
		}
		hasScopedEntries = true
		if !callerPathMatches(mod.FileName, entry.CallerPath) {
			continue
		}
		if entry.CallID == tfmodules.ModuleCallID(entry.CallerPath, mod) {
			return entry, true, true
		}
	}
	return ManifestEntry{}, false, hasScopedEntries
}

func (r *PrefetchedResolver) findLegacyEntry(
	mod *tfmodules.ParsedModule,
	keys []string,
) (ManifestEntry, bool) {
	for _, key := range []string{manifestModuleKey(mod.Source, mod.Version), mod.Source} {
		if entry, ok := r.manifest.Modules[key]; ok {
			return entry, true
		}
	}
	for _, key := range keys {
		entry := r.manifest.Modules[key]
		if entry.CallID != "" {
			continue
		}
		if entry.CanonicalSource == mod.Source &&
			(entry.RequestedVersion == "" ||
				strings.TrimSpace(entry.RequestedVersion) == strings.TrimSpace(mod.Version)) {
			return entry, true
		}
	}
	return ManifestEntry{}, false
}

func callerPathMatches(fileName, callerPath string) bool {
	fileName = filepath.ToSlash(filepath.Clean(fileName))
	callerPath = filepath.ToSlash(filepath.Clean(callerPath))
	if filepath.IsAbs(callerPath) {
		return fileName == callerPath
	}
	return fileName == callerPath || strings.HasSuffix(fileName, "/"+callerPath)
}

func manifestEntryResolved(outcome string) bool {
	switch strings.ToLower(strings.TrimSpace(outcome)) {
	case "", "resolved", "success":
		return true
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
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
