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

type ManifestDiscoveryCall struct {
	CallID           string `json:"call_id"`
	ParentCallID     string `json:"parent_call_id,omitempty"`
	CallerPath       string `json:"caller_path"`
	Name             string `json:"name"`
	Source           string `json:"source"`
	RequestedVersion string `json:"requested_version,omitempty"`
}

type ManifestModuleMapping struct {
	CallID          string `json:"call_id"`
	LocalPath       string `json:"local_path,omitempty"`
	Version         string `json:"version,omitempty"`
	ResolvedVersion string `json:"resolved_version,omitempty"`
	CanonicalSource string `json:"canonical_source,omitempty"`
	ContentDigest   string `json:"content_digest,omitempty"`
	Provenance      string `json:"provenance,omitempty"`
	Outcome         string `json:"outcome,omitempty"`
}

type ManifestDiscovery struct {
	Complete       bool                    `json:"complete,omitempty"`
	Calls          []ManifestDiscoveryCall `json:"calls,omitempty"`
	ScanPaths      []string                `json:"scan_paths,omitempty"`
	SourceMappings map[string]string       `json:"source_mappings,omitempty"`
	ModuleMappings []ManifestModuleMapping `json:"module_mappings,omitempty"`
}

// Manifest is validated JSON: optional root Dir plus source or source@version → ManifestEntry.
type Manifest struct {
	Version       int                      `json:"version,omitempty"`
	SchemaVersion int                      `json:"schema_version,omitempty"`
	Dir           string                   `json:"dir"`
	Modules       map[string]ManifestEntry `json:"modules"`
	Discovery     *ManifestDiscovery       `json:"discovery,omitempty"`
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
	if err := m.validateDiscovery(resolvedDir); err != nil {
		return err
	}
	return nil
}

func validateManifestVersions(version, schemaVersion int) error {
	if version < 0 || version > 3 {
		return fmt.Errorf("unsupported manifest version %d", version)
	}
	if schemaVersion < 0 || schemaVersion > 3 {
		return fmt.Errorf("unsupported schema_version %d", schemaVersion)
	}
	if version != 0 && schemaVersion != 0 && version != schemaVersion {
		return fmt.Errorf("manifest version %d does not match schema_version %d", version, schemaVersion)
	}
	return nil
}

func (m *Manifest) HasCompleteDiscovery() bool {
	return m != nil && m.Discovery != nil && m.Discovery.Complete
}

func (m *Manifest) validateDiscovery(resolvedDir string) error {
	if m.Discovery == nil || !m.Discovery.Complete {
		return nil
	}
	if m.SchemaVersion != 3 {
		return fmt.Errorf("complete discovery requires schema_version 3")
	}
	if m.Dir == "" {
		return fmt.Errorf("complete discovery requires dir")
	}

	calls, err := validateDiscoveryCalls(m.Discovery.Calls)
	if err != nil {
		return err
	}
	if err := validateDiscoveryPaths(m.Discovery, m.Dir, resolvedDir); err != nil {
		return err
	}
	if err := validateDiscoveryMappings(m.Discovery, calls, m.Dir, resolvedDir); err != nil {
		return err
	}
	sort.Slice(m.Discovery.Calls, func(i, j int) bool {
		return m.Discovery.Calls[i].CallID < m.Discovery.Calls[j].CallID
	})
	sort.Strings(m.Discovery.ScanPaths)
	sort.Slice(m.Discovery.ModuleMappings, func(i, j int) bool {
		return m.Discovery.ModuleMappings[i].CallID < m.Discovery.ModuleMappings[j].CallID
	})
	return nil
}

func validateDiscoveryCalls(entries []ManifestDiscoveryCall) (map[string]ManifestDiscoveryCall, error) {
	calls := make(map[string]ManifestDiscoveryCall, len(entries))
	for i := range entries {
		call := entries[i]
		if call.CallID == "" {
			return nil, fmt.Errorf("discovery call %d: call_id is required", i)
		}
		if _, exists := calls[call.CallID]; exists {
			return nil, fmt.Errorf("discovery call %q is duplicated", call.CallID)
		}
		if call.CallerPath == "" || call.Name == "" || call.Source == "" {
			return nil, fmt.Errorf("discovery call %q requires caller_path, name, and source", call.CallID)
		}
		calls[call.CallID] = call
	}
	for _, call := range calls {
		if call.ParentCallID != "" {
			if _, exists := calls[call.ParentCallID]; !exists {
				return nil, fmt.Errorf(
					"discovery call %q references missing parent %q",
					call.CallID, call.ParentCallID,
				)
			}
		}
	}
	if err := validateDiscoveryCycles(calls); err != nil {
		return nil, err
	}
	return calls, nil
}

func validateDiscoveryPaths(discovery *ManifestDiscovery, dir, resolvedDir string) error {
	seenScanPaths := make(map[string]bool, len(discovery.ScanPaths))
	for _, scanPath := range discovery.ScanPaths {
		if seenScanPaths[scanPath] {
			return fmt.Errorf("discovery scan_path %q is duplicated", scanPath)
		}
		seenScanPaths[scanPath] = true
		if err := validateDiscoveryFile(scanPath, dir, resolvedDir); err != nil {
			return fmt.Errorf("discovery scan_path %q: %w", scanPath, err)
		}
	}
	for localPath, source := range discovery.SourceMappings {
		if source == "" {
			return fmt.Errorf("discovery source_mapping %q has an empty source", localPath)
		}
		if err := validateDiscoveryPath(localPath, dir, resolvedDir); err != nil {
			return fmt.Errorf("discovery source_mapping %q: %w", localPath, err)
		}
	}
	for _, scanPath := range discovery.ScanPaths {
		if !pathCoveredBySourceMapping(scanPath, discovery.SourceMappings) {
			return fmt.Errorf("discovery scan_path %q has no source_mapping", scanPath)
		}
	}
	return nil
}

func validateDiscoveryMappings(
	discovery *ManifestDiscovery,
	calls map[string]ManifestDiscoveryCall,
	dir, resolvedDir string,
) error {
	mappedCalls := make(map[string]bool, len(discovery.ModuleMappings))
	for i := range discovery.ModuleMappings {
		mapping := discovery.ModuleMappings[i]
		call, exists := calls[mapping.CallID]
		if !exists {
			return fmt.Errorf("discovery module_mapping references missing call %q", mapping.CallID)
		}
		if mappedCalls[mapping.CallID] {
			return fmt.Errorf("discovery module_mapping for call %q is duplicated", mapping.CallID)
		}
		mappedCalls[mapping.CallID] = true
		entry := ManifestEntry{
			LocalPath:        mapping.LocalPath,
			Version:          mapping.Version,
			ResolvedVersion:  mapping.ResolvedVersion,
			RequestedVersion: call.RequestedVersion,
			Outcome:          mapping.Outcome,
		}
		if err := validateManifestEntry(mapping.CallID, &entry, dir, resolvedDir); err != nil {
			return fmt.Errorf("discovery module_mapping: %w", err)
		}
		if manifestEntryResolved(mapping.Outcome) {
			if _, exists := discovery.SourceMappings[mapping.LocalPath]; !exists {
				return fmt.Errorf(
					"discovery module_mapping for call %q has no source_mapping for %q",
					mapping.CallID, mapping.LocalPath,
				)
			}
		}
	}
	return nil
}

func validateDiscoveryCycles(calls map[string]ManifestDiscoveryCall) error {
	const (
		visiting = 1
		visited  = 2
	)
	state := make(map[string]int, len(calls))
	var visit func(string) error
	visit = func(callID string) error {
		switch state[callID] {
		case visiting:
			return fmt.Errorf("discovery calls contain a cycle at %q", callID)
		case visited:
			return nil
		}
		state[callID] = visiting
		if parent := calls[callID].ParentCallID; parent != "" {
			if err := visit(parent); err != nil {
				return err
			}
		}
		state[callID] = visited
		return nil
	}
	for callID := range calls {
		if err := visit(callID); err != nil {
			return err
		}
	}
	return nil
}

func validateDiscoveryFile(filePath, dir, resolvedDir string) error {
	if !strings.EqualFold(filepath.Ext(filePath), ".tf") {
		return fmt.Errorf("path must identify a Terraform file")
	}
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot stat path: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("path identifies a directory")
	}
	return validateDiscoveryPath(filePath, dir, resolvedDir)
}

func validateDiscoveryPath(candidate, dir, resolvedDir string) error {
	if !filepath.IsAbs(candidate) {
		return fmt.Errorf("path must be absolute")
	}
	if !pathConfinedTo(dir, candidate) {
		return fmt.Errorf("path is not confined to dir %q", dir)
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return fmt.Errorf("cannot resolve symlinks: %w", err)
	}
	if !pathConfinedTo(resolvedDir, resolved) {
		return fmt.Errorf("resolved path escapes dir %q", dir)
	}
	return nil
}

func pathCoveredBySourceMapping(scanPath string, mappings map[string]string) bool {
	for localPath := range mappings {
		if pathConfinedTo(localPath, scanPath) {
			return true
		}
	}
	return false
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
