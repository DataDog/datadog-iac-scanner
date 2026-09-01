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

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
)

const (
	ManifestSchemaVersion    = 1
	ManifestStatusResolved   = "resolved"
	ManifestStatusUnresolved = "unresolved"
)

type ManifestEntry struct {
	LocalPath        string `json:"local_path"`
	PackageRoot      string `json:"package_root,omitempty"`
	Version          string `json:"version,omitempty"`
	Origin           string `json:"origin,omitempty"`
	RequestedVersion string `json:"requested_version,omitempty"`
	ResolvedVersion  string `json:"resolved_version,omitempty"`
	ResolvedRef      string `json:"resolved_ref,omitempty"`
	Status           string `json:"status,omitempty"`
	Failure          string `json:"failure,omitempty"`
}

type Manifest struct {
	SchemaVersion   int                      `json:"schema_version,omitempty"`
	Root            string                   `json:"root,omitempty"`
	Dir             string                   `json:"dir,omitempty"`
	Modules         map[string]ManifestEntry `json:"modules,omitempty"`
	Entries         []ManifestModule         `json:"-"`
	candidates      map[string][]manifestCandidate
	verifiedDigests map[string]string
}

type manifestCandidate struct {
	entry        ManifestEntry
	declarations []ManifestDeclaration
}

type ManifestModule struct {
	ID               string                `json:"id,omitempty"`
	Source           string                `json:"source"`
	CanonicalSource  string                `json:"canonical_source,omitempty"`
	SourceType       string                `json:"source_type,omitempty"`
	RegistryScope    string                `json:"registry_scope,omitempty"`
	RequestedVersion string                `json:"requested_version,omitempty"`
	ResolvedVersion  string                `json:"resolved_version,omitempty"`
	ResolvedRef      string                `json:"resolved_ref,omitempty"`
	ContentDigest    string                `json:"content_digest,omitempty"`
	PackageRoot      string                `json:"package_root,omitempty"`
	LocalPath        string                `json:"local_path,omitempty"`
	Status           string                `json:"status"`
	Failure          string                `json:"failure,omitempty"`
	Declarations     []ManifestDeclaration `json:"declarations"`
}

type ManifestDeclaration struct {
	Filename   string `json:"filename"`
	LineStart  int    `json:"line_start"`
	LineEnd    int    `json:"line_end"`
	ModuleName string `json:"module_name"`
}

type manifestEnvelope struct {
	SchemaVersion *int            `json:"schema_version"`
	Root          string          `json:"root"`
	Dir           string          `json:"dir"`
	Modules       json.RawMessage `json:"modules"`
}

func LoadManifest(ctx context.Context, path string) (*Manifest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	manifestPath := filepath.Clean(path)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("reading manifest %q: %w", path, err)
	}
	var envelope manifestEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("parsing manifest %q: %w", path, err)
	}
	var m *Manifest
	if envelope.SchemaVersion == nil {
		m, err = loadLegacyManifest(envelope)
	} else if *envelope.SchemaVersion == ManifestSchemaVersion {
		m, err = loadManifestV1(ctx, manifestPath, envelope)
	} else {
		err = fmt.Errorf("unsupported schema_version %d", *envelope.SchemaVersion)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid manifest %q: %w", path, err)
	}
	if err := m.validate(ctx); err != nil {
		return nil, fmt.Errorf("invalid manifest %q: %w", path, err)
	}
	return m, nil
}

func loadLegacyManifest(envelope manifestEnvelope) (*Manifest, error) {
	var modules map[string]ManifestEntry
	if err := json.Unmarshal(envelope.Modules, &modules); err != nil {
		return nil, fmt.Errorf("parsing legacy modules: %w", err)
	}
	for key := range modules {
		entry := modules[key]
		entry.RequestedVersion = entry.Version
		entry.ResolvedVersion = entry.Version
		entry.Status = ManifestStatusResolved
		modules[key] = entry
	}
	return &Manifest{Dir: envelope.Dir, Modules: modules}, nil
}

func loadManifestV1(ctx context.Context, manifestPath string, envelope manifestEnvelope) (*Manifest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if envelope.Root == "" || !filepath.IsLocal(envelope.Root) {
		return nil, fmt.Errorf("root must be a non-empty relative path")
	}
	root := filepath.Join(filepath.Dir(manifestPath), filepath.FromSlash(envelope.Root))
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolving root: %w", err)
	}
	if _, err = resolveDirectory(ctx, root); err != nil {
		return nil, fmt.Errorf("resolving root: %w", err)
	}
	var entries []ManifestModule
	if err := json.Unmarshal(envelope.Modules, &entries); err != nil {
		return nil, fmt.Errorf("parsing modules: %w", err)
	}
	if entries == nil {
		return nil, fmt.Errorf("modules must be an array")
	}
	manifest := &Manifest{
		SchemaVersion:   ManifestSchemaVersion,
		Root:            root,
		Dir:             root,
		Modules:         make(map[string]ManifestEntry, len(entries)),
		Entries:         entries,
		candidates:      make(map[string][]manifestCandidate, len(entries)),
		verifiedDigests: make(map[string]string),
	}
	for i := range manifest.Entries {
		if err := manifest.addV1Entry(ctx, &manifest.Entries[i]); err != nil {
			return nil, fmt.Errorf("modules[%d]: %w", i, err)
		}
	}
	return manifest, nil
}

func (m *Manifest) addV1Entry(ctx context.Context, module *ManifestModule) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	module.Source = strings.TrimSpace(module.Source)
	if module.Source == "" {
		return fmt.Errorf("source is required")
	}
	if err := validateManifestDeclarations(module.Declarations); err != nil {
		return err
	}
	key := manifestModuleKey(module.Source, strings.TrimSpace(module.RequestedVersion))
	entry := ManifestEntry{
		RequestedVersion: strings.TrimSpace(module.RequestedVersion),
		ResolvedVersion:  strings.TrimSpace(module.ResolvedVersion),
		ResolvedRef:      strings.TrimSpace(module.ResolvedRef),
		Status:           module.Status,
		Failure:          module.Failure,
		Origin:           module.SourceType,
	}
	switch module.Status {
	case ManifestStatusResolved:
		if err := m.resolveV1Paths(ctx, module, &entry); err != nil {
			return err
		}
		if module.ContentDigest == "" {
			return fmt.Errorf("content_digest is required for a resolved module")
		}
		digest, verified := m.verifiedDigests[entry.PackageRoot]
		if !verified {
			var err error
			digest, err = ComputePackageDigest(ctx, entry.PackageRoot)
			if err != nil {
				return fmt.Errorf("computing content digest: %w", err)
			}
			m.verifiedDigests[entry.PackageRoot] = digest
		}
		if !strings.EqualFold(module.ContentDigest, digest) {
			return fmt.Errorf("content_digest mismatch: got %q, computed %q", module.ContentDigest, digest)
		}
	case ManifestStatusUnresolved:
		if strings.TrimSpace(module.Failure) == "" {
			return fmt.Errorf("failure is required for an unresolved module")
		}
	default:
		return fmt.Errorf("status must be resolved or unresolved")
	}
	for i := range m.candidates[key] {
		if declarationsOverlap(m.candidates[key][i].declarations, module.Declarations) {
			return fmt.Errorf("duplicate module declaration for %q", key)
		}
	}
	m.candidates[key] = append(m.candidates[key], manifestCandidate{
		entry:        entry,
		declarations: append([]ManifestDeclaration(nil), module.Declarations...),
	})
	if _, exists := m.Modules[key]; !exists {
		m.Modules[key] = entry
	}
	return nil
}

func declarationsOverlap(left, right []ManifestDeclaration) bool {
	for _, first := range left {
		for _, second := range right {
			if first.Filename == second.Filename &&
				first.ModuleName == second.ModuleName &&
				first.LineStart == second.LineStart {
				return true
			}
		}
	}
	return false
}

func (m *Manifest) resolveV1Paths(ctx context.Context, module *ManifestModule, entry *ManifestEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if module.LocalPath == "" || !filepath.IsLocal(module.LocalPath) {
		return fmt.Errorf("local_path must be a non-empty relative path")
	}
	packageRoot := module.PackageRoot
	if packageRoot == "" {
		packageRoot = module.LocalPath
	}
	if !filepath.IsLocal(packageRoot) {
		return fmt.Errorf("package_root must be a relative path")
	}
	entry.LocalPath = filepath.Join(m.Root, filepath.FromSlash(module.LocalPath))
	entry.PackageRoot = filepath.Join(m.Root, filepath.FromSlash(packageRoot))
	if _, err := ResolvePathWithinRoot(ctx, m.Root, entry.PackageRoot); err != nil {
		return fmt.Errorf("package_root %q escapes root: %w", module.PackageRoot, err)
	}
	if _, err := ResolvePathWithinRoot(ctx, entry.PackageRoot, entry.LocalPath); err != nil {
		return fmt.Errorf("local_path %q escapes package root: %w", module.LocalPath, err)
	}
	return nil
}

func validateManifestDeclarations(declarations []ManifestDeclaration) error {
	if len(declarations) == 0 {
		return fmt.Errorf("declarations must not be empty")
	}
	for i, declaration := range declarations {
		if declaration.Filename == "" || !filepath.IsLocal(declaration.Filename) {
			return fmt.Errorf("declarations[%d].filename must be a non-empty relative path", i)
		}
		if declaration.ModuleName == "" {
			return fmt.Errorf("declarations[%d].module_name is required", i)
		}
		if declaration.LineStart <= 0 || declaration.LineEnd < declaration.LineStart {
			return fmt.Errorf("declarations[%d] has an invalid line range", i)
		}
	}
	return nil
}

func (m *Manifest) validate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for src := range m.Modules {
		entry := m.Modules[src]
		if entry.Status == ManifestStatusUnresolved {
			continue
		}
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
		confined, err := ConfineResolution(ctx, Resolution{
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
				if _, err := ResolvePathWithinRoot(ctx, m.Dir, path); err != nil {
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

func (r *PrefetchedResolver) Resolve(ctx context.Context, mod *tfmodules.ParsedModule) (Resolution, error) {
	if mod.IsLocal {
		return Resolution{}, &tfmodules.UnresolvedError{Reason: "local modules are handled by LocalResolver"}
	}
	key := manifestModuleKey(mod.Source, mod.Version)
	if candidates := r.manifest.candidates[key]; len(candidates) > 0 {
		entry, err := selectManifestCandidate(mod, candidates)
		if err != nil {
			return Resolution{}, err
		}
		return resolveManifestEntry(ctx, mod, entry)
	}
	entry, ok := r.manifest.Modules[key]
	if !ok {
		entry, ok = r.manifest.Modules[legacyManifestModuleKey(mod.Source, mod.Version)]
	}
	if !ok {
		entry, ok = r.manifest.Modules[mod.Source]
	}
	if !ok {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("module %q not found in manifest", mod.Source),
		}
	}
	return resolveManifestEntry(ctx, mod, &entry)
}

func selectManifestCandidate(
	mod *tfmodules.ParsedModule, candidates []manifestCandidate,
) (*ManifestEntry, error) {
	if len(candidates) == 1 {
		return &candidates[0].entry, nil
	}
	matches := make([]*ManifestEntry, 0, len(candidates))
	bestSpecificity := -1
	for i := range candidates {
		candidateSpecificity := -1
		for _, declaration := range candidates[i].declarations {
			if declarationMatchesModule(declaration, mod) {
				candidateSpecificity = max(candidateSpecificity, len(filepath.Clean(declaration.Filename)))
			}
		}
		switch {
		case candidateSpecificity > bestSpecificity:
			bestSpecificity = candidateSpecificity
			matches = []*ManifestEntry{&candidates[i].entry}
		case candidateSpecificity >= 0 && candidateSpecificity == bestSpecificity:
			matches = append(matches, &candidates[i].entry)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	reason := fmt.Sprintf("module %q declaration not found in manifest", mod.Source)
	if len(matches) > 1 {
		reason = fmt.Sprintf("module %q declaration is ambiguous in manifest", mod.Source)
	}
	return nil, &tfmodules.UnresolvedError{Reason: reason}
}

func declarationMatchesModule(declaration ManifestDeclaration, mod *tfmodules.ParsedModule) bool {
	if declaration.ModuleName != mod.Name {
		return false
	}
	if mod.DefLine > 0 && declaration.LineStart != mod.DefLine {
		return false
	}
	filename := filepath.ToSlash(filepath.Clean(mod.FileName))
	declared := filepath.ToSlash(filepath.Clean(declaration.Filename))
	return filename == declared || strings.HasSuffix(filename, "/"+declared)
}

func resolveManifestEntry(
	ctx context.Context, mod *tfmodules.ParsedModule, entry *ManifestEntry,
) (Resolution, error) {
	if entry.Status == ManifestStatusUnresolved {
		return Resolution{}, &tfmodules.UnresolvedError{Reason: entry.Failure}
	}
	if entry.RequestedVersion != "" && mod.Version != "" && entry.RequestedVersion != mod.Version {
		return Resolution{}, &tfmodules.UnresolvedError{
			Reason: fmt.Sprintf("module %q version %q not found in manifest", mod.Source, mod.Version),
		}
	}
	return ConfineResolution(ctx, Resolution{
		LocalPath:       entry.LocalPath,
		PackageRoot:     entry.PackageRoot,
		ResolvedVersion: firstNonEmpty(entry.ResolvedVersion, entry.Version),
		ResolvedRef:     entry.ResolvedRef,
	})
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func manifestModuleKey(source, version string) string {
	source = model.RedactURLCredentials(source)
	return legacyManifestModuleKey(source, version)
}

func legacyManifestModuleKey(source, version string) string {
	if version == "" {
		return source
	}
	return source + "@" + version
}
