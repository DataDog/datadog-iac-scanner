/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package moduleprepare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
)

const (
	StagedKindArchive   = "archive"
	StagedKindDirectory = "directory"

	maxStagedInputBytes = 16 * 1024 * 1024
)

type StagedModules struct {
	SchemaVersion int            `json:"schema_version"`
	Modules       []StagedModule `json:"modules"`
}

type StagedModule struct {
	RequestID        string                         `json:"request_id"`
	Source           string                         `json:"source"`
	RequestedVersion string                         `json:"requested_version,omitempty"`
	ResolvedVersion  string                         `json:"resolved_version,omitempty"`
	ResolvedRef      string                         `json:"resolved_ref,omitempty"`
	CanonicalSource  string                         `json:"canonical_source,omitempty"`
	Kind             string                         `json:"kind"`
	ArtifactPath     string                         `json:"artifact_path,omitempty"`
	ArchiveFormat    string                         `json:"archive_format,omitempty"`
	TransportDigest  string                         `json:"transport_digest,omitempty"`
	PackagePath      string                         `json:"package_path,omitempty"`
	Declarations     []resolver.ManifestDeclaration `json:"declarations"`
}

func WriteStagedManifest(
	ctx context.Context,
	inputPath string,
	outputPath string,
	moduleRoot string,
	limits resolver.ResourceLimits,
) error {
	input, err := readStagedModules(inputPath)
	if err != nil {
		return err
	}
	root, err := filepath.Abs(moduleRoot)
	if err != nil {
		return fmt.Errorf("resolving module root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolving module root: %w", err)
	}
	entries, err := materializeStagedModules(ctx, root, input.Modules, limits)
	if err != nil {
		return err
	}
	return resolver.WriteManifest(ctx, outputPath, root, entries)
}

func readStagedModules(path string) (StagedModules, error) {
	file, err := os.Open(path) //nolint:gosec
	if err != nil {
		return StagedModules{}, fmt.Errorf("reading staged modules: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxStagedInputBytes+1))
	if err != nil {
		return StagedModules{}, fmt.Errorf("reading staged modules: %w", err)
	}
	if len(data) > maxStagedInputBytes {
		return StagedModules{}, fmt.Errorf("staged modules exceeds %d bytes", maxStagedInputBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var input StagedModules
	if err := decoder.Decode(&input); err != nil {
		return StagedModules{}, fmt.Errorf("parsing staged modules: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return StagedModules{}, fmt.Errorf("parsing staged modules: trailing JSON content")
	}
	if input.SchemaVersion != ResponseSchemaVersion {
		return StagedModules{}, fmt.Errorf("unsupported staged modules schema_version %d", input.SchemaVersion)
	}
	if input.Modules == nil {
		return StagedModules{}, fmt.Errorf("staged modules must contain a modules array")
	}
	return input, nil
}

func materializeStagedModules(
	ctx context.Context,
	root string,
	modules []StagedModule,
	limits resolver.ResourceLimits,
) ([]resolver.ManifestModule, error) {
	entries := make([]resolver.ManifestModule, 0, len(modules))
	seen := make(map[string]bool, len(modules))
	for index := range modules {
		staged := &modules[index]
		staged.RequestID = strings.TrimSpace(staged.RequestID)
		staged.Source = strings.TrimSpace(staged.Source)
		if staged.RequestID == "" {
			return nil, fmt.Errorf("modules[%d].request_id is required", index)
		}
		if seen[staged.RequestID] {
			return nil, fmt.Errorf("modules[%d].request_id %q is duplicated", index, staged.RequestID)
		}
		seen[staged.RequestID] = true
		if staged.Source == "" {
			return nil, fmt.Errorf("modules[%d].source is required", index)
		}
		packageRoot, err := materializeStagedModule(ctx, root, staged, limits)
		if err != nil {
			return nil, fmt.Errorf("modules[%d]: %w", index, err)
		}
		if err := validateStagedPackage(ctx, packageRoot, limits); err != nil {
			return nil, fmt.Errorf("modules[%d].package: %w", index, err)
		}
		contentDigest, err := resolver.ComputePackageDigest(ctx, packageRoot)
		if err != nil {
			return nil, fmt.Errorf("modules[%d].content_digest: %w", index, err)
		}
		descriptor := resolver.DescribeModuleSource(staged.Source, staged.RequestedVersion)
		localPath := packageRoot
		if descriptor.Subdirectory != "" {
			localPath = filepath.Join(packageRoot, filepath.FromSlash(descriptor.Subdirectory))
		}
		if _, err := resolver.ResolvePathWithinRoot(ctx, packageRoot, localPath); err != nil {
			return nil, fmt.Errorf("modules[%d].subdirectory: %w", index, err)
		}
		relativePackageRoot, err := relativePathWithinRoot(ctx, root, packageRoot)
		if err != nil {
			return nil, fmt.Errorf("modules[%d].package: %w", index, err)
		}
		relativeLocalPath, err := relativePathWithinRoot(ctx, root, localPath)
		if err != nil {
			return nil, fmt.Errorf("modules[%d].subdirectory: %w", index, err)
		}
		entries = append(entries, resolver.ManifestModule{
			RequestID:        staged.RequestID,
			AcquisitionKey:   resolver.ModuleAcquisitionKey(staged.Source, staged.RequestedVersion),
			Source:           staged.Source,
			NormalizedSource: descriptor.NormalizedSource,
			CanonicalSource:  staged.CanonicalSource,
			SourceType:       descriptor.SourceType,
			SourceCategory:   descriptor.SourceCategory,
			RegistryScope:    descriptor.RegistryScope,
			RequestedVersion: descriptor.RequestedVersion,
			RequestedRef:     descriptor.RequestedRef,
			Subdirectory:     descriptor.Subdirectory,
			ResolvedVersion:  strings.TrimSpace(staged.ResolvedVersion),
			ResolvedRef:      strings.TrimSpace(staged.ResolvedRef),
			ContentDigest:    contentDigest,
			PackageRoot:      relativePackageRoot,
			LocalPath:        relativeLocalPath,
			Status:           resolver.ManifestStatusResolved,
			Declarations:     staged.Declarations,
		})
	}
	return entries, nil
}

func materializeStagedModule(
	ctx context.Context,
	root string,
	staged *StagedModule,
	limits resolver.ResourceLimits,
) (string, error) {
	switch staged.Kind {
	case StagedKindDirectory:
		if staged.ArtifactPath != "" || staged.ArchiveFormat != "" || staged.TransportDigest != "" {
			return "", fmt.Errorf("directory staging accepts package_path only")
		}
		return stagedPath(ctx, root, staged.PackagePath)
	case StagedKindArchive:
		if staged.PackagePath != "" {
			return "", fmt.Errorf("archive staging does not accept package_path")
		}
		return materializeArchive(ctx, root, staged, limits)
	default:
		return "", fmt.Errorf("kind must be %q or %q", StagedKindArchive, StagedKindDirectory)
	}
}

func materializeArchive(
	ctx context.Context,
	root string,
	staged *StagedModule,
	limits resolver.ResourceLimits,
) (string, error) {
	artifactPath, err := stagedFilePath(ctx, root, staged.ArtifactPath)
	if err != nil {
		return "", fmt.Errorf("artifact_path: %w", err)
	}
	rawDigest, err := verifyTransportDigest(ctx, artifactPath, staged.TransportDigest, limits.MaxPackageBytes)
	if err != nil {
		return "", err
	}
	packagesRoot := filepath.Join(root, "packages")
	if err := os.MkdirAll(packagesRoot, privateDirectoryMode); err != nil {
		return "", fmt.Errorf("creating staged packages root: %w", err)
	}
	destination := filepath.Join(packagesRoot, strings.TrimPrefix(rawDigest, "sha256:"))
	if info, statErr := os.Stat(destination); statErr == nil && info.IsDir() {
		return normalizedPackageRoot(destination)
	}
	temp, err := os.MkdirTemp(packagesRoot, ".extract-")
	if err != nil {
		return "", fmt.Errorf("creating staged package directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(temp) }()
	if err := resolver.ExtractModuleArchive(ctx, artifactPath, temp, staged.ArchiveFormat, limits); err != nil {
		return "", fmt.Errorf("extracting module archive: %w", err)
	}
	relativePackageRoot, err := normalizedPackageRootRelative(temp)
	if err != nil {
		return "", err
	}
	if err := os.Rename(temp, destination); err != nil {
		if info, statErr := os.Stat(destination); statErr != nil || !info.IsDir() {
			return "", fmt.Errorf("publishing staged package: %w", err)
		}
		return normalizedPackageRoot(destination)
	}
	return filepath.Join(destination, relativePackageRoot), nil
}

func verifyTransportDigest(
	ctx context.Context,
	path string,
	expected string,
	maximumBytes int64,
) (string, error) {
	expected = strings.ToLower(strings.TrimSpace(expected))
	if !strings.HasPrefix(expected, "sha256:") {
		return "", fmt.Errorf("transport_digest must use sha256")
	}
	rawHex := strings.TrimPrefix(expected, "sha256:")
	if len(rawHex) != sha256.Size*2 {
		return "", fmt.Errorf("transport_digest must contain a SHA-256 digest")
	}
	if _, err := hex.DecodeString(rawHex); err != nil {
		return "", fmt.Errorf("transport_digest must contain a SHA-256 digest")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("reading staged archive: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("staged archive must be a regular file")
	}
	if maximumBytes > 0 && info.Size() > maximumBytes {
		return "", &resolver.BudgetExceededError{
			Gate:     "staging",
			Limit:    "archive_bytes",
			Maximum:  maximumBytes,
			Measured: info.Size(),
		}
	}
	file, err := os.Open(path) //nolint:gosec
	if err != nil {
		return "", fmt.Errorf("opening staged archive: %w", err)
	}
	defer func() { _ = file.Close() }()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, &contextReader{ctx: ctx, reader: file}); err != nil {
		return "", fmt.Errorf("hashing staged archive: %w", err)
	}
	actual := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if actual != expected {
		return "", fmt.Errorf("transport_digest mismatch: got %q, computed %q", expected, actual)
	}
	return actual, nil
}

func stagedPath(ctx context.Context, root, relative string) (string, error) {
	if relative == "" || !filepath.IsLocal(relative) {
		return "", fmt.Errorf("must be a non-empty relative path")
	}
	path := filepath.Join(root, filepath.FromSlash(relative))
	if _, err := resolver.ResolvePathWithinRoot(ctx, root, path); err != nil {
		return "", err
	}
	return path, nil
}

func stagedFilePath(ctx context.Context, root, relative string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if relative == "" || !filepath.IsLocal(relative) {
		return "", fmt.Errorf("must be a non-empty relative path")
	}
	path, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("path escapes module root")
	}
	return path, nil
}

func normalizedPackageRoot(root string) (string, error) {
	relative, err := normalizedPackageRootRelative(root)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, relative), nil
}

func normalizedPackageRootRelative(root string) (string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("reading extracted module: %w", err)
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("module archive is empty")
	}
	if len(entries) == 1 && entries[0].IsDir() {
		return entries[0].Name(), nil
	}
	return ".", nil
}

func validateStagedPackage(ctx context.Context, root string, limits resolver.ResourceLimits) error {
	counter := resolver.NewResourceBudget(limits).NewPackageCounter()
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			if filepath.Clean(path) == filepath.Clean(root) {
				return nil
			}
			return counter.AddEntry(0)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("package entry %q is not a regular file", path)
		}
		return counter.AddEntry(info.Size())
	})
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
