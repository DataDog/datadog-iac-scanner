/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package moduleprepare

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/modulegraph"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
)

const (
	ResponseSchemaVersion = 1
	StatusComplete        = "complete"
	StatusRequiresStaging = "requires_staging"
	StatusIncomplete      = "incomplete"

	privateDirectoryMode = 0o750
	privateFileMode      = 0o600
	maxResponseBytes     = 16 * 1024 * 1024
)

type Response struct {
	SchemaVersion   int                       `json:"schema_version"`
	Status          string                    `json:"status"`
	ManifestPath    string                    `json:"manifest_path,omitempty"`
	Modules         []resolver.ManifestModule `json:"modules"`
	Requests        []resolver.ManifestModule `json:"requests,omitempty"`
	OmittedModules  int                       `json:"omitted_modules,omitempty"`
	OmittedRequests int                       `json:"omitted_requests,omitempty"`
	Termination     Termination               `json:"termination"`
}

type Termination struct {
	TimedOut            bool          `json:"timed_out"`
	ModuleLimitReached  bool          `json:"module_limit_reached"`
	BudgetEvents        []BudgetEvent `json:"budget_events,omitempty"`
	OmittedBudgetEvents int           `json:"omitted_budget_events,omitempty"`
}

type BudgetEvent struct {
	Source   string `json:"source"`
	Gate     string `json:"gate"`
	Limit    string `json:"limit"`
	Maximum  int64  `json:"maximum"`
	Measured int64  `json:"measured"`
}

func WriteResult(
	ctx context.Context,
	responsePath string,
	manifestPath string,
	moduleRoot string,
	repositoryRoots []string,
	result *modulegraph.Result,
	maxResponseEntries int,
) (Response, error) {
	if result == nil {
		return Response{}, fmt.Errorf("module graph result is required")
	}
	if strings.TrimSpace(responsePath) == "" || strings.TrimSpace(manifestPath) == "" {
		return Response{}, fmt.Errorf("response and manifest paths are required")
	}
	if filepath.Clean(responsePath) == filepath.Clean(manifestPath) {
		return Response{}, fmt.Errorf("response and manifest paths must be distinct")
	}
	entries, err := manifestEntries(ctx, moduleRoot, repositoryRoots, result)
	if err != nil {
		return Response{}, err
	}
	response := buildResponse(entries, result, maxResponseEntries)
	if response.Status == StatusComplete {
		if err := resolver.WriteManifest(ctx, manifestPath, moduleRoot, entries); err != nil {
			return Response{}, err
		}
		response.ManifestPath = filepath.ToSlash(manifestPath)
	} else if err := removeStaleManifest(manifestPath); err != nil {
		return Response{}, err
	}
	if err := writeResponse(responsePath, &response); err != nil {
		return Response{}, err
	}
	return response, nil
}

func buildResponse(
	entries []resolver.ManifestModule,
	result *modulegraph.Result,
	maxResponseEntries int,
) Response {
	response := Response{
		SchemaVersion: ResponseSchemaVersion,
		Status:        StatusComplete,
		Termination: Termination{
			TimedOut:           result.TimedOut,
			ModuleLimitReached: result.ModuleLimitReached,
		},
	}
	var modules []resolver.ManifestModule
	var requests []resolver.ManifestModule
	for index := range entries {
		if entries[index].Status == resolver.ManifestStatusUnresolved {
			requests = append(requests, entries[index])
		} else {
			modules = append(modules, entries[index])
		}
	}
	response.Modules, response.OmittedModules = limitManifestEntries(modules, maxResponseEntries)
	response.Requests, response.OmittedRequests = limitManifestEntries(requests, maxResponseEntries)
	sort.Slice(response.Requests, func(left, right int) bool {
		return response.Requests[left].RequestID < response.Requests[right].RequestID
	})

	events := make([]BudgetEvent, 0, len(result.BudgetEvents))
	for _, event := range result.BudgetEvents {
		events = append(events, BudgetEvent{
			Source:   model.RedactURLCredentials(event.Source),
			Gate:     event.Gate,
			Limit:    event.Limit,
			Maximum:  event.Maximum,
			Measured: event.Measured,
		})
	}
	sort.Slice(events, func(left, right int) bool {
		a, b := events[left], events[right]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Gate != b.Gate {
			return a.Gate < b.Gate
		}
		if a.Limit != b.Limit {
			return a.Limit < b.Limit
		}
		if a.Maximum != b.Maximum {
			return a.Maximum < b.Maximum
		}
		return a.Measured < b.Measured
	})
	if maxResponseEntries > 0 && len(events) > maxResponseEntries {
		response.Termination.OmittedBudgetEvents = len(events) - maxResponseEntries
		events = events[:maxResponseEntries]
	}
	response.Termination.BudgetEvents = events

	switch {
	case result.TimedOut || result.ModuleLimitReached || len(result.BudgetEvents) > 0:
		response.Status = StatusIncomplete
	case len(requests) > 0:
		response.Status = StatusRequiresStaging
	}
	return response
}

func manifestEntries(
	ctx context.Context,
	moduleRoot string,
	repositoryRoots []string,
	result *modulegraph.Result,
) ([]resolver.ManifestModule, error) {
	resolvedRoot, err := filepath.Abs(moduleRoot)
	if err != nil {
		return nil, fmt.Errorf("resolving module root: %w", err)
	}
	resolvedRoot, err = filepath.EvalSymlinks(resolvedRoot)
	if err != nil {
		return nil, fmt.Errorf("resolving module root: %w", err)
	}
	roots, err := resolvedRoots(repositoryRoots)
	if err != nil {
		return nil, err
	}

	entries := make([]resolver.ManifestModule, 0, len(result.Modules)+len(result.Failures))
	digests := make(map[string]string)
	for index := range result.Modules {
		module := &result.Modules[index]
		packageRoot, err := relativePathWithinRoot(ctx, resolvedRoot, module.PackageRoot)
		if err != nil {
			return nil, fmt.Errorf("module %q package root: %w", module.Source, err)
		}
		localPath, err := relativePathWithinRoot(ctx, resolvedRoot, module.LocalPath)
		if err != nil {
			return nil, fmt.Errorf("module %q local path: %w", module.Source, err)
		}
		digest := digests[module.PackageRoot]
		if digest == "" {
			digest, err = resolver.ComputePackageDigest(ctx, module.PackageRoot)
			if err != nil {
				return nil, fmt.Errorf("module %q digest: %w", module.Source, err)
			}
			digests[module.PackageRoot] = digest
		}
		descriptor := resolver.DescribeModuleSource(module.Source, module.Version)
		safeSource := model.RedactURLCredentials(module.Source)
		requestID := module.RequestID
		if requestID == "" {
			requestID = resolver.ModuleCallID(
				module.CallerFile,
				module.CallerLine,
				module.CallerEndLine,
				module.Name,
				module.Source,
				module.Version,
			)
		}
		entries = append(entries, resolver.ManifestModule{
			RequestID:        requestID,
			AcquisitionKey:   resolver.ModuleAcquisitionKey(module.Source, module.Version),
			Source:           safeSource,
			NormalizedSource: descriptor.NormalizedSource,
			CanonicalSource:  model.RedactURLCredentials(module.CanonicalSource),
			SourceType:       descriptor.SourceType,
			SourceCategory:   descriptor.SourceCategory,
			RegistryScope:    descriptor.RegistryScope,
			RequestedVersion: descriptor.RequestedVersion,
			RequestedRef:     descriptor.RequestedRef,
			Subdirectory:     descriptor.Subdirectory,
			ResolvedVersion:  module.ResolvedVersion,
			ResolvedRef:      module.ResolvedRef,
			ContentDigest:    digest,
			PackageRoot:      packageRoot,
			LocalPath:        localPath,
			Status:           resolver.ManifestStatusResolved,
			Declarations: []resolver.ManifestDeclaration{
				resolvedDeclaration(module, result.Modules, roots, resolvedRoot),
			},
		})
	}

	for index := range result.Failures {
		failure := &result.Failures[index]
		descriptor := resolver.DescribeModuleSource(failure.Source, failure.Version)
		safeSource := model.RedactURLCredentials(failure.Source)
		requestID := failure.RequestID
		if requestID == "" {
			requestID = resolver.ModuleCallID(
				failure.CallerFile,
				failure.CallerLine,
				failure.CallerEndLine,
				failure.Name,
				failure.Source,
				failure.Version,
			)
		}
		entries = append(entries, resolver.ManifestModule{
			RequestID:        requestID,
			AcquisitionKey:   resolver.ModuleAcquisitionKey(failure.Source, failure.Version),
			Source:           safeSource,
			NormalizedSource: descriptor.NormalizedSource,
			SourceType:       descriptor.SourceType,
			SourceCategory:   descriptor.SourceCategory,
			RegistryScope:    descriptor.RegistryScope,
			RequestedVersion: descriptor.RequestedVersion,
			RequestedRef:     descriptor.RequestedRef,
			Subdirectory:     descriptor.Subdirectory,
			Status:           resolver.ManifestStatusUnresolved,
			Failure:          failure.Reason,
			Declarations: []resolver.ManifestDeclaration{{
				Filename:     relativeDeclarationPath(failure.CallerFile, roots, resolvedRoot),
				LineStart:    failure.CallerLine,
				LineEnd:      failure.CallerEndLine,
				ModuleName:   failure.Name,
				CallerModule: callerModuleForFile(failure.CallerFile, result.Modules),
			}},
		})
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].RequestID < entries[right].RequestID
	})
	return entries, nil
}

func resolvedDeclaration(
	module *modulegraph.ResolvedModule,
	all []modulegraph.ResolvedModule,
	repositoryRoots []string,
	moduleRoot string,
) resolver.ManifestDeclaration {
	return resolver.ManifestDeclaration{
		Filename:     relativeDeclarationPath(module.CallerFile, repositoryRoots, moduleRoot),
		LineStart:    module.CallerLine,
		LineEnd:      module.CallerEndLine,
		ModuleName:   module.Name,
		CallerModule: callerModuleForPackage(module.ParentPackageRoot, all),
	}
}

func callerModuleForFile(path string, modules []modulegraph.ResolvedModule) string {
	bestLength := -1
	caller := ""
	for index := range modules {
		module := &modules[index]
		relative, err := filepath.Rel(module.LocalPath, path)
		if err != nil || !filepath.IsLocal(relative) || len(module.LocalPath) <= bestLength {
			continue
		}
		bestLength = len(module.LocalPath)
		caller = module.CanonicalSource
	}
	return caller
}

func callerModuleForPackage(packageRoot string, modules []modulegraph.ResolvedModule) string {
	if packageRoot == "" {
		return ""
	}
	for index := range modules {
		if filepath.Clean(modules[index].PackageRoot) == filepath.Clean(packageRoot) {
			return modules[index].CanonicalSource
		}
	}
	return ""
}

func relativeDeclarationPath(path string, repositoryRoots []string, moduleRoot string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	for _, root := range append(repositoryRoots, moduleRoot) {
		relative, err := filepath.Rel(root, path)
		if err == nil && filepath.IsLocal(relative) {
			return filepath.ToSlash(relative)
		}
	}
	return filepath.ToSlash(filepath.Base(path))
}

func resolvedRoots(paths []string) ([]string, error) {
	roots := make([]string, 0, len(paths))
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolving repository root %q: %w", path, err)
		}
		resolved, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			return nil, fmt.Errorf("resolving repository root %q: %w", path, err)
		}
		roots = append(roots, resolved)
	}
	sort.Strings(roots)
	return roots, nil
}

func relativePathWithinRoot(ctx context.Context, root, path string) (string, error) {
	if _, err := resolver.ResolvePathWithinRoot(ctx, root, path); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil || !filepath.IsLocal(relative) {
		return "", fmt.Errorf("path %q is outside module root %q", path, root)
	}
	return filepath.ToSlash(relative), nil
}

func limitManifestEntries(
	entries []resolver.ManifestModule,
	maximum int,
) (limited []resolver.ManifestModule, omitted int) {
	if maximum <= 0 || len(entries) <= maximum {
		limited = make([]resolver.ManifestModule, len(entries))
		copy(limited, entries)
		return limited, 0
	}
	limited = make([]resolver.ManifestModule, maximum)
	copy(limited, entries[:maximum])
	return limited, len(entries) - maximum
}

func removeStaleManifest(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing stale module manifest: %w", err)
	}
	return nil
}

func writeResponse(path string, response *Response) error {
	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding module preparation response: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxResponseBytes {
		return fmt.Errorf("module preparation response exceeds %d bytes", maxResponseBytes)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, privateDirectoryMode); err != nil {
		return fmt.Errorf("creating response directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".module-response-*.json")
	if err != nil {
		return fmt.Errorf("creating temporary response: %w", err)
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if err := temp.Chmod(privateFileMode); err != nil {
		_ = temp.Close()
		return fmt.Errorf("setting response permissions: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("writing response: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("closing response: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replacing response: %w", err)
	}
	return nil
}
