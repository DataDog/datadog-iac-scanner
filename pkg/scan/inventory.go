/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package scan

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/modulegraph"
	"github.com/google/uuid"
)

// Inventory statuses and failure reasons reported in the scan metadata.
const (
	InventoryWritten = "written"
	InventoryFailed  = "failed"

	InventoryReasonStaleFile    = "stale_file"
	InventoryReasonWriteError   = "write_error"
	InventoryReasonPanic        = "panic"
	InventoryReasonPathConflict = "path_conflict"
)

// inventoryRun is the inventory of one scan, when the scan was asked for one.
type inventoryRun struct {
	collector *inventory.Collector
	scanID    string
	platforms []string
	// filePlatform is the analyzer's platform per file, by slash path.
	filePlatform map[string]string
	// tooLarge holds the files skipped for their size, with their platform.
	tooLarge map[string]string
	// external holds the fetched remote modules, which are not part of the
	// repository even when they sit inside it.
	external map[string]bool
	// failure is set when the run can no longer produce an inventory.
	failure *InventoryMetadata
}

// noteFiles keeps what the scan learnt about its files before parsing them.
// A nil run, a scan without inventory, ignores it.
func (run *inventoryRun) noteFiles(filePlatform map[string]string, remoteModulePaths []string) {
	if run == nil {
		return
	}
	run.filePlatform = filePlatform
	run.external = make(map[string]bool, len(remoteModulePaths))
	for _, p := range remoteModulePaths {
		run.external[filepath.Clean(p)] = true
	}
}

// noteTooLarge keeps the files the analyzer skipped for their size.
func (run *inventoryRun) noteTooLarge(tooLarge map[string]string) {
	if run != nil {
		run.tooLarge = tooLarge
	}
}

// writes reports whether the scan will write an inventory at its path.
func (run *inventoryRun) writes() bool {
	return run != nil && run.failure == nil
}

// sink is where the engine reports resources, nil without an inventory.
func (run *inventoryRun) sink() engine.InventorySink {
	if run == nil {
		return nil
	}
	return run.collector
}

// noteModuleFailures records the remote modules the scan could not resolve.
func (run *inventoryRun) noteModuleFailures(failures []modulegraph.ResolutionFailure) {
	if run == nil {
		return
	}
	for i := range failures {
		f := &failures[i]
		source := inventory.SanitizeSource(f.Source)
		if f.Version != "" {
			source += "@" + f.Version
		}
		run.collector.AddUnresolvedSource(inventory.UnresolvedSource{
			Platform: inventory.PlatformTerraform,
			Source:   source,
			Reason:   cmp.Or(f.Code, inventory.ReasonUnknown),
		})
	}
}

// isExternal reports whether path belongs to a fetched remote module.
func (run *inventoryRun) isExternal(path string) bool {
	if len(run.external) == 0 {
		return false
	}
	for p := filepath.Clean(path); ; {
		if run.external[p] {
			return true
		}
		parent := filepath.Dir(p)
		if parent == p {
			return false
		}
		p = parent
	}
}

// startInventory prepares the inventory of a scan that asked for one. It runs
// before the scan, so the platforms are the ones requested rather than the
// ones the analyzer later found.
func (c *Client) startInventory(ctx context.Context) {
	path := c.ScanParams.InventoryPath
	if path == "" {
		return
	}
	platforms := c.ScanParams.GetEffectivePlatforms()
	run := &inventoryRun{
		collector: inventory.NewCollector(c.ScanParams.RepoPath),
		scanID:    uuid.NewString(),
		platforms: make([]string, 0, len(platforms)),
	}
	for _, p := range platforms {
		run.platforms = append(run.platforms, strings.ToLower(p))
	}
	contextLogger := logger.FromContext(ctx)
	// The inventory must never replace another file of the scan.
	if other := c.inventoryPathConflict(path); other != "" {
		run.failure = inventoryFailure(InventoryReasonPathConflict, fmt.Errorf("the inventory path is also %s", other))
		contextLogger.Error().Msgf("the inventory path %s is also %s; not writing an inventory", path, other)
		c.inventory = run
		return
	}
	// A scan that ends without writing an inventory must not leave the one of
	// an earlier scan in its place.
	if err := inventory.RemoveStale(path); err != nil {
		reason := InventoryReasonStaleFile
		if errors.Is(err, inventory.ErrNotInventory) {
			reason = InventoryReasonPathConflict
		}
		run.failure = inventoryFailure(reason, err)
		contextLogger.Error().Err(err).Msgf("failed to remove the previous inventory %s", path)
	}
	// The storage keeps where the findings it drops as duplicates were
	// raised, so that the kept finding links to each of their resources.
	if run.failure == nil && c.Storage != nil {
		c.Storage.RecordDuplicates()
	}
	c.inventory = run
}

// inventoryPathConflict names the other output or input of the scan at the
// inventory path, "" when there is none. A report is checked when the
// inventory is written, since only the report writers know their names.
func (c *Client) inventoryPathConflict(path string) string {
	// The metadata and the payload are written after the inventory: a path
	// under one of them would make a directory where it goes.
	others := []struct {
		name, path string
		laterFile  bool
	}{
		{"the metadata path", c.ScanParams.MetadataPath, true},
		{"the payload path", c.ScanParams.PayloadPath, true},
	}
	for _, input := range c.ScanParams.Path {
		others = append(others, struct {
			name, path string
			laterFile  bool
		}{"a scanned path", input, false})
	}
	for _, other := range others {
		if other.path == "" {
			continue
		}
		if samePath(path, other.path) {
			return other.name
		}
		if other.laterFile && isUnder(path, other.path) {
			return "under " + other.name
		}
	}
	return ""
}

// isUnder reports whether path lies inside dir.
func isUnder(path, dir string) bool {
	absPath, errPath := filepath.Abs(path)
	absDir, errDir := filepath.Abs(dir)
	if errPath != nil || errDir != nil {
		return false
	}
	rel, err := filepath.Rel(absDir, absPath)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// samePath reports whether two paths name the same file, through symlinks
// when both exist.
func samePath(a, b string) bool {
	if ai, err := os.Stat(a); err == nil {
		if bi, err := os.Stat(b); err == nil {
			return os.SameFile(ai, bi)
		}
	}
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	return errA == nil && errB == nil && absA == absB
}

// finishInventory writes the inventory and reports what happened. A failure
// never fails the scan: the findings are already written, and no inventory
// file is left behind.
func (c *Client) finishInventory(ctx context.Context, results *Results, summary *model.Summary) (status *InventoryMetadata) {
	run := c.inventory
	if run == nil {
		return nil
	}
	contextLogger := logger.FromContext(ctx)
	if run.failure != nil {
		return run.failure
	}
	path := c.ScanParams.InventoryPath
	defer func() {
		if r := recover(); r != nil {
			_ = inventory.RemoveStale(path)
			status = inventoryFailure(InventoryReasonPanic, fmt.Errorf("%v", r))
			contextLogger.Error().Interface("panic", r).Msg("failed to build the inventory")
		}
	}()

	var files model.FileMetadatas
	var extractionMap map[string]model.ExtractedPathObject
	if results != nil {
		files, extractionMap = results.Files, results.ExtractedPaths.ExtractionMap
	}
	if reason := run.collector.Failure(); reason != "" {
		contextLogger.Error().Str("reason", reason).Msg("the inventory may miss resources; not writing it")
		return &InventoryMetadata{Status: InventoryFailed, Reason: reason}
	}
	c.recordManifest(run, files)
	recordFindings(run.collector, files, summary)
	// A resource of a fetched module is named after where the module came
	// from, as in the reports.
	run.collector.SetPathResolver(func(path string) string {
		if !run.isExternal(path) {
			if rel, ok := run.collector.RelPath(path); ok {
				return rel
			}
		}
		return filepath.ToSlash(model.ReportPath(path, extractionMap, c.ScanParams.RepoPath))
	})
	commit := c.ScanParams.SCIInfo.RepositoryCommitInfo
	inv := run.collector.Build(&inventory.Metadata{
		ScanID:         run.scanID,
		ScannerVersion: constants.Version,
		ScannedAt:      c.ScanStartTime,
		Repository: inventory.Repository{
			URL:       model.RedactURLCredentials(commit.RepositoryUrl),
			CommitSHA: commit.CommitSHA,
			Branch:    commit.Branch,
		},
		PlatformsScanned: run.platforms,
	})
	// The path was cleared when the scan started, so a file there now is one
	// the scan wrote, such as a report given the same name.
	if _, err := os.Lstat(path); err == nil {
		contextLogger.Error().Msgf("the scan wrote another file at the inventory path %s; not writing an inventory", path)
		return inventoryFailure(InventoryReasonPathConflict, fmt.Errorf("the scan wrote another file at %s", path))
	}
	if err := inventory.WriteFile(path, inv); err != nil {
		contextLogger.Error().Err(err).Msgf("failed to write the inventory %s", path)
		return inventoryFailure(InventoryReasonWriteError, err)
	}
	contextLogger.Info().
		Int("resources", inv.Stats.Resources).
		Int("files", len(inv.Files)).
		Int("files_failed", inv.Stats.FilesFailed).
		Msgf("Inventory written to %s", path)
	return &InventoryMetadata{
		Status:      InventoryWritten,
		Resources:   inv.Stats.Resources,
		Files:       len(inv.Files),
		FilesFailed: inv.Stats.FilesFailed,
	}
}

// recordManifest records the outcome of every file the scan considered: each
// file a parser was given, and each file skipped for its size. Files outside
// the repository and fetched remote modules are left out.
func (c *Client) recordManifest(run *inventoryRun, files model.FileMetadatas) {
	// A parsed file takes the platform its documents were scanned as; a file
	// that never parsed takes the analyzer's.
	parsedPlatform := make(map[string]string, len(files))
	for _, f := range files {
		if f == nil || f.Platform == "" {
			continue
		}
		key := filepath.ToSlash(f.FilePath)
		if prev, ok := parsedPlatform[key]; !ok || f.Platform < prev {
			parsedPlatform[key] = f.Platform
		}
	}
	record := func(path, platform, status, reason string) {
		if run.isExternal(path) {
			return
		}
		rel, ok := run.collector.RelPath(path)
		if !ok {
			return
		}
		if platform == "" {
			key := filepath.ToSlash(path)
			platform = cmp.Or(parsedPlatform[key], run.filePlatform[key])
		}
		run.collector.RecordFile(rel, platform, status, reason)
	}

	if t := c.Tracker; t != nil {
		for path := range t.BagOfFilesFound {
			switch {
			case t.BagOfFilesParse[path] > 0 || t.EmptyFiles[path]:
				record(path, "", inventory.FileScanned, "")
			case t.FailedFiles[path] != "":
				record(path, "", inventory.FileFailed, t.FailedFiles[path])
			default:
				record(path, "", inventory.FileFailed, inventory.ReasonUnknown)
			}
		}
	}
	for path, platform := range run.tooLarge {
		record(path, platform, inventory.FileFailed, inventory.ReasonTooLarge)
	}
}

// recordFindings gives the collector every finding the SARIF report holds,
// to link them to their rows.
func recordFindings(collector *inventory.Collector, files model.FileMetadatas, summary *model.Summary) {
	if summary == nil {
		return
	}
	paths := make(map[string]string, len(files))
	for _, f := range files {
		if f != nil {
			paths[f.ID] = f.FilePath
		}
	}
	for i := range summary.Queries {
		for j := range summary.Queries[i].Files {
			vf := &summary.Queries[i].Files[j]
			// The SARIF report leaves out a finding with no location.
			if vf.ResourceLocation.Start.Line < 1 || vf.ResourceLocation.End.Line < 1 {
				continue
			}
			// The finding stands for every place its identity was raised.
			places := append([]model.RaisedOn{{FileID: vf.FileID, Line: vf.Line, SearchKey: vf.SearchKey,
				BlockStart: vf.BlockLocation.Start.Line}}, vf.AlsoRaisedOn...)
			for _, place := range places {
				// A module instance's document is named after its file's.
				fileID, _, _ := strings.Cut(place.FileID, "\x00")
				collector.AddFinding(&inventory.Finding{
					Fingerprint:     vf.Fingerprint,
					DocumentID:      place.FileID,
					File:            paths[fileID],
					Line:            place.Line,
					SearchKey:       place.SearchKey,
					BlockStart:      place.BlockStart,
					ModuleCallChain: vf.ModuleCallChain,
				})
			}
		}
	}
}

func inventoryFailure(reason string, err error) *InventoryMetadata {
	return &InventoryMetadata{Status: InventoryFailed, Reason: reason, Error: err.Error()}
}
