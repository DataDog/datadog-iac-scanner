/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package scan

import (
	"context"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/inventory"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/google/uuid"
)

// Inventory statuses and failure reasons reported in the scan metadata.
const (
	InventoryWritten = "written"
	InventoryFailed  = "failed"

	InventoryReasonStaleFile  = "stale_file"
	InventoryReasonWriteError = "write_error"
	InventoryReasonPanic      = "panic"
)

// inventoryRun is the inventory of one scan, when the scan was asked for one.
type inventoryRun struct {
	collector *inventory.Collector
	scanID    string
	platforms []string
	// failure is set when the run can no longer produce an inventory.
	failure *InventoryMetadata
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
	// A scan that ends without writing an inventory must not leave the one of
	// an earlier scan in its place.
	if err := inventory.RemoveStale(path); err != nil {
		run.failure = inventoryFailure(InventoryReasonStaleFile, err)
		contextLogger := logger.FromContext(ctx)
		contextLogger.Error().Err(err).Msgf("failed to remove the previous inventory %s", path)
	}
	c.inventory = run
}

// finishInventory writes the inventory and reports what happened. A failure
// never fails the scan: the findings are already written, and no inventory
// file is left behind.
func (c *Client) finishInventory(ctx context.Context) (status *InventoryMetadata) {
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

func inventoryFailure(reason string, err error) *InventoryMetadata {
	return &InventoryMetadata{Status: InventoryFailed, Reason: reason, Error: err.Error()}
}
