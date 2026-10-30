/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tracker

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/rs/zerolog/log"
)

// CITracker contains information of how many queries were loaded and executed
// and how many files were found and executed

var (
	trackerMu sync.Mutex
)

type CITracker struct {
	ExecutingQueries     int
	ExecutedQueries      int
	FoundFiles           int
	LoadedQueries        int
	ParsedFiles          int
	lines                int
	FoundCountLines      int
	ParsedCountLines     int
	IgnoreCountLines     int
	BagOfFilesParse      map[string]int
	BagOfFilesFound      map[string]int
	syncFileMutex        sync.Mutex
	FoundResources       int
	LineInfoLoadFailures int
	SupersededResults    int64
	IdentityGaps         int64
}

// NewTracker will create a new instance of a tracker with the number of lines to display in results output
// number of lines can not be smaller than 1
func NewTracker(previewLines int) (*CITracker, error) {
	if previewLines < constants.MinimumPreviewLines || previewLines > constants.MaximumPreviewLines {
		return &CITracker{},
			fmt.Errorf("output lines minimum is %v and maximum is %v", constants.MinimumPreviewLines, constants.MaximumPreviewLines)
	}
	return &CITracker{
		lines:           previewLines,
		BagOfFilesParse: make(map[string]int),
		BagOfFilesFound: make(map[string]int),
	}, nil
}

// GetOutputLines returns the number of lines to display in results output
func (c *CITracker) GetOutputLines() int {
	return c.lines
}

// TrackQueryLoad adds a loaded query
func (c *CITracker) TrackQueryLoad(queryAggregation int) {
	trackerMu.Lock()
	defer trackerMu.Unlock()
	c.LoadedQueries += queryAggregation
}

// TrackQueryExecuting adds a executing queries
func (c *CITracker) TrackQueryExecuting(queryAggregation int) {
	trackerMu.Lock()
	defer trackerMu.Unlock()
	c.ExecutingQueries += queryAggregation
}

// TrackQueryExecution adds a query executed
func (c *CITracker) TrackQueryExecution(queryAggregation int) {
	trackerMu.Lock()
	defer trackerMu.Unlock()
	c.ExecutedQueries += queryAggregation
}

// TrackFileFound adds a found file to be scanned
func (c *CITracker) TrackFileFound(path string) {
	c.syncFileMutex.Lock()
	defer c.syncFileMutex.Unlock()
	count, value := c.BagOfFilesFound[path]
	if !value {
		c.BagOfFilesFound[path] = 1
		c.FoundFiles++
	} else {
		c.BagOfFilesFound[path] = count + 1
	}
}

// TrackFileParse adds a successful parsed file to be scanned
func (c *CITracker) TrackFileParse(path string) {
	c.syncFileMutex.Lock()
	defer c.syncFileMutex.Unlock()
	count, value := c.BagOfFilesParse[path]
	if !value {
		c.BagOfFilesParse[path] = 1
		c.ParsedFiles++
	} else {
		c.BagOfFilesParse[path] = count + 1
	}
}

// FailedDetectLine - queries that fail to detect line are counted as failed to execute queries
func (c *CITracker) FailedDetectLine() {
	trackerMu.Lock()
	defer trackerMu.Unlock()
	c.ExecutedQueries--
}

// FailedLineInfoDocument counts lazy line-info document load failures.
func (c *CITracker) FailedLineInfoDocument() {
	trackerMu.Lock()
	defer trackerMu.Unlock()
	c.LineInfoLoadFailures++
}

// SkippedSupersededResult counts a result dropped before its line was detected.
func (c *CITracker) SkippedSupersededResult() {
	atomic.AddInt64(&c.SupersededResults, 1)
}

// FindingWithoutIdentity counts a Terraform finding whose resourceType and
// resourceName named no declared block, so it kept the legacy fingerprint
// (K9CODESEC-7158), and logs the first one: a count above zero is a gap in the
// rules or the identity resolution, to fix at the source.
func (c *CITracker) FindingWithoutIdentity() {
	if atomic.AddInt64(&c.IdentityGaps, 1) == 1 {
		// The global logger, which the CLI configures: the tracker carries no
		// context, and a context lookup here would return zerolog's disabled
		// logger and silence the one warning the scan owes.
		log.Warn().Msg("terraform findings without identity; keeping the legacy fingerprint for them")
	}
}

// TrackFileFoundCountLines - information about the lines of the scanned files
func (c *CITracker) TrackFileFoundCountLines(countLines int) {
	trackerMu.Lock()
	defer trackerMu.Unlock()
	c.FoundCountLines += countLines
}

// TrackFileParseCountLines - information about the lines of the parsed files
func (c *CITracker) TrackFileParseCountLines(countLines int) {
	trackerMu.Lock()
	defer trackerMu.Unlock()
	c.ParsedCountLines += countLines
}

// TrackFileIgnoreCountLines - information about the lines ignored of the parsed files
func (c *CITracker) TrackFileIgnoreCountLines(countLines int) {
	trackerMu.Lock()
	defer trackerMu.Unlock()
	c.IgnoreCountLines += countLines
}

// TrackResourceFoundCountLines - information about the resources of the scanned files
func (c *CITracker) TrackFileFoundCountResources(countResources int) {
	trackerMu.Lock()
	defer trackerMu.Unlock()
	c.FoundResources += countResources
}
