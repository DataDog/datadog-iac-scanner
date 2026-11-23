/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package tracker

import (
	"fmt"
	"sync"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
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
	ParsedTerraformPlans int
	lines                int
	FoundCountLines      int
	ParsedCountLines     int
	IgnoreCountLines     int
	BagOfFilesParse      map[string]int
	BagOfFilesFound      map[string]int
	BagOfTerraformPlans  map[string]bool
	FailedFiles          map[string]string
	EmptyFiles           map[string]bool
	FailedRenders        map[string]bool
	syncFileMutex        sync.Mutex
	FoundResources       int
	LineInfoLoadFailures int
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

// TrackTerraformPlanParse adds a file successfully parsed as a Terraform plan.
// A file is counted once, however often it is tracked.
func (c *CITracker) TrackTerraformPlanParse(path string) {
	c.syncFileMutex.Lock()
	defer c.syncFileMutex.Unlock()
	if c.BagOfTerraformPlans == nil {
		c.BagOfTerraformPlans = make(map[string]bool)
	}
	if !c.BagOfTerraformPlans[path] {
		c.BagOfTerraformPlans[path] = true
		c.ParsedTerraformPlans++
	}
}

// TrackFileFailed records in FailedFiles why a found file gave no documents.
// Of several reasons for one file, the first in sort order is kept, so the
// result does not depend on which parser finished first. No counter changes.
func (c *CITracker) TrackFileFailed(path, reason string) {
	c.syncFileMutex.Lock()
	defer c.syncFileMutex.Unlock()
	if c.FailedFiles == nil {
		c.FailedFiles = make(map[string]string)
	}
	if prev, ok := c.FailedFiles[path]; !ok || reason < prev {
		c.FailedFiles[path] = reason
	}
}

// TrackFileEmpty records in EmptyFiles a found file that rightly gave no
// documents, such as a Helm template that renders nothing. No counter changes.
func (c *CITracker) TrackFileEmpty(path string) {
	c.syncFileMutex.Lock()
	defer c.syncFileMutex.Unlock()
	if c.EmptyFiles == nil {
		c.EmptyFiles = make(map[string]bool)
	}
	c.EmptyFiles[path] = true
}

// TrackRenderFailed records in FailedRenders a chart that failed to render.
// Its files may still parse, rendered on their own as a dependency of
// another chart, so this outcome is kept apart from theirs. No counter
// changes.
func (c *CITracker) TrackRenderFailed(chart string) {
	c.syncFileMutex.Lock()
	defer c.syncFileMutex.Unlock()
	if c.FailedRenders == nil {
		c.FailedRenders = make(map[string]bool)
	}
	c.FailedRenders[chart] = true
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
