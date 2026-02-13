/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package scan

import (
	"context"
	_ "embed" // Embed kics CLI img and scan-flags
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	consoleHelpers "github.com/DataDog/datadog-iac-scanner/internal/console/helpers"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/provider"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	consolePrinter "github.com/DataDog/datadog-iac-scanner/pkg/printer"
	"github.com/DataDog/datadog-iac-scanner/pkg/report"
)

func (c *Client) getSummary(ctx context.Context, results []model.Vulnerability,
	end time.Time, pathParameters model.PathParameters) model.Summary {
	counters := model.Counters{
		ScannedFiles:           c.Tracker.FoundFiles,
		ScannedFilesLines:      c.Tracker.FoundCountLines,
		ParsedFilesLines:       c.Tracker.ParsedCountLines,
		ParsedFiles:            c.Tracker.ParsedFiles,
		IgnoredFilesLines:      c.Tracker.IgnoreCountLines,
		TotalQueries:           c.Tracker.LoadedQueries,
		FailedToExecuteQueries: c.Tracker.ExecutingQueries - c.Tracker.ExecutedQueries,
		FailedSimilarityID:     c.Tracker.FailedSimilarityID,
		FoundResources:         c.Tracker.FoundResources,
	}

	summary := model.CreateSummary(
		ctx,
		counters,
		results,
		c.ScanParams.ScanID,
		pathParameters.PathExtractionMap,
		c.ScanParams.OutputPath,
	)
	summary.Times = model.Times{
		Start: c.ScanStartTime,
		End:   end,
	}

	return summary
}

func (c *Client) resolveOutputs(
	ctx context.Context,
	summary *model.Summary,
	documents model.Documents,
	printer *consolePrinter.Printer,
) error {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("console.resolveOutputs()")

	usingCustomQueries := usingCustomQueries(c.ScanParams.QueriesPath)
	if err := consolePrinter.PrintResult(ctx, summary, printer, usingCustomQueries, c.ScanParams.SCIInfo); err != nil {
		return err
	}
	if c.ScanParams.PayloadPath != "" {
		if err := report.ExportJSONReport(
			ctx,
			filepath.Dir(c.ScanParams.PayloadPath),
			filepath.Base(c.ScanParams.PayloadPath),
			documents,
		); err != nil {
			return err
		}
	}

	return printOutput(
		ctx,
		c.ScanParams.OutputPath,
		c.ScanParams.OutputName,
		summary, c.ScanParams.ReportFormats,
		&c.ScanParams.SCIInfo,
	)
}

func printOutput(ctx context.Context, outputPath, filename string, body interface{}, formats []string, sciInfo *model.SCIInfo) error {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("console.printOutput()")
	if outputPath == "" {
		return nil
	}
	if len(formats) == 0 {
		formats = []string{"json"}
	}

	contextLogger.Debug().Msgf("Output formats provided [%v]", strings.Join(formats, ","))
	contextLogger.Debug().Msgf("SCIInfo: %v", sciInfo)
	err := consoleHelpers.GenerateReport(ctx, outputPath, filename, body, formats, sciInfo)

	return err
}

// postScan is responsible for the output results
func (c *Client) postScan(ctx context.Context, scanResults *Results) (ScanMetadata, error) {
	contextLogger := logger.FromContext(ctx)
	metadata := ScanMetadata{}
	if scanResults == nil {
		contextLogger.Info().Msg("No files were scanned")
		scanResults = &Results{
			Results:        []model.Vulnerability{},
			ExtractedPaths: provider.ExtractedPath{},
			Files:          model.FileMetadatas{},
			FailedQueries:  map[string]error{},
		}
	}

	sort.Strings(c.ScanParams.Path)
	summary := c.getSummary(ctx, scanResults.Results, time.Now(), model.PathParameters{
		ScannedPaths:      c.ScanParams.Path,
		PathExtractionMap: scanResults.ExtractedPaths.ExtractionMap,
	})

	if err := c.resolveOutputs(
		ctx,
		&summary,
		scanResults.Files.Combine(ctx, c.ScanParams.LineInfoPayload),
		c.Printer); err != nil {
		contextLogger.Err(err).Msgf("failed to resolve outputs %v", err)
		return metadata, err
	}

	endTime := time.Now()
	scanDuration := endTime.Sub(c.ScanStartTime)
	consolePrinter.PrintScanDuration(ctx, scanDuration)

	handler, exitCode := consoleHelpers.ResultsExitCode(&summary)
	if handler.ShowError("results") && exitCode != 0 {
		os.Exit(exitCode)
	}

	// generate metadata payload
	metadata = c.generateMetadata(scanResults, c.ScanStartTime, endTime)

	return metadata, nil
}

func (c *Client) generateMetadata(scanResults *Results, startTime, endTime time.Time) ScanMetadata {
	stats := c.generateStats(scanResults, endTime.Sub(startTime))
	ruleStats := c.generateRuleStats(scanResults)

	metadata := ScanMetadata{
		StartTime:      startTime,
		EndTime:        endTime,
		CoresAvailable: int(consoleHelpers.GetNumCPU()),
		DiffAware:      c.ScanParams.SCIInfo.DiffAware.Enabled,
		Stats:          stats,
		RuleStats:      ruleStats,
	}

	return metadata
}

func (c *Client) generateStats(scanResults *Results, scanDuration time.Duration) ScanStats {
	// iterate through scanResults and create a map of severity to count
	violationBreakdowns := make(map[string]map[string]int)
	severitySet := make(map[model.Severity]bool)
	for _, sev := range model.AllSeverities {
		severitySet[sev] = true
	}

	// nolint:gocritic
	for _, vuln := range scanResults.Results {
		if !severitySet[vuln.Severity] {
			continue
		}

		if _, exists := violationBreakdowns[string(vuln.Severity)]; !exists {
			violationBreakdowns[string(vuln.Severity)] = make(map[string]int)
		}

		violationBreakdowns[string(vuln.Severity)][vuln.QueryID]++
	}

	return ScanStats{
		Violations:          len(scanResults.Results),
		Files:               c.Tracker.FoundFiles,
		Rules:               c.Tracker.ExecutedQueries,
		Duration:            scanDuration,
		ViolationBreakdowns: violationBreakdowns,
		ResourcesScanned:    c.Tracker.FoundResources,
	}
}

func (c *Client) generateRuleStats(scanResults *Results) RuleStats {
	failedQueries := make([]string, 0, len(scanResults.FailedQueries))

	return RuleStats{
		TimedOut:          failedQueries,
		MostExpensiveRule: getLongestRunningQuery(scanResults.Results),
		SlowestRule:       getLongestRunningQuery(scanResults.Results),
	}
}

func getLongestRunningQuery(vulns []model.Vulnerability) RuleTiming {
	longestQuery := ""
	longestQueryTime := time.Duration(0)
	// nolint:gocritic
	for _, vuln := range vulns {
		if vuln.QueryDuration > longestQueryTime {
			longestQueryTime = vuln.QueryDuration
			longestQuery = vuln.QueryName
		}
	}
	return RuleTiming{
		Name: longestQuery,
		Time: longestQueryTime,
	}
}
