/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package printer

import (
	"context"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/gookit/color"
)

// Printer wil print console output with colors
// Medium is for medium sevevity results
// High is for high sevevity results
// Low is for low sevevity results
// Info is for info sevevity results
// Success is for successful prints
// Line is the color to print the line with the vulnerability
// minVersion is a bool that if true will print the results output in a minimum version
type Printer struct {
	Critical            color.RGBColor
	Medium              color.RGBColor
	High                color.RGBColor
	Low                 color.RGBColor
	Info                color.RGBColor
	Success             color.RGBColor
	Line                color.RGBColor
	VersionMessage      color.RGBColor
	ContributionMessage color.RGBColor
}

// PrintResult prints on output the summary results
// nolint:gocritic
func PrintResult(ctx context.Context, summary *model.Summary, printer *Printer, usingCustomQueries bool, sciInfo model.SCIInfo) error {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Msg("helpers.PrintResult()")
	fmt.Printf("\n\n")

	for index := range summary.Queries {
		idx := len(summary.Queries) - index - 1
		if summary.Queries[idx].Severity == model.SeverityTrace {
			continue
		}

		contextLogger.Info().Msgf(
			"%s, Severity: %s, Results: %d\n",
			printer.PrintBySev(summary.Queries[idx].QueryName, string(summary.Queries[idx].Severity)),
			printer.PrintBySev(string(summary.Queries[idx].Severity), string(summary.Queries[idx].Severity)),
			len(summary.Queries[idx].Files),
		)

		if summary.Queries[idx].Experimental {
			contextLogger.Info().Msgf("Note: this is an experimental query")
		}

		printFiles(ctx, &summary.Queries[idx], printer)
	}
	contextLogger.Info().Msgf("\nResults Summary:\n")
	printSeverityCounter(ctx, model.SeverityCritical, summary.SeverityCounters[model.SeverityCritical])
	printSeverityCounter(ctx, model.SeverityHigh, summary.SeverityCounters[model.SeverityHigh])
	printSeverityCounter(ctx, model.SeverityMedium, summary.SeverityCounters[model.SeverityMedium])
	printSeverityCounter(ctx, model.SeverityLow, summary.SeverityCounters[model.SeverityLow])
	printSeverityCounter(ctx, model.SeverityInfo, summary.SeverityCounters[model.SeverityInfo])
	contextLogger.Info().Msgf("TOTAL: %d\n\n", summary.TotalCounter)

	contextLogger.Info().Int64(
		"org", sciInfo.OrgId,
	).Str(
		"branch", sciInfo.RepositoryCommitInfo.Branch,
	).Str(
		"sha", sciInfo.RepositoryCommitInfo.CommitSHA,
	).Str(
		"repository", sciInfo.RepositoryCommitInfo.RepositoryUrl,
	).Msgf("Scanned Files: %d", summary.ScannedFiles)

	contextLogger.Info().Int64(
		"org", sciInfo.OrgId,
	).Str(
		"branch", sciInfo.RepositoryCommitInfo.Branch,
	).Str(
		"sha", sciInfo.RepositoryCommitInfo.CommitSHA,
	).Str(
		"repository", sciInfo.RepositoryCommitInfo.RepositoryUrl,
	).Msgf("Parsed Files: %d", summary.ParsedFiles)

	contextLogger.Info().Msgf("Scanned Lines: %d", summary.ScannedFilesLines)
	contextLogger.Info().Msgf("Parsed Lines: %d", summary.ParsedFilesLines)
	contextLogger.Info().Msgf("Ignored Lines: %d", summary.IgnoredFilesLines)
	contextLogger.Info().Msgf("Queries loaded: %d", summary.TotalQueries)
	contextLogger.Info().Msgf("Queries failed to execute: %d", summary.FailedToExecuteQueries)
	contextLogger.Info().Msg("Inspector stopped")

	return nil
}

func printSeverityCounter(ctx context.Context, severity string, counter int) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Info().Msgf("%s: %d\n", severity, counter)
}

func printFiles(ctx context.Context, query *model.QueryResult, printer *Printer) {
	contextLogger := logger.FromContext(ctx)
	for fileIdx := range query.Files {
		contextLogger.Info().Msgf("\t%s %s:%s\n", printer.PrintBySev(fmt.Sprintf("[%d]:", fileIdx+1), string(query.Severity)),
			query.Files[fileIdx].FileName, printer.Success.Sprint(query.Files[fileIdx].Line))
	}
}

// NewPrinter initializes a new Printer
func NewPrinter() *Printer {
	return &Printer{
		Critical:            color.HEX("#ff0000"),
		Medium:              color.HEX("#ff7213"),
		High:                color.HEX("#bb2124"),
		Low:                 color.HEX("#edd57e"),
		Success:             color.HEX("#22bb33"),
		Info:                color.HEX("#5bc0de"),
		Line:                color.HEX("#f0ad4e"),
		VersionMessage:      color.HEX("#ff9913"),
		ContributionMessage: color.HEX("#ffe313"),
	}
}

// PrintBySev will print the output with the specific severity color given the severity of the result
func (p *Printer) PrintBySev(content, sev string) string {
	switch strings.ToUpper(sev) {
	case model.SeverityCritical:
		return p.Critical.Sprintf(content)
	case model.SeverityHigh:
		return p.High.Sprintf(content)
	case model.SeverityMedium:
		return p.Medium.Sprintf(content)
	case model.SeverityLow:
		return p.Low.Sprintf(content)
	case model.SeverityInfo:
		return p.Info.Sprintf(content)
	}
	return content
}
