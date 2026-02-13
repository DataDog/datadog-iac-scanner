/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package report

import (
	"context"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	reportModel "github.com/DataDog/datadog-iac-scanner/pkg/report/model"
)

// PrintCSVReport prints the CSV report in the given path and filename with the given body
func PrintCSVReport(ctx context.Context, path, filename string, body interface{}, sciInfo *model.SCIInfo) error {
	if !strings.HasSuffix(filename, ".csv") {
		filename += ".csv"
	}

	var report []reportModel.CSVReport
	if body != "" {
		summary, err := getSummary(body)
		if err != nil {
			return err
		}

		report = reportModel.BuildCSVReport(&summary)
	}

	return exportCSVReport(ctx, path, filename, report)
}
