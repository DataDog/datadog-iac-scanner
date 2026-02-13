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

// PrintJUnitReport prints the JUnit report in the given path and filename with the given body
func PrintJUnitReport(ctx context.Context, path, filename string, body interface{}, sciInfo *model.SCIInfo) error {
	if !strings.HasPrefix(filename, "junit-") {
		filename = "junit-" + filename
	}

	summary := model.Summary{}

	if body != "" {
		var err error
		summary, err = getSummary(body)
		if err != nil {
			return err
		}
	}

	jUnitReport := reportModel.NewJUnitReport(summary.Times.End.Sub(summary.Times.Start).String())
	for idx := range summary.Queries {
		jUnitReport.GenerateTestEntry(&summary.Queries[idx])
	}

	jUnitReport.FinishReport()

	return exportXMLReport(ctx, path, filename, jUnitReport)
}
