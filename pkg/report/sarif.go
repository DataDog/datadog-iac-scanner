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

// PrintSarifReport creates a report file on sarif format, fetching the ID and GUID from relationships to be inputted to taxonomies field
func PrintSarifReport(ctx context.Context, path, filename string, body interface{}, sciInfo *model.SCIInfo) error {
	if !strings.HasSuffix(filename, ".sarif") {
		filename += ".sarif"
	}
	if body != "" {
		summary, err := getSummary(body)
		if err != nil {
			return err
		}

		sarifReport := reportModel.NewSarifReport()
		auxGUID := map[string]string{}
		for idx := range summary.Queries {
			if cwe, err := sarifReport.BuildSarifIssue(ctx, &summary.Queries[idx], *sciInfo); err != nil {
				return err
			} else if cwe != "" {
				guid := sarifReport.GetGUIDFromRelationships(idx, cwe)
				auxGUID[cwe] = guid
			}
		}
		if err := sarifReport.AddTags(ctx, &summary, &sciInfo.DiffAware); err != nil {
			return err
		}

		body = sarifReport
	}

	return ExportJSONReport(ctx, path, filename, body)
}
