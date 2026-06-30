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
)

// SimpleJSONFinding represents one finding in the simple-json report.
type SimpleJSONFinding struct {
	QueryID     string `json:"queryID"`
	QueryName   string `json:"queryName"`
	Severity    string `json:"severity"`
	Platform    string `json:"platform"`
	Line        int    `json:"line"`
	FileName    string `json:"fileName"`
	FingerPrint string `json:"fingerPrint"`
}

// PrintSimpleJSONReport prints a flat JSON array of findings, one entry per (query × file) pair.
func PrintSimpleJSONReport(ctx context.Context, path, filename string, body interface{}, sciInfo *model.SCIInfo) error {
	if !strings.HasSuffix(filename, ".simple.json") {
		filename += ".simple.json"
	}

	findings := []SimpleJSONFinding{}
	if body != "" {
		summary, err := getSummary(body)
		if err != nil {
			return err
		}
		for i := range summary.Queries {
			q := &summary.Queries[i]
			for j := range q.Files {
				findings = append(findings, SimpleJSONFinding{
					QueryID:     q.QueryID,
					QueryName:   q.QueryName,
					Severity:    string(q.Severity),
					Platform:    q.Platform,
					Line:        q.Files[j].Line,
					FileName:    q.Files[j].FileName,
					FingerPrint: q.Files[j].Fingerprint,
				})
			}
		}
	}

	return ExportJSONReport(ctx, path, filename, findings)
}
