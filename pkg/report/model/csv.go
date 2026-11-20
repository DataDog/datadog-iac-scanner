/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import "github.com/DataDog/datadog-iac-scanner/pkg/model"

// CSVReport struct contains all the info to create the csv report
type CSVReport struct {
	QueryName                   string `csv:"query_name"`
	QueryID                     string `csv:"query_id"`
	QueryURI                    string `csv:"query_uri"`
	Severity                    string `csv:"severity"`
	Platform                    string `csv:"platform"`
	CWE                         string `csv:"cwe,omitempty"`
	CloudProvider               string `csv:"cloud_provider"`
	Category                    string `csv:"category"`
	DescriptionID               string `csv:"description_id"`
	Description                 string `csv:"description"`
	CISDescriptionIDFormatted   string `csv:"cis_description_id"`
	CISDescriptionTitle         string `csv:"cis_description_title"`
	CISDescriptionTextFormatted string `csv:"cis_description_text"`
	FileName                    string `csv:"file_name"`
	Fingerprint                 string `csv:"fingerprint"`
	Line                        int    `csv:"line"`
	SearchKey                   string `csv:"search_key"`
	SearchLine                  int    `csv:"search_line"`
	SearchValue                 string `csv:"search_value"`
}

// BuildCSVReport builds the CSV report
// It projects findings only; the report frontend owns evaluation-status capability checks.
func BuildCSVReport(queries model.QueryResultSlice) []CSVReport {
	csvReport := []CSVReport{}

	for i := range queries {
		for j := range queries[i].Files {
			csvReport = append(csvReport, CSVReport{
				QueryName:                   queries[i].QueryName,
				QueryID:                     queries[i].QueryID,
				QueryURI:                    queries[i].QueryURI,
				Severity:                    string(queries[i].Severity),
				Platform:                    queries[i].Platform,
				CWE:                         queries[i].CWE,
				CloudProvider:               queries[i].CloudProvider,
				Category:                    queries[i].Category,
				DescriptionID:               queries[i].DescriptionID,
				Description:                 queries[i].Description,
				CISDescriptionIDFormatted:   queries[i].CISDescriptionIDFormatted,
				CISDescriptionTitle:         queries[i].CISDescriptionTitle,
				CISDescriptionTextFormatted: queries[i].CISDescriptionTextFormatted,
				FileName:                    queries[i].Files[j].FileName,
				Fingerprint:                 queries[i].Files[j].Fingerprint,
				Line:                        queries[i].Files[j].Line,
				SearchKey:                   queries[i].Files[j].SearchKey,
				SearchLine:                  queries[i].Files[j].SearchLine,
				SearchValue:                 queries[i].Files[j].SearchValue,
			})
		}
	}

	return csvReport
}
