/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// streamedReport builds a report with results of two rules and taxonomies.
func streamedReport(t *testing.T, results int) *sarifReport {
	t.Helper()
	report := NewSarifReport().(*sarifReport)
	for _, rule := range []string{"<html> & rule", "other rule"} {
		q := model.QueryResult{
			QueryName: rule, QueryID: "id-" + rule, Description: "desc <b>", Severity: model.SeverityHigh,
			Category: "Access Control", Platform: "Terraform", CWE: "284",
		}
		for i := range results {
			q.Files = append(q.Files, model.VulnerableFile{
				FileName: fmt.Sprintf("modules/m%d/main.tf", i), Line: i + 1, ResourceType: "aws_s3_bucket",
				ResourceName: fmt.Sprintf("b[%d]", i), ModuleCallChain: fmt.Sprintf("r/main.tf|module.m[%d]", i),
				ResourceLocation: model.ResourceLocation{Start: model.ResourceLine{Line: i + 1, Col: 1}, End: model.ResourceLine{Line: i + 2, Col: 2}},
			})
		}
		_, err := report.BuildSarifIssue(context.Background(), &q, model.SCIInfo{})
		require.NoError(t, err)
	}
	require.NoError(t, report.AddTags(context.Background(), &model.Summary{}, &model.DiffAware{}))
	return report
}

// The streamed report is byte for byte what encoding the whole report writes.
func TestEncodeJSON_MatchesEncoder(t *testing.T) {
	for _, c := range []struct {
		results    int
		nilResults bool
	}{{0, false}, {3, false}, {50, false}, {0, true}} {
		t.Run(fmt.Sprintf("%+v", c), func(t *testing.T) {
			report := streamedReport(t, c.results)
			if c.nilResults {
				report.Runs[0].Results = nil
			}
			var want, got bytes.Buffer
			require.NoError(t, json.NewEncoder(&want).Encode(report))
			require.NoError(t, report.EncodeJSON(&got))
			require.Equal(t, want.String(), got.String())
		})
	}
}
