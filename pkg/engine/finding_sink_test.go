/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"fmt"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
	"github.com/stretchr/testify/require"
)

func reportedFindings(t *testing.T, vulns []model.Vulnerability) map[string]model.Vulnerability {
	t.Helper()
	store := storage.NewMemoryStorage()
	require.NoError(t, store.SaveVulnerabilities(context.Background(), vulns))
	unique, err := store.GetVulnerabilities(context.Background(), "")
	require.NoError(t, err)
	out := make(map[string]model.Vulnerability, len(unique))
	for i := range unique {
		v := unique[i]
		out[model.FindingIdentity(&v, utils.ChooseQueryID(v.QueryID, v.LegacyQueryID))] = v
	}
	return out
}

// A rule's findings collected through a sink are the findings the report
// keeps when every finding of the scan is routed and handed over at once.
func TestFindingSink_ReportsWhatTheWholeScanReports(t *testing.T) {
	extras := map[string][]extraCallerInfo{
		"doc-1": {{callChain: "stack-b|module.m", docID: "doc-1b"}},
		"doc-2": {{callChain: "stack-b|module.m", docID: "doc-2b"}, {callChain: "stack-c|module.m", docID: "doc-2c"}},
	}
	var raised []model.Vulnerability
	for i := 0; i < 40; i++ {
		raised = append(raised, model.Vulnerability{
			FileID:          fmt.Sprintf("doc-%d", i%3),
			FileName:        "modules/m/main.tf",
			Platform:        "Terraform",
			QueryID:         fmt.Sprintf("rule-%d", i%2),
			ResourceType:    "aws_s3_bucket",
			ResourceName:    fmt.Sprintf("b%d", i%4),
			ModuleCallChain: "stack-a|module.m",
			// Distinguishes the findings of one identity, so the test sees
			// which of them is reported.
			Line:      i,
			SearchKey: fmt.Sprintf("raised-%d", i),
		})
	}

	whole := expandModuleFindings(append([]model.Vulnerability(nil), raised...), extras)
	want := reportedFindings(t, whole)

	routing := &findingRouting{extras: extras}
	var collected []model.Vulnerability
	for _, rule := range []string{"rule-0", "rule-1"} {
		sink := newFindingSink(context.Background(), &Inspector{}, routing)
		for i := range raised {
			if raised[i].QueryID == rule {
				sink.add(&raised[i])
			}
		}
		collected = append(collected, sink.out...)
	}
	require.Len(t, collected, len(want), "a sink holds one finding per identity")
	require.Equal(t, want, reportedFindings(t, collected))
}
