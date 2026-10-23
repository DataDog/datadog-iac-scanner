/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// A complete scan's SARIF is unchanged: no invocation, no completeness tag.
func TestAddTags_CompleteScanAddsNoInvocation(t *testing.T) {
	report := NewSarifReport().(*sarifReport)
	require.NoError(t, report.AddTags(context.Background(), &model.Summary{}, &model.DiffAware{}))
	require.Empty(t, report.Runs[0].Invocations)
	require.NotContains(t, report.Runs[0].Tool.Driver.Properties.Tags, "DATADOG_SCAN_COMPLETE:false")
	out, err := json.Marshal(report)
	require.NoError(t, err)
	require.NotContains(t, string(out), "invocations")
}

// An incomplete scan says so in a machine-readable way: a run tag, and an
// invocation notification per reason with its count and examples.
func TestAddTags_IncompleteScanReportsEveryReason(t *testing.T) {
	summary := &model.Summary{Incomplete: []model.IncompleteReason{
		{Reason: "instance_limit", Count: 1, Examples: []string{"more than 10 instances"}},
		{Reason: "module_cycle", Count: 2, Examples: []string{"module.a.module.b.module.a"}},
	}}
	report := NewSarifReport().(*sarifReport)
	require.NoError(t, report.AddTags(context.Background(), summary, &model.DiffAware{}))
	require.Contains(t, report.Runs[0].Tool.Driver.Properties.Tags, "DATADOG_SCAN_COMPLETE:false")

	out, err := json.Marshal(report)
	require.NoError(t, err)
	var parsed struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful        bool `json:"executionSuccessful"`
				ToolExecutionNotifications []struct {
					Descriptor struct{ ID string }
					Level      string
					Properties struct {
						Reason   string
						Count    int
						Examples []string
					}
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(out, &parsed))
	require.Len(t, parsed.Runs[0].Invocations, 1)
	inv := parsed.Runs[0].Invocations[0]
	require.True(t, inv.ExecutionSuccessful)
	require.Len(t, inv.ToolExecutionNotifications, 2)
	for i, want := range summary.Incomplete {
		n := inv.ToolExecutionNotifications[i]
		require.Equal(t, incompleteNotificationID, n.Descriptor.ID)
		require.Equal(t, "warning", n.Level)
		require.Equal(t, want.Reason, n.Properties.Reason)
		require.Equal(t, want.Count, n.Properties.Count)
		require.Equal(t, want.Examples, n.Properties.Examples)
	}
}
