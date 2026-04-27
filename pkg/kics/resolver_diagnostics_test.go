/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package kics

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/internal/storage"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// Regression: diagnostics that share (QueryID, FilePath, Line) but have distinct messages
// must all survive MemoryStorage de-dup, which keys on KeyActualValue and ignores SearchValue.
func TestSaveResolverDiagnostics_DistinctMessagesArePreserved(t *testing.T) {
	ctx := context.Background()
	s := &Service{
		Storage:             storage.NewMemoryStorage(),
		ResolverDiagnostics: NewResolverDiagnosticsState(),
	}
	scanID := "scan-1"
	diags := []model.ResolverDiagnostic{
		{QueryID: "q1", FilePath: "/repo/a.yaml", Line: 10, Message: "first"},
		{QueryID: "q1", FilePath: "/repo/a.yaml", Line: 10, Message: "second"},
	}

	require.NoError(t, s.saveResolverDiagnostics(ctx, scanID, diags))

	got, err := s.Storage.GetVulnerabilities(ctx, scanID)
	require.NoError(t, err)
	require.Len(t, got, 2)

	messages := map[string]bool{}
	for _, v := range got {
		messages[v.SearchValue] = true
	}
	require.True(t, messages["first"], "first message must survive storage de-dup")
	require.True(t, messages["second"], "second message must survive storage de-dup")
}
