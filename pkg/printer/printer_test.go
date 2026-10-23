/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package printer

import (
	"bytes"
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/gookit/color"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// Suppressed findings are neither printed nor counted, and the printed ones
// are numbered in order.
func TestPrintResult_SkipsSuppressedFindings(t *testing.T) {
	color.Disable()
	var out bytes.Buffer
	ctx := zerolog.New(&out).WithContext(context.Background())
	summary := &model.Summary{Queries: model.QueryResultSlice{{
		QueryName: "rule", Severity: model.SeverityHigh,
		Files: []model.VulnerableFile{
			{FileName: "a.tf", Line: 1},
			{FileName: "b.tf", Line: 2, IsSuppressed: true},
			{FileName: "c.tf", Line: 3},
		},
	}, {
		QueryName: "silenced", Severity: model.SeverityLow,
		Files: []model.VulnerableFile{{FileName: "d.tf", Line: 4, IsSuppressed: true}},
	}}}
	require.NoError(t, PrintResult(ctx, summary, NewPrinter(), false, model.SCIInfo{}))
	printed := out.String()
	require.Contains(t, printed, `rule, Severity: HIGH, Results: 2`)
	require.Contains(t, printed, `\t[1]: a.tf:1\n`)
	require.Contains(t, printed, `\t[2]: c.tf:3\n`)
	require.NotContains(t, printed, "b.tf")
	require.NotContains(t, printed, "silenced")
}
