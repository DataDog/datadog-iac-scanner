package report

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/test"
	"github.com/stretchr/testify/require"
)

func TestPrintSimpleJSONReport(t *testing.T) {
	tests := []struct {
		name            string
		summary         model.Summary
		filename        string
		expectedLen     int
		expectedOutFile string
	}{
		{
			name:            "two findings from single query",
			summary:         test.SummaryMock,
			filename:        "output",
			expectedLen:     2,
			expectedOutFile: "output.json",
		},
		{
			name:            "one finding critical",
			summary:         test.SummaryMockCritical,
			filename:        "output2",
			expectedLen:     1,
			expectedOutFile: "output2.json",
		},
		{
			name:            "multi-query flattened",
			summary:         test.ComplexSummaryMock,
			filename:        "output3",
			expectedLen:     6,
			expectedOutFile: "output3.json",
		},
		{
			name:            "strips existing extension from filename",
			summary:         test.SummaryMockCritical,
			filename:        "result.sarif",
			expectedLen:     1,
			expectedOutFile: "result.json",
		},
	}

	ctx := context.Background()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()

			err := PrintSimpleJSONReport(ctx, dir, tc.filename, tc.summary, &model.SCIInfo{})
			require.NoError(t, err)

			outPath := filepath.Join(dir, tc.expectedOutFile)
			require.FileExists(t, outPath)

			raw, err := os.ReadFile(outPath)
			require.NoError(t, err)

			var findings []SimpleJSONFinding
			require.NoError(t, json.Unmarshal(raw, &findings))
			require.Len(t, findings, tc.expectedLen)

			for _, f := range findings {
				require.NotEmpty(t, f.QueryName)
				require.NotEmpty(t, f.Severity)
				require.NotEmpty(t, f.FileName)
			}
		})
	}
}
