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

func readFindings(t *testing.T, dir, filename string) []SimpleJSONFinding {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, filename))
	require.NoError(t, err)
	var findings []SimpleJSONFinding
	require.NoError(t, json.Unmarshal(raw, &findings))
	return findings
}

func TestPrintSimpleJSONReport(t *testing.T) {
	ctx := context.Background()

	t.Run("single query two findings", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, PrintSimpleJSONReport(ctx, dir, "output", test.SummaryMock, &model.SCIInfo{}))

		require.FileExists(t, filepath.Join(dir, "output.simple.json"))
		findings := readFindings(t, dir, "output.simple.json")
		require.Len(t, findings, 2)

		// queryHigh: QueryID "de7f5e83-da88-4046-871f-ea18504b1d43", severity HIGH, platform ""
		require.Equal(t, "de7f5e83-da88-4046-871f-ea18504b1d43", findings[0].QueryID)
		require.Equal(t, "ALB protocol is HTTP", findings[0].QueryName)
		require.Equal(t, "HIGH", findings[0].Severity)
		require.Equal(t, "positive.tf", filepath.Base(findings[0].FileName))
		require.Equal(t, 25, findings[0].Line)

		require.Equal(t, "de7f5e83-da88-4046-871f-ea18504b1d43", findings[1].QueryID)
		require.Equal(t, 19, findings[1].Line)
	})

	t.Run("single critical finding", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, PrintSimpleJSONReport(ctx, dir, "output", test.SummaryMockCritical, &model.SCIInfo{}))

		require.FileExists(t, filepath.Join(dir, "output.simple.json"))
		findings := readFindings(t, dir, "output.simple.json")
		require.Len(t, findings, 1)

		// queryCritical: QueryID "316278b3-87ac-444c-8f8f-a733a28da609", severity CRITICAL
		require.Equal(t, "316278b3-87ac-444c-8f8f-a733a28da609", findings[0].QueryID)
		require.Equal(t, "AmazonMQ Broker Encryption Disabled", findings[0].QueryName)
		require.Equal(t, "CRITICAL", findings[0].Severity)
		require.Equal(t, 6, findings[0].Line)
	})

	t.Run("multi-query flattened", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, PrintSimpleJSONReport(ctx, dir, "output", test.ComplexSummaryMock, &model.SCIInfo{}))

		require.FileExists(t, filepath.Join(dir, "output.simple.json"))
		findings := readFindings(t, dir, "output.simple.json")
		// ComplexSummaryMock: queryHigh(2) + queryMedium(1) + queryHighCWE(2) + queryCriticalCLI(1) = 6
		require.Len(t, findings, 6)

		// All findings must have non-empty required fields
		for i, f := range findings {
			require.NotEmpty(t, f.QueryID, "finding %d: QueryID empty", i)
			require.NotEmpty(t, f.QueryName, "finding %d: QueryName empty", i)
			require.NotEmpty(t, f.Severity, "finding %d: Severity empty", i)
			require.NotEmpty(t, f.FileName, "finding %d: FileName empty", i)
		}
	})

	t.Run("fingerprint passed through from VulnerableFile", func(t *testing.T) {
		summary := model.Summary{
			Queries: []model.QueryResult{
				{
					QueryID:   "test-query-id",
					QueryName: "Test Query",
					Severity:  model.SeverityHigh,
					Platform:  "Terraform",
					Files: []model.VulnerableFile{
						{FileName: "main.tf", Line: 1, Fingerprint: "abc123fingerprint"},
					},
				},
			},
		}
		dir := t.TempDir()
		require.NoError(t, PrintSimpleJSONReport(ctx, dir, "output", summary, &model.SCIInfo{}))

		findings := readFindings(t, dir, "output.simple.json")
		require.Len(t, findings, 1)
		require.Equal(t, "abc123fingerprint", findings[0].FingerPrint)
		require.Equal(t, "test-query-id", findings[0].QueryID)
		require.Equal(t, "Terraform", findings[0].Platform)
	})

	t.Run("empty body produces empty array", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, PrintSimpleJSONReport(ctx, dir, "output", "", &model.SCIInfo{}))

		findings := readFindings(t, dir, "output.simple.json")
		require.Empty(t, findings)
	})
}
