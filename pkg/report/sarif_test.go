package report

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	reportModel "github.com/DataDog/datadog-iac-scanner/pkg/report/model"
	"github.com/DataDog/datadog-iac-scanner/test"
	"github.com/stretchr/testify/require"
)

type reportTestCase struct {
	caseTest       jsonCaseTest
	expectedResult model.Summary
}

type sarifReport struct {
	basePath     string                 `json:"-"`
	Schema       string                 `json:"$schema"`
	SarifVersion string                 `json:"version"`
	Runs         []reportModel.SarifRun `json:"runs"`
}

var sarifTests = []reportTestCase{
	{
		caseTest: jsonCaseTest{
			summary:  test.SummaryMock,
			path:     "./testdir",
			filename: "testout",
		},
		expectedResult: test.SummaryMock,
	},
	{
		caseTest: jsonCaseTest{
			summary:  test.SummaryMockCritical,
			path:     "./testdir",
			filename: "testout2",
		},
		expectedResult: test.SummaryMockCritical,
	},
}

// TestPrintSarifReport tests the functions [PrintSarifReport()] and all the methods called by them
func TestPrintSarifReport(t *testing.T) {
	ctx := context.Background()
	for idx, sarifTest := range sarifTests {
		t.Run(fmt.Sprintf("Sarif File test case %d", idx), func(t *testing.T) {
			if err := os.MkdirAll(sarifTest.caseTest.path, os.ModePerm); err != nil {
				t.Fatal(err)
			}
			err := PrintSarifReport(ctx, sarifTest.caseTest.path, sarifTest.caseTest.filename, sarifTest.caseTest.summary, &model.SCIInfo{})
			checkFileExists(t, err, &sarifTest, "sarif")
			jsonResult, err := os.ReadFile(filepath.Join(sarifTest.caseTest.path, sarifTest.caseTest.filename+".sarif"))
			require.NoError(t, err)
			var resultSarif sarifReport
			err = json.Unmarshal(jsonResult, &resultSarif)
			require.NoError(t, err)
			require.Equal(t, "", resultSarif.basePath)
			require.Equal(t, "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", resultSarif.Schema)
			require.Equal(t, "2.1.0", resultSarif.SarifVersion)
			require.Len(t, resultSarif.Runs, len(sarifTest.expectedResult.Queries))
			require.NoError(t, os.RemoveAll(sarifTest.caseTest.path))
		})
	}
}

func TestPrintSarifReportWithToolVersionFullScan(t *testing.T) {
	ctx := context.Background()
	for idx, sarifTest := range sarifTests {
		t.Run(fmt.Sprintf("Sarif File test case %d", idx), func(t *testing.T) {
			if err := os.MkdirAll(sarifTest.caseTest.path, os.ModePerm); err != nil {
				t.Fatal(err)
			}
			err := PrintSarifReport(ctx, sarifTest.caseTest.path, sarifTest.caseTest.filename, sarifTest.caseTest.summary, &model.SCIInfo{RunType: "full_scan"})
			checkFileExists(t, err, &sarifTest, "sarif")
			jsonResult, err := os.ReadFile(filepath.Join(sarifTest.caseTest.path, sarifTest.caseTest.filename+".sarif"))
			require.NoError(t, err)
			var resultSarif sarifReport
			err = json.Unmarshal(jsonResult, &resultSarif)
			require.NoError(t, err)
			require.Len(t, resultSarif.Runs, len(sarifTest.expectedResult.Queries))
			require.Equal(t, resultSarif.Runs[0].Tool.Driver.ToolVersion, "full_scan")
			require.NoError(t, os.RemoveAll(sarifTest.caseTest.path))
		})
	}
}

func TestPrintSarifReportWithToolVersionCodeUpdate(t *testing.T) {
	ctx := context.Background()
	for idx, sarifTest := range sarifTests {
		t.Run(fmt.Sprintf("Sarif File test case %d", idx), func(t *testing.T) {
			if err := os.MkdirAll(sarifTest.caseTest.path, os.ModePerm); err != nil {
				t.Fatal(err)
			}
			err := PrintSarifReport(ctx, sarifTest.caseTest.path, sarifTest.caseTest.filename, sarifTest.caseTest.summary, &model.SCIInfo{RunType: "code_update"})
			checkFileExists(t, err, &sarifTest, "sarif")
			jsonResult, err := os.ReadFile(filepath.Join(sarifTest.caseTest.path, sarifTest.caseTest.filename+".sarif"))
			require.NoError(t, err)
			var resultSarif sarifReport
			err = json.Unmarshal(jsonResult, &resultSarif)
			require.NoError(t, err)
			require.Len(t, resultSarif.Runs, len(sarifTest.expectedResult.Queries))
			require.Equal(t, resultSarif.Runs[0].Tool.Driver.ToolVersion, "code_update")
			require.NoError(t, os.RemoveAll(sarifTest.caseTest.path))
		})
	}
}

func checkFileExists(t *testing.T, err error, tc *reportTestCase, extension string) {
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(tc.caseTest.path, tc.caseTest.filename+fmt.Sprintf(".%s", extension)))
}
