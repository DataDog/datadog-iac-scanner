/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package helpers

import (
	"fmt"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/test"
	"github.com/stretchr/testify/require"
)

type resultExitCode struct {
	summary model.Summary
	failOn  map[string]struct{}
}

var resultsExitCodeTests = []struct {
	caseTest       resultExitCode
	expectedResult int
}{
	{
		caseTest: resultExitCode{
			summary: test.SummaryMock,
			failOn: map[string]struct{}{
				"critical": {},
				"high":     {},
				"medium":   {},
				"low":      {},
				"info":     {},
			},
		},
		expectedResult: 50,
	},
	{
		caseTest: resultExitCode{
			summary: test.SummaryMock,
			failOn: map[string]struct{}{
				"medium": {},
			},
		},
		expectedResult: 0,
	},
	{
		caseTest: resultExitCode{
			summary: test.ComplexSummaryMock,
			failOn: map[string]struct{}{
				"medium": {},
			},
		},
		expectedResult: 40,
	},
	{
		caseTest: resultExitCode{
			summary: test.ComplexSummaryMock,
			failOn: map[string]struct{}{
				"critical": {},
				"high":     {},
				"medium":   {},
				"low":      {},
				"info":     {},
			},
		},
		expectedResult: 60,
	},
}

func TestExitHandler_ResultsExitCode(t *testing.T) {
	for idx, testCase := range resultsExitCodeTests {
		t.Run(fmt.Sprintf("Print test case %d", idx), func(t *testing.T) {
			config := NewExitHandler()
			config.ShouldFail = testCase.caseTest.failOn
			result := ResultsExitCodeWithConfig(config, &testCase.caseTest.summary)
			require.Equal(t, testCase.expectedResult, result)
		})
	}
}

var showResultsTests = []struct {
	caseTest       string
	expectedResult bool
}{
	{
		caseTest:       "none",
		expectedResult: true,
	},
	{
		caseTest:       "all",
		expectedResult: false,
	},
	{
		caseTest:       "results",
		expectedResult: true,
	},
	{
		caseTest:       "errors",
		expectedResult: false,
	},
}

func TestExitHandler_ShowError(t *testing.T) {
	for idx, testCase := range showResultsTests {
		t.Run(fmt.Sprintf("Print test case %d", idx), func(t *testing.T) {
			config := NewExitHandler()
			config.ShouldIgnore = testCase.caseTest
			result := config.ShowError("errors")
			require.Equal(t, testCase.expectedResult, result)
		})
	}
}
