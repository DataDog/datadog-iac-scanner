package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/DataDog/datadog-iac-scanner/e2e/testcases"
	"github.com/DataDog/datadog-iac-scanner/e2e/utils"
	"github.com/stretchr/testify/require"
)

func Test_E2E_CLI(t *testing.T) {
	localBin := utils.GetScannerLocalBin()
	// Make sure that the scanner binary is available.
	if _, err := os.Stat(localBin); os.IsNotExist(err) {
		t.Skip("E2E local execution must have a scanner binary in the 'bin' folder.\nPath not found: " + localBin)
	}

	scanStartTime := time.Now()

	if testing.Short() {
		t.Skip("skipping E2E tests in short mode.")
	}

	templates := prepareTemplates()

	for _, tt := range testcases.Tests {
		for arg := range tt.Args.Args {
			tt := tt
			arg := arg
			t.Run(fmt.Sprintf("%s_%d", tt.Name, arg), func(t *testing.T) {
				t.Parallel()

				out, err := utils.RunCommand(tt.Args.Args[arg])
				// Check command Error
				require.NoError(t, err, "Capture CLI output should not yield an error")

				// Check exit status code (required)
				require.True(t, arg < len(tt.WantStatus),
					"No status code associated to this test. Check the wantStatus of the test case.")

				if tt.WantStatus[arg] != out.Status {
					printTestDetails(out.Output)
				}

				require.Equalf(t, tt.WantStatus[arg], out.Status,
					"Actual scanner status code: %v\nExpected scanner status code: %v",
					out.Status, tt.WantStatus[arg])

				if tt.Validation != nil {
					fullString := strings.Join(out.Output, ";")
					validation := tt.Validation(fullString)
					if !validation {
						printTestDetails(out.Output)
					}
					require.True(t, validation, "Scanner CLI output doesn't match the regex validation.")
				}

				if tt.Args.ExpectedResult != nil && arg < len(tt.Args.ExpectedResult) {
					checkExpectedOutput(t, &tt, arg)
				}

				if tt.Args.ExpectedAnalyzerResults != nil && arg < len(tt.Args.ExpectedResult) {
					checkExpectedAnalyzerResults(t, &tt, arg)
				}

				if tt.Args.ExpectedPayload != nil {
					// Check payload file
					utils.FileCheck(t, tt.Args.ExpectedPayload[arg], tt.Args.ExpectedPayload[arg], "payload")
				}

				if tt.Args.ExpectedLog.ValidationFunc != nil {
					// Check log file
					logData, _ := utils.ReadFixture(tt.Args.ExpectedLog.LogFile, "output")
					validation := tt.Args.ExpectedLog.ValidationFunc(logData)

					require.Truef(t, validation, "The output log file 'output/%s' doesn't match the regex validation",
						tt.Args.ExpectedLog.LogFile)
				}

				if tt.Args.ExpectedOut != nil {
					// Get and preapare expected output
					want, errPrep := utils.PrepareExpected(tt.Args.ExpectedOut[arg], "fixtures")
					require.NoErrorf(t, errPrep, "[fixtures/%s] Reading a fixture should not yield an error",
						tt.Args.ExpectedOut[arg])

					formattedWant := loadTemplates(want, templates)

					// Check number of Lines
					require.Equal(t, len(formattedWant), len(out.Output),
						"[fixtures/%s] Expected number lines: %d\n[CLI] Actual scanner output lines: %d",
						tt.Args.ExpectedOut[arg], len(formattedWant), len(out.Output))

					// Check output lines
					for idx := range formattedWant {
						utils.CheckLine(t, formattedWant[idx], out.Output[idx], idx+1)
					}
				}
			})
		}
	}

	t.Cleanup(func() {
		err := os.RemoveAll("output")
		if err != nil {
			t.Logf("\nError when trying to remove tests output folder %v\n", err)
		}
		t.Logf("E2E tests ::ellapsed time:: %v", time.Since(scanStartTime))
	})
}

func checkExpectedAnalyzerResults(t *testing.T, tt *testcases.TestCase, argIndex int) {
	jsonFileName := tt.Args.ExpectedResult[argIndex].ResultsFile + ".json"
	utils.JSONSchemaValidationFromFile(t, jsonFileName, "AnalyzerResults.json")
}

func checkExpectedOutput(t *testing.T, tt *testcases.TestCase, argIndex int) {
	jsonFileName := tt.Args.ExpectedResult[argIndex].ResultsFile + ".json"
	resultsFormats := tt.Args.ExpectedResult[argIndex].ResultsFormats
	// Check result file (compare with sample)
	if _, err := os.Stat(filepath.Join("fixtures", jsonFileName)); err == nil {
		utils.FileCheck(t, jsonFileName, jsonFileName, "result")
	}
	// Check result file (SARIF)
	if slices.Contains(resultsFormats, "sarif") {
		utils.JSONSchemaValidationFromFile(t, tt.Args.ExpectedResult[argIndex].ResultsFile+".sarif", "result-sarif.json")
	}
}

func prepareTemplates() testcases.TestTemplates {
	var help, errH = utils.PrepareExpected("help", "fixtures/assets")
	if errH != nil {
		help = []string{}
	}

	var scanHelp, errSH = utils.PrepareExpected("scan_help", "fixtures/assets")
	if errSH != nil {
		scanHelp = []string{}
	}

	var remediateHelp, errFH = utils.PrepareExpected("remediate_help", "fixtures/assets")
	if errFH != nil {
		remediateHelp = []string{}
	}

	var analyzeHelp, errAH = utils.PrepareExpected("analyze_help", "fixtures/assets")
	if errAH != nil {
		analyzeHelp = []string{}
	}

	return testcases.TestTemplates{
		Help:          strings.Join(help, "\n"),
		ScanHelp:      strings.Join(scanHelp, "\n"),
		RemediateHelp: strings.Join(remediateHelp, "\n"),
		AnalyzeHelp:   strings.Join(analyzeHelp, "\n"),
	}
}

func loadTemplates(lines []string, templates testcases.TestTemplates) []string {
	temp, err := template.New("templates").Parse(strings.Join(lines, "\n"))
	if err != nil {
		return []string{}
	}

	builder := &strings.Builder{}

	err = temp.Execute(builder, templates)
	if err != nil {
		return []string{}
	}

	t := builder.String()

	builder.Reset()
	builder = nil

	return strings.Split(t, "\n")
}

func printTestDetails(output []string) {
	fmt.Println("\nSCANNER OUTPUT:")
	fmt.Println("====== BEGIN ======")
	for _, line := range output {
		fmt.Println(line)
	}
	fmt.Println("======= END =======")
}
