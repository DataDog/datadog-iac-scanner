package testcases

// E2E-CLI-030 - Scan command with --output-path flags
// should export the result file (default json) to the path provided by this flag.
func init() { //nolint
	testSample := TestCase{
		Name: "should export the result files to provided path [E2E-CLI-030]",
		Args: args{
			Args: []cmdArgs{
				[]string{"scan", "--output-path", "/path/e2e/output",
					"-p", "/path/e2e/fixtures/samples/positive.yaml"},
			},
			ExpectedResult: []ResultsValidation{
				{
					ResultsFile:    "datadog-iac-scanner-result",
					ResultsFormats: []string{"sarif"},
				},
			},
		},
		WantStatus: []int{50},
	}

	Tests = append(Tests, testSample)
}
