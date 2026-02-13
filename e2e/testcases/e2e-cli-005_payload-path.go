package testcases

// E2E-CLI-005 - Scan with -- payload-path flag should create a file with the
// passed name containing the payload of the files scanned

func init() { //nolint
	testSample := TestCase{
		Name: "should create a payload file [E2E-CLI-005]",
		Args: args{
			Args: []cmdArgs{
				[]string{"scan", "-p", "/path/e2e/fixtures/samples/terraform.tf",
					"--payload-path", "/path/e2e/output/E2E_CLI_005_PAYLOAD.json"},
			},
			ExpectedPayload: []string{
				"E2E_CLI_005_PAYLOAD.json",
			},
		},
		WantStatus: []int{50},
	}

	Tests = append(Tests, testSample)
}
