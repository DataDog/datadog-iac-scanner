package testcases

// E2E-CLI-056 - Scan command with timeout flag
// should stop a query execution when reaching the provided timeout (seconds)
func init() { //nolint
	testSample := TestCase{
		Name: "should timeout queries when reaching the timeout limit [E2E-CLI-056]",
		Args: args{
			Args: []cmdArgs{
				[]string{"scan", "-p", "/path/e2e/fixtures/samples/positive.yaml", "--timeout", "1"},
				[]string{"scan", "-p", "/path/e2e/fixtures/samples/positive.yaml", "--timeout", "0"},
			},
		},
		WantStatus: []int{50, 0},
	}

	Tests = append(Tests, testSample)
}
