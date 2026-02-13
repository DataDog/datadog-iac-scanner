package testcases

// E2E-CLI-021 - Scanner can return different status code based in the scan results (High/Medium/Low..)
// when excluding categories/queries and losing results we can get a different status code.
func init() { //nolint
	testSample := TestCase{
		Name: "should validate the scanner result status code [E2E-CLI-021]",
		Args: args{
			Args: []cmdArgs{
				[]string{"scan",
					"-p", "/path/e2e/fixtures/samples/positive.yaml"},

				[]string{"scan",
					"-p", "/path/e2e/fixtures/samples/tf-eval-func-unknown-type/main.tf"},
			},
		},
		WantStatus: []int{50, 40},
	}

	Tests = append(Tests, testSample)
}
