package testcases

// E2E-CLI-019 - Scan with multiple paths
// should run a scan for all provided paths/files
func init() { //nolint
	testSample := TestCase{
		Name: "should run a scan in multiple paths [E2E-CLI-019]",
		Args: args{
			Args: []cmdArgs{
				[]string{"scan", "-p", "/path/e2e/fixtures/samples/long_terraform.tf,/path/e2e/fixtures/samples/positive.yaml"},
			},
		},
		WantStatus: []int{50},
	}

	Tests = append(Tests, testSample)
}
