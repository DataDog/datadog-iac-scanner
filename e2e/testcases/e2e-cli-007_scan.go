package testcases

import "regexp"

// E2E-CLI-007 - the default scan must show informations such as 'Files scanned',
// 'Rules found', '...' in the CLI
func init() { //nolint
	testSample := TestCase{
		Name: "should perform a simple scan [E2E-CLI-007]",
		Args: args{
			Args: []cmdArgs{
				[]string{"scan", "-p", "/path/e2e/fixtures/samples/positive.yaml"},
			},
		},
		WantStatus: []int{50},
		Validation: func(outputText string) bool {
			match1, _ := regexp.MatchString(`Scanned repository .*`, outputText)
			match2, _ := regexp.MatchString(`\d+ files? scanned in .*`, outputText)
			match3, _ := regexp.MatchString(`\d+ rules? found \d+ violations?`, outputText)
			return match1 && match2 && match3
		},
	}

	Tests = append(Tests, testSample)
}
