package main

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/ruletest"
	"github.com/stretchr/testify/assert"
)

func TestFormatMismatches(t *testing.T) {
	f := ruletest.Finding{QueryName: "q", Severity: "HIGH", Line: 3, FileName: "positive.tf"}
	assert.Equal(t, []string{
		`Missing expected: main.ruleFinding{QueryName:"q", Severity:"HIGH", Line:3, FileName:"positive.tf"}`,
		`Unexpected finding: main.ruleFinding{QueryName:"q", Severity:"HIGH", Line:3, FileName:"positive.tf"}`,
		`Result missing required field "searchKey"`,
		`case 2 with arguments: Unexpected finding: main.ruleFinding{QueryName:"q", Severity:"HIGH", Line:3, FileName:"positive.tf"}`,
		`case 1 without arguments: No argument test sample files found`,
	}, formatMismatches([]ruletest.Mismatch{
		{Kind: ruletest.MissingFinding, Finding: f},
		{Kind: ruletest.UnexpectedFinding, Finding: f},
		{Kind: ruletest.InvalidResult, Message: `Result missing required field "searchKey"`},
		{Kind: ruletest.UnexpectedFinding, Case: 2, Arguments: true, Finding: f},
		{Kind: ruletest.MissingFixtures, Case: 1, Message: "No argument test sample files found"},
	}))
}
