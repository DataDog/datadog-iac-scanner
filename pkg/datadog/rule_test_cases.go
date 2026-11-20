/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package datadog

// RuleTestCasesFile is an optional versioned manifest carried in RuleTests.Files.
// Older clients continue to consume the unchanged Files and Expected fields.
const RuleTestCasesFile = ".dd-iac-test-cases.json"

type RuleTestInput string

const (
	RuleTestDocuments     RuleTestInput = "documents"
	RuleTestConfiguration RuleTestInput = "configuration"
)

type RuleTestCases struct {
	Version int            `json:"version"`
	Cases   []RuleTestCase `json:"cases"`
}

// RuleTestCase owns its exact assets and target set. Configuration inputs also
// declare their source root; documents never acquire neighboring source files.
type RuleTestCase struct {
	Name     string        `json:"name"`
	Input    RuleTestInput `json:"input"`
	Root     string        `json:"root,omitempty"`
	Targets  []string      `json:"targets"`
	Assets   []string      `json:"assets"`
	Expected []TestFinding `json:"expected"`
}
