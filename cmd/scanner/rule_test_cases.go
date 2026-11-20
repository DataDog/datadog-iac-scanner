/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/engine/source"
	"github.com/DataDog/datadog-iac-scanner/pkg/rulefixture"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

type ruleFixtureFormat uint8

const (
	legacyRuleFixture ruleFixtureFormat = iota
	explicitRuleFixture
)

type ruleFixtureInput struct {
	format ruleFixtureFormat
	root   string
	files  []string
	fsys   vfs.FS
	domain datadog.RuleTestInput
}

func runRuleTestCases(ctx context.Context, cases *rulefixture.Suite, rule *datadog.Rule, libraries source.QueriesSource) ([]string, error) {
	query := source.ConvertRule(rule)
	var mismatches []string
	namespace, err := os.MkdirTemp("", "iac-rule-cases-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(namespace) // nolint:errcheck
	for index := range cases.Len() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		input, err := cases.Prepare(index, filepath.Join(namespace, strconv.Itoa(index)))
		if err != nil {
			return nil, err
		}
		found, shape, err := runFiles(ctx, rule.ID, &query, &ruleFixtureInput{
			root: input.Root, files: input.Targets, fsys: input.Filesystem, domain: input.Domain, format: explicitRuleFixture,
		}, libraries)
		if err != nil {
			return nil, fmt.Errorf("case %q: %w", input.Name, err)
		}
		shape = append(shape, compareFindings(expectedRuleFindings(input.Expected), found)...)
		for _, mismatch := range shape {
			mismatches = append(mismatches, fmt.Sprintf("case %q: %s", input.Name, mismatch))
		}
	}
	return mismatches, nil
}

func expectedRuleFindings(expected []datadog.TestFinding) []ruleFinding {
	findings := make([]ruleFinding, len(expected))
	for i, item := range expected {
		findings[i] = ruleFinding{QueryName: item.ShortDescription, Severity: item.Severity, Line: item.Line, FileName: item.FileName}
	}
	return findings
}
