package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/ruletest/harness"
	cli "github.com/urfave/cli/v3"
)

const (
	defaultRuleTestTimeout = 3 * time.Minute
	ruleTestPlatformFlag   = "type"
)

type ruleOutcome struct {
	id         string
	mismatches []string
}

var testRulesAction = &cli.Command{
	Name:  "test-rules",
	Usage: "runs published or local rule fixtures against the local engine",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{Name: "rule", Usage: "only test these rule IDs or legacy IDs"},
		&cli.StringSliceFlag{Name: ruleTestPlatformFlag, Aliases: []string{"t"}, Usage: "only test these platforms"},
		&cli.StringFlag{Name: "rules-dir", Usage: "local assets directory containing queries and libraries"},
		&cli.BoolFlag{Name: "unknown-mutations", Usage: "check v2 Terraform findings against unknown HCL attribute mutations"},
		&cli.BoolFlag{Name: "unknown-pairs", Usage: "also check simultaneous pairs of unknown HCL attributes"},
	},
	Action: runTestRules,
}

func runTestRules(ctx context.Context, c *cli.Command) error {
	var suite *harness.Suite
	var err error
	local := c.String("rules-dir")
	if local != "" {
		suite, err = harness.LoadDir(ctx, local)
	} else {
		suite, err = harness.LoadAPI(ctx, datadog.NewDatadogClient())
	}
	if err != nil {
		return err
	}
	opts := ruleTestOptions(local, c.Bool("unknown-mutations"), c.Bool("unknown-pairs"))
	var results []ruleOutcome
	allPass := true
	for _, rule := range suite.Rules {
		if !rule.Match(c.StringSlice(ruleTestPlatformFlag), c.StringSlice("rule")) {
			continue
		}
		result, err := suite.Run(ctx, rule, opts)
		if err != nil {
			return fmt.Errorf("testing rule %s: %w", rule.ID, err)
		}
		var mismatches []string
		for _, mismatch := range result.Mismatches {
			switch mismatch.Kind {
			case harness.MissingFinding:
				mismatches = append(mismatches, fmt.Sprintf("Missing expected: %#v", mismatch.Finding))
			case harness.UnexpectedFinding:
				mismatches = append(mismatches, fmt.Sprintf("Unexpected finding: %#v", mismatch.Finding))
			default:
				mismatches = append(mismatches, mismatch.Message)
			}
		}
		results = append(results, ruleOutcome{id: rule.ID, mismatches: mismatches})
		allPass = allPass && result.Passed()
	}
	return finishTests(results, allPass)
}

func ruleTestOptions(localRulesDir string, unknownMutations, unknownPairs bool) harness.Options {
	return harness.Options{
		Timeout:                  defaultRuleTestTimeout,
		RequireFixtures:          localRulesDir != "",
		LegacyRoots:              true,
		CheckOrderDeterminism:    true,
		UnknownMutations:         unknownMutations,
		PairwiseUnknownMutations: unknownPairs,
	}
}

func finishTests(results []ruleOutcome, allPass bool) error {
	if allPass {
		if len(results) == 0 {
			fmt.Println("No rules with tests were found")
			os.Exit(1)
		}
		fmt.Printf("PASS: %s\n", plural("%d rule", "%d rules", len(results)))
		return nil
	}

	var failed, passed int
	for _, r := range results {
		if len(r.mismatches) == 0 {
			passed++
			fmt.Printf("PASS: %s\n", r.id)
		} else {
			failed++
			fmt.Printf("FAIL: %s\n", r.id)
			for _, m := range r.mismatches {
				fmt.Printf("  %s\n", m)
			}
		}
	}
	fmt.Printf("FAIL: %s, %s\n",
		plural("%d rule failed", "%d rules failed", failed),
		plural("%d rule passed", "%d rules passed", passed))
	os.Exit(1)
	return nil
}
