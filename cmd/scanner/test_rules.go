package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/ruletest"
	cli "github.com/urfave/cli/v3"
)

// Heavy Terraform CloudWatch alarm-missing rules evaluate many filter-pattern
// helpers per fixture; 60s was too tight under GOMAXPROCS=1.
const defaultRuleTestTimeout = 3 * time.Minute

// ruleFinding is how findings are printed in mismatch lines.
type ruleFinding struct {
	QueryName string
	Severity  string
	Line      int
	FileName  string
}

type ruleOutcome struct {
	id         string
	mismatches []string
}

var testRulesAction = &cli.Command{
	Name:  "test-rules",
	Usage: "runs rule tests against the local engine, from the Datadog backend or from a local rules directory",
	Description: "With --rules-dir, each top-level positive* or negative* fixture file is evaluated as its own root " +
		"and each top-level subdirectory of a test directory is one multi-file root per polarity. " +
		"The tests stored in the Datadog backend evaluate all positive (negative) fixtures of a rule as one root.",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:  "rule",
			Usage: "only test rules with these IDs or names (default: all rules)",
		},
		&cli.StringSliceFlag{
			Name:    "type",
			Aliases: []string{"t"},
			Usage:   "only test rules for these platforms",
		},
		&cli.StringFlag{
			Name: "rules-dir",
			Usage: "test the rules of this assets directory (queries/<platform>/.../<rule> and libraries/) " +
				"instead of the rules stored in the Datadog backend",
		},
	},
	Action: runTestRules,
}

func runTestRules(ctx context.Context, c *cli.Command) error {
	var suite *ruletest.Suite
	var err error
	opts := ruletest.Options{Timeout: defaultRuleTestTimeout}
	if dir := c.String("rules-dir"); dir != "" {
		suite, err = ruletest.LoadDir(ctx, dir)
		opts.RequireFixtures = true
	} else {
		suite, err = ruletest.LoadAPI(ctx, datadog.NewDatadogClient())
		opts.LegacyRoots = true
	}
	if err != nil {
		return err
	}

	ruleFilter := c.StringSlice("rule")
	platformFilter := c.StringSlice("type")

	var results []ruleOutcome
	allPass := true
	for _, rule := range suite.Rules {
		if !rule.Match(platformFilter, ruleFilter) {
			continue
		}
		res, err := suite.Run(ctx, rule, opts)
		if err != nil {
			return fmt.Errorf("testing rule %s: %w", rule.ID, err)
		}
		results = append(results, ruleOutcome{id: rule.ID, mismatches: formatMismatches(res.Mismatches)})
		allPass = allPass && res.Passed()
	}
	return finishTests(results, allPass)
}

func formatMismatches(mismatches []ruletest.Mismatch) []string {
	out := make([]string, 0, len(mismatches))
	for _, m := range mismatches {
		var line string
		switch m.Kind {
		case ruletest.MissingFinding:
			line = fmt.Sprintf("Missing expected: %#v", ruleFinding(m.Finding))
		case ruletest.UnexpectedFinding:
			line = fmt.Sprintf("Unexpected finding: %#v", ruleFinding(m.Finding))
		default:
			line = m.Message
		}
		if m.Case > 0 {
			label := "without arguments"
			if m.Arguments {
				label = "with arguments"
			}
			line = fmt.Sprintf("case %d %s: %s", m.Case, label, line)
		}
		out = append(out, line)
	}
	return out
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
