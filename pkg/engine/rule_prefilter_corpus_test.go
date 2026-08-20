/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This is the gate the prefilter needs to be safe to productize: for every rule
// in the ruleset, the fixture that is known to trigger it must declare
// something the rule is anchored on. A rule that fails it would be skipped on a
// repository it should have reported, so a new rule idiom that escapes the
// static bound fails here instead of silently dropping findings.
//
// Point RULES_DIR at a checkout of the ruleset to run it, e.g.
//
//	RULES_DIR=~/dd/datadog-iac-scanner-default-rules go test ./pkg/engine -run Corpus -v
func TestRuleAnchorsCoverRuleFixtures(t *testing.T) {
	rulesDir := os.Getenv("RULES_DIR")
	if rulesDir == "" {
		t.Skip("set RULES_DIR to a ruleset checkout")
	}
	queries := filepath.Join(rulesDir, "assets", "queries", "terraform")

	var analysed, unbounded, noAnchors, checked int
	var falseSkips []string

	err := filepath.Walk(queries, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Name() != "query.rego" {
			return err
		}
		analysed++
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		anchors, bounded := ruleAnchors(string(content))
		switch {
		case !bounded:
			unbounded++
			return nil
		case len(anchors) == 0:
			noAnchors++
			return nil
		}

		present, ok := fixtureAnchors(t, filepath.Dir(path))
		if !ok {
			return nil
		}
		checked++
		if !anyAnchorPresent(anchors, present) {
			falseSkips = append(falseSkips, filepath.Base(filepath.Dir(path)))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", queries, err)
	}
	if analysed == 0 {
		t.Fatalf("no rules found under %s", queries)
	}

	t.Logf("rules=%d unbounded=%d no-anchors=%d cross-checked=%d",
		analysed, unbounded, noAnchors, checked)
	if len(falseSkips) > 0 {
		t.Fatalf("%d rules would be skipped on their own positive fixture: %v",
			len(falseSkips), falseSkips)
	}
}

var (
	fixtureResource = regexp.MustCompile(`(?m)^\s*resource\s+"([^"]+)"`)
	fixtureData     = regexp.MustCompile(`(?m)^\s*data\s+"([^"]+)"`)
	fixtureBlock    = regexp.MustCompile(`(?m)^\s*(module|provider|terraform|output|variable|locals)\b`)
)

// fixtureAnchors reads the anchors a rule's positive fixtures declare. It reads
// the fixture text rather than parsing it, which is enough to answer whether the
// blocks a rule is anchored on are present.
func fixtureAnchors(t *testing.T, ruleDir string) (map[string]bool, bool) {
	t.Helper()
	present := make(map[string]bool)
	found := false
	_ = filepath.Walk(filepath.Join(ruleDir, "test"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasPrefix(info.Name(), "positive") {
			return nil //nolint:nilerr // a rule without fixtures is reported by the caller
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		found = true
		for _, m := range fixtureResource.FindAllStringSubmatch(string(body), -1) {
			present[resourceAnchor(m[1])] = true
		}
		for _, m := range fixtureData.FindAllStringSubmatch(string(body), -1) {
			present[dataAnchor(m[1])] = true
		}
		for _, m := range fixtureBlock.FindAllStringSubmatch(string(body), -1) {
			present[blockAnchor(m[1])] = true
		}
		return nil
	})
	return present, found
}
