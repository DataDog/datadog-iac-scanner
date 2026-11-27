package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
	"github.com/DataDog/datadog-iac-scanner/pkg/ruletest/harness"
)

func TestRuleTestOptionsKeepLegacyRootParityForEverySource(t *testing.T) {
	for _, tc := range []struct {
		name          string
		localRulesDir string
		wantFixtures  bool
	}{
		{name: "API source"},
		{name: "rules directory", localRulesDir: "/rules/assets", wantFixtures: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := ruleTestOptions(tc.localRulesDir, true, true)
			require.Equal(t, 3*time.Minute, opts.Timeout)
			require.True(t, opts.LegacyRoots)
			require.True(t, opts.CheckOrderDeterminism)
			require.Equal(t, tc.wantFixtures, opts.RequireFixtures)
			require.True(t, opts.UnknownMutations)
			require.True(t, opts.PairwiseUnknownMutations)
		})
	}
}

func TestAPIRuleFilterMatch(t *testing.T) {
	rule := &datadog.Rule{
		ID:          "platform-provider-slug",
		Platform:    "Terraform",
		IsPublished: true,
		LegacyId:    func() *string { s := "old-legacy-id"; return &s }(),
		LegacyIds:   []string{"renamed-away-id", "merged-rule-id"},
		Tests:       &datadog.RuleTests{},
	}

	for _, tc := range []struct {
		name       string
		platform   []string
		ruleFilter []string
		wantRun    bool
	}{
		{name: "no_filter_runs", ruleFilter: nil, wantRun: true},
		{name: "canonical_id", ruleFilter: []string{"platform-provider-slug"}, wantRun: true},
		{name: "legacy_id", ruleFilter: []string{"old-legacy-id"}, wantRun: true},
		{name: "legacy_ids_entry", ruleFilter: []string{"merged-rule-id"}, wantRun: true},
		{name: "unknown_id_skipped", ruleFilter: []string{"unrelated-id"}, wantRun: false},
		{name: "platform_mismatch_skipped", platform: []string{"Dockerfile"}, ruleFilter: []string{"platform-provider-slug"}, wantRun: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			platformFilter := tc.platform
			if platformFilter == nil {
				platformFilter = []string{"Terraform"}
			}
			require.Equal(t, tc.wantRun, harness.FromAPIRule(rule).Match(platformFilter, tc.ruleFilter))
		})
	}

}
