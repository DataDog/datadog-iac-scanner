package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-iac-scanner/pkg/datadog"
)

func TestShouldRunRule(t *testing.T) {
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
			require.Equal(t, tc.wantRun, shouldRunRule(rule, platformFilter, tc.ruleFilter))
		})
	}

	// A rule without tests is never selected, whatever the filter matches.
	untested := *rule
	untested.Tests = nil
	require.False(t, shouldRunRule(&untested, []string{"Terraform"}, []string{"platform-provider-slug"}))
}
