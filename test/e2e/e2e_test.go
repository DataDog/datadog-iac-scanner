package test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/internal/console"
	"github.com/DataDog/datadog-iac-scanner/pkg/featureflags"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	"github.com/stretchr/testify/require"
)

func Test_E2EExclusions(t *testing.T) {
	tests := []struct {
		name           string
		testFile       string
		expectedOutput scan.ScanStats
	}{
		{
			name:     "no exclusions",
			testFile: filepath.Join("fixtures", "no-exclusions.tf"),
			expectedOutput: scan.ScanStats{
				Violations: 5,
				Files:      1,
				Rules:      1123,
				ViolationBreakdowns: map[string]map[string]int{
					"LOW": {
						"terraform-aws-team-tag-not-present":                 1,
						"terraform-aws-s3-bucket-without-enabled-mfa-delete": 2,
					},
					"MEDIUM": {
						"terraform-aws-s3-bucket-logging-disabled":   1,
						"terraform-aws-s3-bucket-without-versioning": 1,
					},
				},
			},
		},
		{
			name:     "disabled rule inline",
			testFile: filepath.Join("fixtures", "inline-disabled-rule.tf"),
			expectedOutput: scan.ScanStats{
				Violations: 4,
				Files:      1,
				Rules:      1123,
				ViolationBreakdowns: map[string]map[string]int{
					"LOW": {
						"terraform-aws-s3-bucket-without-enabled-mfa-delete": 2,
					},
					"MEDIUM": {
						"terraform-aws-s3-bucket-logging-disabled":   1,
						"terraform-aws-s3-bucket-without-versioning": 1,
					},
				},
			},
		},
		{
			name:     "k8s no exclusions",
			testFile: filepath.Join("fixtures", "k8s-no-exclusions.yaml"),
			expectedOutput: scan.ScanStats{
				Violations: 12,
				Files:      1,
				Rules:      142,
				ViolationBreakdowns: map[string]map[string]int{
					"HIGH": {
						"kubernetes-container-is-privileged": 1,
					},
					"MEDIUM": {
						"kubernetes-containers-run-with-low-uid":                  1,
						"kubernetes-net-raw-capabilities-not-being-dropped":       1,
						"kubernetes-seccomp-profile-is-not-configured":            1,
						"kubernetes-service-account-token-automount-not-disabled": 1,
						"kubernetes-using-unrecommended-namespace":                1,
					},
					"LOW": {
						"kubernetes-image-pull-policy-of-container-is-not-always": 1,
						"kubernetes-image-without-digest":                         1,
						"kubernetes-missing-app-armor-config":                     1,
						"kubernetes-no-drop-capabilities-for-containers":          1,
						"kubernetes-pod-or-container-without-limit-range":         1,
						"kubernetes-pod-or-container-without-resource-quota":      1,
					},
				},
			},
		},
		{
			name:     "k8s disabled rule inline",
			testFile: filepath.Join("fixtures", "k8s-inline-disabled-rule.yaml"),
			expectedOutput: scan.ScanStats{
				Violations: 11,
				Files:      1,
				Rules:      142,
				ViolationBreakdowns: map[string]map[string]int{
					"MEDIUM": {
						"kubernetes-containers-run-with-low-uid":                  1,
						"kubernetes-net-raw-capabilities-not-being-dropped":       1,
						"kubernetes-seccomp-profile-is-not-configured":            1,
						"kubernetes-service-account-token-automount-not-disabled": 1,
						"kubernetes-using-unrecommended-namespace":                1,
					},
					"LOW": {
						"kubernetes-image-pull-policy-of-container-is-not-always": 1,
						"kubernetes-image-without-digest":                         1,
						"kubernetes-missing-app-armor-config":                     1,
						"kubernetes-no-drop-capabilities-for-containers":          1,
						"kubernetes-pod-or-container-without-limit-range":         1,
						"kubernetes-pod-or-container-without-resource-quota":      1,
					},
				},
			},
		},
		{
			name:     "cicd no exclusions",
			testFile: filepath.Join("fixtures", ".github/cicd-no-exclusions.yaml"),
			expectedOutput: scan.ScanStats{
				Violations: 4,
				Files:      1,
				Rules:      26,
				ViolationBreakdowns: map[string]map[string]int{
					"LOW": {
						"cicd-github-anonymous-definition":                    1,
						"cicd-github-concurrency-limits":                      1,
						"cicd-github-unpinned-actions-full-length-commit-sha": 1,
					},
					"MEDIUM": {
						"cicd-github-unspecified-workflows-permissions": 1,
					},
				},
			},
		},
		{
			name:     "cicd disabled rule inline",
			testFile: filepath.Join("fixtures", ".github/cicd-inline-disabled-rule.yaml"),
			expectedOutput: scan.ScanStats{
				Violations: 3,
				Files:      1,
				Rules:      26,
				ViolationBreakdowns: map[string]map[string]int{
					"LOW": {
						"cicd-github-anonymous-definition": 1,
						"cicd-github-concurrency-limits":   1,
					},
					"MEDIUM": {
						"cicd-github-unspecified-workflows-permissions": 1,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, ctx := scan.GetDefaultParameters(context.Background(), "")
			params.Path = []string{tt.testFile}
			params.OutputPath = t.TempDir()
			params.SCIInfo = model.SCIInfo{DiffAware: model.DiffAware{Enabled: false}, RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"}}
			params.FlagEvaluator = featureflags.NewLocalEvaluator()
			metadata, err := console.ExecuteScan(ctx, params)
			require.NoError(t, err)
			require.Equal(t, tt.expectedOutput.Violations, metadata.Stats.Violations)
			require.Equal(t, tt.expectedOutput.Files, metadata.Stats.Files)
			require.Equal(t, tt.expectedOutput.Rules, metadata.Stats.Rules)
			require.Equal(t, tt.expectedOutput.ViolationBreakdowns, metadata.Stats.ViolationBreakdowns)
		})
	}

}
