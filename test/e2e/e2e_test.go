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
				Rules:      1125,
				ViolationBreakdowns: map[string]map[string]int{
					"LOW": {
						"a2b3c4d5-e6f7-8901-gh23-ijkl456m7890": 1,
						"c5b31ab9-0f26-4a49-b8aa-4cc064392f4d": 2,
					},
					"MEDIUM": {
						"f861041c-8c9f-4156-acfc-5e6e524f5884": 1,
						"568a4d22-3517-44a6-a7ad-6a7eed88722c": 1,
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
				Rules:      1125,
				ViolationBreakdowns: map[string]map[string]int{
					"LOW": {
						"c5b31ab9-0f26-4a49-b8aa-4cc064392f4d": 2,
					},
					"MEDIUM": {
						"f861041c-8c9f-4156-acfc-5e6e524f5884": 1,
						"568a4d22-3517-44a6-a7ad-6a7eed88722c": 1,
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
						"dd29336b-fe57-445b-a26e-e6aa867ae609": 1,
					},
					"MEDIUM": {
						"02323c00-cdc3-4fdc-a310-4f2b3e7a1660": 1,
						"48471392-d4d0-47c0-b135-cdec95eb3eef": 1,
						"611ab018-c4aa-4ba2-b0f6-a448337509a6": 1,
						"dbbc6705-d541-43b0-b166-dd4be8208b54": 1,
						"f377b83e-bd07-4f48-a591-60c82b14a78b": 1,
					},
					"LOW": {
						"268ca686-7fb7-4ae9-b129-955a2a89064e": 1,
						"48a5beba-e4c0-4584-a2aa-e6894e4cf424": 1,
						"4a20ebac-1060-4c81-95d1-1f7f620e983b": 1,
						"7c81d34c-8e5a-402b-9798-9f442630e678": 1,
						"8b36775e-183d-4d46-b0f7-96a6f34a723f": 1,
						"caa3479d-885d-4882-9aac-95e5e78ef5c2": 1,
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
						"02323c00-cdc3-4fdc-a310-4f2b3e7a1660": 1,
						"48471392-d4d0-47c0-b135-cdec95eb3eef": 1,
						"611ab018-c4aa-4ba2-b0f6-a448337509a6": 1,
						"dbbc6705-d541-43b0-b166-dd4be8208b54": 1,
						"f377b83e-bd07-4f48-a591-60c82b14a78b": 1,
					},
					"LOW": {
						"268ca686-7fb7-4ae9-b129-955a2a89064e": 1,
						"48a5beba-e4c0-4584-a2aa-e6894e4cf424": 1,
						"4a20ebac-1060-4c81-95d1-1f7f620e983b": 1,
						"7c81d34c-8e5a-402b-9798-9f442630e678": 1,
						"8b36775e-183d-4d46-b0f7-96a6f34a723f": 1,
						"caa3479d-885d-4882-9aac-95e5e78ef5c2": 1,
					},
				},
			},
		},
		{
			name:     "cicd no exclusions",
			testFile: filepath.Join("fixtures", "cicd-no-exclusions.yaml"),
			expectedOutput: scan.ScanStats{
				Violations: 2,
				Files:      1,
				Rules:      5,
				ViolationBreakdowns: map[string]map[string]int{
					"LOW": {
						"555ab8f9-2001-455e-a077-f2d0f41e2fb9": 1,
					},
					"MEDIUM": {
						"d946b13a-0b2b-49c5-b560-45b9666373e1": 1,
					},
				},
			},
		},
		{
			name:     "cicd disabled rule inline",
			testFile: filepath.Join("fixtures", "cicd-inline-disabled-rule.yaml"),
			expectedOutput: scan.ScanStats{
				Violations: 1,
				Files:      1,
				Rules:      5,
				ViolationBreakdowns: map[string]map[string]int{
					"MEDIUM": {
						"d946b13a-0b2b-49c5-b560-45b9666373e1": 1,
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
			params.SCIInfo = model.SCIInfo{DiffAware: model.DiffAware{Enabled: false}, RunType: "code_update", RepositoryCommitInfo: model.RepositoryCommitInfo{RepositoryUrl: "test/url", CommitSHA: "test/hash", Branch: "test/branch"}}
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
