package main

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	"github.com/stretchr/testify/assert"
	cli "github.com/urfave/cli/v3"
)

func TestApplyPlatformFilters(t *testing.T) {
	all := []string{"Ansible", "CICD", "CloudFormation", "Dockerfile", "Kubernetes", "Terraform"}

	tests := []struct {
		name            string
		cliPlatforms    []string
		onlyPlatforms   []string
		ignorePlatforms []string
		want            []string
	}{
		{
			name:         "no filters returns cli platforms unchanged",
			cliPlatforms: all,
			want:         all,
		},
		{
			name:          "only-platforms restricts to subset",
			cliPlatforms:  all,
			onlyPlatforms: []string{"Terraform", "Kubernetes"},
			want:          []string{"Terraform", "Kubernetes"},
		},
		{
			name:            "ignore-platforms removes entries",
			cliPlatforms:    all,
			ignorePlatforms: []string{"Dockerfile"},
			want:            []string{"Ansible", "CICD", "CloudFormation", "Kubernetes", "Terraform"},
		},
		{
			name:            "case-insensitive only-platforms",
			cliPlatforms:    all,
			onlyPlatforms:   []string{"terraform"},
			want:            []string{"Terraform"},
		},
		{
			name:            "case-insensitive ignore-platforms",
			cliPlatforms:    all,
			ignorePlatforms: []string{"kubernetes"},
			want:            []string{"Ansible", "CICD", "CloudFormation", "Dockerfile", "Terraform"},
		},
		{
			name:            "only and ignore combined",
			cliPlatforms:    all,
			onlyPlatforms:   []string{"Terraform", "Kubernetes", "Dockerfile"},
			ignorePlatforms: []string{"Dockerfile"},
			want:            []string{"Kubernetes", "Terraform"},
		},
		{
			name:          "only-platforms not in cli list returns empty",
			cliPlatforms:  []string{"Terraform"},
			onlyPlatforms: []string{"Kubernetes"},
			want:          []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scan.ApplyPlatformFilters(tt.cliPlatforms, tt.onlyPlatforms, tt.ignorePlatforms)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestTerraformPlanFlag(t *testing.T) {
	tests := []struct {
		name     string
		flagSet  bool
		expected bool
	}{
		{
			name:     "flag is present in command definition",
			flagSet:  false,
			expected: false,
		},
		{
			name:     "flag defaults to false",
			flagSet:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify flag exists in scanAction command
			var foundFlag *cli.BoolFlag
			for _, flag := range scanAction.Flags {
				if boolFlag, ok := flag.(*cli.BoolFlag); ok && boolFlag.Name == "x-terraform-plan" {
					foundFlag = boolFlag
					break
				}
			}

			assert.NotNil(t, foundFlag, "x-terraform-plan flag should be defined")
			assert.True(t, foundFlag.Hidden, "x-terraform-plan flag should be hidden")
			assert.Equal(t, false, foundFlag.Value, "x-terraform-plan flag should default to false")
			assert.Contains(t, foundFlag.Usage, "experimental", "flag usage should indicate experimental status")
		})
	}
}
