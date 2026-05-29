package main

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/scan"
	"github.com/stretchr/testify/assert"
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
