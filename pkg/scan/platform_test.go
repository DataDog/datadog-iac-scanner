package scan

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestGetEffectivePlatforms(t *testing.T) {
	tests := []struct {
		name            string
		platform        []string
		ignorePlatforms []string
		onlyPlatforms   []string
		want            []string
	}{
		{
			name:     "no config returns full platform list",
			platform: []string{"Ansible", "Kubernetes", "Terraform"},
			want:     []string{"Ansible", "Kubernetes", "Terraform"},
		},
		{
			name:            "ignore one platform removes it",
			platform:        []string{"Ansible", "Kubernetes", "Terraform"},
			ignorePlatforms: []string{"Ansible"},
			want:            []string{"Kubernetes", "Terraform"},
		},
		{
			name:            "ignore multiple platforms removes all of them",
			platform:        []string{"Ansible", "Kubernetes", "Terraform"},
			ignorePlatforms: []string{"Ansible", "Terraform"},
			want:            []string{"Kubernetes"},
		},
		{
			name:          "only one platform restricts to it",
			platform:      []string{"Ansible", "Kubernetes", "Terraform"},
			onlyPlatforms: []string{"Terraform"},
			want:          []string{"Terraform"},
		},
		{
			name:            "only and ignore combined: ignore wins",
			platform:        []string{"Ansible", "Kubernetes", "Terraform"},
			onlyPlatforms:   []string{"Kubernetes", "Terraform"},
			ignorePlatforms: []string{"Kubernetes"},
			want:            []string{"Terraform"},
		},
		{
			name:            "ignore platform not in list is a no-op",
			platform:        []string{"Terraform"},
			ignorePlatforms: []string{"Ansible"},
			want:            []string{"Terraform"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parameters{
				Platform: tt.platform,
				Config: config.IacConfig{
					IgnorePlatforms: tt.ignorePlatforms,
					OnlyPlatforms:   tt.onlyPlatforms,
				},
			}
			assert.ElementsMatch(t, tt.want, p.GetEffectivePlatforms())
		})
	}
}
