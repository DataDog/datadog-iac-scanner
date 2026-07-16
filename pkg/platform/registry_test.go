/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package platform_test

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalID_UnknownReturnsFalse(t *testing.T) {
	_, ok := platform.CanonicalID("totallymadeup")
	assert.False(t, ok)
}

func TestCanonicalID_CaseInsensitive(t *testing.T) {
	cases := []struct {
		input  string
		wantID platform.ID
	}{
		{"terraform", platform.Terraform},
		{"Terraform", platform.Terraform},
		{"TERRAFORM", platform.Terraform},
		{"cloudformation", platform.CloudFormation},
		{"CloudFormation", platform.CloudFormation},
		{"cloudFormation", platform.CloudFormation},
		{"CF", platform.CloudFormation},
		{"cf", platform.CloudFormation},
		{"kubernetes", platform.Kubernetes},
		{"k8s", platform.Kubernetes},
		{"K8S", platform.Kubernetes},
		{"ansible", platform.Ansible},
		{"Ansible", platform.Ansible},
		{"cicd", platform.CICD},
		{"CICD", platform.CICD},
		{"dockerfile", platform.Dockerfile},
		{"Dockerfile", platform.Dockerfile},
		{"knative", platform.Knative},
		{"Knative", platform.Knative},
		{"serverlessfw", platform.ServerlessFW},
		{"ServerlessFW", platform.ServerlessFW},
		{"crossplane", platform.Crossplane},
		{"bicep", platform.AzureResourceManager},
		{"AzureResourceManager", platform.AzureResourceManager},
		{"openapi", platform.OpenAPI},
		{"OpenAPI", platform.OpenAPI},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			id, ok := platform.CanonicalID(tc.input)
			require.True(t, ok, "expected %q to be found", tc.input)
			assert.Equal(t, tc.wantID, id)
		})
	}
}

func TestLibraryIdentity_CloudFormation(t *testing.T) {
	lib, ok := platform.LibraryIdentity("cloudFormation")
	require.True(t, ok)
	assert.Equal(t, "cloudFormation", lib)
}

func TestLibraryIdentity_K8s(t *testing.T) {
	lib, ok := platform.LibraryIdentity("k8s")
	require.True(t, ok)
	assert.Equal(t, "k8s", lib)
}

func TestLibraryIdentityOrUnknown(t *testing.T) {
	tests := []struct {
		platform string
		want     string
	}{
		{"Common", "common"},
		{"Ansible", "ansible"},
		{"CloudFormation", "cloudFormation"},
		{"CICD", "cicd"},
		{"Kubernetes", "k8s"},
		{"OpenAPI", "openAPI"},
		{"Terraform", "terraform"},
		{"AzureResourceManager", "azureResourceManager"},
		{"Unknown", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			assert.Equal(t, tt.want, platform.LibraryIdentityOrUnknown(tt.platform))
		})
	}
}

func TestLibraryName(t *testing.T) {
	assert.Equal(t, "terraform", platform.LibraryName("Terraform"))
	assert.Equal(t, "custom", platform.LibraryName("Custom"))
}

func TestCompareKey_Aliases(t *testing.T) {
	assert.Equal(t, string(platform.Kubernetes), platform.CompareKey("k8s"))
	assert.Equal(t, string(platform.Kubernetes), platform.CompareKey("Kubernetes"))
	assert.Equal(t, string(platform.CloudFormation), platform.CompareKey("CF"))
	assert.Equal(t, string(platform.CloudFormation), platform.CompareKey("cloudFormation"))
}

func TestMatches_Aliases(t *testing.T) {
	assert.True(t, platform.Matches("k8s", "Kubernetes"))
	assert.True(t, platform.Matches("CF", "CloudFormation"))
	assert.False(t, platform.Matches("terraform", "k8s"))
}

func TestRoundTrip_MigratedPlatforms(t *testing.T) {
	cases := []struct {
		name    string
		wantLib string
	}{
		{"terraform", "terraform"},
		{"ansible", "ansible"},
		{"cicd", "cicd"},
		{"dockerfile", "dockerfile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lib, ok := platform.LibraryIdentity(tc.name)
			require.True(t, ok)
			assert.Equal(t, tc.wantLib, lib)

			id, ok := platform.CanonicalID(tc.name)
			require.True(t, ok)
			assert.Equal(t, platform.ID(tc.name), id)
		})
	}
}

func TestPayloadTargets(t *testing.T) {
	cases := []struct {
		platform string
		want     []platform.ID
	}{
		{string(platform.CloudFormation), []platform.ID{platform.CloudFormation}},
		{string(platform.Kubernetes), []platform.ID{platform.Kubernetes}},
		{string(platform.Knative), []platform.ID{platform.Knative, platform.Kubernetes}},
		{string(platform.ServerlessFW), []platform.ID{platform.ServerlessFW, platform.CloudFormation}},
	}
	for _, tc := range cases {
		t.Run(tc.platform, func(t *testing.T) {
			assert.ElementsMatch(t, tc.want, platform.PayloadTargets(tc.platform))
		})
	}
}
