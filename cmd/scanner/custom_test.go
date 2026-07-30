package main

import (
	"testing"

	iacplatforms "github.com/DataDog/datadog-iac-scanner/pkg/platforms"
	"github.com/stretchr/testify/assert"
)

func TestValidatePlatform_SupportedPlatforms(t *testing.T) {
	for _, p := range iacplatforms.Supported {
		assert.NoError(t, validatePlatform(p), "platform %q", p)
	}
}

func TestValidatePlatform_CaseInsensitive(t *testing.T) {
	assert.NoError(t, validatePlatform("TERRAFORM"))
	assert.NoError(t, validatePlatform("cicd"))
}

func TestValidatePlatform_Unsupported(t *testing.T) {
	err := validatePlatform("foobar")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "foobar")
}

func TestValidatePlatform_ARMRejected(t *testing.T) {
	err := validatePlatform("azureresourcemanager")
	assert.Error(t, err)
}
