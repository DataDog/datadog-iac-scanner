package resolver

import (
	"path/filepath"
	"testing"

	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/stretchr/testify/require"
)

func TestModuleIdentitiesSeparateCallsAndDeduplicateAcquisition(t *testing.T) {
	first := &tfmodules.ParsedModule{
		FileName:   filepath.Join("/repo", "a", "main.tf"),
		DefLine:    1,
		DefEndLine: 3,
		Name:       "vpc_a",
		Source:     "git::https://github.com/acme/network.git//modules/a?ref=v1",
	}
	second := &tfmodules.ParsedModule{
		FileName:   filepath.Join("/repo", "b", "main.tf"),
		DefLine:    1,
		DefEndLine: 3,
		Name:       "vpc_b",
		Source:     "git::https://github.com/acme/network.git//modules/b?ref=v1",
	}

	require.NotEqual(t, ParsedModuleCallID(first), ParsedModuleCallID(second))
	require.Equal(
		t,
		ModuleAcquisitionKey(first.Source, first.Version),
		ModuleAcquisitionKey(second.Source, second.Version),
	)
}
