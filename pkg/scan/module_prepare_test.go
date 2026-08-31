package scan

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrepareTerraformModulesRequiresNetworkIsolation(t *testing.T) {
	_, err := PrepareTerraformModules(t.Context(), &Parameters{}, nil, nil)
	require.ErrorContains(t, err, "requires network isolation")
}
