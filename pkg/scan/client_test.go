package scan

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTerraformModulesMode(t *testing.T) {
	for _, value := range []string{"off", "offline", "fetch"} {
		mode, err := ParseTerraformModulesMode(value)
		require.NoError(t, err)
		require.Equal(t, TerraformModulesMode(value), mode)
	}

	_, err := ParseTerraformModulesMode("online")
	require.ErrorContains(t, err, "expected off, offline, or fetch")
}

func Test_Client(t *testing.T) {
	ctx := context.Background()
	params := &Parameters{
		PreviewLines: 3,
	}

	client, err := NewClient(ctx, params, nil)

	require.NotNil(t, client)
	require.NoError(t, err)
}

func Test_ClientError(t *testing.T) {
	ctx := context.Background()
	params := &Parameters{
		PreviewLines: 0,
	}

	client, err := NewClient(ctx, params, nil)

	require.Nil(t, client)
	require.Error(t, err)
}

func Test_ShouldScanTfPlans_ParameterPropagation(t *testing.T) {
	tests := []struct {
		name              string
		shouldScanTfPlans bool
	}{
		{
			name:              "ShouldScanTfPlans set to true",
			shouldScanTfPlans: true,
		},
		{
			name:              "ShouldScanTfPlans set to false",
			shouldScanTfPlans: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			params := &Parameters{
				PreviewLines:      3,
				ShouldScanTfPlans: tt.shouldScanTfPlans,
			}

			client, err := NewClient(ctx, params, nil)

			require.NoError(t, err)
			require.NotNil(t, client)
			assert.Equal(t, tt.shouldScanTfPlans, client.ScanParams.ShouldScanTfPlans,
				"ShouldScanTfPlans should be propagated to client")
		})
	}
}
