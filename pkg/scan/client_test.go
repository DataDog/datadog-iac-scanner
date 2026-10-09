package scan

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseTerraformModules(t *testing.T) {
	for _, value := range []string{"off", "on"} {
		setting, err := ParseTerraformModules(value)
		require.NoError(t, err)
		require.Equal(t, TerraformModulesSetting(value), setting)
	}

	for _, value := range []string{"offline", "fetch", "online"} {
		_, err := ParseTerraformModules(value)
		require.ErrorContains(t, err, "expected off or on")
	}
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

