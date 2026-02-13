package scan

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Client(t *testing.T) {
	ctx := context.Background()
	params := &Parameters{
		PreviewLines:   3,
		ExcludeResults: []string{},
	}

	client, err := NewClient(ctx, params, nil)

	require.NotNil(t, client)
	require.NoError(t, err)
}

func Test_ClientError(t *testing.T) {
	ctx := context.Background()
	params := &Parameters{
		PreviewLines:   0,
		ExcludeResults: []string{},
	}

	client, err := NewClient(ctx, params, nil)

	require.Nil(t, client)
	require.Error(t, err)
}
