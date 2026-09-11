package platforms

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDockerComposeIsSupported(t *testing.T) {
	require.Contains(t, Supported, "DockerCompose")
}
