package helm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInvocationRoundTrip(t *testing.T) {
	marker := invocationMarker(6, 12)
	require.Equal(t, "# KICS_HELM_INVOCATION_6_12:\n", marker)
	require.True(t, hasInvocationMarker("a\n"+marker))
	line, col, ok := parseInvocationMarker(marker[:len(marker)-1])
	require.True(t, ok)
	require.Equal(t, [2]int{6, 12}, [2]int{line, col})
	_, _, ok = parseInvocationMarker("# something else")
	require.False(t, ok)
	require.Equal(t, "a\nb\n", removeInvocationMarkers("a\n"+marker+"b\n"))
}
