package helm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInvocationMarkerRoundTrip(t *testing.T) {
	marker := invocationMarker{Line: 6, Col: 12}.String()
	require.Equal(t, "# KICS_HELM_INVOCATION_6_12:\n", marker)
	require.True(t, hasInvocationMarker("a\n"+marker))
	for _, form := range []string{marker, marker[:len(marker)-1], "  " + marker} {
		got, ok := parseInvocationMarker(form)
		require.True(t, ok, form)
		require.Equal(t, invocationMarker{Line: 6, Col: 12}, got)
	}
	for _, line := range []string{
		"# something else", "# KICS_HELM_INVOCATION_6:", "# KICS_HELM_INVOCATION_6_12", "# KICS_HELM_INVOCATION_-6_12:",
		"# KICS_HELM_INVOCATION_6_12: text", `x: "# KICS_HELM_INVOCATION_6_12:"`,
	} {
		_, ok := parseInvocationMarker(line)
		require.False(t, ok, line)
	}
	require.Equal(t, "a\nb\n", removeInvocationMarkers("a\n"+marker+"b\n"))
	require.Equal(t, "a: \"# KICS_HELM_INVOCATION_6_12:\"\n", removeInvocationMarkers("a: \"# KICS_HELM_INVOCATION_6_12:\"\n"))
}

// A marker records the line of the template as written: the ID stamps above it
// are not counted.
func TestSourceLinesLeaveStampsOut(t *testing.T) {
	source := "# KICS_HELM_ID_0_0:\napiVersion: v1\nkind: A\n---\n# KICS_HELM_ID_0_4:\napiVersion: v1\n{{ include \"x\" . }}\n"
	lines := sourceLines{source: source, line: 1}
	require.Equal(t, 1, lines.lineOf(len("# KICS_HELM_ID_0_0:\n")))
	require.Equal(t, 5, lines.lineOf(len(source)-len("{{ include \"x\" . }}\n")))
	require.Equal(t, 5, lines.lineOf(len(source)-len(" . }}\n")))
}
