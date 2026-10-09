package helmmarker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIDRoundTrip(t *testing.T) {
	id := ID{Template: 3, Line: 17}
	require.Equal(t, "# KICS_HELM_ID_3_17:\n", string(id.Append(nil)))
	require.Equal(t, "# KICS_HELM_ID_3_17:", id.String())
	require.Equal(t, "KICS_HELM_ID_3_17", id.SearchKey())
	for _, line := range []string{string(id.Append(nil)), id.String(), "  " + id.String() + " \r"} {
		got, ok := ParseIDLine(line)
		require.True(t, ok, line)
		require.Equal(t, id, got, line)
	}
	for _, key := range []string{id.SearchKey(), id.SearchKey() + ":"} {
		got, ok := ParseSearchKey(key)
		require.True(t, ok, key)
		require.Equal(t, id, got, key)
	}
	_, ok := ParseSearchKey("KICS_HELM_ID_3")
	require.False(t, ok)
	_, ok = ParseSearchKey("metadata:")
	require.False(t, ok)
}

func TestRemoveIDLines(t *testing.T) {
	in := []byte("a: 1\n# KICS_HELM_ID_0_1:\n  # KICS_HELM_ID_2_5:\r\nb: 2\n# KICS_HELM_ID_0_9:")
	require.Equal(t, "a: 1\nb: 2\n", string(RemoveIDLines(in)))
}

// Text that only mentions the prefix is not a stamp, so a template holding it
// in a string does not shift lines or lose its content.
func TestIDLineIsStrict(t *testing.T) {
	for line, want := range map[string]bool{
		"# KICS_HELM_ID_3_14:":          true,
		"  # KICS_HELM_ID_3_14:":        true,
		`  x: "# KICS_HELM_ID_"`:        false,
		"# KICS_HELM_ID_3_14: trailing": false,
		"# KICS_HELM_ID_3_:":            false,
		"# KICS_HELM_ID_a_1:":           false,
		"# KICS_HELM_ID_-3_1:":          false,
		"# KICS_HELM_ID_3_14":           false,
		"data: # KICS_HELM_ID_3_14:":    false,
		"":                              false,
	} {
		_, ok := ParseIDLine(line)
		require.Equal(t, want, ok, line)
	}
	require.Equal(t, "# KICS_HELM_ID_1_2:", FirstID("a: \"# KICS_HELM_ID_\"\n# KICS_HELM_ID_1_2:\nb: 1\n"))
	require.Empty(t, FirstID("a: \"# KICS_HELM_ID_\"\n"))
	require.Equal(t, "a: \"# KICS_HELM_ID_\"\n", string(RemoveIDLines([]byte("a: \"# KICS_HELM_ID_\"\n# KICS_HELM_ID_1_2:\n"))))
}
