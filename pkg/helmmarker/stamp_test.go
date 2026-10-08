package helmmarker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIDRoundTrip(t *testing.T) {
	stamp := string(AppendID(nil, 3, 17))
	require.Equal(t, "# KICS_HELM_ID_3_17:\n", stamp)
	for _, form := range []string{stamp, "# KICS_HELM_ID_3_17:", "KICS_HELM_ID_3_17", SearchKey(stamp)} {
		template, line, ok := ParseID(form)
		require.True(t, ok, form)
		require.Equal(t, [2]int{3, 17}, [2]int{template, line}, form)
	}
	_, _, ok := ParseID("# KICS_HELM_ID_3:")
	require.False(t, ok)
	_, _, ok = ParseID("apiVersion: v1")
	require.False(t, ok)
}

func TestIsIDKeyMatchesOnlyItsOwnStamp(t *testing.T) {
	key := "KICS_HELM_ID_1_0:"
	require.True(t, IsIDKey("# KICS_HELM_ID_1_0:", key))
	require.True(t, IsIDKey("  # KICS_HELM_ID_1_0:  ", key))
	require.False(t, IsIDKey("# KICS_HELM_ID_1_40:", key), `"0:" must not match "40:"`)
	require.False(t, IsIDKey("# KICS_HELM_ID_11_0:", key))
	require.False(t, IsIDKey("kind: Pod # KICS_HELM_ID_1_0:", key))
}

func TestRemoveIDLines(t *testing.T) {
	in := []byte("a: 1\n# KICS_HELM_ID_0_1:\n  # KICS_HELM_ID_2_5:\r\nb: 2\n")
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
		"# KICS_HELM_ID_3_14":           false,
		"data: # KICS_HELM_ID_3_14:":    false,
		"":                              false,
	} {
		require.Equal(t, want, IsIDLine(line), line)
	}
	require.Equal(t, "# KICS_HELM_ID_1_2:", FirstID("a: \"# KICS_HELM_ID_\"\n# KICS_HELM_ID_1_2:\nb: 1\n"))
	require.Empty(t, FirstID("a: \"# KICS_HELM_ID_\"\n"))
	require.Equal(t, "a: \"# KICS_HELM_ID_\"\n", string(RemoveIDLines([]byte("a: \"# KICS_HELM_ID_\"\n# KICS_HELM_ID_1_2:\n"))))
}
