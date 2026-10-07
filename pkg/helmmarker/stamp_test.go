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
	in := []byte("a: 1\n# KICS_HELM_ID_0_1:\n  # KICS_HELM_ID_2_5: x\r\nb: 2\n")
	require.Equal(t, "a: 1\nb: 2\n", string(RemoveIDLines(in)))
}

func TestInvocationRoundTrip(t *testing.T) {
	marker := Invocation(6, 12)
	require.Equal(t, "# KICS_HELM_INVOCATION_6_12:\n", marker)
	require.True(t, HasInvocation("a\n"+marker))
	line, col, ok := ParseInvocation(marker[:len(marker)-1])
	require.True(t, ok)
	require.Equal(t, [2]int{6, 12}, [2]int{line, col})
	_, _, ok = ParseInvocation("# something else")
	require.False(t, ok)
	require.Equal(t, "a\nb\n", RemoveInvocations("a\n"+marker+"b\n"))
}
