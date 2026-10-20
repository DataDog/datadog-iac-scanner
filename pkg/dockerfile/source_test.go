package dockerfile

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSourceLinesSharedWithParser(t *testing.T) {
	source := []byte("# escape=`\nfrom alpine\nrun echo `\n hi\nCOPY <<EOF /x\nFROM busybox\nEOF\n")
	var recorded []string
	calls := 0
	parsed, err := Parse(WithSourceLines(t.Context(), strings.Split(string(source), "\n"), func(lines []string) { recorded = lines; calls++ }), source)
	require.NoError(t, err)
	require.Len(t, parsed.AST.Children, 3)
	require.Equal(t, 1, calls)
	require.Equal(t, InstructionLines(strings.Split(string(source), "\n")), recorded)
	require.Equal(t, "run echo  hi", recorded[2])
	require.Empty(t, recorded[3])
	require.Empty(t, recorded[5], "heredoc payloads do not become instructions")
}
