package helm

import (
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

// Two value lines with the same prefix could each have written the rendered
// line; the line must not be guessed from the first of them.
func TestUniqueLineTwoValueCandidatesIsNotGuessed(t *testing.T) {
	lines := []string{"apiVersion: v1", "kind: Pod", "metadata:", "  name: {{ .Values.a }}", "spec:", "  name: {{ .Values.b }}"}
	rendered := []string{"apiVersion: v1", "kind: Pod", "metadata:", "  name: A", "spec:", "  name: B"}
	invocations := model.HelmInvocations{{RenderedLine: 1, Position: model.ResourceLine{Line: 1}}}
	_, ok := uniqueLine(lines, rendered, invocations, 5, 1)
	require.False(t, ok)
}

// A line of plain text outside every block prints its own text once, so it is
// the writer even when a value line shares the prefix.
func TestUniqueLinePlainTextWriterAmongValueCandidates(t *testing.T) {
	lines := []string{"apiVersion: v1", "kind: Pod", "metadata:", "  name: {{ .Values.a }}", "spec:", "  name: Fixed"}
	rendered := []string{"apiVersion: v1", "kind: Pod", "metadata:", "  name: A", "spec:", "  name: Fixed"}
	invocations := model.HelmInvocations{{RenderedLine: 1, Position: model.ResourceLine{Line: 1}}}
	line, ok := uniqueLine(lines, rendered, invocations, 5, 1)
	require.True(t, ok)
	require.Equal(t, 5, line)
}

// A document starting with text of the template is searched from its stamp, not
// from its first include: a line written before the include is not told apart
// from a value printed after it.
func TestUniqueLineSearchesTheDocumentBeforeItsFirstInclude(t *testing.T) {
	lines := []string{"# KICS_HELM_ID_0_0:", "apiVersion: v1", "kind: Pod", "spec:", "  containers:",
		"    - image: {{ .Values.image }}", `  {{- include "volumes" . | nindent 2 }}`, "  selector: {{ .Values.s }}"}
	rendered := []string{"# KICS_HELM_ID_0_0:", "apiVersion: v1", "kind: Pod", "spec:", "  containers:",
		"    - image: nginx", "  volumes: []", "  selector: x"}
	invocations := model.HelmInvocations{{RenderedLine: 7, RenderedEnd: 8, Position: model.ResourceLine{Line: 6, Col: 2}}}
	start := documentStart(lines, lines[0], invocations)
	require.Equal(t, 1, start)
	line, ok := uniqueLine(lines, rendered, invocations, 5, start)
	require.True(t, ok)
	require.Equal(t, 5, line)
}

// The first line of a document is a line of plain text like the others.
func TestPlainLinesStartAtTheFirstSourceLine(t *testing.T) {
	lines := []string{"# KICS_HELM_ID_0_0:", "apiVersion: v1", "kind: Pod", "spec:", "  x: {{ .V }}"}
	written, next := plainLines(lines, nil, 1)
	require.Equal(t, []int{1, 2, 3}, written)
	require.Equal(t, 4, next)
}
