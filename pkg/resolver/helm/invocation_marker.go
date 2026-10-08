package helm

import (
	"strconv"
	"strings"
)

// invocationPrefix starts every invocation marker line.
const invocationPrefix = "# KICS_HELM_INVOCATION_"

// invocationMarker is printed ahead of the output of an include and records
// where the action is in the template as written, without ID stamps: its
// 1-based line and 0-based byte column. "# KICS_HELM_INVOCATION_<line>_<col>:".
type invocationMarker struct {
	Line, Col int
}

// String is the marker line, with its line break.
func (m invocationMarker) String() string {
	return invocationPrefix + strconv.Itoa(m.Line) + "_" + strconv.Itoa(m.Col) + ":\n"
}

// parseInvocationMarker reads a marker line, as String writes it.
func parseInvocationMarker(line string) (invocationMarker, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), invocationPrefix)
	if !ok {
		return invocationMarker{}, false
	}
	rest, ok = strings.CutSuffix(rest, ":")
	if !ok {
		return invocationMarker{}, false
	}
	lineText, colText, ok := strings.Cut(rest, "_")
	if !ok {
		return invocationMarker{}, false
	}
	l, lErr := strconv.ParseUint(lineText, 10, 31)
	c, cErr := strconv.ParseUint(colText, 10, 31)
	return invocationMarker{Line: int(l), Col: int(c)}, lErr == nil && cErr == nil
}

// hasInvocationMarker reports whether content may hold a marker.
func hasInvocationMarker(content string) bool {
	return strings.Contains(content, invocationPrefix)
}

// removeInvocationMarkers drops every marker line from content.
func removeInvocationMarkers(content string) string {
	if !hasInvocationMarker(content) {
		return content
	}
	var kept strings.Builder
	kept.Grow(len(content))
	for content != "" {
		line := content
		if i := strings.IndexByte(content, '\n'); i >= 0 {
			line = content[:i+1]
		}
		content = content[len(line):]
		if _, ok := parseInvocationMarker(line); !ok {
			kept.WriteString(line)
		}
	}
	return kept.String()
}
