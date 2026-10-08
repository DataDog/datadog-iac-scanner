package helm

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// invocationPrefix starts every invocation marker line. A marker is printed
// ahead of the output of an include and records where the action is:
// "# KICS_HELM_INVOCATION_<line>_<column>:".
const invocationPrefix = "# KICS_HELM_INVOCATION_"

var (
	invocationLinePattern   = regexp.MustCompile(`(?m)^[ \t]*# KICS_HELM_INVOCATION_\d+_\d+:[^\r\n]*(?:\r?\n|$)`)
	invocationMarkerPattern = regexp.MustCompile(`^[ \t]*# KICS_HELM_INVOCATION_(\d+)_(\d+):`)
)

// invocationMarker is the marker line, with its line break, for the action at line
// and column of a template source.
func invocationMarker(line, col int) string {
	return fmt.Sprintf("%s%d_%d:\n", invocationPrefix, line, col)
}

// hasInvocationMarker reports whether content holds a marker.
func hasInvocationMarker(content string) bool {
	return strings.Contains(content, invocationPrefix)
}

// removeInvocationMarkers drops every marker line from content.
func removeInvocationMarkers(content string) string {
	return invocationLinePattern.ReplaceAllString(content, "")
}

// parseInvocationMarker reads a marker line.
func parseInvocationMarker(line string) (srcLine, col int, ok bool) {
	match := invocationMarkerPattern.FindStringSubmatch(line)
	if match == nil {
		return 0, 0, false
	}
	srcLine, lineErr := strconv.Atoi(match[1])
	col, colErr := strconv.Atoi(match[2])
	return srcLine, col, lineErr == nil && colErr == nil
}
