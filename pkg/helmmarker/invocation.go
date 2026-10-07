package helmmarker

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// InvocationPrefix starts every invocation marker line. A marker is printed
// ahead of the output of an include and records where the action is:
// "# KICS_HELM_INVOCATION_<line>_<column>:".
const InvocationPrefix = "# KICS_HELM_INVOCATION_"

var (
	invocationLinePattern   = regexp.MustCompile(`(?m)^[ \t]*# KICS_HELM_INVOCATION_\d+_\d+:[^\r\n]*(?:\r?\n|$)`)
	invocationMarkerPattern = regexp.MustCompile(`^[ \t]*# KICS_HELM_INVOCATION_(\d+)_(\d+):`)
)

// Invocation is the marker line, with its line break, for the action at line
// and column of a template source.
func Invocation(line, col int) string {
	return fmt.Sprintf("%s%d_%d:\n", InvocationPrefix, line, col)
}

// HasInvocation reports whether content holds a marker.
func HasInvocation(content string) bool {
	return strings.Contains(content, InvocationPrefix)
}

// RemoveInvocations drops every marker line from content.
func RemoveInvocations(content string) string {
	return invocationLinePattern.ReplaceAllString(content, "")
}

// ParseInvocation reads a marker line.
func ParseInvocation(line string) (srcLine, col int, ok bool) {
	match := invocationMarkerPattern.FindStringSubmatch(line)
	if match == nil {
		return 0, 0, false
	}
	srcLine, lineErr := strconv.Atoi(match[1])
	col, colErr := strconv.Atoi(match[2])
	return srcLine, col, lineErr == nil && colErr == nil
}
