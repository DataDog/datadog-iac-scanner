package helmmarker

import (
	"regexp"
	"strconv"
	"strings"
)

// decimal is the base stamp numbers are written in.
const decimal = 10

// IDPrefix starts every ID stamp line. A stamp is added above each top-level
// "apiVersion" of a template and names the template and the line it sits on:
// "# KICS_HELM_ID_<template>_<line>:".
const IDPrefix = "# KICS_HELM_ID_"

// idLinePattern matches a whole stamp line, with its line break.
var idLinePattern = regexp.MustCompile(`(?m)^[ \t]*# KICS_HELM_ID_\d+_\d+:[^\r\n]*(?:\r?\n|$)`)

// AppendID appends the stamp line of the template numbered template for the
// source line line (counted from 0).
func AppendID(dst []byte, template, line int) []byte {
	dst = append(dst, IDPrefix...)
	dst = strconv.AppendInt(dst, int64(template), decimal)
	dst = append(dst, '_')
	dst = strconv.AppendInt(dst, int64(line), decimal)
	return append(dst, ':', '\n')
}

// IsIDLine reports whether line holds a stamp.
func IsIDLine(line string) bool {
	return strings.Contains(line, IDPrefix)
}

// RemoveIDLines drops every stamp line from content.
func RemoveIDLines(content []byte) []byte {
	return idLinePattern.ReplaceAll(content, nil)
}

// ParseID reads the template number and source line of a stamp, given as the
// stamp line or the text of it without the leading "# " or trailing ":".
func ParseID(stamp string) (template, line int, ok bool) {
	rest := strings.TrimSuffix(strings.TrimSpace(stamp), ":")
	i := strings.Index(rest, strings.TrimPrefix(IDPrefix, "# "))
	if i < 0 {
		return 0, 0, false
	}
	rest = rest[i+len(strings.TrimPrefix(IDPrefix, "# ")):]
	t, l, found := strings.Cut(rest, "_")
	if !found {
		return 0, 0, false
	}
	template, err := strconv.Atoi(t)
	if err != nil {
		return 0, 0, false
	}
	line, err = strconv.Atoi(l)
	return template, line, err == nil
}

// SearchKey is the stamp as the first key of a search key: without the leading
// "# " and the trailing ":".
func SearchKey(stamp string) string {
	return strings.TrimRight(strings.TrimLeft(stamp, "# "), ":")
}

// IsIDKey reports whether line is exactly the stamp that key stands for, as
// SearchKey builds it. A stamp stands only for its own ID, not for one it is a
// prefix of.
func IsIDKey(line, key string) bool {
	return IsIDLine(line) && strings.TrimSpace(line) == "# "+strings.TrimSuffix(key, ":")+":"
}
