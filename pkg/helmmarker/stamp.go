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
var idLinePattern = regexp.MustCompile(`(?m)^[ \t]*# KICS_HELM_ID_\d+_\d+:[ \t]*(?:\r?\n|$)`)

// AppendID appends the stamp line of the template numbered template for the
// source line line (counted from 0).
func AppendID(dst []byte, template, line int) []byte {
	dst = append(dst, IDPrefix...)
	dst = strconv.AppendInt(dst, int64(template), decimal)
	dst = append(dst, '_')
	dst = strconv.AppendInt(dst, int64(line), decimal)
	return append(dst, ':', '\n')
}

// IsIDLine reports whether line is a stamp, as AppendID writes it. Text that
// merely mentions the prefix, such as a string in a template, is not one.
func IsIDLine(line string) bool {
	line = strings.TrimSpace(line)
	rest, ok := strings.CutPrefix(line, IDPrefix)
	if !ok {
		return false
	}
	template, line2, ok := strings.Cut(strings.TrimSuffix(rest, ":"), "_")
	return ok && strings.HasSuffix(rest, ":") && isDigits(template) && isDigits(line2)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// FirstID returns the first stamp line of content, or "" when it has none.
func FirstID(content string) string {
	for content != "" {
		line, rest, _ := strings.Cut(content, "\n")
		if IsIDLine(line) {
			return strings.TrimSpace(line)
		}
		content = rest
	}
	return ""
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

// IsIDSearchKey reports whether key, a key of a search key, names a stamp as
// SearchKey builds it.
func IsIDSearchKey(key string) bool {
	return strings.HasPrefix(key, strings.TrimPrefix(IDPrefix, "# "))
}

// IsIDKey reports whether line is exactly the stamp that key stands for, as
// SearchKey builds it. A stamp stands only for its own ID, not for one it is a
// prefix of.
func IsIDKey(line, key string) bool {
	return IsIDLine(line) && strings.TrimSpace(line) == "# "+strings.TrimSuffix(key, ":")+":"
}
