package helmmarker

import (
	"bytes"
	"strconv"
	"strings"
)

// decimal is the base stamp numbers are written in.
const decimal = 10

// idName starts the text of every stamp, which a stamp line comments out and a
// search key starts with.
const idName = "KICS_HELM_ID_"

// IDPrefix starts every ID stamp line.
const IDPrefix = "# " + idName

// ID is a stamp, added above each top-level "apiVersion" of a template. It
// names the template and the source line, counted from 0, the stamp sits on:
// "# KICS_HELM_ID_<template>_<line>:".
type ID struct {
	Template, Line int
}

// Append appends the stamp line of id, with its line break.
func (id ID) Append(dst []byte) []byte {
	dst = append(dst, IDPrefix...)
	dst = strconv.AppendInt(dst, int64(id.Template), decimal)
	dst = append(dst, '_')
	dst = strconv.AppendInt(dst, int64(id.Line), decimal)
	return append(dst, ':', '\n')
}

// String is the stamp line of id, without its line break.
func (id ID) String() string {
	line := id.Append(nil)
	return string(line[:len(line)-1])
}

// SearchKey is id as the first key of a search key.
func (id ID) SearchKey() string {
	return strings.TrimSuffix(strings.TrimPrefix(id.String(), "# "), ":")
}

// ParseIDLine reads a stamp line, as Append writes it. Text that merely
// mentions the prefix, such as a string in a template, is not one.
func ParseIDLine(line string) (ID, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), IDPrefix)
	if !ok {
		return ID{}, false
	}
	rest, ok = strings.CutSuffix(rest, ":")
	if !ok {
		return ID{}, false
	}
	return parseNumbers(rest)
}

// ParseSearchKey reads a key of a search key that stands for a stamp, as
// SearchKey writes it, with or without the colon a key is matched with.
func ParseSearchKey(key string) (ID, bool) {
	rest, ok := strings.CutPrefix(key, idName)
	if !ok {
		return ID{}, false
	}
	return parseNumbers(strings.TrimSuffix(rest, ":"))
}

// parseNumbers reads the "<template>_<line>" of a stamp.
func parseNumbers(s string) (ID, bool) {
	template, line, ok := strings.Cut(s, "_")
	if !ok || !isDigits(template) || !isDigits(line) {
		return ID{}, false
	}
	t, tErr := strconv.Atoi(template)
	l, lErr := strconv.Atoi(line)
	return ID{Template: t, Line: l}, tErr == nil && lErr == nil
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

// FirstID returns the first stamp line of content, without its line break, or
// "" when it has none.
func FirstID(content string) string {
	for content != "" {
		line, rest, _ := strings.Cut(content, "\n")
		if id, ok := ParseIDLine(line); ok {
			return id.String()
		}
		content = rest
	}
	return ""
}

// RemoveIDLines drops every stamp line from content.
func RemoveIDLines(content []byte) []byte {
	if !bytes.Contains(content, []byte(IDPrefix)) {
		return content
	}
	kept := make([]byte, 0, len(content))
	for len(content) > 0 {
		line := content
		if i := bytes.IndexByte(content, '\n'); i >= 0 {
			line = content[:i+1]
		}
		content = content[len(line):]
		if bytes.Contains(line, []byte(IDPrefix)) {
			if _, ok := ParseIDLine(string(line)); ok {
				continue
			}
		}
		kept = append(kept, line...)
	}
	return kept
}
