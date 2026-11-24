/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package dockerfile provides Dockerfile source validation helpers shared by
// file classification and pushed-content filtering.
package dockerfile

import (
	"bytes"
	"strings"
	"unicode"

	"github.com/moby/buildkit/frontend/dockerfile/command"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

const maxHeaderScanBytes = 64 << 10

var (
	utf8BOM  = []byte{0xef, 0xbb, 0xbf}
	argWord  = []byte(command.Arg)
	fromWord = []byte(command.From)
)

// HasFrom reports whether content is a parseable Dockerfile whose first
// non-ARG instruction is a FROM with an image or stage argument.
// Obvious non-Dockerfile headers are rejected before invoking BuildKit.
func HasFrom(content []byte) bool {
	if rejectsHeader(content) {
		return false
	}
	parsed, err := parser.Parse(bytes.NewReader(content))
	return err == nil && startsWithFrom(parsed)
}

func startsWithFrom(parsed *parser.Result) bool {
	if parsed == nil || parsed.AST == nil {
		return false
	}
	for _, node := range parsed.AST.Children {
		if strings.EqualFold(node.Value, command.Arg) {
			continue
		}
		return strings.EqualFold(node.Value, command.From) && node.Next != nil
	}
	return false
}

// rejectsHeader cheaply filters out files whose first non-comment, non-ARG
// line cannot begin a FROM instruction. Any line with a backslash or backtick
// escape token is deferred to BuildKit rather than reimplementing its
// directive and continuation grammar.
func rejectsHeader(content []byte) bool {
	rest := bytes.TrimPrefix(content, utf8BOM)
	scanned := 0
	for len(rest) > 0 {
		if scanned >= maxHeaderScanBytes {
			return false
		}
		var line []byte
		if nl := bytes.IndexByte(rest, '\n'); nl >= 0 {
			line, rest = rest[:nl], rest[nl+1:]
			scanned += nl + 1
		} else {
			line, rest = rest, nil
			scanned += len(line)
		}
		trimmed := bytes.TrimLeftFunc(line, unicode.IsSpace)
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}
		word := firstToken(trimmed)
		// A keyword or ARG may be continued across lines using \ or `.
		if bytes.ContainsAny(word, "\\`") {
			return false
		}
		if bytes.EqualFold(word, fromWord) {
			return false
		}
		if !bytes.EqualFold(word, argWord) {
			return true
		}
		// Multi-line leading ARG is deferred to BuildKit.
		if bytes.ContainsAny(trimmed, "\\`") {
			return false
		}
	}
	// Reached EOF within maxHeaderScanBytes without seeing FROM or an escape.
	return true
}

func firstToken(line []byte) []byte {
	if end := bytes.IndexAny(line, " \t\r\v\f"); end >= 0 {
		return line[:end]
	}
	return line
}
