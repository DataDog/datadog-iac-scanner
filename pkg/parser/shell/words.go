/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package shell

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Literal performs only quote removal for a single grammar-delimited word.
// Expansion, globbing, ANSI-C quoting and command substitution remain unknown.
func Literal(raw string) Value {
	if len(raw) > maxScriptBytes {
		return Value{Raw: raw}
	}
	var parsed *syntax.Word
	count := 0
	err := syntax.NewParser().Words(strings.NewReader(raw), func(w *syntax.Word) bool {
		count++
		if count == 1 {
			parsed = w
		}
		return count == 1
	})
	if err != nil || count != 1 || parsed == nil {
		return Value{Raw: raw}
	}
	if int(parsed.Pos().Offset()) != 0 || int(parsed.End().Offset()) != len(raw) {
		return Value{Raw: raw}
	}
	return wordValue(parsed, raw)
}

func wordValue(word *syntax.Word, raw string) Value {
	result := Value{Raw: raw}
	var text strings.Builder
	pattern := false
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.SglQuoted:
			if p.Dollar {
				return result
			}
			text.WriteString(p.Value)
		case *syntax.DblQuoted:
			if p.Dollar || !appendDoubleQuoted(&text, p.Parts) {
				return result
			}
		case *syntax.Lit:
			if !appendUnquotedLit(&text, p.Value, &pattern) {
				return result
			}
		default:
			return result
		}
	}
	if pattern {
		result.Pattern = text.String()
		return result
	}
	result.Text = text.String()
	if result.Raw == result.Text {
		result.Raw = ""
	}
	result.Known = true
	return result
}

func appendDoubleQuoted(text *strings.Builder, parts []syntax.WordPart) bool {
	for _, part := range parts {
		lit, ok := part.(*syntax.Lit)
		if !ok {
			return false
		}
		escaped := false
		for _, r := range lit.Value {
			if escaped {
				if !strings.ContainsRune("$`\"\\\n", r) {
					text.WriteByte('\\')
				}
				if r != '\n' {
					text.WriteRune(r)
				}
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			text.WriteRune(r)
		}
		if escaped {
			return false
		}
	}
	return true
}

func appendUnquotedLit(text *strings.Builder, value string, pattern *bool) bool {
	escaped := false
	var previous rune
	for _, r := range value {
		if escaped {
			if r != '\n' {
				text.WriteRune(r)
				previous = r
			}
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '~' && (text.Len() == 0 || previous == '=' || previous == ':') {
			return false
		}
		if r == '(' || r == ')' {
			return false
		}
		if strings.ContainsRune("*?[]{}", r) {
			*pattern = true
		}
		text.WriteRune(r)
		previous = r
	}
	return !escaped
}
