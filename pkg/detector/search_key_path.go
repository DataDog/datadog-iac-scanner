/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package detector

import (
	"strconv"
	"strings"
)

// splitProtectedSearchKey replaces wrapped values before tokenising the key.
// The caller's placeholder and split policies preserve its search syntax.
func splitProtectedSearchKey(
	searchKey string, placeholder func(int) string, split func(string) []string,
) (segments []string, extracted [][]string) {
	extracted = GetBracketValues(searchKey, nil, "")
	for i, wrapped := range extracted {
		searchKey = strings.ReplaceAll(searchKey, wrapped[0], placeholder(i))
	}
	return split(searchKey), extracted
}

func legacySearchKeyPlaceholder(index int) string {
	return "{{" + strconv.Itoa(index) + "}}"
}

func opaqueSearchKeyPlaceholder(index int) string {
	return "\x00" + strconv.Itoa(index) + "\x00"
}

func resolvePlaceholders(seg string, extracted [][]string) string {
	for i, wrapped := range extracted {
		seg = strings.ReplaceAll(seg, legacySearchKeyPlaceholder(i), wrapped[1])
	}
	return seg
}

func splitLiteralDots(searchKey string) []string {
	return strings.Split(searchKey, ".")
}

func splitLegacySearchKey(searchKey string, split func(string) []string) (segments []string, extracted [][]string) {
	segments, extracted = splitProtectedSearchKey(searchKey, legacySearchKeyPlaceholder, split)

	// Keep dots in $ref values so a segment such as the 0 in v1.0.Foo
	// is never mistaken for an array index.
	for i, segment := range segments {
		if strings.Contains(segment, "$ref") {
			segments[i] = strings.Join(segments[i:], ".")
			return segments[:i+1], extracted
		}
	}
	return segments, extracted
}

// expandSearchKeyPath turns a search key into structural path components:
// dropping any value anchor ("key=value"), splitting on top-level dots, and
// expanding bracket groups ("group[name]" -> group, name), stripping the
// "{{ }}" templating some Rego rules wrap the name in.
//
// Bracket contents can contain dots (module-prefixed keys, e.g.
// "type[module.foo.name]") and/or a count/for_each suffix bracket (e.g.
// "type[this[0]]"), so the top-level dot-split ignores dots inside an
// unclosed "[...]" (see splitTopLevelDots), and a group's closing bracket is
// found by findMatchingBracket, which is quote- and nesting-aware since a
// for_each key can itself contain a literal "]" (e.g. module.secrets["prod]eu"]).
func expandSearchKeyPath(searchKey string) []string {
	// Drop the value anchor (key=value) up front; the value may contain dots.
	if eq := strings.Index(searchKey, "="); eq >= 0 {
		searchKey = searchKey[:eq]
	}
	var comps []string
	for _, seg := range splitTopLevelDots(searchKey) {
		comps = appendBracketSegment(comps, strings.TrimSpace(seg), nil, trimWrappedBracketKey)
	}
	return comps
}

// appendBracketSegment expands a segment like Statement[0] into path
// components. When extracted is supplied, each component is restored only
// after its bracket boundaries have been identified.
func appendBracketSegment(parts []string, seg string, extracted [][]string, bracketKey func(string) string) []string {
	for seg != "" {
		open := strings.Index(seg, "[")
		if open < 0 {
			return append(parts, resolvePlaceholders(seg, extracted))
		}
		if head := seg[:open]; head != "" {
			parts = append(parts, resolvePlaceholders(head, extracted))
		}
		closeIdx := findMatchingBracket(seg, open)
		if closeIdx < 0 {
			break
		}
		inner := bracketKey(resolvePlaceholders(seg[open+1:closeIdx], extracted))
		if inner != "" {
			parts = append(parts, inner)
		}
		seg = seg[closeIdx+1:]
	}
	return parts
}

func trimWrappedBracketKey(inner string) string {
	return strings.TrimSuffix(strings.TrimPrefix(inner, "{{"), "}}")
}

func unquoteWrappedBracketKey(inner string) string {
	inner = trimWrappedBracketKey(inner)
	if len(inner) < 2 || inner[0] != '"' || inner[len(inner)-1] != '"' {
		return inner
	}
	if unquoted, err := strconv.Unquote(inner); err == nil {
		return unquoted
	}
	return inner[1 : len(inner)-1]
}

// findMatchingBracket finds the "]" closing the "[" at open in s, tracking
// nested brackets and quoting so a quoted for_each key's own "]" isn't mistaken
// for the group's close.
func findMatchingBracket(s string, open int) int {
	depth := 0
	for i := open + 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			i = skipQuotedSearchKey(s, i)
		case '[':
			depth++
		case ']':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}

// splitTopLevelDots splits s on "." like strings.Split, except dots inside an
// unclosed "[...]" group aren't treated as separators, e.g.
// "type[module.foo.name].attr" splits into ["type[module.foo.name]", "attr"].
// Quote-aware like findMatchingBracket.
func splitTopLevelDots(s string) []string {
	var segs []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			i = skipQuotedSearchKey(s, i)
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case '.':
			if depth == 0 {
				segs = append(segs, s[start:i])
				start = i + 1
			}
		}
	}
	return append(segs, s[start:])
}

// skipQuotedSearchKey returns the closing quote's index, or len(s) if the
// quoted text runs to the end. An escaped quote stays inside the key.
func skipQuotedSearchKey(s string, open int) int {
	for i := open + 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}
	return len(s)
}

// SourceSearchPath interprets the legacy path syntax for trusted source routing.
// Wrapped literal names remain intact, including dots and equals signs.
func SourceSearchPath(searchKey string) []string {
	var path []string
	for _, part := range sourceSelectors(searchKey) {
		if part.value != nil {
			return nil
		}
		path = append(path, part.key)
	}
	return path
}
